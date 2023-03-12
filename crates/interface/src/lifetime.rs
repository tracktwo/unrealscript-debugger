//! Lifetime management for the Unrealscript debugger interface.
//!
//! This module contains functions and data structures related to maintaining
//! state outside of Unreal for the lifetime of a debugging session.
//!
//! The debug adapter DLL's lifetime is entirely controlled by Unreal. The
//! DLL is loaded when a debugging session starts, and is unloaded when the
//! debugging session ends. This is a toal unload and the DLL is unmapped from
//! memory entirely, so we need to be careful to allow for graceful shutdown
//! when the debugging session is ending. This is made more difficult because
//! Unreal doesn't actually directly tell us when this is going to happen,
//! we can only infer it.
//!
//! A debugging session can start in two ways:
//!
//! - When the game is launched with -autoDebug. The debugger interface is then
//! loaded as part of game startup and we receive a normal init sequence and then
//! unreal will automatically break at the first opportunity.
//!
//! - When the user enters a '\toggledebugger' command. The debugger interface
//! is loaded and we receive an init sequence, but Unreal does not break.
//!
//! The debugging session can end in three ways:
//!
//! - When the user quits the game while a debugging session is active.
//! - When the user enters the '\toggledebugger' command while a debugging
//! session is active.
//! - When the 'stopdebugging' command is sent to Unreal.
//!
//! The first two cases are the same, the last is slightly different because
//! the command originates inside the debugger interface. But all three perform
//! the same shutdown sequence and then unload the DLL from memory. We must be
//! _very_ careful to ensure this happens cleanly, as any lingering code that
//! tries to run after the DLL is unloaded will almost certainly cause a crash.
//!
//! The 'initialize' function is used to set up the debugger state when we are
//! starting a debugging session.

use std::{
    net::SocketAddr,
    sync::{Condvar, Mutex},
    thread,
};

use common::{UnrealCommand, UnrealInterfaceMessage, DEFAULT_PORT};
use flexi_logger::{FileSpec, FlexiLoggerError, Logger, LoggerHandle};
use futures::prelude::*;
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Builder,
    select,
    sync::{
        broadcast::{self, Receiver},
        mpsc,
    },
};
use tokio_serde::formats::SymmetricalJson;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::{
    api::UnrealCallback,
    debugger::{CommandAction, Debugger, DebuggerError},
};

/// The debugger state. Calls from Unreal are dispatched into this instance.
pub static DEBUGGER: Mutex<Option<Debugger>> = Mutex::new(None);

static LOGGER: Mutex<Option<LoggerHandle>> = Mutex::new(None);

pub static VARIABLE_REQUST_CONDVAR: Condvar = Condvar::new();

/// Initialize the debugger instance. This should be called exactly once when
/// Unreal first initializes us. Responsible for building the shared state object
/// the other Unreal entry points will use and spawning the main loop thread
/// that will perform I/O with the debugger adapter.
pub fn initialize(cb: UnrealCallback) {
    if let Ok(dbg) = DEBUGGER.lock().as_mut() {
        assert!(dbg.is_none(), "Initialize already called.");

        // Start the logger. If this fails there isn't much we can do.
        let _ = init_logger();

        // Register a panic handler that will log to the log file, since our stdout/stderr
        // are not connected to anything.
        std::panic::set_hook(Box::new(|p| {
            log::error!("Panic: {p:#?}");
        }));

        // Create a channel pair for shutting down the interface. This is used when
        // we receive a signal that Unreal is about to kill the debugging session. The
        // debugger instance owns the tx side and can send the event when this happens.
        // The separate thread we spawn below owns the receiving side and uses this to
        // cleanly stop itself.
        let (ctx, crx) = broadcast::channel(10);

        // Start the main loop that will listen for connections so we can
        // communiate the debugger state to the adapter. This will spin up a
        // new async runtime for this thread only and wait for the main loop
        // to complete.
        let handle = thread::spawn(move || {
            let rt = Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("Failed to create runtime");
            rt.block_on(async {
                match main_loop(cb, crx).await {
                    Ok(()) => (),
                    Err(e) => {
                        // Something catastrophic failed in the main loop. Log it
                        // and exit the thread, there is little else we can do.
                        log::error!("Error in debugger main loop: {e}");
                    }
                }
            });
        });

        // Construct the debugger state.
        dbg.replace(Debugger::new(ctx, Some(handle)));
    }
}

/// Initialize the logging interface.
fn init_logger() -> Result<(), FlexiLoggerError> {
    let mut logger = LOGGER.lock().unwrap();
    assert!(logger.is_none(), "Already have a logger. Multiple inits?");
    let new_logger = Logger::try_with_env_or_str("trace")?
        .log_to_file(FileSpec::default().directory("DebuggerLogs"))
        .start()?;
    logger.replace(new_logger);
    Ok(())
}

/// An enum representing the result of a client connection.
enum ConnectionResult {
    /// The client disconnected without signalling that the debugging session
    /// should end. This could be due to an interruption and the client may
    /// be able to reconnect later. This result means the lifetime of the debugging
    /// session hasn't ended and that we should try to accept another connection.
    Disconnected,
    Shutdown,
}

/// The main worker thread for the debugger interface. This is created when the
/// debugger session is created, and returns when the debugger session ends.
async fn main_loop(cb: UnrealCallback, mut crx: Receiver<()>) -> Result<(), tokio::io::Error> {
    // Start listening on a socket for connections from the adapter.
    let addr: SocketAddr = format!("127.0.0.1:{DEFAULT_PORT}")
        .parse()
        .expect("Failed to parse address");

    let server = TcpListener::bind(addr).await?;
    loop {
        select! {
            conn = server.accept() => {
                let (mut socket, addr) = conn?;
                log::info!("Received connection from {addr}");
                match handle_connection(&mut socket, cb, &mut crx).await? {
                    // Client disconnected: keep looping and accept another connection
                    ConnectionResult::Disconnected => (),
                    // We're shutting down: close down this loop.
                    ConnectionResult::Shutdown => break,
                }
            }
            _ = crx.recv() => {
                log::info!("Received shutdown message. Closing main loop.");
                break;
            }
        }
    }
    Ok(())
}

/// Accept one connection from the debugger adapter and process commands from it until it
/// disconnects.
///
/// We accept only a single connection at a time, if multiple adapters attempt to connect
/// we'll process them in sequence.
async fn handle_connection(
    stream: &mut TcpStream,
    cb: UnrealCallback,
    crx: &mut Receiver<()>,
) -> Result<ConnectionResult, tokio::io::Error> {
    // Create a new message passing channel and send the sender to the debugger.
    let (etx, mut erx) = mpsc::channel(128);

    {
        // TODO Remove this: have the channel persist across connections by moving
        // it to the constructor for the debugger.
        let mut hnd = DEBUGGER.lock().unwrap();
        let dbg = hnd.as_mut().unwrap();
        dbg.new_connection(etx);
    }
    let (reader, writer) = stream.split();
    let delimiter = FramedRead::new(reader, LengthDelimitedCodec::new());

    let mut deserializer = tokio_serde::SymmetricallyFramed::new(
        delimiter,
        SymmetricalJson::<UnrealCommand>::default(),
    );

    let delimiter = FramedWrite::new(writer, LengthDelimitedCodec::new());
    let mut serializer = tokio_serde::SymmetricallyFramed::new(
        delimiter,
        SymmetricalJson::<UnrealInterfaceMessage>::default(),
    );

    loop {
        select! {
            command = deserializer.try_next() => {
                match command? {
                    Some(command) => {
                        match dispatch_command(command) {
                            CommandAction::Nothing => (),
                            CommandAction::Callback(vec) => (cb)(vec.as_ptr()),
                            CommandAction::StopDebugging => return Ok(ConnectionResult::Shutdown),
                        }
                    },
                    None => break,
                };
            },
            evt = erx.recv() => {
                match evt {
                    // TODO fix unwrap
                    Some(evt) => serializer.send(evt).await.unwrap(),
                    None => break,
                };
            },
            _ = crx.recv() => {
                log::info!("Received shutdown message. Closing connection.");
                return Ok(ConnectionResult::Shutdown);
            }
        }
    }

    log::info!("Client disconnected.");
    Ok(ConnectionResult::Disconnected)
}

fn dispatch_command(command: UnrealCommand) -> CommandAction {
    let mut hnd = DEBUGGER.lock().unwrap();
    loop {
        let dbg = hnd.as_mut().unwrap();
        if dbg.pending_variable_request() {
            // There is still an outstanding variable request. We can't do anything until
            // this is finished.
            log::info!("Waiting for variable request to complete...");
            hnd = VARIABLE_REQUST_CONDVAR.wait(hnd).unwrap();
        } else {
            break;
        }
    }
    let dbg = hnd.as_mut().unwrap();
    match dbg.handle_command(command) {
        Ok(action) => action,

        // TODO fix the error cases.
        Err(DebuggerError::InitializeFailure) => {
            log::error!("Failed to initialize");
            CommandAction::Nothing
        }
        Err(DebuggerError::NotConnected) => {
            log::error!("Not connected");
            CommandAction::Nothing
        }
    }
}
