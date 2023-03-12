//! TCP-based connection to Unreal

use std::time::Duration;

use common::{UnrealCommand, UnrealEvent, UnrealInterfaceMessage, UnrealResponse};
use futures::SinkExt;
use tokio::{
    net::TcpStream,
    select,
    sync::mpsc::{channel, Receiver, Sender},
    task::JoinHandle,
};
use tokio_serde::formats::Json;
use tokio_stream::StreamExt;
use tokio_util::codec::LengthDelimitedCodec;

use super::{Connection, ConnectionError};

/// The number of connection attempts to make
const CONNECT_ATTEMPTS: i32 = 10;
// The amount of time to wait between each connection
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// A TCP-based connection between the debug adapter and the Unreal debugger
/// interface.
pub struct TcpConnection {
    response_receiver: Receiver<UnrealResponse>,
    command_sender: Sender<UnrealCommand>,
    event_receiver: Receiver<UnrealEvent>,
    handle: JoinHandle<()>,
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl TcpConnection {
    /// Connect to an unreal debugger adapter running at the given port number on the local computer.
    pub async fn connect(port: u16) -> Result<TcpConnection, ConnectionError> {
        let mut tcp: Option<TcpStream> = None;

        // Try to connect, sleeping between attempts. This sleep is intended to give
        // enough time for a launched Unreal process to get to the point where the
        // interface has opened the listening socket.
        for _ in 0..CONNECT_ATTEMPTS {
            match TcpStream::connect(format!("127.0.0.1:{port}")).await {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(CONNECT_TIMEOUT).await;
                }
            }
        }

        // If we failed to connect we can't go any further.
        let tcp = tcp.ok_or(ConnectionError::Disconnected)?;

        log::trace!("Connected to interface");

        // Create channels to manage sending commands to and receiving events from the
        // interface TCP connection.
        let (ctx, crx) = channel(128);
        let (rtx, rrx) = channel(128);
        let (etx, erx) = channel(128);

        // Spawn a new task to manage these channels and the TCP connection.
        let handle = tokio::spawn(async { debuggee_tcp_loop(tcp, rtx, etx, crx).await });
        Ok(TcpConnection {
            response_receiver: rrx,
            command_sender: ctx,
            event_receiver: erx,
            handle,
        })
    }
}

impl Connection for TcpConnection {
    fn send_command(&mut self, command: UnrealCommand) -> Result<(), ConnectionError> {
        match futures::executor::block_on(self.command_sender.send(command)) {
            Ok(()) => Ok(()),
            Err(_) => Err(ConnectionError::Disconnected),
        }
    }

    fn next_response(&mut self) -> Result<UnrealResponse, ConnectionError> {
        log::trace!("Waiting for next response...");
        futures::executor::block_on(self.response_receiver.recv())
            .ok_or(ConnectionError::Disconnected)
    }

    fn event_receiver(&mut self) -> &mut Receiver<UnrealEvent> {
        &mut self.event_receiver
    }
}

/// Task for managing a TCP connection to the debugger interface.
///
/// This is intended to be spawned as an independent task which will coordinate
/// communication between the interface's socket and the main debugger adapter.
/// This communication is done via channels.
async fn debuggee_tcp_loop(
    tcp: TcpStream,
    response_sender: Sender<UnrealResponse>,
    event_sender: Sender<UnrealEvent>,
    mut command_receiver: Receiver<UnrealCommand>,
) {
    // Adapt the tcp socket into an asymmetrical source + sink for Json objects.
    // Across this TCP socket we will send UnrealCommands to the interface, and
    // receive UnrealEvents from that interface. These will always be length-delimited.

    // Construct a frame codec using length-delimited fields.
    let frame = tokio_util::codec::Framed::new(tcp, LengthDelimitedCodec::new());

    // Build a json formatter that can deserialize events and serialize commands.
    let format: Json<UnrealInterfaceMessage, UnrealCommand> = Json::default();

    // Build a source + sink for that Json format on top of our framing system.
    let mut tcp_stream = tokio_serde::Framed::new(frame, format);

    loop {
        select! {
            event = tcp_stream.next() => {
                match event {
                    Some(Ok(UnrealInterfaceMessage::Event(event))) => {
                        // We've received an event from the interface. Send it along to the
                        // adapter's main processing loop where it will decode the event and
                        // decide what to do with it. The receiving side must still be alive
                        // since it's tied to the lifetime of the connection object which
                        // would have aborted this task if it was dropping.
                        event_sender.send(event).await.expect("Event receiver must still be alive");
                    },
                    Some(Ok(UnrealInterfaceMessage::Response(resp))) => {
                        // We've received an event from the interface. Send it along to the
                        // adapter. See above for the rationale why expect is safe here.
                        response_sender.send(resp).await.expect("Response receiver must still be alive");
                    },
                    Some(Err(e)) => {
                        // An error has occurred.
                        log::error!("Error receiving event from interface: {e}");
                        return;
                    }
                    None => {
                        // The connection has closed. If this was a graceful shutdown
                        // we should have received a shutdown event first and dispatched
                        // it to the adapter. Or, perhaps Unreal has crashed.
                        log::info!("Connection closed from interface.");
                        return;
                    }
                };
            }
            command = command_receiver.recv() => {
                match command {
                    Some(command) => {
                        // We've received a command from the adapter. Send it to the
                        // interface. When this happens we'll log the error and return,
                        // which will drop the sending portions of the response and event
                        // channels that we own. This will be detected either by the
                        // main adapter loop.
                        match tcp_stream.send(command).await {
                            Ok(()) => {},
                            Err(e) => {
                                log::error!("IO error sending command to Unreal: {e}");
                                return;
                            }
                        } ;
                    },
                    None => {
                        // The adapter has dropped the sending part of this stream.
                        // This should never happen since we abort this task in the destructor
                        // for the connection object before the command sender is dropped.
                        unreachable!("TCP task should be cancelled before the sender drops");
                    }
                }
            }
        }
    }
}
