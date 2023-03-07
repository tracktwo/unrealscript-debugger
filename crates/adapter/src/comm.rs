use std::time::Duration;

use common::{
    Breakpoint, Frame, FrameIndex, StackTraceRequest, StackTraceResponse, UnrealCommand,
    UnrealEvent, UnrealInterfaceMessage, UnrealResponse, Variable, VariableIndex, WatchKind,
};
use futures::SinkExt;
use thiserror::Error;
use tokio::{net::TcpStream, select, sync::mpsc, task::spawn_blocking};
use tokio_serde::formats::Json;
use tokio_stream::StreamExt;
use tokio_util::codec::LengthDelimitedCodec;

/// An error sending or receiving data across the channel.
#[derive(Debug, Error)]
pub enum ChannelError {
    /// Timed out waiting for a response.
    #[error("Timeout")]
    Timeout,
    /// An I/O error communicating across the channel
    #[error("Connection error")]
    ConnectionError,
    /// A serialization or deserialization error.
    #[error("IO error: {0}")]
    IoError(std::io::Error),

    /// Received an unexpected response.
    #[error("Protocol error")]
    ProtocolError,
}

impl From<std::io::Error> for ChannelError {
    fn from(value: std::io::Error) -> Self {
        ChannelError::IoError(value)
    }
}

/// The UnrealChannel uses two communications modes for talking to the debugger interface.
///
/// A TCP socket is used to send commands from the adapter to the interface. This socket
/// can also receive asynchronous events from the interface to the adapter.
///
/// It also has a separate shared memory channel to send responses from the
/// interface to the adapter. These are guaranteed to arrive in a specific order in response
/// to commands, and some of the responses can be very large (e.g. watch data).
///
/// This split model allows for a simpler communications scheme between the adapter and the
/// interface, since the order in which responses appear in the shared memory channel are
/// predictable and no asynchronous events may appear in that communicaiton channel at
/// unpredictable times. For example, when setting a breaking the code can rely on the
/// breakpoint response appearing next in the response channel, even if asynchronous log
/// events come in from Unreal at the same time.
pub struct UnrealChannel {
    response_receiver: mpsc::Receiver<UnrealResponse>,
    event_receiver: mpsc::Receiver<UnrealEvent>,
    command_sender: mpsc::Sender<UnrealCommand>,
}

/// The amount of time to wait for the connection to complete.
const CONNECT_TIMEOUT: i32 = 30;

macro_rules! expect_response {
    ($e:expr, $p:path) => {
        match $e {
            Some($p(x)) => Ok(x),
            Some(_) => Err(ChannelError::ProtocolError),
            None => Err(ChannelError::ConnectionError),
        }
    };
}

impl UnrealChannel {
    pub fn new(
        response_receiver: mpsc::Receiver<UnrealResponse>,
        event_receiver: tokio::sync::mpsc::Receiver<UnrealEvent>,
        command_sender: mpsc::Sender<UnrealCommand>,
    ) -> Self {
        Self {
            response_receiver,
            event_receiver,
            command_sender,
        }
    }

    /// Fetch the next response from the channel.
    fn next_response(&mut self) -> Option<UnrealResponse> {
        self.response_receiver.blocking_recv()
    }

    /// Fetch the next event from the channel.
    pub async fn next_event(&mut self) -> Option<UnrealEvent> {
        self.event_receiver.recv().await
    }

    // TODO Are all these unwraps ok?
    pub fn add_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::AddBreakpoint(bp))
            .unwrap();
        expect_response!(self.next_response(), UnrealResponse::BreakpointAdded)
    }

    pub fn remove_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::RemoveBreakpoint(bp))
            .unwrap();
        expect_response!(self.next_response(), UnrealResponse::BreakpointRemoved)
    }

    /// Send a stack trace request across the channel and read the resulting stack frames.
    pub fn stack_trace(
        &mut self,
        req: StackTraceRequest,
    ) -> Result<StackTraceResponse, ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::StackTrace(req))
            .unwrap();
        expect_response!(self.next_response(), UnrealResponse::StackTrace)
    }

    pub fn watch_count(
        &mut self,
        kind: WatchKind,
        parent: VariableIndex,
    ) -> Result<usize, ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::WatchCount(kind, parent))
            .unwrap();
        expect_response!(self.next_response(), UnrealResponse::WatchCount)
    }

    pub fn frame(&mut self, frame: FrameIndex) -> Result<Option<Frame>, ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::Frame(frame))
            .unwrap();
        expect_response!(self.next_response(), UnrealResponse::Frame)
    }

    pub fn evaluate(&mut self, expr: &str) -> Result<Option<Variable>, ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::Evaluate(expr.to_string()))
            .unwrap();
        expect_response!(self.next_response(), UnrealResponse::Evaluate)
    }

    pub fn variables(
        &mut self,
        kind: WatchKind,
        frame: FrameIndex,
        variable: VariableIndex,
        start: usize,
        count: usize,
    ) -> Result<(Vec<Variable>, bool), ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::Variables(
                kind, frame, variable, start, count,
            ))
            .unwrap();

        // A variables response can result in one of two different message cases
        // depending on whether the result was deferred or not.
        match self.next_response() {
            Some(UnrealResponse::Variables(vars)) => Ok((vars, false)),
            Some(UnrealResponse::DeferredVariables(vars)) => Ok((vars, true)),
            Some(_) => Err(ChannelError::ProtocolError),
            None => Err(ChannelError::ConnectionError),
        }
    }

    // TODO This and below don't need to return result
    pub fn pause(&mut self) -> Result<(), ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::Pause)
            .unwrap();
        Ok(())
    }

    pub fn go(&mut self) -> Result<(), ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::Go)
            .unwrap();
        Ok(())
    }

    pub fn next(&mut self) -> Result<(), ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::Next)
            .unwrap();
        Ok(())
    }

    pub fn step_in(&mut self) -> Result<(), ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::StepIn)
            .unwrap();
        Ok(())
    }

    pub fn step_out(&mut self) -> Result<(), ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::StepOut)
            .unwrap();
        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), ChannelError> {
        self.command_sender
            .blocking_send(UnrealCommand::Disconnect)
            .unwrap();
        Ok(())
    }
}

/// Connect to an unreal debugger adapter running at the given port number on the local computer.
pub async fn connect(port: u16) -> Result<UnrealChannel, ChannelError> {
    let mut tcp: Option<TcpStream> = None;

    // Try to connect, sleeping between attempts.
    for _ in 0..CONNECT_TIMEOUT {
        match TcpStream::connect(format!("127.0.0.1:{port}")).await {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(_) => {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    // If we failed to connect we can't go any further.
    let tcp = tcp.ok_or(ChannelError::ConnectionError)?;

    // Create channels to manage sending commands to and receiving events from the
    // interface TCP connection.
    let (ctx, crx) = mpsc::channel(128);
    let (etx, erx) = mpsc::channel(128);
    let (rtx, rrx) = mpsc::channel(128);

    // Spawn a new task to manage these channels and the TCP connection.
    tokio::spawn(async { debuggee_tcp_loop(tcp, rtx, etx, crx).await });
    Ok(UnrealChannel {
        response_receiver: rrx,
        event_receiver: erx,
        command_sender: ctx,
    })
}

/// Task for managing a TCP connection to the debugger interface.
///
/// This is intended to be spawned as an independent task which will coordinate
/// communication between the interface's socket and the main debugger adapter.
/// This communication is done via channels.
async fn debuggee_tcp_loop(
    tcp: TcpStream,
    response_sender: mpsc::Sender<UnrealResponse>,
    event_sender: mpsc::Sender<UnrealEvent>,
    mut command_receiver: mpsc::Receiver<UnrealCommand>,
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
                        // adapter.
                        event_sender.send(event).await.unwrap();
                    },
                    Some(Ok(UnrealInterfaceMessage::Response(resp))) => {
                        // We've received an event from the interface. Send it along to the
                        // adapter.
                        response_sender.send(resp).await.unwrap();
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
                        // TODO: We should cancel this task before dropping the adapter, then
                        // this can't happen.
                        log::error!("End of stream reading from the command channel.");
                        return;
                    }
                }
            }
        }
    }
}
