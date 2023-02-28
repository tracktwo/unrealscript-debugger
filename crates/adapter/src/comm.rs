use std::{net::TcpStream, time::Duration};

use common::{
    Breakpoint, Frame, FrameIndex, StackTraceRequest, StackTraceResponse, UnrealCommand,
    UnrealResponse, Variable, VariableIndex, WatchKind,
};
use ipmpsc::{Receiver, SharedRingBuffer};
use serde::Serialize;
use serde_json::{de::IoRead, Deserializer, Serializer};
use thiserror::Error;

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
    #[error("Serialization error: {0}")]
    SerializationError(serde_json::Error),

    /// Received an unexpected response.
    #[error("Protocol error")]
    ProtocolError,
}

impl From<serde_json::Error> for ChannelError {
    fn from(value: serde_json::Error) -> Self {
        ChannelError::SerializationError(value)
    }
}

/// A representation for communications between the adapter and interface.
///
// TODO: Currently the adapter is sent across a thread boundary, and the adapter
// holds the channel so this must be Send + 'static. This could be eliminated if
// we restructure things so that the adapter can be constructed inside the thread
// instead of being moved into it.
pub trait UnrealChannel: Send + 'static {
    /// Add a breakpoint, receiving the verified breakpoint from unreal.
    fn add_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ChannelError>;

    // Remove a breakpoint, receiving the removed breakpoint from unreal.
    fn remove_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ChannelError>;

    fn stack_trace(&mut self, stack: StackTraceRequest)
        -> Result<StackTraceResponse, ChannelError>;

    fn watch_count(
        &mut self,
        kind: WatchKind,
        parent: VariableIndex,
    ) -> Result<usize, ChannelError>;

    fn frame(&mut self, frame: FrameIndex) -> Result<Option<Frame>, ChannelError>;

    fn variables(
        &mut self,
        kind: WatchKind,
        frame: FrameIndex,
        variable: VariableIndex,
        start: usize,
        count: usize,
    ) -> Result<(Vec<Variable>, bool), ChannelError>;

    fn evaluate(&mut self, expr: &str) -> Result<Option<Variable>, ChannelError>;

    fn go(&mut self) -> Result<(), ChannelError>;
    fn pause(&mut self) -> Result<(), ChannelError>;
    fn next(&mut self) -> Result<(), ChannelError>;
    fn step_in(&mut self) -> Result<(), ChannelError>;
    fn step_out(&mut self) -> Result<(), ChannelError>;
}

/// The DefaultChannel uses two communications modes for talking to the debugger interface.
///
/// A TCP socket is used to send commands from the adapter to the interface. This socket
/// can also receive asynchronous events from the interface to the adapter.
///
/// It also has a separate shared memory channel to send responses from the
/// interface to the adapter. These are guaranteed to arrive in a specific order in response
/// to commands, and some of the responses can be very large (e.g. watch data).
///
/// This split model allows for a simpler communications scheme between the adapter and the
/// interface:
///
///  - The adapter can spin up a thread responsible only for monitoring the TCP socket for
///  asynchronous events. These can occur at any time in unpredictable orders.
///  - Synchronous communication of command to one or more responses can be done on the adapter's
///  main message processing thread.
pub struct DefaultChannel {
    response_receiver: Receiver,
    sender: Serializer<TcpStream>,
}

/// The default size for the shared memory buffer.
const SHARED_MEMORY_SIZE: u32 = 1024 * 1024 * 16;

/// The timeout for receiving responses from the adapter
const RECV_TIMEOUT: Duration = Duration::from_secs(15);

/// The amount of time to wait for the connection to complete.
const CONNECT_TIMEOUT: i32 = 30;

impl DefaultChannel {
    /// Fetch the next response from the channel.
    ///
    /// ### Errors:
    ///   Returns a ChannelError::ConnectionError if the message channel encounters an error.
    ///   Returns a ChannelError::Timeout if a message does not appear in a reasonable time.
    fn next_response(&mut self) -> Result<UnrealResponse, ChannelError> {
        self.response_receiver
            .recv_timeout(RECV_TIMEOUT)
            .or(Err(ChannelError::ConnectionError))?
            .ok_or(ChannelError::Timeout)
    }
}
impl UnrealChannel for DefaultChannel {
    fn add_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ChannelError> {
        // Send the breakpoint to the interface
        UnrealCommand::AddBreakpoint(bp).serialize(&mut self.sender)?;

        // This should result in exactly one breakpoint response from the interface.
        match self.next_response() {
            Ok(UnrealResponse::BreakpointAdded(bp)) => Ok(bp),
            Ok(_) => Err(ChannelError::ProtocolError),
            Err(e) => Err(e),
        }
    }

    fn remove_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ChannelError> {
        // Send the breakpoint removal to the interface
        UnrealCommand::RemoveBreakpoint(bp).serialize(&mut self.sender)?;

        // This should result in exactly one breakpoint response from the interface.
        match self.next_response() {
            Ok(UnrealResponse::BreakpointRemoved(bp)) => Ok(bp),
            Ok(_) => Err(ChannelError::ProtocolError),
            Err(e) => Err(e),
        }
    }

    /// Send a stack trace request across the channel and read the resulting stack frames.
    fn stack_trace(&mut self, req: StackTraceRequest) -> Result<StackTraceResponse, ChannelError> {
        UnrealCommand::StackTrace(req).serialize(&mut self.sender)?;

        match self.next_response() {
            Ok(UnrealResponse::StackTrace(stack)) => Ok(stack),
            Ok(_) => Err(ChannelError::ProtocolError),
            Err(e) => Err(e),
        }
    }

    fn watch_count(
        &mut self,
        kind: WatchKind,
        parent: VariableIndex,
    ) -> Result<usize, ChannelError> {
        UnrealCommand::WatchCount(kind, parent).serialize(&mut self.sender)?;
        match self.next_response() {
            Ok(UnrealResponse::WatchCount(count)) => Ok(count),
            Ok(_) => Err(ChannelError::ProtocolError),
            Err(e) => Err(e),
        }
    }

    fn frame(&mut self, frame: FrameIndex) -> Result<Option<Frame>, ChannelError> {
        UnrealCommand::Frame(frame).serialize(&mut self.sender)?;

        match self.next_response() {
            Ok(UnrealResponse::Frame(frame)) => Ok(frame),
            Ok(_) => Err(ChannelError::ProtocolError),
            Err(e) => Err(e),
        }
    }

    fn evaluate(&mut self, expr: &str) -> Result<Option<Variable>, ChannelError> {
        UnrealCommand::Evaluate(expr.to_string()).serialize(&mut self.sender)?;
        match self.next_response() {
            Ok(UnrealResponse::Evaluate(val)) => Ok(val),
            Ok(_) => Err(ChannelError::ProtocolError),
            Err(e) => Err(e),
        }
    }

    fn variables(
        &mut self,
        kind: WatchKind,
        frame: FrameIndex,
        variable: VariableIndex,
        start: usize,
        count: usize,
    ) -> Result<(Vec<Variable>, bool), ChannelError> {
        UnrealCommand::Variables(kind, frame, variable, start, count)
            .serialize(&mut self.sender)?;

        match self.next_response() {
            Ok(UnrealResponse::Variables(vars)) => Ok((vars, false)),
            Ok(UnrealResponse::DeferredVariables(vars)) => Ok((vars, true)),
            Ok(_) => Err(ChannelError::ProtocolError),
            Err(e) => Err(e),
        }
    }

    fn pause(&mut self) -> Result<(), ChannelError> {
        UnrealCommand::Pause.serialize(&mut self.sender)?;
        Ok(())
    }

    fn go(&mut self) -> Result<(), ChannelError> {
        UnrealCommand::Go.serialize(&mut self.sender)?;
        Ok(())
    }

    fn next(&mut self) -> Result<(), ChannelError> {
        UnrealCommand::Next.serialize(&mut self.sender)?;
        Ok(())
    }

    fn step_in(&mut self) -> Result<(), ChannelError> {
        UnrealCommand::StepIn.serialize(&mut self.sender)?;
        Ok(())
    }

    fn step_out(&mut self) -> Result<(), ChannelError> {
        UnrealCommand::StepOut.serialize(&mut self.sender)?;
        Ok(())
    }
}

/// Connect to an unreal debugger adapter running at the given port number on the local computer.
pub fn connect(
    port: u16,
) -> Result<(Box<dyn UnrealChannel>, Deserializer<IoRead<TcpStream>>), ChannelError> {
    let mut tcp: Option<TcpStream> = None;

    // Try to connect, sleeping between attempts.
    for _ in 0..CONNECT_TIMEOUT {
        match TcpStream::connect(format!("127.0.0.1:{port}")) {
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

    let (path, shmem) =
        SharedRingBuffer::create_temp(SHARED_MEMORY_SIZE).or(Err(ChannelError::ConnectionError))?;

    // Send the path of the shared memory buffer to the interface.
    let mut serializer = Serializer::new(tcp.try_clone().or(Err(ChannelError::ConnectionError))?);
    UnrealCommand::Initialize(path).serialize(&mut serializer)?;

    let deserializer = serde_json::Deserializer::from_reader(tcp);
    Ok((
        Box::new(DefaultChannel {
            response_receiver: Receiver::new(shmem),
            sender: serializer,
        }),
        deserializer,
    ))
}
