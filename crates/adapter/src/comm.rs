use std::{net::TcpStream, time::Duration};

use common::{Breakpoint, UnrealCommand, UnrealResponse, StackTraceRequest, StackTraceResponse};
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

    fn stack_trace(&mut self, stack: StackTraceRequest) -> Result<StackTraceResponse, ChannelError>;
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
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

impl DefaultChannel {

    /// Fetch the next response from the channel.
    ///
    /// ### Errors:
    ///   Returns a ChannelError::ConnectionError if the message channel encounters an error.
    ///   Returns a ChannelError::Timeout if a message does not appear in a reasonable time.
    fn next_response(&mut self) -> Result<UnrealResponse, ChannelError> {
        self
            .response_receiver
            .recv_timeout(DEFAULT_TIMEOUT)
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
            Err(e) => Err(e)
        }
    }
}

/// Connect to an unreal debugger adapter running at the given port number on the local computer.
pub fn connect(
    port: i32,
) -> Result<(Box<dyn UnrealChannel>, Deserializer<IoRead<TcpStream>>), ChannelError> {
    let tcp =
        TcpStream::connect(format!("127.0.0.1:{port}")).or(Err(ChannelError::ConnectionError))?;
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
