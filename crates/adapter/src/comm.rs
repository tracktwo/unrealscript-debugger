pub mod tcp;

use common::{
    Breakpoint, FrameIndex, StackTraceRequest, StackTraceResponse, UnrealCommand, UnrealEvent,
    UnrealResponse, Variable, VariableIndex, WatchKind,
};
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

/// An error sending or receiving data across the channel.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// Timed out waiting for a response.
    #[error("Timeout")]
    Timeout,
    /// The connection has been interrupted
    #[error("Disconnected")]
    Disconnected,
    /// A serialization or deserialization error.
    #[error("IO error: {0}")]
    IoError(std::io::Error),

    /// Received an unexpected response.
    #[error("Protocol error")]
    ProtocolError,
}

impl From<std::io::Error> for ConnectionError {
    fn from(value: std::io::Error) -> Self {
        ConnectionError::IoError(value)
    }
}

macro_rules! expect_response {
    ($e:expr, $p:path) => {
        match $e {
            Ok($p(x)) => Ok(x),
            Ok(_) => Err(ConnectionError::ProtocolError),
            Err(e) => Err(e),
        }
    };
}

/// A trait for representing a connection to an Unreal debug adapter.
///
/// The connection to unreal is partially synchronous and partially asynchronous.
/// This helps simplify the logic in both the adapter and the interface by limiting
/// the amount of concurrency it needs to manage. The communications protocol between
/// these two components is like a limited form of DAP itself, but since it's partially
/// synchronous we do not need to deal with sequence numbers or to manage complex
/// state within either component to account for multiple concurrent messages.
///
/// The trait defines only three required methods:
///
/// - send_command: To synchronously send a command from the adapter to the interface.
///   This blocks until the command has been successfully sent, preventing multiple
///   commands from being sent at the same time.
/// - next_response: To synchronously read a response from the interface to the adapter.
///   This blocks until a response has been received.
/// - register_event_sender: Allows the adapter to provide a channel the connection can
///   use to send events. This channel is asynchronous.
///
/// The trait also provides a higher-level interface of synchronous functions to manage
/// a transaction from the adapter to the interface, usually a command that results in
/// a particular response, although some commands have no response. Because these
/// are synchronous the caller is greatly simplified: we know that after sending an
/// 'add_breakpoints' command we will get exactly one response with the result, and
/// there can be no other interleaved commands to worry about as all of these
/// functions require an exclusive reference to this connection.
///
/// The downside to this is that since all sends and receives are blocking if the
/// protocol gets out of sync with the interface we may block forever for a response
/// that will never come. The protocol is very simple, so any out of sync error is
/// likely to be an interrupted connection which will close the channel and unblock
/// the caller anyway.
pub trait Connection: Send {
    fn send_command(&mut self, command: UnrealCommand) -> Result<(), ConnectionError>;
    fn next_response(&mut self) -> Result<UnrealResponse, ConnectionError>;
    fn event_receiver(&mut self) -> &mut Receiver<UnrealEvent>;

    fn add_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ConnectionError> {
        self.send_command(UnrealCommand::AddBreakpoint(bp))?;
        expect_response!(self.next_response(), UnrealResponse::BreakpointAdded)
    }

    fn remove_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ConnectionError> {
        self.send_command(UnrealCommand::RemoveBreakpoint(bp))?;
        expect_response!(self.next_response(), UnrealResponse::BreakpointRemoved)
    }

    /// Send a stack trace request across the channel and read the resulting stack frames.
    fn stack_trace(
        &mut self,
        req: StackTraceRequest,
    ) -> Result<StackTraceResponse, ConnectionError> {
        self.send_command(UnrealCommand::StackTrace(req))?;
        expect_response!(self.next_response(), UnrealResponse::StackTrace)
    }

    fn watch_count(
        &mut self,
        kind: WatchKind,
        parent: VariableIndex,
    ) -> Result<usize, ConnectionError> {
        self.send_command(UnrealCommand::WatchCount(kind, parent))?;
        expect_response!(self.next_response(), UnrealResponse::WatchCount)
    }

    fn evaluate(&mut self, expr: &str) -> Result<Option<Variable>, ConnectionError> {
        self.send_command(UnrealCommand::Evaluate(expr.to_string()))?;
        expect_response!(self.next_response(), UnrealResponse::Evaluate)
    }

    fn variables(
        &mut self,
        kind: WatchKind,
        frame: FrameIndex,
        variable: VariableIndex,
        start: usize,
        count: usize,
    ) -> Result<(Vec<Variable>, bool), ConnectionError> {
        self.send_command(UnrealCommand::Variables(
            kind, frame, variable, start, count,
        ))?;

        // A variables response can result in one of two different message cases
        // depending on whether the result was deferred or not.
        match self.next_response() {
            Ok(UnrealResponse::Variables(vars)) => Ok((vars, false)),
            Ok(UnrealResponse::DeferredVariables(vars)) => Ok((vars, true)),
            Ok(_) => Err(ConnectionError::ProtocolError),
            Err(e) => Err(e),
        }
    }

    fn pause(&mut self) -> Result<(), ConnectionError> {
        self.send_command(UnrealCommand::Pause)?;
        Ok(())
    }

    fn go(&mut self) -> Result<(), ConnectionError> {
        self.send_command(UnrealCommand::Go)?;
        Ok(())
    }

    fn next(&mut self) -> Result<(), ConnectionError> {
        self.send_command(UnrealCommand::Next)?;
        Ok(())
    }

    fn step_in(&mut self) -> Result<(), ConnectionError> {
        self.send_command(UnrealCommand::StepIn)?;
        Ok(())
    }

    fn step_out(&mut self) -> Result<(), ConnectionError> {
        self.send_command(UnrealCommand::StepOut)?;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), ConnectionError> {
        self.send_command(UnrealCommand::Disconnect)?;
        Ok(())
    }
}
