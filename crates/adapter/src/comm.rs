//! Module for managing communications with the debugger interface.
//!
//! This defines the [`Connection`] trait for implementing the low-level communications
//! channel between the debug adapter and interface, and a higher-level protocol
//! on top of this for managing request/response transactions.
pub mod tcp;

use std::io::{Error, ErrorKind};

use common::{
    Breakpoint, FrameIndex, InitializeRequest, StackTraceRequest, StackTraceResponse,
    UnrealCommand, UnrealResponse, Variable, VariableIndex, Version, WatchKind,
};

macro_rules! expect_response {
    ($e:expr, $p:path) => {
        match $e {
            Ok($p(x)) => Ok(x),
            Ok(r) => Err(Error::new(
                ErrorKind::Other,
                format!("Protocol Error: {r:?}"),
            )),
            Err(e) => Err(e),
        }
    };
}

/// A trait for representing a connection to an Unreal debug adapter.
///
/// The connection to Unreal is partially synchronous and partially asynchronous.
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
/// - event_receiver: Returns a reference to a receiver that can be used to read events.
///   This channel is asynchronous.
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
    /// Send the given command to the interface.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the command cannot be sent.
    fn send_command(&mut self, command: UnrealCommand) -> Result<(), Error>;

    /// Receive the next response from the interface.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the response cannot be read.
    fn next_response(&mut self) -> Result<UnrealResponse, Error>;

    /// Send an initialize request to the interface and retrieve the response. Exchanges
    /// version information and other config data.
    fn initialize(
        &mut self,
        version: Version,
        enable_stack_hack: bool,
        overridden_log_level: Option<&String>,
    ) -> Result<Version, Error> {
        self.send_command(UnrealCommand::Initialize(InitializeRequest {
            version,
            enable_stack_hack,
            overridden_log_level: overridden_log_level.cloned(),
        }))?;
        let response = expect_response!(self.next_response(), UnrealResponse::Initialize)?;
        Ok(response.version)
    }

    /// Add a breakpoint.
    fn add_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, Error> {
        self.send_command(UnrealCommand::AddBreakpoint(bp))?;
        expect_response!(self.next_response(), UnrealResponse::BreakpointAdded)
    }

    /// Remove a breakpoint.
    fn remove_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, Error> {
        self.send_command(UnrealCommand::RemoveBreakpoint(bp))?;
        expect_response!(self.next_response(), UnrealResponse::BreakpointRemoved)
    }

    /// Request a full or partial stack trace.
    fn stack_trace(&mut self, req: StackTraceRequest) -> Result<StackTraceResponse, Error> {
        self.send_command(UnrealCommand::StackTrace(req))?;
        expect_response!(self.next_response(), UnrealResponse::StackTrace)
    }

    /// Request the number of children of the variable (or scope) of the given
    /// kind.
    ///
    /// The total number of variables of a given kind can be obtained by using the
    /// SCOPE pseudo-variable index. For any other index it will request the number of
    /// children of that variable, which may be zero.
    ///
    /// This can only obtain child counts for the current frame.
    fn watch_count(&mut self, kind: WatchKind, parent: VariableIndex) -> Result<usize, Error> {
        self.send_command(UnrealCommand::WatchCount(kind, parent))?;
        expect_response!(self.next_response(), UnrealResponse::WatchCount)
    }

    /// Evaluate the given string in the current debugger context.
    fn evaluate(&mut self, frame: FrameIndex, expr: &str) -> Result<Vec<Variable>, Error> {
        self.send_command(UnrealCommand::Evaluate(frame, expr.to_string()))?;
        match self.next_response() {
            Ok(UnrealResponse::Variables(vars)) => Ok(vars),
            Ok(UnrealResponse::DeferredVariables(vars)) => Ok(vars),
            Ok(r) => Err(Error::new(
                ErrorKind::Other,
                format!("Protocol Error: {r:?}"),
            )),
            Err(e) => Err(e),
        }
    }

    /// Request a list of variables. This may be a list of top-level variables
    /// or the list of children for a given variable.
    ///
    /// The request specifies the kind, frame, and variable index to identify
    /// the variable and a start and count value to allow paginated responses.
    fn variables(
        &mut self,
        kind: WatchKind,
        frame: FrameIndex,
        variable: VariableIndex,
        start: usize,
        count: usize,
    ) -> Result<(Vec<Variable>, bool), Error> {
        self.send_command(UnrealCommand::Variables(
            kind, frame, variable, start, count,
        ))?;

        // A variables response can result in one of two different message cases
        // depending on whether the result was deferred or not.
        match self.next_response() {
            Ok(UnrealResponse::Variables(vars)) => Ok((vars, false)),
            Ok(UnrealResponse::DeferredVariables(vars)) => Ok((vars, true)),
            Ok(r) => Err(Error::new(
                ErrorKind::Other,
                format!("Protocol Error: {r:?}"),
            )),
            Err(e) => Err(e),
        }
    }

    /// Request the debugger stop as soon as it can.
    fn pause(&mut self) -> Result<(), Error> {
        self.send_command(UnrealCommand::Pause)?;
        Ok(())
    }

    /// Resume execution.
    fn go(&mut self) -> Result<(), Error> {
        self.send_command(UnrealCommand::Go)?;
        Ok(())
    }

    /// Step over the next statement.
    fn next(&mut self) -> Result<(), Error> {
        self.send_command(UnrealCommand::Next)?;
        Ok(())
    }

    /// Step into the next statement.
    fn step_in(&mut self) -> Result<(), Error> {
        self.send_command(UnrealCommand::StepIn)?;
        Ok(())
    }

    /// Step out of the current function.
    fn step_out(&mut self) -> Result<(), Error> {
        self.send_command(UnrealCommand::StepOut)?;
        Ok(())
    }

    /// Disconnect from the interface, shutting down the debugger
    /// session.
    fn disconnect(&mut self) -> Result<(), Error> {
        self.send_command(UnrealCommand::Disconnect)?;
        Ok(())
    }
}
