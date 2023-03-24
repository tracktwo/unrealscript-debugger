//! DAP requests
//!
//! Requests are sent from the client (editor) to the adapter and expect a
//! response.

use serde::Deserialize;
use strum::Display;

use crate::types::{Source, SourceBreakpoint};

/// A request from the DAP client.
#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename = "request")]
pub struct Request {
    /// The sequence number for the request.
    pub seq: i64,
    /// The request command.
    #[serde(flatten)]
    pub command: Command,
}

/// The DAP request 'command' or type.
#[derive(Deserialize, Debug, Display)]
#[serde(tag = "command", content = "arguments", rename_all = "camelCase")]
#[strum(serialize_all = "camelCase")]
pub enum Command {
    /// Attach to a running process.
    Attach(AttachArguments),
    /// The client has finished the configuration stage.
    ConfigurationDone,
    /// Continue execution.
    Continue(IgnoredArguments),
    /// Disconnect from the debuggee. We treat this as shutting down the
    /// debugging session. If we launched the debuggee it will close the process
    /// too.
    Disconnect(IgnoredArguments),
    /// Evaluate a given watch expression.
    Evaluate(EvaluateArguments),
    /// Initialize the connection with the client. Contains configuration details
    /// about the client.
    Initialize(InitializeArguments),
    /// Launch an application and optionally debug it.
    Launch(LaunchArguments),
    /// Step over the next statement.
    Next(IgnoredArguments),
    /// Tell the debuggee to break.
    Pause(IgnoredArguments),
    /// Request for scope information. Unrealscript has only two real scopes: local scope
    /// and global (class) scope.
    Scopes(ScopesArguments),
    /// Set breakpoints for a given file. This completely replaces all previous breakpoints
    /// in the file.
    SetBreakpoints(SetBreakpointsArguments),
    /// Request stack trace information.
    StackTrace(StackTraceArguments),
    /// Step into the next statement.
    StepIn(IgnoredArguments),
    /// Step out of the current function.
    StepOut(IgnoredArguments),
    /// Request information about the currently running threads. Unreal has only a single thread.
    Threads,
    /// Request information about variables.
    Variables(VariablesArguments),
}

/// A dummy struct with no members.
///
/// This is used as a parameter type for [`Command`] variants where we don't
/// care about any of the arguments DAP provides, but we need something to tell
/// serde that it will still have an `arguments` key that needs to map to something.
#[derive(Deserialize, Debug)]
pub struct IgnoredArguments {}

/// Arguments for an [`Command::Attach`] command.
///
/// These are almost entirely implementation-defined, and are usually populated
/// from the launch configuration of the editor.
#[derive(Deserialize, Debug)]
pub struct AttachArguments {
    /// An ordered list of directories in which to search for source files. This is required
    /// so that we can tell the editor what file to open when the debugger breaks in some
    /// Unreal class. It relies on the naming and directory layout convention of Unreal so
    /// we can map a package and class name to a source file.
    pub source_roots: Option<Vec<String>>,
    /// If true enable the 'stack hack', an experimental feature to provide full line information
    /// for all frames in a stack trace. By default Unreal only provides line information for
    /// the top-most entry of the stack, but DAP and most editors want to know the line number for
    /// each element in the trace.
    pub enable_stack_hack: Option<bool>,

    /// Override the log level with the given log spec. Can be one of 'trace', 'debug', 'info',
    /// 'warn', or 'error'; or a more complex log spec.
    pub log_level: Option<String>,
}

/// Arguments for a [`Command::Evaluate`] command.
///
/// This is used to add watch expressions.
#[derive(Deserialize, Debug)]
pub struct EvaluateArguments {
    /// The expression to evaluate.
    pub expression: String,
    #[serde(rename = "frameId")]
    /// The id of the frame in which this expression should be evaluated.
    pub frame_id: Option<i64>,
}

/// Arguments for a [`Command::Initialize`] command.
///
/// This command has configuration details for the client.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InitializeArguments {
    /// Lines start at 1 (true or unset) or 0 (false).
    pub lines_start_at1: Option<bool>,

    /// If true the client supports 'type' fields in variables. If this is not
    /// set to true we will not send type info as part of variables responses.
    pub supports_variable_type: Option<bool>,

    /// If true the client supports 'invalidated' events. If not set to true
    /// we will not send [`crate::events::EventBody::Invalidated`] events when switching
    /// stack frames. In such an editor we will not have line information for any
    /// stack frame other than the top-most unless the stack hack is enabled.
    pub supports_invalidated_event: Option<bool>,
}

/// Arguments for a [`Command::Launch`] request.
///
/// This is sent as part of initialization when the client wants us to launch
/// a process to debug.
///
/// All arguments are implementation-defined.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LaunchArguments {
    /// If `true` we will launch but not debug the program.
    pub no_debug: Option<bool>,
    /// The list of source roots. See [`AttachArguments::source_roots`].
    pub source_roots: Option<Vec<String>>,
    /// Enable the stack hack. See [`AttachArguments::enable_stack_hack`].
    pub enable_stack_hack: Option<bool>,
    /// Full path to the program to launch.
    pub program: Option<String>,
    /// An array of arguments to pass to the program.
    pub args: Option<Vec<String>>,
    /// Override the log level with the given log spec. Can be one of 'trace', 'debug', 'info',
    /// 'warn', or 'error'; or a more complex log spec.
    pub log_level: Option<String>,
    /// Specify the port number to use for communications with the interface.
    pub port: Option<i64>,
}

/// Arguments for a [`Command::Scopes`] request.
///
/// The client requests this when it wants to display variable information
/// for a particular stack frame. This occurs when we first break for the
/// topmost frame and then whenever we switch frames in the editor.
///
/// Scopes in Unrealscript are limited and are always just two: the locals
/// scope and the globals scope (class scope).
#[derive(Deserialize, Debug)]
pub struct ScopesArguments {
    /// The frame id to request scope info for.
    #[serde(rename = "frameId")]
    pub frame_id: i64,
}

/// Arguments for a [`Command::SetBreakpoints`] request.
///
/// This is used to set breakpoints in the given file. Each time this
/// request is processed the list of breakpoints sent completely replaces
/// any previous breakpoints, e.g. removing the last breakpoint in the file
/// will send a set breakpoints request with an empty breakpoint list.
#[derive(Deserialize, Debug)]
pub struct SetBreakpointsArguments {
    /// The source file for which to add breakpoints.
    pub source: Source,
    /// The complete list of breakpoints for this file.
    pub breakpoints: Option<Vec<SourceBreakpoint>>,
}

/// Arguments for a [`Command::StackTrace`] request.
///
/// This requests stack information and is usually requested each time the
/// debugger breaks.
///
/// DAP numbers stack frames starting from 0 as the top-most frame and works
/// down the stack with increasing numbers.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StackTraceArguments {
    /// The thread ID we are requesting info for.
    pub thread_id: i64,
    /// If set, the first frame we want info for. If not set or set to 0 we
    /// request info starting at the top-most frame. Used with [`Self::levels`] to
    /// implement paginated processing of frames.
    pub start_frame: Option<i64>,
    /// If set, the number of frames to send in this response. Used with
    /// [`Self::start_frame`] to implement paginated processing of frames.
    pub levels: Option<i64>,
}

/// Arguments for a [`Command::Variables`] request.
///
/// This requests information about the variables in a given scope, or the
/// children of a variable for structured variables.
#[derive(Deserialize, Debug)]
pub struct VariablesArguments {
    /// The variable reference we are requesting info for. This will represent
    /// either a scope that we returned from a [`crate::requests::Command::Scopes`] request or
    /// a variable we have returned from a previous `Variables` request.
    #[serde(rename = "variablesReference")]
    pub variables_reference: i64,
    /// If set this is the index of child variables to start from. If not set
    /// or 0 we start from the first child.
    pub start: Option<i64>,
    /// If set this is the number of variables to request. If not set or 0
    /// we return all children.
    pub count: Option<i64>,
}
