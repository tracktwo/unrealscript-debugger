//! DAP Types. Data structures used as part of the protocol.

use serde::{Deserialize, Serialize};

/// Capabilities are sent as part of the [`crate::responses::ResponseBody::Initialize`]
/// response and tell the client about specific features the adapter supports. Unrealscript is
/// quite limited and doesn't support many features a more sophisticated debugger might.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// The client may send a [`crate::requests::Command::ConfigurationDone`] request
    /// when it is completed its configuration.
    pub supports_configuration_done_request: bool,
    /// The client may request the stack trace to be sent in chunks instead of
    /// all at once.
    pub supports_delayed_stack_trace_loading: bool,
}

/// Breakpoints are sent as part of the [`crate::responses::ResponseBody::SetBreakpoints`] response.
///
/// These indicate where a breakpoint was actually set. In pratice Unreal does not modify
/// the positions of breakpoints, so this will always be exactly the same as the position
/// the client requested.
#[derive(Serialize, Debug)]
#[serde(rename = "breakpoint")]
pub struct Breakpoint {
    /// If true the breakpoint was successfully set. Unreal doesn't tell us if a breakpoint
    /// was successfully set or not so we just have to assume true always.
    pub verified: bool,
    /// The source file for the breakpoint.
    pub source: Source,
    /// The line number the breakpoint is on.
    pub line: i64,
}

/// A source file.
///
/// Sent by the client in [`crate::requests::Command::SetBreakpoints`] and sent by the
/// adapter in [`crate::responses::ResponseBody::SetBreakpoints`].
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "source")]
pub struct Source {
    /// The name of the file
    pub name: Option<String>,
    /// The full path to the file
    pub path: Option<String>,
}

/// A stack frame, sent as part of a `[crate::responses::ResponseBody::StackTrace`] response.
#[derive(Serialize, Debug)]
pub struct StackFrame {
    /// The id of the frame. The topmost frame is 0 and grows downward.
    pub id: i64,
    /// A name for the frame, usually the function name.
    pub name: String,
    /// The source file for this frame.
    pub source: Option<Source>,
    /// The line number for this frame. If the stack hack is not enabled this will be
    /// 0 for all stack frames other than the top-most because Unreal does not provide
    /// this info.
    pub line: i64,
    /// The column number for this frame. Unreal does not support column info so this
    /// is always 0.
    pub column: i64,
}

/// A scope, sent as part of a [`crate::responses::ResponseBody::Scopes`] response.
///
/// Contains information about the variables in the scope.
#[derive(Serialize, Debug)]
pub struct Scope {
    /// The name of the scope.
    pub name: String,
    #[serde(flatten)]
    /// Variable information for this scope. This struct is not part of DAP but
    /// is used to represent some common pieces of info shared among several parts of
    /// this implementation.
    pub variable_info: VariableReferenceInfo,
    /// If true the number of variables in this scope is either very large or
    /// expensive to fetch. This is not currently used and is always false. Setting this
    /// to true does have an impact on VSCode which seems to disable variable hovers
    /// in stack frames where the expensive flag is set on a scope.
    pub expensive: bool,
}

/// A variable, sent as part of a [`crate::responses::ResponseBody::Variables`] response.
#[derive(Serialize, Debug)]
pub struct Variable {
    /// The name of the variable.
    pub name: String,
    /// The value of the variable.
    pub value: String,
    /// The type of the variable. Sent only if
    /// [`crate::requests::InitializeArguments::supports_variable_type`] was sent by the
    /// client in the initialize request.
    #[serde(rename = "type")]
    pub ty: Option<String>,
    /// Variable reference info. This is not part of DAP and is a wrapper struct to hold
    /// common info for this implementation.
    #[serde(flatten)]
    pub variable_info: VariableReferenceInfo,
}

/// A thread, sent as part of a [`crate::responses::ResponseBody::Threads`] response.
///
/// Unrealscript has only one thread, so this is always the same.
#[derive(Serialize, Debug)]
pub struct Thread {
    /// The thread ID, a fixed number.
    pub id: i64,
    /// The name of the thread.
    pub name: String,
}

/// A source breakpoint, sent by the client as part of [`crate::requests::Command::SetBreakpoints`]
/// request.
#[derive(Deserialize, Debug)]
pub struct SourceBreakpoint {
    /// The line for this breakpoint.
    pub line: i64,
    // TODO implement log points
}

/// A type to abstract some common parts of DAP responses relating to variables.
///
/// This type does not appear in DAP directly and should always be flattened
/// in any type that uses it. The purpose of this struct is only to make it
/// easier to serialize certain data structures we sent to the client.
#[derive(Serialize, Debug)]
pub struct VariableReferenceInfo {
    /// The variable reference, a number that uniquely identifies this variable. The
    /// number persists only as long as the debugger remains stopped. The client may use
    /// this number to request further structured info such as the children of this variable.
    #[serde(rename = "variablesReference")]
    pub variables_reference: i64,
    /// The number of named children (e.g. struct fields) in this variable.
    #[serde(rename = "namedVariables")]
    pub named_variables: Option<i64>,
    /// The number of indexed children (e.g. array indices) in this variable.
    #[serde(rename = "indexedVariables")]
    pub indexed_variables: Option<i64>,
}

/// A type for error messages
#[derive(Serialize, Debug)]
#[serde(rename = "message")]
pub struct Message {
    /// An implementation-specific ID. This number should be unique per error message
    /// kind. Can be used to help the user look up info on the error.
    pub id: i64,
    /// The error contents.
    pub format: String,
    /// If true this error should be displayed to the user.
    #[serde(rename = "showUser")]
    pub show_user: bool,
}

impl VariableReferenceInfo {
    /// Construct a new variable reference info struct for a variable with no
    /// children.
    pub fn new_childless(reference: i64) -> Self {
        Self {
            variables_reference: reference,
            named_variables: None,
            indexed_variables: None,
        }
    }
    /// Make a reference for some variable with the given child count and a flag
    /// indicating whether or not it is an array.
    pub fn new(reference: i64, count: i64, is_array: bool) -> Self {
        if is_array {
            Self {
                variables_reference: reference,
                named_variables: None,
                indexed_variables: Some(count),
            }
        } else {
            Self {
                variables_reference: reference,
                named_variables: Some(count),
                indexed_variables: None,
            }
        }
    }
}
