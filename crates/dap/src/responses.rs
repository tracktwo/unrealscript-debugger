//! DAP Responses.
//!
//! Responses are sent for each DAP [`crate::requests::Request`] and can indicate success
//! or some failure.

use serde::Serialize;

use crate::{
    requests::Request,
    types::{
        Breakpoint, Capabilities, Message, Scope, StackFrame, Thread, Variable,
        VariableReferenceInfo,
    },
};

/// The top-level protocol message for a response. This is typically used directly only by
/// the client, the adapter builds `Response` messages.
#[derive(Serialize)]
#[serde(tag = "type", rename = "response")]
pub struct ResponseMessage {
    /// The sequence number for this response.
    pub seq: i64,
    /// The response contents.
    #[serde(flatten)]
    pub response: Response,
}

/// A Response object. This is the top-level type directly used by the adapter to build responses
/// to requests.
#[derive(Serialize)]
pub struct Response {
    /// The sequence number of the request we are responding to.
    pub request_seq: i64,
    /// If true the request was successfully processed.
    pub success: bool,
    /// The request command.
    pub command: String,
    /// If [`Self::success`] is false, an optional message to display in the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// A response-specific body. Can also be error details if [`Self::success`] is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<ResponseBody>,
}

impl Response {
    /// Helper to construct a 'success' response to the given request with the
    /// given body.
    pub fn make_success(request: &Request, body: ResponseBody) -> Self {
        Self {
            request_seq: request.seq,
            success: true,
            message: None,
            body: Some(body),
            command: request.command.to_string(),
        }
    }

    /// Helper to make a simple 'ack' response. Several DAP responses have no
    /// bodies and are simply empty ack responses.
    pub fn make_ack(request: &Request) -> Self {
        Self {
            request_seq: request.seq,
            success: true,
            message: None,
            body: None,
            command: request.command.to_string(),
        }
    }

    /// Helper to construct an error response to the ginen request with the given
    /// title and body.
    pub fn make_error(request: &Request, title: String, message: Message) -> Self {
        Self {
            request_seq: request.seq,
            success: false,
            message: Some(title),
            body: Some(ResponseBody::Error(ErrorResponseBody { error: message })),
            command: request.command.to_string(),
        }
    }
}

/// A response body. This is a request-specific variant.
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ResponseBody {
    /// The response to an [`crate::requests::Command::Initialize`] request.
    Initialize(Option<Capabilities>),
    /// The response to an [`crate::requests::Command::SetBreakpoints`] request.
    SetBreakpoints(SetBreakpointsResponseBody),
    /// The response to an [`crate::requests::Command::Continue`] request.
    Continue(ContinueResponseBody),
    /// The response to an [`crate::requests::Command::StackTrace`] request.
    StackTrace(StackTraceResponseBody),
    /// The response to an [`crate::requests::Command::Scopes`] request.
    Scopes(ScopesResponseBody),
    /// The response to an [`crate::requests::Command::Variables`] request.
    Variables(VariablesResponseBody),
    /// The response to an [`crate::requests::Command::Threads`] request.
    Threads(ThreadsResponseBody),
    /// The response to an [`crate::requests::Command::Evaluate`] request.
    Evaluate(EvaluateResponseBody),
    /// The response body for an error response.
    Error(ErrorResponseBody),
}

/// A [`ResponseBody::SetBreakpoints`] response. Contains the list of breakpoints
/// that was set.
///
/// Typically this is used to indicate the actual line a breakpoint was set on
/// if it was automatically adjusted (e.g. for a multi-line statement) or if the
/// breakpoint was successfully validated by the debugger. Unreal doesn't tell us
/// any information and will happily report a breakpoint set in a completely invalid
/// spot such as a comment. These breakpoints will simply never be hit.
#[derive(Serialize, Debug)]
#[serde(rename = "setBreakpoints")]
pub struct SetBreakpointsResponseBody {
    /// The list of breakpoints for the file in the request.
    pub breakpoints: Vec<Breakpoint>,
}

/// A [`ResponseBody::Continue`] response. Indicates whether all threads were
/// continued or not. Since Unrealscript only has one thread this is always true.
#[derive(Serialize, Debug)]
#[serde(rename = "continue")]
pub struct ContinueResponseBody {
    /// If true all threads were continued. In this implementation this is always
    /// true because there is only one thread.
    #[serde(rename = "allThreadsContinued")]
    pub all_threads_continued: bool,
}

/// A [`ResponseBody::StackTrace`] response. Contains information about the current
/// call stack.
///
/// DAP expects the stack frame entries to have line numbers, but we only have
/// full line info if the stack hack is enabled. If not we only have a line number
/// for the top-most frame and all other frames have the line set to 0.
#[derive(Serialize, Debug)]
#[serde(rename = "stackTrace")]
pub struct StackTraceResponseBody {
    /// The list of stack frames.
    #[serde(rename = "stackFrames")]
    pub stack_frames: Vec<StackFrame>,
}

/// A [`ResponseBody::Scopes`] response.
/// Contains information about the global and local scopes including an identitier to use when
/// requesting variables in these scopes and counts of the number of variables.
#[derive(Serialize, Debug)]
#[serde(rename = "scopes")]
pub struct ScopesResponseBody {
    /// The list of scopes. In Unrealscript this will always be a 2-element
    /// array with locals and globals.
    pub scopes: Vec<Scope>,
}

/// A [`ResponseBody::Variables`] response.
///
/// Contains information about the child variables for the variable reference
/// in the request. This reference could be a scope or a variable itself.
#[derive(Serialize, Debug)]
#[serde(rename = "variables")]
pub struct VariablesResponseBody {
    /// A list of variables that are considered children of whatever variable reference
    /// was in the request, which could be a scope or a variable itself.
    pub variables: Vec<Variable>,
}

/// A [`ResponseBody::Threads`] response.
///
/// Unrealscript has only a single thread, so this response always has the
/// same content.
#[derive(Serialize, Debug)]
#[serde(rename = "threads")]
pub struct ThreadsResponseBody {
    /// The list of threads. Always a single element.
    pub threads: Vec<Thread>,
}

/// A [`ResponseBody::Evaluate`] response.
///
/// Evaluate requests are mapped to user watches in Unrealscript. The response
/// has the value of the given expression as a variable.
#[derive(Serialize, Debug)]
#[serde(rename = "evaluate")]
pub struct EvaluateResponseBody {
    /// The result of the expression.
    pub result: String,
    /// The type of the expression. Only sent if
    /// [`crate::requests::InitializeArguments::supports_variable_type`] was sent by the client in the
    /// initialize request.
    #[serde(rename = "type")]
    pub ty: Option<String>,
    /// Variable reference info. This is not part of DAP but is a flattened struct that holds
    /// pieces common to several responses.
    #[serde(flatten)]
    pub variable_info: VariableReferenceInfo,
}

/// A response body for an error response
#[derive(Serialize, Debug)]
#[serde(rename = "error")]
pub struct ErrorResponseBody {
    /// The error message
    pub error: Message,
}
