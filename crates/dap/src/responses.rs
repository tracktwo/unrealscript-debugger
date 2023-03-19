use serde::Serialize;

use crate::{
    requests::Request,
    types::{Breakpoint, Capabilities, Scope, StackFrame, Thread, Variable, VariableReferenceInfo},
};

#[derive(Serialize)]
#[serde(tag = "type", rename = "response")]
pub struct ResponseMessage {
    pub seq: i64,
    #[serde(flatten)]
    pub response: Response,
}

#[derive(Serialize)]
pub struct Response {
    pub request_seq: i64,
    pub success: bool,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<ResponseBody>,
}

impl Response {
    pub fn make_success(request: &Request, body: ResponseBody) -> Self {
        Self {
            request_seq: request.seq,
            success: true,
            message: None,
            body: Some(body),
            command: request.command.to_string(),
        }
    }

    pub fn make_ack(request: &Request) -> Self {
        Self {
            request_seq: request.seq,
            success: true,
            message: None,
            body: None,
            command: request.command.to_string(),
        }
    }

    pub fn make_error(request: &Request, title: String, message: MessageResponseBody) -> Self {
        Self {
            request_seq: request.seq,
            success: false,
            message: Some(title),
            body: Some(ResponseBody::Message(message)),
            command: request.command.to_string(),
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ResponseBody {
    Initialize(Option<Capabilities>),
    SetBreakpoints(SetBreakpointsResponseBody),
    Continue(ContinueResponseBody),
    StackTrace(StackTraceResponseBody),
    Scopes(ScopesResponseBody),
    Variables(VariablesResponseBody),
    Threads(ThreadsResponseBody),
    Evaluate(EvaluateResponseBody),
    Message(MessageResponseBody),
}

#[derive(Serialize, Debug)]
#[serde(rename = "setBreakpoints")]
pub struct SetBreakpointsResponseBody {
    pub breakpoints: Vec<Breakpoint>,
}

#[derive(Serialize, Debug)]
#[serde(rename = "continue")]
pub struct ContinueResponseBody {
    #[serde(rename = "allThreadsContinued")]
    pub all_threads_continued: bool,
}

#[derive(Serialize, Debug)]
#[serde(rename = "stackTrace")]
pub struct StackTraceResponseBody {
    pub stack_frames: Vec<StackFrame>,
}

#[derive(Serialize, Debug)]
#[serde(rename = "scopes")]
pub struct ScopesResponseBody {
    pub scopes: Vec<Scope>,
}

#[derive(Serialize, Debug)]
#[serde(rename = "variables")]
pub struct VariablesResponseBody {
    pub variables: Vec<Variable>,
}

#[derive(Serialize, Debug)]
#[serde(rename = "threads")]
pub struct ThreadsResponseBody {
    pub threads: Vec<Thread>,
}

#[derive(Serialize, Debug)]
#[serde(rename = "evaluate")]
pub struct EvaluateResponseBody {
    pub result: String,
    #[serde(rename = "type")]
    pub ty: Option<String>,
    #[serde(flatten)]
    pub variable_info: VariableReferenceInfo,
}

#[derive(Serialize, Debug)]
#[serde(rename = "message")]
pub struct MessageResponseBody {
    pub id: i64,
    pub format: String,
    #[serde(rename = "showUser")]
    pub show_user: bool,
}
