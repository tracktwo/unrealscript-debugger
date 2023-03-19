use serde::Deserialize;
use strum::Display;

use crate::types::{Source, SourceBreakpoint};

#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename = "request")]
pub struct Request {
    pub seq: i64,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Deserialize, Debug, Display)]
#[serde(tag = "command", content = "arguments", rename_all = "camelCase")]
#[strum(serialize_all = "camelCase")]
pub enum Command {
    Attach(AttachArguments),
    ConfigurationDone,
    Continue,
    Disconnect,
    Evaluate(EvaluateArguments),
    Initialize(InitializeArguments),
    Launch(LaunchArguments),
    Next,
    Pause,
    Scopes(ScopesArguments),
    SetBreakpoints(SetBreakpointsArguments),
    StackTrace(StackTraceArguments),
    StepIn,
    StepOut,
    Threads,
    Variables(VariablesArguments),
}

#[derive(Deserialize, Debug)]
pub struct AttachArguments {
    pub port: Option<u16>,
    pub source_roots: Option<Vec<String>>,
    pub enable_stack_hack: Option<bool>,
}

#[derive(Deserialize, Debug)]
pub struct EvaluateArguments {
    pub expression: String,
    #[serde(rename = "frameId")]
    pub frame_id: i64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InitializeArguments {
    pub lines_start_at1: Option<bool>,
    pub supports_variable_type: Option<bool>,
    pub supports_invalidated_event: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LaunchArguments {
    pub port: Option<u16>,
    pub no_debug: Option<bool>,
    pub source_roots: Option<Vec<String>>,
    pub enable_stack_hack: Option<bool>,
    pub program: Option<String>,
    pub arguments: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
pub struct ScopesArguments {
    #[serde(rename = "frameId")]
    pub frame_id: i64,
}

#[derive(Deserialize, Debug)]
pub struct SetBreakpointsArguments {
    pub source: Source,
    pub breakpoints: Option<Vec<SourceBreakpoint>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StackTraceArguments {
    pub thread_id: i64,
    pub start_frame: Option<i64>,
    pub levels: Option<i64>,
}

#[derive(Deserialize, Debug)]
pub struct VariablesArguments {
    #[serde(rename = "variablesReference")]
    pub variables_reference: i64,
    pub start: Option<i64>,
    pub count: Option<i64>,
}

/// Implementation-specific options for launch and attach.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UnrealscriptAdapterOptions {}
