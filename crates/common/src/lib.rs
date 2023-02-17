//! Communications interface between the debugger interface (Unreal) and the adapter.
//!
//! This module defines the data format between the two. There are three types
//! of message that can be sent between the components:
//!
//! Commands are sent from the adapter to the interface, and instruct the deubgger
//! to do something (e.g. set a breakpoint, or step over the next line).
//!
//! Responses are sent from the interface to the adapter, always in predictable
//! ways: A specific command will result in zero or more responses, and the response
//! set for a specific command has a fixed structure (e.g. a set breakpoint command
//! results in exactly one set breakpoint response).
//!
//! Events are unpredictable, asynchronous events that are not tied to a particular
//! command (e.g. a log line being added or a break event).

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: i32 = 18777;

/// Representation of a breakpoint.
#[derive(Serialize, Deserialize, Clone)]
pub struct Breakpoint {
    pub qualified_name: String,
    pub line: i32,
}

impl Breakpoint {
    pub fn new(qualified_name: &str, line: i32) -> Breakpoint {
        Breakpoint {
            qualified_name: qualified_name.to_string(),
            line,
        }
    }
}

/// A variable watch.
pub struct Watch {
    pub parent: i32,
    pub name: String,
    pub value: String,
}

/// A callstack frame.
pub struct Frame {
    pub class_name: String,
    pub line: i32,
}

/// The kind of watch, e.g. scope or user-defined watches.
pub enum WatchKind {
    Local,
    Global,
    User,
}

impl WatchKind {
    /// Map an integer value to a WatchKind
    pub fn from_int(kind: i32) -> Option<WatchKind> {
        match kind {
            0 => Some(WatchKind::Local),
            1 => Some(WatchKind::Global),
            2 => Some(WatchKind::User),
            _ => None,
        }
    }
}

/// Commands that can be sent from the adapter to the debugger interface.
#[derive(Serialize, Deserialize)]
pub enum UnrealCommand {
    /// Initialize a new connection with the given path as a shared memory file.
    Initialize(String),
    /// Set a breakpoint
    AddBreakpoint(Breakpoint),
    /// Remove a breakpoint
    RemoveBreakpoint(Breakpoint),
}

/// Responses that can be sent from the debugger interface to the adapter, but only
/// in a well-defined order in response to a command from the adapter.
#[derive(Serialize, Deserialize)]
pub enum UnrealResponse {
    BreakpointAdded(Breakpoint),
    BreakpointRemoved(Breakpoint),
}

/// Events that can be sent from the interface at any time.
#[derive(Serialize, Deserialize, Debug)]
pub enum UnrealEvent {
    Log(String),
    Stopped,
}
