//! Communications interface between the debugger interface (Unreal) and the adapter.
//!
//! This module defines the data format between the two. The adapter sends
//! commands to the interface, and the interface sends events to the adapter.
use serde::{Serialize, Deserialize};

/// Representation of a breakpoint.
#[derive(Serialize,Deserialize)]
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

/// Commands that can be sent from the adapter to the debugger interface.
#[derive(Serialize,Deserialize)]
pub enum UnrealCommand {
    /// Initialize a new connection with the given path as a shared memory file.
    Initialize(String),
    /// Set a breakpoint
    SetBreakpoint(Breakpoint),
    /// Remove a breakpoint
    RemoveBreakpoint(Breakpoint),
}

/// Events that can be sent from the debugger interface to the adapter.
#[derive(Serialize,Deserialize)]
pub enum UnrealEvent {
    BreakpointAdded(Breakpoint),
    BreakpointRemoved(Breakpoint),
}

/// Communications channel between Unreal and the debugger interface.
pub struct UnrealChannel;

impl UnrealChannel {
    pub fn new() -> UnrealChannel {
        UnrealChannel {}
    }

    /// Synchronous command: add the given breakpoint.
    pub fn add_breakpoint(&mut self, bp: Breakpoint) -> Breakpoint {
        bp
    }

    /// Synchronous command: remove the given breakpoint.
    pub fn remove_breakpoint(&mut self, bp: Breakpoint) -> Breakpoint {
        bp
    }
}

