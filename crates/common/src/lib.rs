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

use std::fmt::Display;

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: u16 = 18777u16;

#[derive(Debug)]
pub struct OutOfRangeError;

/// A valid frame index. Unreal does not impose a limit on the number of frames,
/// and DAP has no practical limit (it uses a 'number' for them) but our variable
/// encoding scheme allocates only 9 bits to a frame index.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq)]
pub struct FrameIndex(u16);

impl FrameIndex {
    pub const MAX: u16 = 0x1FF;

    pub const TOP_FRAME: FrameIndex = FrameIndex(0);

    pub fn create(val: i64) -> Result<Self, OutOfRangeError> {
        if val > Self::MAX.into() {
            Err(OutOfRangeError)
        } else {
            Ok(FrameIndex(val.try_into().unwrap()))
        }
    }
}

impl Into<usize> for FrameIndex {
    fn into(self) -> usize {
        self.0.into()
    }
}

impl Into<u64> for FrameIndex {
    fn into(self) -> u64 {
        self.0.into()
    }
}

impl Into<i64> for FrameIndex {
    fn into(self) -> i64 {
        self.0.into()
    }
}

impl Display for FrameIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A valid variable index. Unreal uses a signed 32-bit integer to represent
/// variables returned from AddAWatch, but it's not documented if negative
/// values are actually supported other than the special -1 value it uses to
/// represent root variables. We don't expose the negative value outside of the
/// interface so will use an unsigned value, but we do limit variable indices
/// to only 20 bits.
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub struct VariableIndex(u32);

impl VariableIndex {
    /// The largest variable index we can represent: must fit in 20 bits.
    pub const MAX: u32 = 0xF_FFFF;

    /// A variable index reprsenting a scope root.
    pub const SCOPE: VariableIndex = VariableIndex(0);

    pub fn create(val: u32) -> Result<Self, OutOfRangeError> {
        if val > Self::MAX {
            Err(OutOfRangeError)
        } else {
            Ok(VariableIndex(val))
        }
    }
}

impl Into<u32> for VariableIndex {
    fn into(self) -> u32 {
        self.0
    }
}

impl Into<u64> for VariableIndex {
    fn into(self) -> u64 {
        self.0.into()
    }
}

impl Into<usize> for VariableIndex {
    /// Convert a variable index to a 'usize'. This is guaranteed to work on any
    /// platform where usize >= 32 bits, and Unreal doesn't run on any platforms
    /// where this isn't the case.
    fn into(self) -> usize {
        self.0.try_into().unwrap()
    }
}

impl Display for VariableIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

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

#[derive(Serialize, Deserialize)]
pub struct StackTraceRequest {
    pub start_frame: u32,
    pub levels: u32,
}

#[derive(Serialize, Deserialize)]
pub struct StackTraceResponse {
    pub frames: Vec<Frame>,
}

/// A callstack frame.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Frame {
    pub function_name: String,
    pub qualified_name: String,
    pub line: i32,
}

/// The kind of watch, e.g. scope or user-defined watches.
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
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

/// A representation of a variable. Each variable (watch) provided by Unreal
/// has a name, type, and value (all represented as strings). Each variable is
/// also assigned an index that can be used to locate its children (if it has any).
/// Structs, classes, static and dynamic arrays can all have children, with the
/// last two being considered 'arrays'. This distinction can be important to
/// some clients that differentiate between 'named' and 'indexed' children.
#[derive(Serialize, Deserialize, Debug)]
pub struct Variable {
    pub name: String,
    pub ty: String,
    pub value: String,
    pub index: VariableIndex,
    pub has_children: bool,
    pub is_array: bool,
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
    /// Request the call stack - may request the full stack or only a subset.
    StackTrace(StackTraceRequest),
    /// Determine the number of watches of the given kind in the currently active
    /// frame.
    WatchCount(WatchKind, VariableIndex),
    /// Retreive information about a particular frame.
    Frame(FrameIndex),
    /// Retreive variables. This returns all children of a particular parent (either a scope or
    /// a structured variable).
    Variables(WatchKind, FrameIndex, VariableIndex, usize, usize),

    /// Evaluate a given variable expression
    Evaluate(String),

    /// Break as soon as possible
    Pause,

    /// Continue execution
    Go,

    /// Step over the next statement
    Next,

    // Step into the next statement
    StepIn,

    // Step out of the current function
    StepOut,
}

/// Responses that can be sent from the debugger interface to the adapter, but only
/// in a well-defined order in response to a command from the adapter.
#[derive(Serialize, Deserialize)]
pub enum UnrealResponse {
    BreakpointAdded(Breakpoint),
    BreakpointRemoved(Breakpoint),
    StackTrace(StackTraceResponse),
    WatchCount(usize),
    Frame(Option<Frame>),
    DeferredVariables(Vec<Variable>),
    Variables(Vec<Variable>),
    Evaluate(Variable),
}

/// Events that can be sent from the interface at any time.
#[derive(Serialize, Deserialize, Debug)]
pub enum UnrealEvent {
    /// Unreal has generated an output log line.
    Log(String),
    /// The debugger has stopped. Unreal does not tell us why.
    Stopped,
    /// The debugger has disconnected. This can happen when the user either
    /// closes the game or uses `toggledebugger to disable debugging.
    Disconnect,
}
