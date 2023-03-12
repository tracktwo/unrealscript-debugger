//! Communications interface between the debugger interface (Unreal) and the adapter.
//!
//! This module defines the data format between the two. There are three types
//! of message that can be sent between the components:
//!
//! - Commands are sent from the adapter to the interface, and instruct the deubgger
//! to do something (e.g. set a breakpoint, or step over the next line).
//!
//! - Responses are sent from the interface to the adapter, always in predictable
//! ways: A specific command will result in zero or more responses, and the response
//! set for a specific command has a fixed structure (e.g. a set breakpoint command
//! results in exactly one set breakpoint response).
//!
//! - Events are unpredictable, asynchronous events that are not tied to a particular
//! command (e.g. a log line being added or a break event).

#![warn(missing_docs)]

use std::fmt::Display;

use serde::{Deserialize, Serialize};

/// The default port to use for the TCP connection between the interface and
/// adapter.
pub const DEFAULT_PORT: u16 = 18777u16;

/// An error indicating a particular value (such as a frame or variable index)
/// is out of range.
#[derive(Debug)]
pub struct OutOfRangeError;

/// A valid frame index. Unreal does not impose a limit on the number of frames,
/// and DAP has no practical limit (it uses a 'number' for them) but our variable
/// encoding scheme allocates only 9 bits to a frame index.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq)]
pub struct FrameIndex(u16);

impl FrameIndex {
    /// The maximum frame index.
    pub const MAX: u16 = 0x1FF;

    /// The index of the topmost stack frame.
    pub const TOP_FRAME: FrameIndex = FrameIndex(0);

    /// Create a frame index from the given integer.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfRangeError`] if the value is larger than [`FrameIndex::MAX`].
    pub fn create(val: i64) -> Result<Self, OutOfRangeError> {
        if val > Self::MAX.into() {
            Err(OutOfRangeError)
        } else {
            Ok(FrameIndex(val.try_into().unwrap()))
        }
    }
}

impl From<FrameIndex> for usize {
    fn from(val: FrameIndex) -> Self {
        val.0.into()
    }
}

impl From<FrameIndex> for u64 {
    fn from(val: FrameIndex) -> Self {
        val.0.into()
    }
}

impl From<FrameIndex> for i64 {
    fn from(val: FrameIndex) -> Self {
        val.0.into()
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

    /// Create a variable reference from the given value.
    ///
    /// #Errors
    ///
    /// Returns [`OutOfRangeError`] if the value is larger than [`VariableIndex::MAX`].
    pub fn create(val: u32) -> Result<Self, OutOfRangeError> {
        if val > Self::MAX {
            Err(OutOfRangeError)
        } else {
            Ok(VariableIndex(val))
        }
    }
}

impl From<VariableIndex> for u32 {
    fn from(val: VariableIndex) -> Self {
        val.0
    }
}

impl From<VariableIndex> for u64 {
    fn from(val: VariableIndex) -> Self {
        val.0.into()
    }
}

impl From<VariableIndex> for usize {
    fn from(val: VariableIndex) -> Self {
        val.0.try_into().unwrap()
    }
}

impl Display for VariableIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Representation of a breakpoint.
#[derive(Serialize, Deserialize, Debug)]
pub struct Breakpoint {
    /// The qualified name (`package.class`) for the class containing the breakpoint.
    pub qualified_name: String,
    /// The line number for the breakpoint.
    ///
    /// Internally lines are always 1-indexed, regardless of the client settings.
    pub line: i32,
}

impl Breakpoint {
    /// Create a new breakpoint instance for the given qualified name and line.
    pub fn new(qualified_name: &str, line: i32) -> Breakpoint {
        Breakpoint {
            qualified_name: qualified_name.to_string(),
            line,
        }
    }
}

/// A message representing a request from the adapter to the interface to
/// list stack frame entries. Will result in a [`StackTraceResponse`].
#[derive(Serialize, Deserialize, Debug)]
pub struct StackTraceRequest {
    /// The first frame to return. 0 is the topmost frame.
    pub start_frame: u32,
    /// The number of frames to return, or 0 for "all frames".
    pub levels: u32,
}

/// A response to a [`StackTraceRequest`] message.
#[derive(Debug, Serialize, Deserialize)]
pub struct StackTraceResponse {
    /// A vector of requested frames. The returned vector may be shorter
    /// than the initial request's `levels` field.
    pub frames: Vec<Frame>,
}

/// A callstack frame.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Frame {
    /// The name of the function for this frame.
    pub function_name: String,
    /// The qualified name of the class for this frame.
    pub qualified_name: String,
    /// A line number for this frame. Note that this may be '0', indicating
    /// the line is unknown.
    pub line: i32,
}

/// The kind of watch, e.g. scope or user-defined watches.
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum WatchKind {
    /// A local variable
    Local,
    /// A global (i.e. class) variable
    Global,
    /// A user watch
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
    /// The name of the variable
    pub name: String,
    /// The type of the variable, if available. May also be a marker type such
    /// as for a base class.
    pub ty: String,
    /// The value of the variable as a string.
    pub value: String,
    /// The index of this variable within its container, which could be a frame
    /// or another variable.
    pub index: VariableIndex,
    /// True if this variable has children.
    pub has_children: bool,
    /// True if this variable is an array type.
    pub is_array: bool,
}

/// Commands that can be sent from the adapter to the debugger interface.
#[derive(Serialize, Deserialize, Debug)]
pub enum UnrealCommand {
    /// Set a breakpoint
    AddBreakpoint(Breakpoint),
    /// Remove a breakpoint
    RemoveBreakpoint(Breakpoint),
    /// Request the call stack - may request the full stack or only a subset.
    StackTrace(StackTraceRequest),
    /// Determine the number of watches of the given kind in the currently active
    /// frame.
    WatchCount(WatchKind, VariableIndex),
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

    /// Step into the next statement
    StepIn,

    /// Step out of the current function
    StepOut,

    /// Stop debugging - the client has disconnected.
    Disconnect,
}

/// Responses that can be sent from the debugger interface to the adapter, but only
/// in a well-defined order in response to a command from the adapter.
#[derive(Debug, Serialize, Deserialize)]
pub enum UnrealResponse {
    /// A breakpoint has been added.
    BreakpointAdded(Breakpoint),
    /// A breakpoint has been removed.
    BreakpointRemoved(Breakpoint),
    /// A list of zero or more stack frames.
    StackTrace(StackTraceResponse),
    /// The number of watches found.
    WatchCount(usize),
    /// A response to a [`UnrealRequest.Variables`] request with a list of variables
    /// that were immediately accessible.
    Variables(Vec<Variable>),
    /// A response to a [`UnrealRequest.Variables`] request with a list of variables
    /// that required the debugger to change the current stack frame. This can be
    /// used by the adapter to invalidate the stack frame prompting a request of
    /// the frame information again.
    DeferredVariables(Vec<Variable>),
    /// The result of a variable evaluation (i.e. a user watch).
    Evaluate(Option<Variable>),
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

/// A message from the interface to the adapter. Can be either a 'response' or
/// an 'event'. These are multiplexed into the same transport stream, but are
/// split out by the adapter into separate channels for easier processing.
#[derive(Serialize, Deserialize, Debug)]
pub enum UnrealInterfaceMessage {
    /// A response to an UnrealCommand. These can only be sent as a response to
    /// a command from the adapter.
    Response(UnrealResponse),
    /// An event. These can occur at any time without any intervention from the
    /// adapter.
    Event(UnrealEvent),
}
