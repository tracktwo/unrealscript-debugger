//! DAP Events
//!
//! Events are sent at arbitrary times from the adapter to the client.

use serde::Serialize;

/// A DAP event message
///
/// This is typically used only by the client, the adapter uses the [`Event`] type.
#[derive(Serialize, Debug)]
pub struct EventMessage {
    /// The sequence number for this message.
    pub seq: i64,
    #[serde(flatten)]
    /// The event to send.
    pub event: Event,
}

/// A DAP event.
///
/// This is the main structure for a DAP event created by the adapter.
#[derive(Serialize, Debug)]
#[serde(tag = "type", rename = "event")]
pub struct Event {
    /// The event body.
    #[serde(flatten)]
    pub body: EventBody,
}

/// An event-specific event body.
#[derive(Serialize, Debug)]
#[serde(tag = "event", content = "body", rename_all = "camelCase")]
pub enum EventBody {
    /// Initialized event, sent by the adapter after initialization is complete.
    Initialized,

    /// Invalidated event. This is used to invalidate stacks when we don't have
    /// full line number info available.
    Invalidated(InvalidatedEventBody),

    /// Output event. Used to send information to the client. Usually used to
    /// send log info to the editor's debug console, but is also used to send
    /// update notices to the editor when there is a version mismatch between the
    /// adapter and interface.
    Output(OutputEventBody),

    /// Stopped event. Sent when Unreal has stopped at a breakpoint or during
    /// stepping (and it doesn't tell us which).
    Stopped(StoppedEventBody),

    /// Terminated event. Sent when we detect the debuggee has shut down.
    Terminated,
}

/// Body for an invalidated event.
#[derive(Serialize, Debug)]
pub struct InvalidatedEventBody {
    /// The areas that have been invalidated.
    pub areas: Vec<InvalidatedAreas>,
    /// Which stack frame has been invalidated.
    #[serde(rename = "stackFrameId")]
    pub frame_id: i64,
}

/// Areas that may be invalidated.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum InvalidatedAreas {
    /// All areas.
    All,
    /// Stack frames have been invalidated. Used when updating line info.
    Stacks,
    /// Threads have been invalidated. Not used.
    Threads,
    /// Variables have been invalidated. Not used.
    Variables,
}

/// Body for an output event.
#[derive(Serialize, Debug)]
pub struct OutputEventBody {
    /// The output category.
    pub category: OutputEventCategory,
    /// Output text to be displayed.
    pub output: String,
}

/// Categories for output events.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum OutputEventCategory {
    /// Console. Used for debugger information and is written to the debug console.
    ///
    /// This is used for version update info messages.
    Console,

    /// An 'important' message. DAP docs indicate this should be displayed to the user
    /// in a more obvious way (e.g. a popup). VSCode will display a popup but appears to
    /// expect the string to be in some non-textual format or some other fields to be present.
    Important,

    /// Stdout output from the debuggee. Unreal logs are written here.
    Stdout,

    /// Stderr output from the debuggee. Not used; Unreal does not log output to different
    /// channels.
    Stderr,

    /// Telemetry. Not used.
    Telemetry,
}

/// A stopped event body.
#[derive(Serialize, Debug)]
pub struct StoppedEventBody {
    /// The thread that has stopped. Unrealscript only has one thread.
    #[serde(rename = "threadId")]
    pub thread_id: i64,
    /// The reason why we stopped. Unreal doesn't tell us this, so we always
    /// use 'Breakpoint'.
    pub reason: StoppedEventReason,
}

/// The reason why the debugger stopped.
///
/// Other useful reasons would be things like step, but Unreal doesn't give
/// us enough info to be able to make use of different conditions.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum StoppedEventReason {
    /// Stopped due to a breakpoint.
    Breakpoint,
}
