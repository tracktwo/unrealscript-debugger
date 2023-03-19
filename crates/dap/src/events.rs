use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct EventMessage {
    pub seq: i64,
    #[serde(flatten)]
    pub event: Event,
}

#[derive(Serialize, Debug)]
#[serde(tag = "type", rename = "event")]
pub struct Event {
    #[serde(flatten)]
    pub body: EventBody,
}

#[derive(Serialize, Debug)]
#[serde(tag = "event", content = "body", rename_all = "camelCase")]
pub enum EventBody {
    Initialized,
    Invalidated(InvalidatedEventBody),
    Output(OutputEventBody),
    Stopped(StoppedEventBody),
    Terminated,
}

#[derive(Serialize, Debug)]
pub struct InvalidatedEventBody {
    pub areas: Vec<InvalidatedAreas>,
    #[serde(rename = "stackFrameId")]
    pub frame_id: i64,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum InvalidatedAreas {
    All,
    Stacks,
    Threads,
    Variables,
}

#[derive(Serialize, Debug)]
pub struct OutputEventBody {
    pub category: OutputEventCategory,
    pub output: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum OutputEventCategory {
    Console,
    Important,
    Stdout,
    Stderr,
    Telemetry,
}

#[derive(Serialize, Debug)]
pub struct StoppedEventBody {
    #[serde(rename = "threadId")]
    pub thread_id: i64,
    pub reason: StoppedEventReason,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum StoppedEventReason {
    Breakpoint,
}
