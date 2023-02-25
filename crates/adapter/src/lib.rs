mod comm;

pub mod variable_reference;

use std::{
    collections::BTreeMap,
    net::TcpStream,
    num::TryFromIntError,
    path::{Component, Path},
    thread::JoinHandle,
};

use dap::{
    events::{
        EventBody, EventSend, ExitedEventBody, InvalidatedEventBody, OutputEventBody,
        StoppedEventBody,
    },
    prelude::*,
    requests::{
        AttachRequestArguments, ContinueArguments, InitializeArguments, NextArguments,
        ScopesArguments, SetBreakpointsArguments, StackTraceArguments, StepInArguments,
        StepOutArguments, VariablesArguments,
    },
    responses::{ContinueResponse, ErrorMessage, VariablesResponse},
    types::{
        Capabilities, InvalidatedAreas, OutputEventCategory, Scope, Source, StackFrame,
        StoppedEventReason, Thread,
    },
};
use serde_json::{de::IoRead, Deserializer, Value};
use std::fmt::Debug;
use thiserror::Error;
use variable_reference::VariableReference;

use common::{
    Breakpoint, FrameIndex, StackTraceRequest, UnrealEvent, VariableIndex, WatchKind, DEFAULT_PORT,
};

use comm::{ChannelError, UnrealChannel};

/// The thread ID to use for the unrealscript thread. The unreal debugger only supports one thread.
const UNREAL_THREAD_ID: i64 = 1;

/// The exit code to send to the client when we've detected that the interface has shut down in
/// some unexpected way.
const UNREAL_UNEXPECTED_EXIT_CODE: i64 = 1;

pub struct UnrealscriptAdapter {
    class_map: BTreeMap<String, ClassInfo>,
    channel: Option<Box<dyn UnrealChannel>>,
    event_thread: Option<JoinHandle<()>>,
    // If true (the default and Unreal's native mode) the client expects lines to start at 1.
    // Otherwise they start at 0.
    one_based_lines: bool,
    // If true then we will send type information with variables.
    supports_variable_type: bool,
    // If true then we'll send invalidated events when fetching variables that involves a stack
    // change.
    supports_invalidated_event: bool,
}

impl UnrealscriptAdapter {
    pub fn new() -> UnrealscriptAdapter {
        UnrealscriptAdapter {
            class_map: BTreeMap::new(),
            channel: None,
            event_thread: None,
            one_based_lines: true,
            supports_variable_type: false,
            supports_invalidated_event: false,
        }
    }
}

#[derive(Error, Debug)]
pub enum UnrealscriptAdapterError {
    #[error("Unhandled command: {0}")]
    UnhandledCommandError(String),

    #[error("Invalid filename: {0}")]
    InvalidFilename(String),

    #[error("Not connected")]
    NotConnected,

    #[error("Communication error: {0}")]
    CommunicationError(ChannelError),

    #[error("Limit exceeded: {0}")]
    LimitExceeded(String),
}

impl UnrealscriptAdapterError {
    /// Return a fixed id number for an error. This is used in DAP error
    /// responses to uniquely identify messages.
    fn id(&self) -> i64 {
        match self {
            UnrealscriptAdapterError::UnhandledCommandError(_) => 1,
            UnrealscriptAdapterError::InvalidFilename(_) => 2,
            UnrealscriptAdapterError::NotConnected => 3,
            UnrealscriptAdapterError::CommunicationError(_) => 4,
            UnrealscriptAdapterError::LimitExceeded(_) => 5,
        }
    }

    /// Convet an UnrealScriptAdapterError to a DAP error message suitable
    /// for use as a body in an error response.
    pub fn to_error_message(&self) -> ErrorMessage {
        ErrorMessage {
            id: self.id(),
            format: self.to_string(),
            show_user: true,
        }
    }
}

impl From<ChannelError> for UnrealscriptAdapterError {
    /// Convert a ChannelError to an UnrealscriptAdapterError
    fn from(value: ChannelError) -> Self {
        UnrealscriptAdapterError::CommunicationError(value)
    }
}

type Error = UnrealscriptAdapterError;

impl Adapter for UnrealscriptAdapter {
    type Error = UnrealscriptAdapterError;

    /// Process a DAP request, returning a response.
    fn accept(&mut self, request: Request, ctx: &mut dyn Context) -> Result<Response, Self::Error> {
        log::info!("Got request {request:#?}");
        let response = match &request.command {
            Command::Initialize(args) => self.initialize(args),
            Command::SetBreakpoints(args) => self.set_breakpoints(args),
            Command::Threads => self.threads(),
            Command::ConfigurationDone => {
                return Ok(Response::make_ack(&request).expect("ConfigurationDone can be acked"))
            }
            Command::Attach(args) => self.attach(args, ctx),
            Command::Disconnect(_args) => {
                return Ok(Response::make_ack(&request).expect("disconnect can be acked"))
            }
            Command::StackTrace(args) => self.stack_trace(args),
            Command::Scopes(args) => self.scopes(args),
            Command::Variables(args) => self.variables(args, ctx),
            Command::Continue(args) => self.go(args),
            Command::Next(args) => self.next(args),
            Command::StepIn(args) => self.step_in(args),
            Command::StepOut(args) => self.step_out(args),
            cmd => {
                log::error!("Unhandled command: {cmd:#?}");
                Err(UnrealscriptAdapterError::UnhandledCommandError(
                    request.command.name().to_string(),
                ))
            }
        };

        match response {
            Ok(body) => Ok(Response::make_success(&request, body)),
            Err(e) => Ok(Response::make_error(&request, e.to_error_message())),
        }
    }
}

impl UnrealscriptAdapter {
    /// Handle an initialize request
    fn initialize(
        &mut self,
        args: &InitializeArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        // If the client sends linesStartAt1: false then we need to adjust
        // all the line numbers we receive.
        self.one_based_lines = args.lines_start_at1.unwrap_or(true);

        // Remember if the client supports a type field for variables.
        self.supports_variable_type = args.supports_variable_type.unwrap_or(false);

        // Remember if the client supports invalidated events.
        self.supports_invalidated_event = args.supports_invalidated_event.unwrap_or(false);

        Ok(ResponseBody::Initialize(Some(Capabilities {
            supports_configuration_done_request: Some(true),
            supports_delayed_stack_trace_loading: Some(true),
            supports_value_formatting_options: Some(false),
            ..Default::default()
        })))
    }

    /// Utility function for requests that require an active debugger connection.
    /// Returns a unit OK result if we are connected, or an UnrealscriptAdapterError
    /// otherwise.
    fn ensure_connected(&mut self) -> Result<(), UnrealscriptAdapterError> {
        self.channel
            .as_mut()
            .ok_or(UnrealscriptAdapterError::NotConnected)
            .and(Ok(()))
    }

    /// Handle a setBreakpoints request
    fn set_breakpoints(
        &mut self,
        args: &SetBreakpointsArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Set breakpoints request");

        // If we are not connected we cannot proceed
        self.ensure_connected()?;

        // Break the source file out into sections and record it in our map of
        // known classes if necessary.
        let path = args
            .source
            .path
            .as_ref()
            .expect("Clients should provide sources as paths");
        let class_info =
            ClassInfo::make(path.to_string()).or(Err(Error::InvalidFilename(path.to_string())))?;
        let mut qualified_class_name = class_info.qualify();
        qualified_class_name.make_ascii_uppercase();
        let class_info = self
            .class_map
            .entry(qualified_class_name.clone())
            .or_insert(class_info);

        // Remove all the existing breakpoints from this class.
        for bp in class_info.breakpoints.iter() {
            let removed = self
                .channel
                .as_mut()
                .unwrap()
                .remove_breakpoint(Breakpoint::new(&qualified_class_name, *bp))?;

            // The internal state of the adapter's breakpoint list should always be consistent with
            // what unreal thinks the breakpoints are set on.
            assert!(removed.line == *bp);
        }

        class_info.breakpoints.clear();

        let mut dap_breakpoints: Vec<dap::types::Breakpoint> = Vec::new();

        // Now add the new ones (if any)
        if let Some(breakpoints) = &args.breakpoints {
            for bp in breakpoints {
                // Note that Unreal only accepts 32-bit lines.
                if let Ok(mut line) = bp.line.try_into() {
                    // The line number received may require adjustment
                    line += if self.one_based_lines { 0 } else { 1 };

                    let new_bp = self
                        .channel
                        .as_mut()
                        .unwrap()
                        .add_breakpoint(Breakpoint::new(&qualified_class_name, line))?;

                    // Record this breakpoint in our data structure
                    class_info.breakpoints.push(new_bp.line);

                    // Record it in the response
                    dap_breakpoints.push(dap::types::Breakpoint {
                        verified: true,
                        // Line number may require adjustment before sending back out to the
                        // client.
                        line: Some(
                            (new_bp.line + if self.one_based_lines { 0 } else { -1 }).into(),
                        ),
                        source: Some(class_info.to_source()),
                        ..Default::default()
                    });
                }
            }
        }

        Ok(ResponseBody::SetBreakpoints(
            responses::SetBreakpointsResponse {
                breakpoints: dap_breakpoints,
            },
        ))
    }

    /// Handle a threads request
    fn threads(&mut self) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Threads request");
        Ok(ResponseBody::Threads(responses::ThreadsResponse {
            threads: vec![Thread {
                id: 1,
                name: "main".to_string(),
            }],
        }))
    }

    // Extract the port number from an attach arguments value map.
    fn extract_port(value: &Option<Value>) -> Option<i32> {
        value.as_ref()?["port"].as_i64()?.try_into().ok()
    }

    /// Attach to a running unreal process
    fn attach(
        &mut self,
        args: &AttachRequestArguments,
        ctx: &mut dyn Context,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Attach request");

        let port = Self::extract_port(&args.other).unwrap_or(DEFAULT_PORT);

        log::info!("Connecting to port {port}");

        let event_sender = ctx.get_event_sender();
        // Connect to the unrealscript interface and set up the communications channel between
        // it and this adapter.
        //
        // TODO This API is awful, fix it.
        let conn = comm::connect(port)?;

        // The adapter keeps the channel for communicating with the interface: it can send commands
        // and receive responses.
        self.channel = Some(conn.0);

        // The event receiving channel is spun out to a separate thread.
        let event_receiver = conn.1;
        self.event_thread = Some(std::thread::spawn(move || {
            event_loop(event_sender, event_receiver)
        }));

        // Now that we're connected we can tell the client that we're ready to receive breakpoint
        // info, etc. Send the 'initialized' event.
        ctx.send_event(Event {
            body: events::EventBody::Initialized,
        })
        .or(Err(UnrealscriptAdapterError::CommunicationError(
            ChannelError::ConnectionError,
        )))?;

        Ok(ResponseBody::Attach)
    }

    /// Fetch the stack from the interface and send it to the client.
    fn stack_trace(
        &mut self,
        args: &StackTraceArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        let start_frame =
            args.start_frame
                .unwrap_or(0)
                .try_into()
                .or_else(|e: TryFromIntError| {
                    Err(UnrealscriptAdapterError::LimitExceeded(e.to_string()))
                })?;

        let levels = args
            .levels
            .unwrap_or(0)
            .try_into()
            .map_err(|e: TryFromIntError| UnrealscriptAdapterError::LimitExceeded(e.to_string()))?;

        log::info!("Stack trace request for {levels} frames starting at {start_frame}");

        self.ensure_connected()?;

        let response = self
            .channel
            .as_mut()
            .unwrap()
            .stack_trace(StackTraceRequest {
                start_frame,
                levels,
            })?;
        Ok(ResponseBody::StackTrace(
            dap::responses::StackTraceResponse {
                stack_frames: response
                    .frames
                    .into_iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let canonical_name = f.class_name.to_uppercase();
                        let mut source: Option<Source> = None;

                        // TODO Handle source files we haven't seen in our map yet.
                        if let Some(entry) = self.class_map.get(&canonical_name) {
                            source = Some(Source {
                                name: Some(entry.qualify()),
                                path: Some(entry.file_name.clone()),
                                source_reference: None,
                                presentation_hint: None,
                                origin: None,
                                sources: None,
                                adapter_data: None,
                                checksums: None,
                            });
                        }
                        StackFrame {
                            // We'll use the index into the stack frame vector as the id
                            id: i as i64 + start_frame as i64,
                            name: f.class_name,
                            source,
                            line: f.line as i64,
                            column: 0,
                            end_line: None,
                            end_column: None,
                            can_restart: None,
                            instruction_pointer_reference: None,
                            module_id: None,
                            presentation_hint: None,
                        }
                    })
                    .collect(),
                total_frames: None,
            },
        ))
    }

    /// Return the scopes available in this suspended state. Unreal only supports two scopes: Local
    /// and Global (the third watch kind for user watches is handled by DAP and we don't need
    /// native support for it).
    fn scopes(&mut self, args: &ScopesArguments) -> Result<ResponseBody, UnrealscriptAdapterError> {
        let frame_index = FrameIndex::create(args.frame_id).or(Err(
            UnrealscriptAdapterError::LimitExceeded("Frame index out of range".to_string()),
        ))?;

        let globals_ref =
            VariableReference::new(WatchKind::Global, frame_index, VariableIndex::SCOPE);
        let locals_ref =
            VariableReference::new(WatchKind::Local, frame_index, VariableIndex::SCOPE);

        self.ensure_connected()?;

        // For the top-most frame (0) only, fetch all the watch data from the debugger.
        let local_vars = if args.frame_id == 0 {
            Some(
                self.channel
                    .as_mut()
                    .unwrap()
                    .watch_count(WatchKind::Local, VariableIndex::SCOPE)?
                    .try_into()
                    .or(Err(UnrealscriptAdapterError::LimitExceeded(
                        "Too many variables".to_string(),
                    )))?,
            )
        } else {
            None
        };

        let global_vars = if args.frame_id == 0 {
            Some(
                self.channel
                    .as_mut()
                    .unwrap()
                    .watch_count(WatchKind::Global, VariableIndex::SCOPE)?
                    .try_into()
                    .or(Err(UnrealscriptAdapterError::LimitExceeded(
                        "Too many variables".to_string(),
                    )))?,
            )
        } else {
            None
        };

        Ok(ResponseBody::Scopes(responses::ScopesResponse {
            scopes: vec![
                Scope {
                    name: "Locals".to_string(),
                    variables_reference: locals_ref.to_int(),
                    named_variables: local_vars,
                    expensive: args.frame_id != 0,
                    ..Default::default()
                },
                Scope {
                    name: "Globals".to_string(),
                    variables_reference: globals_ref.to_int(),
                    named_variables: global_vars,
                    expensive: args.frame_id != 0,
                    ..Default::default()
                },
            ],
        }))
    }

    /// Return the variables requested.
    fn variables(
        &mut self,
        args: &VariablesArguments,
        ctx: &mut dyn Context,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.ensure_connected()?;

        let var = VariableReference::from_int(args.variables_reference).ok_or(
            UnrealscriptAdapterError::LimitExceeded("Variable reference out of range".to_string()),
        )?;

        // TODO Handle filtering?
        let (vars, invalidated) =
            self.channel.as_mut().unwrap().variables(
                var.kind(),
                var.frame().try_into().unwrap(),
                var.variable().try_into().unwrap(),
                args.start.unwrap_or(0).try_into().or(Err(
                    UnrealscriptAdapterError::LimitExceeded("Start index out of range".to_string()),
                ))?,
                args.count.unwrap_or(0).try_into().or(Err(
                    UnrealscriptAdapterError::LimitExceeded("Count out of range".to_string()),
                ))?,
            )?;

        // If this response involved changing stacks and the client supports it, send an invalidated event
        // This is useful for unreal because we don't have line information for anything except the
        // top-most stack frame until we actually switch to that other frame. This event will
        // instruct the client to refresh this single stack frame, which will allow us to provide a
        // useful line number. This is not perfect: the client tries to switch to the source file
        // and incorrect (0) line number before asking for the variables and before we send this
        // event, so it will jump to the file but the wrong line the first time you switch to that
        // stack frame. Clicking on it again will go to the correct line.
        if invalidated && self.supports_invalidated_event {
            log::trace!("Invalidating frame {}", var.frame());
            ctx.send_event(Event {
                body: EventBody::Invalidated(InvalidatedEventBody {
                    areas: Some(vec![InvalidatedAreas::Stacks]),
                    thread_id: None,
                    stack_frame_id: Some(var.frame().into()),
                }),
            })
            .or(Err(UnrealscriptAdapterError::CommunicationError(
                ChannelError::ConnectionError,
            )))?;
        }

        Ok(ResponseBody::Variables(VariablesResponse {
            variables: vars
                .iter()
                .map(|v| {
                    // If this variable is structured get the child count so we can put it in
                    // the appropriate field of the response.
                    let cnt = if v.has_children {
                        self.channel
                            .as_mut()
                            .unwrap()
                            .watch_count(var.kind(), v.index)
                            .ok()
                            .map(|c| {
                                c.try_into().unwrap_or_else(|_| {
                                    log::error!("Child count for var {} too large", v.name);
                                    0
                                })
                            })
                    } else {
                        None
                    };

                    dap::types::Variable {
                        name: v.name.clone(),
                        value: v.value.clone(),
                        type_field: if self.supports_variable_type {
                            Some(v.ty.clone())
                        } else {
                            None
                        },
                        variables_reference: if v.has_children {
                            VariableReference::new(var.kind(), var.frame(), v.index).to_int()
                        } else {
                            0
                        },
                        named_variables: if !v.is_array { cnt } else { None },
                        indexed_variables: if v.is_array { cnt } else { None },
                        ..Default::default()
                    }
                })
                .collect(),
        }))
    }

    fn go(&mut self, _args: &ContinueArguments) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.ensure_connected()?;
        self.channel.as_mut().unwrap().go()?;

        Ok(ResponseBody::Continue(ContinueResponse {
            all_threads_continued: Some(true),
        }))
    }

    fn next(&mut self, _args: &NextArguments) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.ensure_connected()?;
        self.channel.as_mut().unwrap().next()?;

        Ok(ResponseBody::Next)
    }

    fn step_in(
        &mut self,
        _args: &StepInArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.ensure_connected()?;
        self.channel.as_mut().unwrap().step_in()?;
        Ok(ResponseBody::StepIn)
    }

    fn step_out(
        &mut self,
        _args: &StepOutArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.ensure_connected()?;
        self.channel.as_mut().unwrap().step_out()?;
        Ok(ResponseBody::StepOut)
    }
}

/// The event processing loop for the adapter.
///
/// This is spun up in a dedicated thread once we attacht to the Unreal interface. This will
/// receive a stream of serialized UnrealEvent messages, translate them to DAP events, and dispatch
/// them to the client.
///
/// The adapter itself does not see any events and has no mechanism to process them, but events we
/// pass through to DAP may trigger requests that the adapter will handle.
///
/// This loop will return when we receive a Disconnect event or either the sending channel from
/// Unreal or the receiving side of the event channel are closed. The sending channel closing
/// likely indicates a fatal error in the interface: if the debugger is stopped gracefully from the
/// Unreal side we expect to receive a Disconnect event first. In this case we will send an
/// 'exited' event with a non-zero code before returning.
fn event_loop(sender: Box<dyn EventSend>, receiver: Deserializer<IoRead<TcpStream>>) -> () {
    for evt in receiver.into_iter::<UnrealEvent>() {
        let res = match evt {
            Ok(UnrealEvent::Log(msg)) => sender.send_event(events::Event {
                body: events::EventBody::Output(OutputEventBody {
                    category: Some(OutputEventCategory::Stdout),
                    output: msg,
                    ..Default::default()
                }),
            }),
            Ok(UnrealEvent::Stopped) => sender.send_event(events::Event {
                body: events::EventBody::Stopped(StoppedEventBody {
                    reason: StoppedEventReason::Breakpoint,
                    thread_id: Some(UNREAL_THREAD_ID),
                    description: None,
                    preserve_focus_hint: None,
                    text: None,
                    all_threads_stopped: None,
                    hit_breakpoint_ids: None,
                }),
            }),
            Ok(UnrealEvent::Disconnect) => {
                log::info!("Received disconnect event from Unreal. Closing down the event loop");

                // It's fine if we fail to send this event, in that case the adapter is already
                // closing down too.
                sender
                    .send_event(events::Event {
                        body: events::EventBody::Terminated(None),
                    })
                    .ok();
                return;
            }

            Err(e) => {
                log::error!(
                    "Deserialization error receiving event from the debugger interface: {e}"
                );
                continue;
            }
        };

        // If sending the event through the sender returned an error that can only indicate that
        // the receiving side has closed the channel. This indicates the adapter is shutting down,
        // so we can return.
        if res.is_err() {
            return;
        }
    }

    // The iterator is exhausted, which means we've lost the connection to the interface without
    // receiving a 'Disconnect' event. This likely means something terrible has happened to Unreal.
    // Send the adapter an "Exited" event with a non-zero exit code to indicate this and then
    // stop. Again if this fails to send because the adapter is closing down too then we can just
    // ignore the error.
    sender
        .send_event(events::Event {
            body: events::EventBody::Exited(ExitedEventBody {
                exit_code: UNREAL_UNEXPECTED_EXIT_CODE,
            }),
        })
        .ok();
}

/// Information about a class.
#[derive(Debug)]
pub struct ClassInfo {
    pub file_name: String,
    pub package_name: String,
    pub class_name: String,
    pub breakpoints: Vec<i32>,
}

/// The filename does not conform to the Unreal path conventions for class naming.
#[derive(Debug)]
pub struct BadFilenameError;

impl ClassInfo {
    pub fn make(file_name: String) -> Result<ClassInfo, BadFilenameError> {
        let (package_name, class_name) = split_source(&file_name)?;
        Ok(ClassInfo {
            file_name,
            package_name,
            class_name,
            breakpoints: Vec::new(),
        })
    }

    /// Return a string containing a qualified classname: "package.class"
    pub fn qualify(&self) -> String {
        format!("{}.{}", self.package_name, self.class_name)
    }

    pub fn to_source(&self) -> Source {
        Source {
            name: Some(self.qualify()),
            path: Some(self.file_name.clone()),
            ..Default::default()
        }
    }
}

/// Process a Source entry to obtain information about a class.
///
/// For Unrealscript the details of a class can be determined from its source file.
/// Given a Source entry with a full path to a source file we expect the path to always
/// be of the form:
///
/// <arbitrary leading directories>\Src\PackageName\Classes\ClassName.uc
///
/// From a path of this form we can isolate the package and class names. This naming
/// scheme is mandatory: the Unreal debugger only talks about package and class names,
/// and the client only talks about source files. The Unrealscript compiler uses these
/// same conventions.
pub fn split_source(path_str: &str) -> Result<(String, String), BadFilenameError> {
    let path = Path::new(&path_str);
    let mut iter = path.components().rev();

    // Isolate the filename. This is the last component of the path and should have an extension to
    // strip.
    let component = iter.next().ok_or(BadFilenameError)?;
    let class_name = match component {
        Component::Normal(file_name) => Path::new(file_name).file_stem().ok_or(BadFilenameError),
        _ => Err(BadFilenameError),
    }?
    .to_str()
    .expect("Source path should be valid utf-8")
    .to_owned();

    // Skip the parent
    iter.next();

    // the package name should be the next component.
    let component = iter.next().ok_or(BadFilenameError)?;
    let package_name = match component {
        Component::Normal(file_name) => Ok(file_name),
        _ => Err(BadFilenameError),
    }?
    .to_str()
    .expect("Source path should be vaild utf-8")
    .to_owned();
    Ok((package_name, class_name))
}

#[cfg(test)]
mod tests {
    use common::{Frame, FrameIndex, VariableIndex};
    use dap::types::{Source, SourceBreakpoint};

    use super::*;

    struct MockChannel;

    impl UnrealChannel for MockChannel {
        fn add_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ChannelError> {
            Ok(bp)
        }
        fn remove_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, ChannelError> {
            Ok(bp)
        }

        fn stack_trace(
            &mut self,
            _stack: common::StackTraceRequest,
        ) -> Result<common::StackTraceResponse, ChannelError> {
            Ok(common::StackTraceResponse { frames: vec![] })
        }

        fn watch_count(
            &mut self,
            _kind: WatchKind,
            _parent: VariableIndex,
        ) -> Result<usize, ChannelError> {
            Ok(0)
        }

        fn frame(&mut self, _idx: FrameIndex) -> Result<Option<Frame>, ChannelError> {
            Ok(None)
        }

        fn variables(
            &mut self,
            _kind: WatchKind,
            _frame: FrameIndex,
            _variable: VariableIndex,
            _start: usize,
            _count: usize,
        ) -> Result<(Vec<common::Variable>, bool), ChannelError> {
            Ok((vec![], false))
        }

        fn go(&mut self) -> Result<(), ChannelError> {
            Ok(())
        }

        fn next(&mut self) -> Result<(), ChannelError> {
            Ok(())
        }

        fn step_in(&mut self) -> Result<(), ChannelError> {
            Ok(())
        }

        fn step_out(&mut self) -> Result<(), ChannelError> {
            Ok(())
        }
    }

    const GOOD_PATH: &str = if cfg!(windows) {
        "C:\\foo\\src\\MyPackage\\classes\\SomeClass.uc"
    } else {
        "/home/somebody/src/MyPackage/classes/SomeClass.uc"
    };

    #[test]
    fn can_split_source() {
        let (package, class) = split_source(GOOD_PATH).unwrap();
        assert_eq!(package, "MyPackage");
        assert_eq!(class, "SomeClass");
    }

    #[test]
    fn split_source_bad_classname() {
        let path = if cfg!(windows) {
            "C:\\MyMod\\BadClass.uc"
        } else {
            "/MyMod/BadClass.uc"
        };
        let info = split_source(path);
        assert!(matches!(info, Err(BadFilenameError)));
    }

    #[test]
    fn split_source_forward_slashes() {
        let (package, class) = split_source(GOOD_PATH).unwrap();
        assert_eq!(package, "MyPackage");
        assert_eq!(class, "SomeClass");
    }

    #[test]
    fn qualify_name() {
        let class = ClassInfo::make(GOOD_PATH.to_string()).unwrap();
        let qual = class.qualify();
        assert_eq!(qual, "MyPackage.SomeClass")
    }

    #[test]
    fn add_breakpoint_registers_class() {
        let mut adapter = UnrealscriptAdapter::new();
        adapter.channel = Some(Box::new(MockChannel {}));
        let args = SetBreakpointsArguments {
            source: Source {
                path: Some(GOOD_PATH.to_string()),
                ..Default::default()
            },
            breakpoints: Some(vec![SourceBreakpoint {
                line: 10,
                ..Default::default()
            }]),

            ..Default::default()
        };
        let _response = adapter.set_breakpoints(&args).unwrap();
        // Class cache should be keyed on UPCASED qualified names.
        assert!(adapter.class_map.contains_key("MYPACKAGE.SOMECLASS"));

        // The entry in this map should have 1 breakpoint
        assert_eq!(
            adapter.class_map["MYPACKAGE.SOMECLASS"].breakpoints,
            vec![10]
        );
    }

    #[test]
    fn add_multiple_breakpoints() {
        let mut adapter = UnrealscriptAdapter::new();
        adapter.channel = Some(Box::new(MockChannel {}));
        let args = SetBreakpointsArguments {
            source: Source {
                path: Some(GOOD_PATH.to_string()),
                ..Default::default()
            },
            breakpoints: Some(vec![
                SourceBreakpoint {
                    line: 10,
                    ..Default::default()
                },
                SourceBreakpoint {
                    line: 105,
                    ..Default::default()
                },
            ]),

            ..Default::default()
        };
        let _response = adapter.set_breakpoints(&args).unwrap();
        // The entry in this map should have 2 breakpoints
        assert_eq!(
            adapter.class_map["MYPACKAGE.SOMECLASS"].breakpoints,
            vec![10, 105]
        );
    }

    #[test]
    fn reset_breakpoints() {
        let mut adapter = UnrealscriptAdapter::new();
        adapter.channel = Some(Box::new(MockChannel {}));
        let mut args = SetBreakpointsArguments {
            source: Source {
                path: Some(GOOD_PATH.to_string()),
                ..Default::default()
            },
            breakpoints: Some(vec![
                SourceBreakpoint {
                    line: 10,
                    ..Default::default()
                },
                SourceBreakpoint {
                    line: 105,
                    ..Default::default()
                },
            ]),

            ..Default::default()
        };
        adapter.set_breakpoints(&args).unwrap();

        // Set breakpoints in this class again.
        args = SetBreakpointsArguments {
            source: Source {
                path: Some(GOOD_PATH.to_string()),
                ..Default::default()
            },
            breakpoints: Some(vec![SourceBreakpoint {
                line: 26,
                ..Default::default()
            }]),

            ..Default::default()
        };
        // this should delete the two existing breakpoints and replace them
        // with the new one.
        adapter.set_breakpoints(&args).unwrap();
        assert_eq!(
            adapter.class_map["MYPACKAGE.SOMECLASS"].breakpoints,
            vec![26]
        );
    }
}
