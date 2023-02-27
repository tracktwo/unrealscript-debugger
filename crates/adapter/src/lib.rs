mod comm;

pub mod variable_reference;

use std::{
    collections::BTreeMap,
    net::TcpStream,
    num::TryFromIntError,
    path::{Component, Path},
    process::Child,
    thread::JoinHandle,
};

use dap::{
    events::{
        EventBody, EventSend, ExitedEventBody, InvalidatedEventBody, OutputEventBody,
        StoppedEventBody,
    },
    prelude::*,
    requests::{
        AttachRequestArguments, ContinueArguments, EvaluateArguments, InitializeArguments,
        LaunchRequestArguments, NextArguments, PauseArguments, ScopesArguments,
        SetBreakpointsArguments, StackTraceArguments, StepInArguments, StepOutArguments,
        VariablesArguments,
    },
    responses::{ContinueResponse, ErrorMessage, EvaluateResponse, VariablesResponse},
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
    Breakpoint, FrameIndex, StackTraceRequest, UnrealEvent, Variable, VariableIndex, WatchKind,
    DEFAULT_PORT,
};

use comm::{ChannelError, UnrealChannel};

/// The thread ID to use for the unrealscript thread. The unreal debugger only supports one thread.
const UNREAL_THREAD_ID: i64 = 1;

/// The exit code to send to the client when we've detected that the interface has shut down in
/// some unexpected way.
const UNREAL_UNEXPECTED_EXIT_CODE: i32 = 1;

pub struct UnrealscriptAdapter {
    class_map: BTreeMap<String, ClassInfo>,
    source_roots: Vec<String>,
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
            source_roots: vec![],
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

    #[error("Invalid program: {0}")]
    InvalidProgram(String),
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
            UnrealscriptAdapterError::InvalidProgram(_) => 6,
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
            Command::Launch(args) => self.launch(args, ctx),
            Command::Disconnect(_args) => {
                // TODO send a 'stopdebugging' command, and shut down our event loop.
                return Ok(Response::make_ack(&request).expect("disconnect can be acked"));
            }
            Command::StackTrace(args) => self.stack_trace(args),
            Command::Scopes(args) => self.scopes(args),
            Command::Variables(args) => self.variables(args, ctx),
            Command::Evaluate(args) => self.evaluate(args),
            Command::Pause(args) => self.pause(args),
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

        log::trace!("setting breakpoints for {qualified_class_name}");
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

    /// Extract the port number from a launch/attach arguments value map.
    fn extract_port(value: &Option<Value>) -> Option<u16> {
        value.as_ref()?["port"].as_i64()?.try_into().ok()
    }

    /// Extract the program from launch arguments.
    fn extract_program(value: &Option<Value>) -> Option<&str> {
        value.as_ref()?["program"].as_str()
    }

    /// Extract the argument list from launch arguments.
    fn extract_args(value: &Option<Value>) -> Option<impl Iterator<Item = &str>> {
        let arr = value.as_ref()?["args"].as_array()?;
        Some(
            arr.iter()
                .filter(|e| e.is_string())
                .map(|e| e.as_str().unwrap()),
        )
    }

    /// Extract the source roots list from the launch/attach arguments.
    fn extract_source_roots(value: &Option<Value>) -> Option<Vec<String>> {
        let arr = value.as_ref()?["sourceRoots"].as_array()?;
        Some(
            arr.iter()
                .filter(|e| e.is_string())
                .map(|e| e.as_str().unwrap().to_string())
                .collect(),
        )
    }

    /// Given a package and class name, search the provided source roots in order looking for the
    /// first one that has a file that matches these names.
    fn find_source_file(&mut self, package: &str, class: &str) -> Option<String> {
        for root in &self.source_roots {
            let path = Path::new(root);
            if !path.exists() {
                log::error!("Invalid source root: {root}");
                continue;
            }

            log::info!("Searching source root {root} for {package}.{class}");

            let candidate = path
                .join(package)
                .join("Classes")
                .join(format!("{class}.uc"));
            if !candidate.exists() {
                continue;
            }

            // TODO: Remove the \\? prefix if present.
            let canonical = candidate
                .canonicalize()
                .or_else(|e| {
                    log::error!("Failed to canonicalize path {candidate:#?}");
                    Err(e)
                })
                .ok()?;

            let path = canonical.to_str();
            if !path.is_some() {
                log::error!("Failed to stringize path {candidate:#?}");
                return None;
            }
            let str = path.unwrap().to_string();
            log::info!("Mapped {package}.{class} -> {str}");
            return Some(str);
        }

        log::warn!("No source file found for {package}.{class}");
        None
    }

    /// Given a source file that is not known to our class map, locate the correct location on
    /// disk for that source, add it to the class map, and return a source entry for it.
    /// the correct path.
    fn translate_source(&mut self, canonical_name: String) -> Option<Source> {
        // If this entry does not exist then we need to try to find it by searching source roots.
        if !self.class_map.contains_key(&canonical_name) {
            // This entry does not exist in our map, so try to locate the source file by searching
            // the source roots.
            let mut split = canonical_name.split(".");
            let package = split.next().or_else(|| {
                log::error!("Invalid class name {canonical_name}");
                None
            })?;
            let class = split.next().or_else(|| {
                log::error!("Invalid class name {canonical_name}");
                None
            })?;

            // Find the real source file, or return if we can't.
            let full_path = self.find_source_file(package, class)?;

            // Split the source back out from the obtained filename. Unreal will provide qualified
            // names in all uppercase, but the full path we return will have the on-disk casing.
            // Use that instead since it's 1) less screamy, and 2) consistent with the sources we
            // will add when the first time we encounter a source is from a setBreakpoints request
            // instead of in an unreal callstack since the client will also give us the filename in
            // canonicalized case.
            let (package, class) = split_source(&full_path).ok().or_else(|| {
                log::error!(
                    "Failed to split canonicalized source back into package and class: {full_path}"
                );
                None
            })?;

            // Put this entry in the map for later.
            let class_info = ClassInfo {
                file_name: full_path,
                package_name: package,
                class_name: class,
                breakpoints: vec![],
            };
            self.class_map.insert(canonical_name.clone(), class_info);
        }

        // Find the entry: this should always succeed since we just added it if it wasn't there.
        let entry = self.class_map.get(&canonical_name).unwrap();
        Some(Source {
            name: Some(entry.qualify()),
            path: Some(entry.file_name.clone()),
            source_reference: None,
            presentation_hint: None,
            origin: None,
            sources: None,
            adapter_data: None,
            checksums: None,
        })
    }

    /// Connect to the debugger interface. When connected this will send an 'initialized' event to
    /// DAP. This is shared by both the 'launch' and 'attach' requests.
    fn connect_to_interface(
        &mut self,
        port: u16,
        ctx: &mut dyn Context,
        child: Option<Child>,
    ) -> Result<(), UnrealscriptAdapterError> {
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
            event_loop(event_sender, event_receiver, child)
        }));

        // Now that we're connected we can tell the client that we're ready to receive breakpoint
        // info, etc. Send the 'initialized' event.
        ctx.send_event(Event {
            body: events::EventBody::Initialized,
        })
        .or(Err(UnrealscriptAdapterError::CommunicationError(
            ChannelError::ConnectionError,
        )))?;

        Ok(())
    }

    /// Attach to a running unreal process
    fn attach(
        &mut self,
        args: &AttachRequestArguments,
        ctx: &mut dyn Context,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Attach request");
        let port = Self::extract_port(&args.other).unwrap_or(DEFAULT_PORT);
        match Self::extract_source_roots(&args.other) {
            Some(v) => self.source_roots = v,
            _ => (),
        };
        self.connect_to_interface(port, ctx, None)?;
        Ok(ResponseBody::Attach)
    }

    /// Launch a process and attach to it.
    fn launch(
        &mut self,
        args: &LaunchRequestArguments,
        ctx: &mut dyn Context,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        let program = Self::extract_program(&args.other).ok_or(
            UnrealscriptAdapterError::InvalidProgram("No program provided".to_string()),
        )?;

        match Self::extract_source_roots(&args.other) {
            Some(v) => self.source_roots = v,
            _ => (),
        };

        let program_args = Self::extract_args(&args.other);

        let mut command = &mut std::process::Command::new(program);
        if program_args.is_some() {
            command = command.args(program_args.unwrap());
            log::info!("Program args are {:#?}", command.get_args());
        }

        // Unless instructed otherwise we're going to debug the launched process, so pass
        // '-autoDebug' and try to connect. If 'no_debug' is 'true' then we're just launching and
        // will not try to debug. We could get a later 'attach' request, in which case we can
        // attach, but that also requires the user to enable the debugger from the unreal side with
        // 'toggledebugger'.
        let auto_debug = match args.no_debug {
            Some(true) => false,
            _ => true,
        };

        // Append '-autoDebug' if we're launching so we can be sure the interface will launch and
        // we can connect.
        if auto_debug {
            command = command.arg("-autoDebug");
        }

        log::info!(
            "Launching {} with arguments {:#?}",
            program,
            command.get_args()
        );

        // Spawn the process.
        //
        // Note we must disconnect all streams (or we could pipe them elsewhere...). By
        // default in/out/err streams are inherited from the parent process, and we do _not_ want
        // unreal writing to stdout or reading from stdin since those are our communication
        // channel with the DAP client.
        let child = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .or(Err(UnrealscriptAdapterError::InvalidProgram(format!(
                "Failed to launch {0}",
                program
            ))))?;

        // If we're auto-debugging we can now connect to the interface.
        if auto_debug {
            let port = Self::extract_port(&args.other).unwrap_or(DEFAULT_PORT);
            self.connect_to_interface(port, ctx, Some(child))?;
        }

        Ok(ResponseBody::Launch)
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
                        let canonical_name = f.qualified_name.to_uppercase();
                        // Find the source file for this class.
                        let source = self.translate_source(canonical_name);

                        StackFrame {
                            // We'll use the index into the stack frame vector as the id
                            id: i as i64 + start_frame as i64,
                            name: f.function_name,
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

    fn evaluate(
        &mut self,
        args: &EvaluateArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.ensure_connected()?;

        let var = self.channel.as_mut().unwrap().evaluate(&args.expression)?;
        let child_count = self.get_child_count(WatchKind::User, &var);

        Ok(ResponseBody::Evaluate(EvaluateResponse {
            result: var.value,
            type_field: Some(var.ty),
            presentation_hint: None,
            variables_reference: VariableReference::new(
                WatchKind::User,
                FrameIndex::TOP_FRAME,
                var.index,
            )
            .to_int(),
            named_variables: if !var.is_array { child_count } else { None },
            indexed_variables: if var.is_array { child_count } else { None },
            memory_reference: None,
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
                    let cnt = self.get_child_count(var.kind(), v);
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

    fn get_child_count(&mut self, kind: WatchKind, var: &Variable) -> Option<i64> {
        if var.has_children {
            self.channel
                .as_mut()
                .unwrap()
                .watch_count(kind, var.index)
                .ok()
                .map(|c| {
                    c.try_into().unwrap_or_else(|_| {
                        log::error!("Child count for var {} too large", var.name);
                        0
                    })
                })
        } else {
            None
        }
    }

    /// "Pause": Tell the debugger to break as soon as possible.
    fn pause(&mut self, _args: &PauseArguments) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.ensure_connected()?;
        self.channel.as_mut().unwrap().pause()?;

        Ok(ResponseBody::Pause)
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
fn event_loop(
    sender: Box<dyn EventSend>,
    receiver: Deserializer<IoRead<TcpStream>>,
    child: Option<Child>,
) -> () {
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

    log::info!("Event loop exited: Unreal stopped?");

    // The iterator is exhausted, which means we've lost the connection to the interface without
    // receiving a 'Disconnect' event. This likely means something terrible has happened to Unreal
    // (or the user has just closed it). If we are in a launch configuration then we should be
    // able to check the exit code of the child process.
    //
    // Send the adapter an "Exited" event, followed by a "terminated" event. If either of these
    // fails to send because the adapter is closing down too then we can just ignore the error.

    // Check if we have an exit code from the child process. We're not going to try too hard
    // to get this, if it's not available just return a default code -- we're sending a terminated
    // event so if we were launched the client is going to kill this process anyway so we don't
    // need to worry too much about leaking.
    let exit_code = child
        .and_then(|mut c| c.try_wait().ok())
        .flatten()
        .and_then(|c| c.code())
        .unwrap_or(UNREAL_UNEXPECTED_EXIT_CODE);

    sender
        .send_event(events::Event {
            body: events::EventBody::Exited(ExitedEventBody {
                exit_code: exit_code.into(),
            }),
        })
        .ok();
    sender
        .send_event(events::Event {
            body: events::EventBody::Terminated(None),
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

    /// Convert to a DAP source entry.
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

        fn evaluate(&mut self, _expr: &str) -> Result<Variable, ChannelError> {
            Ok(Variable {
                name: "Var".to_string(),
                ty: "type".to_string(),
                value: "val".to_string(),
                index: VariableIndex::create(1).unwrap(),
                has_children: false,
                is_array: false,
            })
        }

        fn pause(&mut self) -> Result<(), ChannelError> {
            Ok(())
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
