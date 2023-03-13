//! A connected debug adapter.
//!
//! An [`UnrealscriptAdapter`] represents a debug adapter after successfully establishing a
//! connection with the debugger interface. This is transformed from a
//! [`crate::disconnected_adapter::DisconnectedAdapter`] which handles the first part of the DAP
//! protocol.

use std::{
    collections::BTreeMap,
    num::TryFromIntError,
    path::{Component, Path},
    process::Child,
};

use common::{
    Breakpoint, FrameIndex, StackTraceRequest, UnrealEvent, Variable, VariableIndex, WatchKind,
};
use dap::{
    events::{EventBody, InvalidatedEventBody, OutputEventBody, StoppedEventBody},
    prelude::*,
    requests::{
        ContinueArguments, DisconnectArguments, EvaluateArguments, NextArguments, PauseArguments,
        ScopesArguments, SetBreakpointsArguments, StackTraceArguments, StepInArguments,
        StepOutArguments, VariablesArguments,
    },
    responses::{ContinueResponse, EvaluateResponse, VariablesResponse},
    types::{
        InvalidatedAreas, OutputEventCategory, Scope, Source, StackFrame, StoppedEventReason,
        Thread,
    },
};
use futures::executor;
use tokio::{
    select,
    sync::{broadcast, mpsc},
};

use crate::{
    async_client::AsyncClient, client_config::ClientConfig, comm::Connection,
    variable_reference::VariableReference, UnrealscriptAdapterError,
};

/// The thread ID to use for the unrealscript thread. The unreal debugger only supports one thread.
const UNREAL_THREAD_ID: i64 = 1;

// Information about a class.
#[derive(Debug)]
struct ClassInfo {
    pub file_name: String,
    pub package_name: String,
    pub class_name: String,
    pub breakpoints: Vec<i32>,
}

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

/// A connected Unrealscript debug adapter.
pub struct UnrealscriptAdapter<C: AsyncClient + Unpin> {
    client: C,
    config: ClientConfig,
    connection: Box<dyn Connection>,
    class_map: BTreeMap<String, ClassInfo>,
    control: Option<broadcast::Sender<ControlMessage>>,
    events: Option<mpsc::Sender<Event>>,
    child: Option<Child>,
}

#[derive(Debug, Clone, Copy)]
enum ControlMessage {
    Shutdown,
}

impl<C: AsyncClient + Unpin> Drop for UnrealscriptAdapter<C> {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            log::trace!("Killing child process.");
            child.kill().unwrap_or_else(|e| {
                log::error!("Failed to kill child process: {e:?}");
            })
        }
    }
}

impl<C> UnrealscriptAdapter<C>
where
    C: AsyncClient + Unpin,
{
    /// Construct a new connected adapter.
    pub fn new(
        client: C,
        config: ClientConfig,
        connection: Box<dyn Connection>,
        child: Option<Child>,
    ) -> UnrealscriptAdapter<C> {
        UnrealscriptAdapter {
            class_map: BTreeMap::new(),
            connection,
            client,
            config,
            control: None,
            events: None,
            child,
        }
    }

    /// Enqueue an event to the adapter queue.
    fn queue_event(&mut self, evt: Event) {
        executor::block_on(async { self.events.as_ref().unwrap().send(evt).await })
            .expect("Receiver cannot drop.");
    }

    /// Main loop of the adapter process. This monitors several different communications
    /// channels and dispatches messages:
    ///
    /// - Watch the client for incoming requests and send back a response.
    /// - Watch the interface's event queue for incoming events, translate them
    ///   and push them into the adapter's event queue.
    /// - Watch the adapter event queue and push events to the client.
    /// - Watch the control queue for shutdown messages, closing the loop if we
    ///   get one.
    ///
    /// # Errors
    ///
    /// This function returns an io error only in unrecoverable scenarios,
    /// typically if the client or interface communication channels have closed.
    pub async fn process_messages(&mut self) -> Result<(), std::io::Error> {
        // Set up the control channel
        let (ctx, mut crx) = broadcast::channel(10);
        self.control = Some(ctx);

        // Set up the event channel for DAP events. The adapter needs to generate DAP
        // events in response to certain states (in particular sending the Initialized event
        // when initialization completes).
        let (etx, mut erx) = mpsc::channel(128);
        self.events = Some(etx);

        // Now that we're connected we can tell the client that we're ready to receive breakpoint
        // info, etc. Send the 'initialized' event.
        self.queue_event(Event {
            body: events::EventBody::Initialized,
        });

        loop {
            select! {
                request = self.client.next_request() => {
                    match request {
                        Some(Ok(request)) => {
                            let response = match self.accept(&request) {
                                Ok(body) => Response::make_success(&request, body),
                                // An error from the request processing code is recoverable. Send
                                // an error response to the client so it may display it.
                                Err(e) => {
                                    log::error!("Error processing request: {e}");
                                    Response::make_error(&request, e.to_error_message())
                                },
                            };
                            // Failing to send the response is unrecoverable. This indicates
                            // the client connection has closed so we can never send any more
                            // responses or events.
                            self.client.respond(response)?;
                        },
                        // A 'None' from the client means the connection is closed and no
                        // more requests will come. Seeing this without a previous disconnect
                        // message is an error (e.g. the editor crashed?). We can return and
                        // shut down -- this is unrecoverable because we no longer have a
                        // connection to the client.
                        None => return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Client request stream has closed")),
                        // An error response from the client indicates some kind of framing or
                        // protocol error at the DAP level. This is not generally recoverable
                        // since the client is waiting for a response to the message that we
                        // failed to decode, and we can't prepare that response because we don't
                        // know the request id to use in it.
                        Some(Err(e)) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                    }
                }
                evt = self.connection.event_receiver().recv() => {
                    // We received an event from the interface. Translate it to
                    // a DAP event and send to the client.
                    match evt {
                        Some(evt) => {
                            log::trace!("Received unreal event {evt:?}");
                            if let Some(dap_event) = self.process_event(evt) {
                                self.client.send_event(dap_event)?;
                            }
                            // Receiving 'None' from process_event is not an error,
                            // it can indicate that we have received a shutdown event
                            // and this will be sent in the control queue handler below.
                        },
                        None => {
                            // The remote side has closed the connection, so we have to
                            // stop. Send a terminated event to the client and exit the
                            // loop.
                            log::info!("Debuggee has closed the event connection socket.");
                            self.client.send_event(Event{
                                body: EventBody::Terminated(None)
                            })?;
                            return Ok(());
                        }
                    };
                }
                ctrl = crx.recv() => {
                    match ctrl {
                        Ok(ControlMessage::Shutdown) => {
                            log::info!("Shutdown message received. Stopping adapter.");
                            self.client.send_event(Event{
                                body: EventBody::Terminated(None)
                            })?;
                            return Ok(());
                        },
                        Err(broadcast::error::RecvError::Closed) => unreachable!(),
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            log::error!("Control queue full!");
                        },
                    };
                }
                evt = erx.recv() => {
                    match evt {
                        Some(evt) => {
                            log::trace!("Dispatching event: {evt:?}");
                            self.client.send_event(evt)?;
                        },
                        None => {
                            // This should not be possible since self contains the sending end of
                            // the channel.
                            unreachable!("The event channel cannot close while the adapter is running.");
                        }
                    };
                }
            };
        }
    }

    /// Process a DAP request, returning a response body.
    pub fn accept(&mut self, request: &Request) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Got request {request:#?}");
        match &request.command {
            Command::SetBreakpoints(args) => self.set_breakpoints(args),
            Command::Threads => self.threads(),
            Command::ConfigurationDone => Ok(ResponseBody::ConfigurationDone),
            Command::Disconnect(args) => self.disconnect(args),
            Command::StackTrace(args) => self.stack_trace(args),
            Command::Scopes(args) => self.scopes(args),
            Command::Variables(args) => self.variables(args),
            Command::Evaluate(args) => self.evaluate(args),
            Command::Pause(args) => self.pause(args),
            Command::Continue(args) => self.go(args),
            Command::Next(args) => self.next(args),
            Command::StepIn(args) => self.step_in(args),
            Command::StepOut(args) => self.step_out(args),
            cmd => {
                log::error!("Unhandled command: {cmd:#?}");
                Err(UnrealscriptAdapterError::UnhandledCommand(
                    request.command.name().to_string(),
                ))
            }
        }
    }

    /// Handle a setBreakpoints request
    fn set_breakpoints(
        &mut self,
        args: &SetBreakpointsArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Set breakpoints request");

        // Break the source file out into sections and record it in our map of
        // known classes if necessary.
        let path = args
            .source
            .path
            .as_ref()
            .expect("Clients should provide sources as paths");
        let class_info = ClassInfo::make(path.to_string()).or(Err(
            UnrealscriptAdapterError::InvalidFilename(path.to_string()),
        ))?;
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
                .connection
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
                    line += if self.config.one_based_lines { 0 } else { 1 };

                    let new_bp = self
                        .connection
                        .add_breakpoint(Breakpoint::new(&qualified_class_name, line))?;

                    // Record this breakpoint in our data structure
                    class_info.breakpoints.push(new_bp.line);

                    // Record it in the response
                    dap_breakpoints.push(dap::types::Breakpoint {
                        verified: true,
                        // Line number may require adjustment before sending back out to the
                        // client.
                        line: Some(
                            (new_bp.line + if self.config.one_based_lines { 0 } else { -1 }).into(),
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

    /// Given a package and class name, search the provided source roots in order looking for the
    /// first one that has a file that matches these names.
    fn find_source_file(&mut self, package: &str, class: &str) -> Option<String> {
        for root in &self.config.source_roots {
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

            let canonical = candidate
                .canonicalize()
                .map_err(|e| {
                    log::error!("Failed to canonicalize path {candidate:#?}");
                    e
                })
                .ok()?;

            let path = canonical.to_str();
            if path.is_none() {
                log::error!("Failed to stringize path {candidate:#?}");
                return None;
            }

            // Strip the UNC prefix canonicalize added. This is not strictly necessary but makes
            // the pathnames look nicer in the editor.
            let str = path.and_then(|s| s.strip_prefix("\\\\?\\"));
            log::info!("Mapped {package}.{class} -> {str:?}");
            return str.map(|s| s.to_owned());
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
            let mut split = canonical_name.split('.');
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

    fn disconnect(
        &mut self,
        _args: &DisconnectArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.connection.disconnect()?;
        Ok(ResponseBody::Disconnect)
    }

    /// Fetch the stack from the interface and send it to the client.
    fn stack_trace(
        &mut self,
        args: &StackTraceArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        let start_frame = args
            .start_frame
            .unwrap_or(0)
            .try_into()
            .map_err(|e: TryFromIntError| UnrealscriptAdapterError::LimitExceeded(e.to_string()))?;

        let levels = args
            .levels
            .unwrap_or(0)
            .try_into()
            .map_err(|e: TryFromIntError| UnrealscriptAdapterError::LimitExceeded(e.to_string()))?;

        log::info!("Stack trace request for {levels} frames starting at {start_frame}");

        let response = self.connection.stack_trace(StackTraceRequest {
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

        // For the top-most frame (0) only, fetch all the watch data from the debugger.
        let local_vars = if args.frame_id == 0 {
            Some(
                self.connection
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
                self.connection
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
                    name: "self".to_string(),
                    variables_reference: globals_ref.to_int(),
                    named_variables: global_vars,
                    expensive: false,
                    ..Default::default()
                },
                Scope {
                    name: "locals".to_string(),
                    variables_reference: locals_ref.to_int(),
                    named_variables: local_vars,
                    expensive: false,
                    ..Default::default()
                },
            ],
        }))
    }

    fn evaluate(
        &mut self,
        args: &EvaluateArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        let var = self.connection.evaluate(&args.expression)?;

        // We may get back a `None`, which means that something has gone wrong with evaluating this
        // expression. This is not a typical error, passing an invalid expression will usually
        // still provide a valid response with a value indicating that the expression can't be
        // resolved. Send an error back to the client in this case.
        let var = var.ok_or(UnrealscriptAdapterError::WatchError(
            args.expression.clone(),
        ))?;
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
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        let var = VariableReference::from_int(args.variables_reference).ok_or(
            UnrealscriptAdapterError::LimitExceeded("Variable reference out of range".to_string()),
        )?;

        // Note: filtering is not implemented. In Unreal any given variable can have either named
        // or indexed children, but not both. We will never send a variables/scopes response that
        // has a non-zero count for both of these types, so we should also never receive a request
        // for one of the types. Even if the client requested a particular filtering we would
        // either send the whole list (if the filter matched) or nothing (if it didn't).
        let (vars, invalidated) =
            self.connection.variables(
                var.kind(),
                var.frame(),
                var.variable(),
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
        if invalidated && self.config.supports_invalidated_event {
            log::trace!("Invalidating frame {}", var.frame());
            self.queue_event(Event {
                body: EventBody::Invalidated(InvalidatedEventBody {
                    areas: Some(vec![InvalidatedAreas::Stacks]),
                    thread_id: None,
                    stack_frame_id: Some(var.frame().into()),
                }),
            });
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
                        type_field: if self.config.supports_variable_type {
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
            self.connection.watch_count(kind, var.index).ok().map(|c| {
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
        self.connection.pause()?;
        Ok(ResponseBody::Pause)
    }

    fn go(&mut self, _args: &ContinueArguments) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.connection.go()?;
        Ok(ResponseBody::Continue(ContinueResponse {
            all_threads_continued: Some(true),
        }))
    }

    fn next(&mut self, _args: &NextArguments) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.connection.next()?;
        Ok(ResponseBody::Next)
    }

    fn step_in(
        &mut self,
        _args: &StepInArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.connection.step_in()?;
        Ok(ResponseBody::StepIn)
    }

    fn step_out(
        &mut self,
        _args: &StepOutArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        self.connection.step_out()?;
        Ok(ResponseBody::StepOut)
    }

    /// Process an event received from the interface, turning it into an event
    /// to send to the client.
    fn process_event(&mut self, evt: UnrealEvent) -> Option<Event> {
        match evt {
            UnrealEvent::Log(msg) => Some(Event {
                body: events::EventBody::Output(OutputEventBody {
                    category: Some(OutputEventCategory::Stdout),
                    output: msg,
                    ..Default::default()
                }),
            }),
            UnrealEvent::Stopped => Some(Event {
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
            UnrealEvent::Disconnect => {
                // We've received a disconnect event from interface. This means
                // the connection is shutting down. Send the shutdown control
                // message to our control channel so it can cleanly close down
                // the processing loop. We don't return a DAP event here as we
                // will send a terminate event when we close down the loop.
                self.control
                    .as_ref()
                    .unwrap()
                    .send(ControlMessage::Shutdown)
                    .expect("Control channel cannot drop");
                None
            }
        }
    }
}

/// The filename does not conform to the Unreal path conventions for class naming.
#[derive(Debug)]
pub struct BadFilenameError;

/// Process a Source entry to obtain information about a class.
///
/// For Unrealscript the details of a class can be determined from its source file.
/// Given a Source entry with a full path to a source file we expect the path to always
/// be of the form:
///
/// &lt;arbitrary leading directories&gt;\Src\PackageName\Classes\ClassName.uc
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

    use std::io::Error;

    use common::{UnrealCommand, UnrealResponse};
    use dap::types::{Source, SourceBreakpoint};
    use tokio::{
        io::{Stdin, Stdout},
        sync::mpsc::Receiver,
    };

    use crate::async_client::AsyncClientImpl;

    use super::*;

    const GOOD_PATH: &str = if cfg!(windows) {
        "C:\\foo\\src\\MyPackage\\classes\\SomeClass.uc"
    } else {
        "/home/somebody/src/MyPackage/classes/SomeClass.uc"
    };

    fn make_client() -> AsyncClientImpl<tokio::io::Stdin, tokio::io::Stdout> {
        AsyncClientImpl::new(tokio::io::stdin(), tokio::io::stdout())
    }

    struct MockConnection {}

    // A mock connection for testing. This version does not use the low-level required
    // trait methods: they all panic. It reimplements the high-level API to return mocked
    // values instead.
    impl Connection for MockConnection {
        fn send_command(&mut self, _command: UnrealCommand) -> Result<(), Error> {
            unreachable!();
        }

        fn next_response(&mut self) -> Result<UnrealResponse, Error> {
            unreachable!()
        }

        fn event_receiver(&mut self) -> &mut Receiver<UnrealEvent> {
            unreachable!()
        }

        fn add_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, Error> {
            Ok(bp)
        }

        fn remove_breakpoint(&mut self, bp: Breakpoint) -> Result<Breakpoint, Error> {
            Ok(bp)
        }

        fn stack_trace(
            &mut self,
            _req: StackTraceRequest,
        ) -> Result<common::StackTraceResponse, Error> {
            unreachable!()
        }

        fn watch_count(
            &mut self,
            _kind: WatchKind,
            _parent: VariableIndex,
        ) -> Result<usize, Error> {
            unreachable!()
        }

        fn evaluate(&mut self, _expr: &str) -> Result<Option<Variable>, Error> {
            unreachable!()
        }

        fn variables(
            &mut self,
            _kind: WatchKind,
            _frame: FrameIndex,
            _variable: VariableIndex,
            _start: usize,
            _count: usize,
        ) -> Result<(Vec<Variable>, bool), Error> {
            unreachable!()
        }

        fn pause(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn go(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn next(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn step_in(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn step_out(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    fn make_test_adapter() -> UnrealscriptAdapter<AsyncClientImpl<Stdin, Stdout>> {
        UnrealscriptAdapter::new(
            make_client(),
            ClientConfig::new(),
            Box::new(MockConnection {}),
            None,
        )
    }

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
        let mut adapter = make_test_adapter();
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
        let mut adapter = make_test_adapter();
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
        let mut adapter = make_test_adapter();
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
