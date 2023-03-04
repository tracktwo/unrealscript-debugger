use ipmpsc::SharedRingBuffer;
use std::ffi::{c_char, CStr};
use std::ptr;
use textcode::iso8859_1;
use thiserror::Error;
use tokio::sync::mpsc;

use common::{
    Breakpoint, FrameIndex, StackTraceRequest, StackTraceResponse, UnrealCommand, UnrealEvent,
    UnrealResponse, Variable, VariableIndex,
};
use common::{Frame, WatchKind};

use crate::lifetime::VARIABLE_REQUST_CONDVAR;

const MAGIC_DISCONNECT_STRING: &str = "Log: Detaching UnrealScript Debugger (currently detached)";

/// A struct representing the debugger state.
pub struct Debugger {
    class_hierarchy: Vec<String>,
    local_watches: Vec<Watch>,
    global_watches: Vec<Watch>,
    user_watches: Vec<Watch>,
    callstack: Vec<Frame>,
    current_object_name: Option<String>,
    event_channel: Option<tokio::sync::mpsc::Sender<UnrealEvent>>,
    response_channel: Option<ipmpsc::Sender>,
    saw_show_dll: bool,
    pending_break_event: bool,
    current_line: i32,

    // The frame index for which we have received watch info. This is stored
    // in DAP format, with 0 being the top-most frame, which is the _last_
    // frame unreal gives us when building the call stack, but is the only frame
    // it gives us watch info for.
    current_frame: FrameIndex,

    // If we had to switch frames to service a variable request we need to wait
    // until Unreal provides the information before we can generate a response.
    // This stores the current pending variables request so we can send the response
    // when the data are available. There can be at most one pending variable request
    // at any given time, which also means that while waiting for Unreal to finish
    // processing we should not process any more messages from the adapter -- we need
    // to wait for this to complete before taking other actions, especially one that
    // could result in more variable requests.
    pending_variable_request: Option<PendingVariableRequest>,
}

#[derive(Debug)]
struct PendingVariableRequest {
    kind: WatchKind,
    frame: FrameIndex,
    parent: VariableIndex,
    start: usize,
    count: usize,
}

/// A variable watch.
#[derive(Debug)]
pub struct Watch {
    pub parent: usize,
    pub name: String,
    pub ty: String,
    pub value: String,
    pub children: Vec<usize>,
    pub is_array: bool,
}

impl Watch {
    /// Turn a watch into a variable to send to the adapter. Requires the index of
    /// the watch.
    fn to_variable(&self, index: usize) -> Variable {
        Variable {
            name: self.name.clone(),
            ty: self.ty.clone(),
            value: self.value.clone(),
            index: VariableIndex::create((index).try_into().unwrap()).unwrap(),
            has_children: !self.children.is_empty(),
            is_array: self.is_array,
        }
    }
}

#[derive(Error, Debug)]
pub enum DebuggerError {
    #[error("Failed to initialize")]
    InitializeFailure,
    #[error("Not connected")]
    NotConnected,
}

/// The action the debugger processing loop should take after resolving a command.
///
/// Some commands from the adapter require us to dispatch the command to unreal through
/// the callback function. These will take some action on the same thread that calls
/// through the callback, and for some commands these will immediately call back into
/// the debugger interface through some other entry point, again on the same thread.
///
/// This means we cannot hold the debugger mutex across the command, so we can't
/// safely call through the callback while holding the debugger mutex. This enum
/// is used to pass information back to the event loop outside the debugger mutex
/// that it can then dispatch to Unreal.
///
/// ### Examples
///
/// The 'StackTrace' command does not require communication with unreal, we already
/// have the full stack information in the debugger object to prepare the response,
/// so this command does not require any action so is represented by the 'Nothing'
/// variant.
///
/// The 'AddBreakpoint' command requires us to tell Unreal to add the breakpoint,
/// and this will immediately trigger a call to the 'AddBreakpoint' debugger
/// interface API. This is represented by the 'Callback' variant where the string
/// to pass to the callback (e.g. 'addbreakpoint <file> <line>') is part of the
/// variant.
///
/// The 'StopDebugging' command tells Unreal to stop debugging. This requires a
/// callback but is distinct from the 'Callback' variant because we also need to
/// cleanly shut down the event processing loop before sending the command to unreal.
pub enum CommandAction {
    Nothing,
    Callback(Vec<u8>),
    StopDebugging,
}

impl Debugger {
    /// Construct a new debugger instance with an empty state. Note that the callback pointer is
    /// _not_ passed as an argument to the debugger instance. This is because the debugger instance
    /// cannot safely call through the callback as callback calls can immediately re-enter the
    /// interface on the same thread, which would require us to re-acquire the debugger mutex while
    /// we already hold it to perform the callback.
    pub fn new() -> Debugger {
        Debugger {
            class_hierarchy: Vec::new(),
            local_watches: vec![Watch {
                parent: 0,
                name: "ROOT".to_string(),
                ty: "***".to_string(),
                value: "***".to_string(),
                children: vec![],
                is_array: false,
            }],
            global_watches: vec![Watch {
                parent: 0,
                name: "ROOT".to_string(),
                ty: "***".to_string(),
                value: "***".to_string(),
                children: vec![],
                is_array: false,
            }],
            user_watches: vec![Watch {
                parent: 0,
                name: "ROOT".to_string(),
                ty: "***".to_string(),
                value: "***".to_string(),
                children: vec![],
                is_array: false,
            }],
            callstack: Vec::new(),
            current_object_name: None,
            event_channel: None,
            response_channel: None,
            saw_show_dll: false,
            pending_break_event: false,
            current_line: 0,
            current_frame: FrameIndex::TOP_FRAME,
            pending_variable_request: None,
        }
    }

    fn get_watches(&mut self, kind: WatchKind) -> &mut Vec<Watch> {
        match kind {
            WatchKind::Local => &mut self.local_watches,
            WatchKind::Global => &mut self.global_watches,
            WatchKind::User => &mut self.user_watches,
        }
    }

    /// Handle a command from the adapter. This may generate responses either directly or
    /// indirectly. If the command requires a callback into unreal the encoded string will be
    /// returned from this function for the caller to dispatch to Unreal.
    ///
    /// NOTE: It's critical that the caller release the lock on the debugger object before
    /// calling into Unreal, as unreal commands that generate a synchronous response (e.g.
    /// addbreakpoint) will immediately call back into the debugger interface on the same thread.
    /// This means we will need to acquire the mutex lock to process the event, which can't happen
    /// if we're already holding it.
    pub fn handle_command(
        &mut self,
        command: UnrealCommand,
    ) -> Result<CommandAction, DebuggerError> {
        match command {
            UnrealCommand::Initialize(path) => {
                log::trace!("handle_command: initialize");
                let buf =
                    SharedRingBuffer::open(&path).or(Err(DebuggerError::InitializeFailure))?;
                self.response_channel = Some(ipmpsc::Sender::new(buf));
                Ok(CommandAction::Nothing)
            }
            UnrealCommand::AddBreakpoint(bp) => {
                let str = format!("addbreakpoint {} {}", bp.qualified_name, bp.line);
                log::trace!("handle_command: {str}");
                Ok(CommandAction::Callback(self.encode_string(&str)))
            }
            UnrealCommand::RemoveBreakpoint(bp) => {
                let str = format!("removebreakpoint {} {}", bp.qualified_name, bp.line);
                log::trace!("handle_command: {str}");
                Ok(CommandAction::Callback(self.encode_string(&str)))
            }
            UnrealCommand::StackTrace(stack) => {
                // A stack trace request can be handled without talking to unreal: we
                // just return the current call stack state.
                let response = self.handle_stacktrace_request(&stack);
                self.send_response(&UnrealResponse::StackTrace(response))?;

                // This request has been completely handled, no need for the caller to invoke the
                // callback.
                Ok(CommandAction::Nothing)
            }
            UnrealCommand::WatchCount(kind, parent) => {
                log::trace!("WatchCount: {kind:?}");
                let count = self.watch_count(kind, parent.into());
                self.send_response(&UnrealResponse::WatchCount(count))?;
                Ok(CommandAction::Nothing)
            }
            UnrealCommand::Frame(idx) => {
                log::trace!("Frame: {idx}");
                let frame = self.callstack.iter().nth_back(idx.into());
                log::trace!("The {idx}th frame is {frame:#?}");
                self.send_response(&UnrealResponse::Frame(frame.cloned()))?;
                Ok(CommandAction::Nothing)
            }
            UnrealCommand::Variables(kind, frame, parent, start, count) => {
                log::trace!(
                    "Variable: {kind:?} frame={frame} parent={parent} start={start} count={count}"
                );

                if frame != self.current_frame {
                    // We should not be processing new commands while a variable request is
                    // outstanding. This should never happen, but if it does return an empty
                    // variables list -- hopefully we can recover.
                    if self.pending_variable_request.is_some() {
                        log::error!("Variable request for a different stack frame while a change is still pending!");
                        self.send_response(&UnrealResponse::Variables(vec![]))?;
                        return Ok(CommandAction::Nothing);
                    }

                    // We're looking for a variable not in the current stack frame, and we don't
                    // have this info. This requires us to ask Unreal to switch frames and then
                    // send the variable info when its available.
                    let frame_id: usize = frame.into();
                    if frame_id > self.callstack.len() {
                        log::error!("Variable request stack frame {frame_id} is out of  range.");
                        self.send_response(&UnrealResponse::Variables(vec![]))?;
                        return Ok(CommandAction::Nothing);
                    }

                    self.pending_variable_request = Some(PendingVariableRequest {
                        kind,
                        frame,
                        parent,
                        start,
                        count,
                    });

                    // Convert the frame index into the format unreal is expecting.
                    let str = format!("changestack {}", frame_id);
                    log::trace!("handle_command: {str}");

                    return Ok(CommandAction::Callback(self.encode_string(&str)));
                }

                self.send_variable_response(kind, parent, start, count, false)?;
                Ok(CommandAction::Nothing)
            }
            UnrealCommand::Evaluate(expr) => {
                let str = format!("addwatch {expr}");
                log::trace!("handle_command: {str}");

                // Check to see if we have a user watch already registered for this expression.
                // Each user watch is registered as a root variable, so we only need to check
                // children of the root.
                if !self.user_watches.is_empty() {
                    for idx in &self.user_watches[0].children {
                        if self.user_watches[*idx].name == expr {
                            self.send_response(&UnrealResponse::Evaluate(Some(
                                self.user_watches[*idx].to_variable(*idx),
                            )))?;
                            return Ok(CommandAction::Nothing);
                        }
                    }
                }

                // No existing watch, so create one and register a pending variable request to
                // wait for it to come in.
                log::trace!("Registering pending request for new user watch {expr}");
                self.pending_variable_request = Some(PendingVariableRequest {
                    kind: WatchKind::User,
                    frame: self.current_frame,
                    parent: VariableIndex::SCOPE,
                    start: 0,
                    count: 0,
                });
                return Ok(CommandAction::Callback(self.encode_string(&str)));
            }
            UnrealCommand::Pause => {
                log::trace!("Pause");
                let str = "break";
                Ok(CommandAction::Callback(self.encode_string(&str)))
            }
            UnrealCommand::Go => {
                log::trace!("Go");
                let str = "go";
                Ok(CommandAction::Callback(self.encode_string(&str)))
            }
            UnrealCommand::Next => {
                log::trace!("Next");
                let str = "stepover";
                Ok(CommandAction::Callback(self.encode_string(&str)))
            }
            UnrealCommand::StepIn => {
                log::trace!("StepIn");
                let str = "stepinto";
                Ok(CommandAction::Callback(self.encode_string(&str)))
            }
            UnrealCommand::StepOut => {
                log::trace!("StepOut");
                let str = "stepoutof";
                Ok(CommandAction::Callback(self.encode_string(&str)))
            }
            UnrealCommand::Disconnect => {
                log::trace!("Disconnect");
                self.disconnect();
                Ok(CommandAction::StopDebugging)
            }
        }
    }

    /// The adapter has requested we disconnect. This cleans up our internal
    /// state for the debugging session -- no more messages can be sent or received
    /// until a new session is established.
    fn disconnect(&mut self) -> () {
        // Drop our references to the communications channels. The main loop thread is still
        // running but should receive a disconnect from the TCP socket soon and this will
        // cause us to go back and wait for another connection.
        self.event_channel.take();
        self.response_channel.take();
    }

    /// Collect watch info and send a variable response with the variable data. This can be invoked
    /// either directly in response to a variables command (if the current stack frame is the same
    /// as the requested frame) or as a deferred response after Unreal switches frames if the
    /// requested frame is different from the one we had when we got the command.
    fn send_variable_response(
        &mut self,
        kind: WatchKind,
        parent: VariableIndex,
        start: usize,
        count: usize,
        deferred: bool,
    ) -> Result<(), DebuggerError> {
        let list = self.get_watches(kind);

        // A count of 0 means all elements.
        let count = if count == 0 { usize::MAX } else { count };

        let idx: usize = parent.into();

        // If the parent is out of range then we have nothing to return. Log an error and
        // return an empty vector.
        if idx >= list.len() {
            log::error!(
                "Variable: Parent index out of range. Got {idx} but size is {}",
                list.len()
            );
            self.send_response(&UnrealResponse::Variables(vec![]))?;
            return Ok(());
        }

        // Iterate the children of 'parent' according to the requested bounds and return
        // a vector containing clones of the watches for these children.
        let vars: Vec<Variable> = list[idx]
            .children
            .iter()
            .skip(start)
            .take(count)
            .map(|n| {
                let watch = &list[*n];
                Variable {
                    name: watch.name.clone(),
                    ty: watch.ty.clone(),
                    value: watch.value.clone(),
                    index: VariableIndex::create((*n).try_into().unwrap()).unwrap(),
                    has_children: !watch.children.is_empty(),
                    is_array: watch.is_array,
                }
            })
            .collect();

        if deferred {
            self.send_response(&UnrealResponse::DeferredVariables(vars))?;
        } else {
            self.send_response(&UnrealResponse::Variables(vars))?;
        }
        Ok(())
    }

    /// Send a response message. Since responses are always in reaction to a command, this requires
    /// a connected response channel and it is a logic error for this to not exist.
    pub fn send_response(&mut self, response: &UnrealResponse) -> Result<(), DebuggerError> {
        self.response_channel
            .as_mut()
            .ok_or(DebuggerError::NotConnected)?
            .send(response)
            .or(Err(DebuggerError::NotConnected))?;
        Ok(())
    }

    /// The debugger has stopped (maybe).
    ///
    /// Unreal will invoke `show_dll_form` as the last step when the debugger breaks after all
    /// other state has been sent to the interface, making it a great hook to use to tell the
    /// adapter that the debugger has stopped.
    ///
    /// Unfortunately Unreal *also* calls this function once during the initial startup. This
    /// has the sequence:
    ///
    ///  - SetCallback
    ///  - ClearAWatch 0
    ///  - ClearAWatch 1
    ///  - ClearAWatch 2
    ///  - ShowDllForm
    ///
    ///  This first call to ShowDllForm does _not_ indicate that the debugger has stopped - it
    ///  hasn't. This is never a break, even when using -autoDebug to tell the debugger to break
    ///  on startup.
    ///
    ///  All true stops will send a ShowDllForm after another sequence of calls, including loading
    ///  the editor class and line; locking, clearing, setting, and unlocking the watches; and
    ///  clearing and setting the call stack.
    ///
    ///  We don't need to implement a complex state machine to track this, however, since we will
    ///  only get this spurious ShowDllForm once during initialization. So: just ignore the first
    ///  call we see, and from then on treat any ShowDllForm call as a break.
    pub fn show_dll_form(&mut self) -> () {
        self.current_frame = FrameIndex::TOP_FRAME;
        if !self.saw_show_dll {
            // This was the first spurious call to show dll. Just remember we saw it but do
            // nothing, this is not a break. If we did launch with -autoDebug we'll get another
            // call after the rest of the debugger state has been sent.
            self.saw_show_dll = true;
        } else {
            // This is a true break. If we're connected send the Stopped event to the adapter. If
            // we're not connected yet set a flag indicating that we're stopped so we can tell
            // the adapter about this state when it does connect.
            if let Some(channel) = &mut self.event_channel {
                if let Err(e) = channel.blocking_send(UnrealEvent::Stopped) {
                    log::error!("Sending stopped event failed: {e}");
                }
            } else {
                log::trace!("Skipping stopped event: not connected.");
                self.pending_break_event = true;
            }
        }
    }

    /// Add a class to the debugger's class hierarchy.
    pub fn add_class_to_hierarchy(&mut self, arg: *const c_char) -> () {
        let str = self.decode_string(arg);
        self.class_hierarchy.push(str);
    }

    /// Clear the class hierarchy.
    pub fn clear_class_hierarchy(&mut self) -> () {
        self.class_hierarchy.clear();
    }

    pub fn clear_watch(&mut self, kind: WatchKind) -> () {
        let list = self.get_watches(kind);
        list.clear();

        // Add the root node to the list. This will let us track all children
        // of the root for easy access.
        list.push(Watch {
            parent: 0,
            name: "ROOT".to_string(),
            ty: "***".to_string(),
            value: "***".to_string(),
            children: vec![],
            is_array: false,
        });
    }

    pub fn add_watch(
        &mut self,
        kind: WatchKind,
        parent: i32,
        name: *const c_char,
        value: *const c_char,
    ) -> i32 {
        // Unreal will give us watches with a parent of -1 for 'root' variables in a given scope.
        // Map these to index 0.
        let parent = if parent <= 0 { 0 } else { parent as usize };

        let (name, ty, is_array) = self.decompose_name(name);

        let watch = Watch {
            parent,
            name,
            ty: ty.unwrap_or("<unknown type>".to_string()),
            value: self.decode_string(value),
            children: vec![],
            is_array: is_array.unwrap_or(false),
        };
        let vec = self.get_watches(kind);

        // The given parent must be a member of our vector already.
        // We should have already introduced the 'root' node at index 0 when
        // we cleared the watches.
        assert!(parent < vec.len().try_into().unwrap());

        // Add the new entry to the vector and return an identifier for it:
        // the index of this entry in the vector.
        vec.push(watch);

        let new_entry = vec.len() - 1;

        // Record the new entry in the children list of the parent
        vec[parent].children.push(new_entry);

        // Just panic if we overflow the i32 return value Unreal wants us to give it. This is
        // pretty unlikely to ever occur without Unreal running out of memory first...
        new_entry.try_into().unwrap()
    }

    pub fn lock_watchlist(&mut self) -> () {}

    /// Unreal has unlocked a watchlist. We don't perform any locking of the watchlist but this
    /// is the last signal we get after switching stack frames, so we can use this to complete
    /// a pending variable request.
    pub fn unlock_watchlist(&mut self, kind: WatchKind) -> () {
        match kind {
            // The user watchlist is always unlocked last when dumping a frame, and also is locked
            // and unlocked when registering a new user watch. Pending responses are sent only for
            // this kind.
            WatchKind::User => {
                if let Some(req) = self.pending_variable_request.take() {
                    // Update the current stack frame to represent the new state.
                    self.current_frame = req.frame;

                    // If this pending request is a user watch we want to send back an 'Evaluate'
                    // reponse, otherwise we want to send a 'Variables' response.
                    match req.kind {
                        WatchKind::User => {
                            // The new user watch will be the last one added to the user watchlist,
                            // so it's the last child of the root.
                            let var = self.user_watches.get(0).and_then(|n| {
                                n.children
                                    .last()
                                    .and_then(|c| Some(self.user_watches[*c].to_variable(*c)))
                            });
                            if var.is_none() {
                                log::error!("User watchlist unlocked from a pending user watch but watchlist is empty!");
                            }
                            self.send_response(&UnrealResponse::Evaluate(var))
                                .unwrap_or_else(|_| {
                                    log::error!("Failed to send response for user watch");
                                });
                        }
                        _ => {
                            // Send the response to the adapter so it can proceed.
                            self.send_variable_response(
                                req.kind, req.parent, req.start, req.count, true,
                            )
                            .unwrap_or_else(|_| {
                                log::error!(
                                    "Failed to send response for deferred variable request"
                                );
                            });
                        }
                    }

                    // Signal the variable request condvar so we can unblock the command processing thread.
                    VARIABLE_REQUST_CONDVAR.notify_one();
                }
            }
            _ => (),
        }
    }

    /// A breakpoint has been added.
    pub fn add_breakpoint(&mut self, name: *const c_char, line: i32) -> () {
        let bp = Breakpoint {
            qualified_name: self.decode_string(name),
            line,
        };
        log::trace!("Added breakpoint at {}:{}", bp.qualified_name, bp.line);
        if let Err(e) = self.send_response(&UnrealResponse::BreakpointAdded(bp)) {
            log::error!("Sending BreakpointAdded response failed: {e}");
        }
    }

    /// A breakpoint has been removed.
    pub fn remove_breakpoint(&mut self, name: *const c_char, line: i32) -> () {
        let bp = Breakpoint {
            qualified_name: self.decode_string(name),
            line,
        };
        log::trace!("Removed breakpoint at {}:{}", bp.qualified_name, bp.line);
        if let Err(e) = self.send_response(&UnrealResponse::BreakpointRemoved(bp)) {
            log::error!("Sending BreakpointRemoved response failed: {e}");
        }
    }

    /// Clear the callstack.
    pub fn clear_callstack(&mut self) -> () {
        self.callstack.clear();
    }

    /// Add a frame to the callstack.
    pub fn add_frame(&mut self, class_name: *const c_char) -> () {
        // The "name" provided by Unreal is of the form 'Function ClassName:FunctionName'.
        //
        let name = self.decode_string(class_name);
        let mut it = name.split(&[' ', ':']);
        it.next();
        let class_name = it.next().unwrap_or("");
        let function_name = it.next().unwrap_or("");

        // Create the new frame data. We don't know if this will be the last callstack
        // entry or not, and the current line number is for the last entry. Set it
        // pre-emptively, and we'll clear it if and when we get another entry.
        let frame = Frame {
            qualified_name: class_name.to_string(),
            function_name: function_name.to_string(),
            line: self.current_line,
        };

        // If we previously added an entry clear the line since it wasn't the top-most
        // entry.
        if !self.callstack.is_empty() {
            let last = self.callstack.len() - 1;
            self.callstack[last].line = 0;
        }
        self.callstack.push(frame);
    }

    /// Send the current call stack (or subset of it) to the adapter.
    pub fn handle_stacktrace_request(&mut self, req: &StackTraceRequest) -> StackTraceResponse {
        let start = req.start_frame as usize;
        let levels = req.levels as usize;

        // A levels request of '0' means 'all levels'.
        let levels = if levels == 0 { usize::MAX } else { levels };

        // Return some subset of the frames starting from the indicated start position
        // with at most levels elements. This may return a smaller vector of frames
        // than requested, and possible an empty vector if no frames are available at
        // all with the given bounds.
        //
        // Note: The start position is 0-indexed.
        // Note: Unreal gives us stack frames starting from the bottom-most up to the
        // top-most, so this is the order they appear in the vector. DAP clients tend
        // to ask for stack frames starting from the top-most down to the bottom-most.
        // So, reverse the frame list when we return the response.
        StackTraceResponse {
            frames: self
                .callstack
                .iter()
                .rev()
                .skip(start)
                .take(levels)
                .map(|e| e.clone())
                .collect(),
        }
    }

    pub fn watch_count(&mut self, kind: WatchKind, parent: usize) -> usize {
        self.get_watches(kind)[parent].children.len()
    }

    /// Record the current object name. This is updated each time unreal stops.
    pub fn current_object_name(&mut self, obj_name: *const c_char) -> () {
        self.current_object_name = Some(self.decode_string(obj_name));
    }

    /// A line has been added to the log. Send directly to the adapter (if connected).
    pub fn add_line_to_log(&mut self, text: *const c_char) -> () {
        let mut str = self.decode_string(text);

        // Unreal does not have a dedicated signal to tell us when things are
        // shutting down. Instead we just get a log line of a particular format
        // when the user uses \toggledebugging to disable debugging. When this
        // happens we are about to be shut down.
        if str == MAGIC_DISCONNECT_STRING {
            log::info!("Received shutdown message.");

            // TODO Handle shutdown
            return;
        }

        if let Some(sender) = &mut self.event_channel {
            log::trace!("Add to log: {str}");

            // Unreal does not add newlines to log messages, add one for readability.
            str.push_str("\r\n");
            if let Err(e) = sender.blocking_send(UnrealEvent::Log(str)) {
                log::error!("Sending log failed: {e}");
            }
        } else {
            log::trace!("Skipping log entry: not connected.");
        }
    }

    /// Set the current line.
    pub fn goto_line(&mut self, line: i32) -> () {
        // If we have a pending variable request then this is the line for our frame.
        if let Some(var) = &self.pending_variable_request {
            // Set the line number in the frame we are moving to.
            let mut index: usize = self.callstack.len() - 1;
            index -= <FrameIndex as Into<usize>>::into(var.frame);
            log::trace!("Setting line number for frame {} to {}", index, line);
            self.callstack[index].line = line;
        } else {
            // No pending variable request. This goto line is due to the debugger stopping,
            // and the line is associated with whatever the last frame will be. Record this
            // in the debugger object and the add stack frame calls will use it.
            self.current_line = line;
        }
    }

    pub fn pending_variable_request(&self) -> bool {
        self.pending_variable_request.is_some()
    }

    /// Decompose an Unreal variable watch name into a name, type, and whether this
    /// type is an array.
    fn decompose_name(&mut self, ptr: *const c_char) -> (String, Option<String>, Option<bool>) {
        let str = iso8859_1::decode_to_string(make_cstr(ptr).to_bytes());

        // The name string is of the form "Name ( Ty,addr1,addr2 )".
        // If the type is a dynamic array the type will be "Array". If it's
        // a static array it will be "Static Ty Array".
        if let Some(paren) = str.find('(') {
            // Isolate the name. Skip the space before the '('.
            let name = &str[..paren - 1];
            // Skip the space after the '(' to isolate the type.
            let rest = &str[paren + 2..];

            // Find the end of the type. This will be up to the first comma (if there are
            // addresses) or closing paren (if not).
            if let Some(end_of_type) = rest.find([',', ')']) {
                let ty = rest[..end_of_type].trim_end();
                // If the word 'Array' appears in the type then this is some kind of array.
                // Note that we don't have to worry about class names like MyArray incorrectly
                // being treated as arrays as the type will be 'Object' or 'Struct', the actual
                // name of the type does not appear here.
                let is_array = ty.find("Array").is_some();
                return (name.to_string(), Some(ty.to_string()), Some(is_array));
            }
        }
        // The name string is of the form '[[ Base Class ]]'
        else if let Some(_) = str.find("[[") {
            return (str, Some("base class".to_string()), Some(false));
        }
        // The name string is of the form 'ParentName[idx]'
        // TODO: What about arrays of arrays?
        else if let Some(_) = str.find("[") {
            return (str, Some("array element".to_string()), Some(false));
        }

        // If we failed to parse the type just return the whole thing as the name but
        // no type or array flag. This is not an error: user watches for invalid expressions
        // are returned as the name but with no other info.
        //
        // Note: this makes it hard to distinguish a bad watch with a name like
        // "Foo ( Type,addr,addr )" from a real successful user watch.
        (str, None, None)
    }

    /// Decode an Unreal-encoded string to UTF-8.
    fn decode_string(&mut self, ptr: *const c_char) -> String {
        let str = make_cstr(ptr);
        return iso8859_1::decode_to_string(str.to_bytes());
    }

    /// Encode a UTF-8 string to Unreal, ensuring null-termination.
    fn encode_string(&mut self, s: &str) -> Vec<u8> {
        let mut vec = iso8859_1::encode_to_vec(s);
        vec.push(0);
        vec
    }

    /// A new connection has been established from the adapter. Record the tcp stream used to send
    /// events.
    pub fn new_connection(&mut self, tx: mpsc::Sender<UnrealEvent>) -> () {
        self.event_channel = Some(tx);

        // The debugger stopped before we connected (e.g. due to -autoDebug). Send a stopped
        // event to let it know about this.
        if self.pending_break_event {
            log::info!("Sending stored stop event to the new connection.");
            self.pending_break_event = false;
            self.show_dll_form();
        }
    }
}

#[derive(Debug)]
pub struct UnknownCommandError;

/// Convert an unreal C string pointer to a CStr.
fn make_cstr<'a>(raw: *const c_char) -> &'a CStr {
    if raw != ptr::null() {
        unsafe { return CStr::from_ptr(raw) }
    }

    CStr::from_bytes_with_nul(b"\0").unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_to_hierarchy() {
        let cls = "Package.Class\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(dbg.class_hierarchy[0], "Package.Class");
    }

    #[test]
    fn clearing_hierarchy() {
        let cls = "Package.Class\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(dbg.class_hierarchy.len(), 1);
        dbg.clear_class_hierarchy();
        assert!(dbg.class_hierarchy.is_empty());
    }

    #[test]
    fn add_watches_are_independent() {
        let name = "SomeVar\0".as_ptr() as *const i8;
        let val = "10\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        assert_eq!(dbg.add_watch(WatchKind::Local, -1, name, val), 1);
        assert_eq!(dbg.local_watches.len(), 2);
        assert_eq!(dbg.global_watches.len(), 1);
        assert_eq!(dbg.user_watches.len(), 1);
        assert_eq!(dbg.add_watch(WatchKind::Global, -1, name, val), 1);
        assert_eq!(dbg.local_watches.len(), 2);
        assert_eq!(dbg.global_watches.len(), 2);
        assert_eq!(dbg.user_watches.len(), 1);
        assert_eq!(dbg.add_watch(WatchKind::User, -1, name, val), 1);
        assert_eq!(dbg.local_watches.len(), 2);
        assert_eq!(dbg.global_watches.len(), 2);
        assert_eq!(dbg.user_watches.len(), 2);
    }

    #[test]
    fn clear_watches_are_independent() {
        let name = "SomeVar\0".as_ptr() as *const i8;
        let val = "10\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_watch(WatchKind::Local, -1, name, val);
        dbg.add_watch(WatchKind::Global, -1, name, val);
        dbg.add_watch(WatchKind::User, -1, name, val);
        dbg.clear_watch(WatchKind::Local);
        assert_eq!(dbg.local_watches.len(), 1);
        assert_eq!(dbg.global_watches.len(), 2);
        assert_eq!(dbg.user_watches.len(), 2);
    }

    #[test]
    #[should_panic]
    fn add_watch_invalid_parent() {
        let name = "SomeVar\0".as_ptr() as *const i8;
        let val = "10\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_watch(WatchKind::Local, 1, name, val);
    }

    #[test]
    fn log_sends_line() {
        let mut dbg = Debugger::new();
        let (tx, mut rx) = mpsc::channel(1);
        dbg.event_channel = Some(tx);
        let str = "This is a log line\0";
        dbg.add_line_to_log(str.as_ptr() as *const i8);

        let destr: UnrealEvent = rx.blocking_recv().unwrap();
        match destr {
            // Compare the strings. Ignore the null byte in our sending string, and ignore the \r\n
            // appended to the log line in the event.
            UnrealEvent::Log(s) => assert_eq!(str[..str.len() - 1], s[..s.len() - 2]),
            _ => panic!("Expected a log"),
        };
    }

    #[test]
    fn add_frame() {
        let mut dbg = Debugger::new();
        dbg.add_frame("Function MyPackage.Class:MyFunction\0".as_ptr() as *const i8);
        assert_eq!(dbg.callstack[0].qualified_name, "MyPackage.Class");
        assert_eq!(dbg.callstack[0].function_name, "MyFunction");
    }

    #[test]
    fn empty_stacktrace() {
        let mut dbg = Debugger::new();
        let response = dbg.handle_stacktrace_request(&StackTraceRequest {
            start_frame: 0,
            levels: 20,
        });
        assert!(response.frames.is_empty())
    }

    #[test]
    fn with_stacktrace() {
        let mut dbg = Debugger::new();
        dbg.callstack.push(Frame {
            qualified_name: "Class1".to_string(),
            function_name: "foo".to_string(),
            line: 20,
        });
        dbg.callstack.push(Frame {
            qualified_name: "Class2".to_string(),
            function_name: "bar".to_string(),
            line: 84,
        });
        let response = dbg.handle_stacktrace_request(&StackTraceRequest {
            start_frame: 0,
            levels: 20,
        });
        assert_eq!(
            response.frames,
            vec![
                Frame {
                    qualified_name: "Class2".to_string(),
                    function_name: "bar".to_string(),
                    line: 84
                },
                Frame {
                    qualified_name: "Class1".to_string(),
                    function_name: "foo".to_string(),
                    line: 20
                },
            ]
        );
    }

    #[test]
    fn partial_stacktrace_start() {
        let mut dbg = Debugger::new();
        dbg.callstack.push(Frame {
            qualified_name: "Class1".to_string(),
            function_name: "foo".to_string(),
            line: 20,
        });
        dbg.callstack.push(Frame {
            qualified_name: "Class2".to_string(),
            function_name: "bar".to_string(),
            line: 84,
        });
        let response = dbg.handle_stacktrace_request(&StackTraceRequest {
            start_frame: 0,
            levels: 1,
        });
        assert_eq!(
            response.frames,
            vec![Frame {
                qualified_name: "Class2".to_string(),
                function_name: "bar".to_string(),
                line: 84
            },]
        );
    }

    #[test]
    fn partial_stacktrace_end() {
        let mut dbg = Debugger::new();
        dbg.callstack.push(Frame {
            qualified_name: "Class1".to_string(),
            function_name: "foo".to_string(),
            line: 20,
        });
        dbg.callstack.push(Frame {
            qualified_name: "Class2".to_string(),
            function_name: "bar".to_string(),
            line: 84,
        });
        let response = dbg.handle_stacktrace_request(&StackTraceRequest {
            start_frame: 1,
            levels: 1,
        });
        assert_eq!(
            response.frames,
            vec![Frame {
                qualified_name: "Class1".to_string(),
                function_name: "foo".to_string(),
                line: 20
            },]
        );
    }

    #[test]
    fn partial_stacktrace_beyond() {
        let mut dbg = Debugger::new();
        dbg.callstack.push(Frame {
            qualified_name: "Class1".to_string(),
            function_name: "foo".to_string(),
            line: 20,
        });
        dbg.callstack.push(Frame {
            qualified_name: "Class2".to_string(),
            function_name: "bar".to_string(),
            line: 84,
        });
        let response = dbg.handle_stacktrace_request(&StackTraceRequest {
            start_frame: 2,
            levels: 1,
        });
        assert!(response.frames.is_empty());
    }

    #[test]
    fn empty_watch_count() {
        let mut dbg = Debugger::new();
        assert_eq!(dbg.watch_count(WatchKind::Local, 0), 0);
        assert_eq!(dbg.watch_count(WatchKind::Global, 0), 0);
        assert_eq!(dbg.watch_count(WatchKind::User, 0), 0);
    }

    #[test]
    fn local_watch_count() {
        let mut dbg = Debugger::new();
        dbg.add_watch(
            WatchKind::Local,
            -1,
            "Var1\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        dbg.add_watch(
            WatchKind::Local,
            -1,
            "Var2\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        assert_eq!(dbg.watch_count(WatchKind::Local, 0), 2);
        assert_eq!(dbg.watch_count(WatchKind::Local, 0), 2);
        assert_eq!(dbg.watch_count(WatchKind::Global, 0), 0);
        assert_eq!(dbg.watch_count(WatchKind::User, 0), 0);
    }

    #[test]
    fn global_watch_count() {
        let mut dbg = Debugger::new();
        dbg.add_watch(
            WatchKind::Global,
            -1,
            "Var1\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        dbg.add_watch(
            WatchKind::Global,
            -1,
            "Var2\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        assert_eq!(dbg.watch_count(WatchKind::Local, 0), 0);
        assert_eq!(dbg.watch_count(WatchKind::Global, 0), 2);
        assert_eq!(dbg.watch_count(WatchKind::User, 0), 0);
    }

    #[test]
    fn watch_counts_roots_only() {
        let mut dbg = Debugger::new();
        dbg.add_watch(
            WatchKind::Global,
            -1,
            "Var1\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        dbg.add_watch(
            WatchKind::Global,
            1,
            "subfield\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        dbg.add_watch(
            WatchKind::Global,
            1,
            "subfield2\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        dbg.add_watch(
            WatchKind::Global,
            -1,
            "Var2\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        dbg.add_watch(
            WatchKind::Global,
            4,
            "subfield\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        assert_eq!(dbg.watch_count(WatchKind::Global, 0), 2);
    }

    #[test]
    fn simple_name() {
        let mut dbg = Debugger::new();
        let str = "Location ( Struct,00007FF45D513A00,00007FF44F9B52F0 )\0";
        let (name, ty, is_array) = dbg.decompose_name(str.as_ptr() as *const i8);
        assert_eq!(name, "Location");
        assert_eq!(ty.unwrap(), "Struct");
        assert_eq!(is_array.unwrap(), false);
    }

    #[test]
    fn static_array_name() {
        let mut dbg = Debugger::new();
        let str = "CharacterStats ( Static Struct Array )\0";
        let (name, ty, is_array) = dbg.decompose_name(str.as_ptr() as *const i8);
        assert_eq!(name, "CharacterStats");
        assert_eq!(ty.unwrap(), "Static Struct Array");
        assert_eq!(is_array.unwrap(), true);
    }

    #[test]
    fn dynamic_array_name() {
        let mut dbg = Debugger::new();
        let str = "AWCAbilities ( Array )\0";
        let (name, ty, is_array) = dbg.decompose_name(str.as_ptr() as *const i8);
        assert_eq!(name, "AWCAbilities");
        assert_eq!(ty.unwrap(), "Array");
        assert_eq!(is_array.unwrap(), true);
    }

    #[test]
    fn base_class_name() {
        let mut dbg = Debugger::new();
        let str = "[[ Object ]]\0";
        let (name, ty, is_array) = dbg.decompose_name(str.as_ptr() as *const i8);
        assert_eq!(name, "[[ Object ]]");
        assert_eq!(ty.unwrap(), "base class");
        assert_eq!(is_array.unwrap(), false);
    }

    #[test]
    fn array_element_name() {
        let mut dbg = Debugger::new();
        let str = "SomeArray[0]\0";
        let (name, ty, is_array) = dbg.decompose_name(str.as_ptr() as *const i8);
        assert_eq!(name, "SomeArray[0]");
        assert_eq!(ty.unwrap(), "array element");
        assert_eq!(is_array.unwrap(), false);
    }
}
