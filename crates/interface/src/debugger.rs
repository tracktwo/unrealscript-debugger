use flexi_logger::{FileSpec, FlexiLoggerError, Logger, LoggerHandle};
use ipmpsc::{Sender, SharedRingBuffer};
use serde::Serialize;
use serde_json::Serializer;
use std::ffi::{c_char, CStr};
use std::net::{TcpListener, TcpStream};
use std::{io, ptr};
use std::{sync::Mutex, thread};
use textcode::iso8859_1;
use thiserror::Error;

use super::UnrealCallback;
use super::DEBUGGER;
use common::{
    Breakpoint, StackTraceRequest, StackTraceResponse, UnrealCommand, UnrealEvent, UnrealResponse,
};
use common::{Frame, Watch, WatchKind, DEFAULT_PORT};

static LOGGER: Mutex<Option<LoggerHandle>> = Mutex::new(None);

/// A struct representing the debugger state.
pub struct Debugger<W> {
    class_hierarchy: Vec<String>,
    local_watches: Vec<Watch>,
    global_watches: Vec<Watch>,
    user_watches: Vec<Watch>,
    callstack: Vec<Frame>,
    current_object_name: Option<String>,
    event_channel: Option<Serializer<W>>,
    response_channel: Option<Sender>,
    saw_show_dll: bool,
    pending_break_event: bool,
    current_line: i32,
}

#[derive(Error, Debug)]
pub enum DebuggerError {
    #[error("Failed to initialize")]
    InitializeFailure,
    #[error("Serialization error: {0}")]
    SerializationError(serde_json::Error),
    #[error("Not connected")]
    NotConnected,
}

impl From<serde_json::Error> for DebuggerError {
    fn from(value: serde_json::Error) -> Self {
        DebuggerError::SerializationError(value)
    }
}

impl<W> Debugger<W>
where
    W: io::Write,
{
    /// Construct a new debugger instance with an empty state. Note that the callback pointer is
    /// _not_ passed as an argument to the debugger instance. This is because the debugger instance
    /// cannot safely call through the callback as callback calls can immediately re-enter the
    /// interface on the same thread, which would require us to re-acquire the debugger mutex while
    /// we already hold it to perform the callback.
    pub fn new() -> Debugger<W> {
        Debugger {
            class_hierarchy: Vec::new(),
            local_watches: Vec::new(),
            global_watches: Vec::new(),
            user_watches: Vec::new(),
            callstack: Vec::new(),
            current_object_name: None,
            event_channel: None,
            response_channel: None,
            saw_show_dll: false,
            pending_break_event: false,
            current_line: 0,
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
    ) -> Result<Option<Vec<u8>>, DebuggerError> {
        match command {
            UnrealCommand::Initialize(path) => {
                log::trace!("handle_command: initialize");
                let buf =
                    SharedRingBuffer::open(&path).or(Err(DebuggerError::InitializeFailure))?;
                self.response_channel = Some(Sender::new(buf));
                Ok(None)
            }
            UnrealCommand::AddBreakpoint(bp) => {
                let str = format!("addbreakpoint {} {}", bp.qualified_name, bp.line);
                log::trace!("handle_command: {str}");
                Ok(Some(self.encode_string(&str)))
            }
            UnrealCommand::RemoveBreakpoint(bp) => {
                let str = format!("removebreakpoint {} {}", bp.qualified_name, bp.line);
                log::trace!("handle_command: {str}");
                Ok(Some(self.encode_string(&str)))
            }
            UnrealCommand::StackTrace(stack) => {
                // A stack trace request can be handled without talking to unreal: we
                // just return the current call stack state.
                let response = self.handle_stacktrace_request(&stack);
                self.send_response(&UnrealResponse::StackTrace(response))?;

                // This request has been completely handled, no need for the caller to invoke the
                // callback.
                Ok(None)
            }
            UnrealCommand::WatchCount(kind) => {
                log::trace!("WatchCount: {kind:?}");
                let count = self.watch_count(kind);
                self.send_response(&UnrealResponse::WatchCount(count))?;
                Ok(None)
            }
            UnrealCommand::Frame(idx) => {
                log::trace!("Frame: {idx}");
                let idx = idx as usize - 1;
                let frame = self.callstack.iter().nth_back(idx);
                log::trace!("The {idx}th frame is {frame:#?}");
                self.send_response(&UnrealResponse::Frame(frame.cloned()))?;
                Ok(None)
            }
        }
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
    ///  only get this spurious ShowDllForm once during initialization, even in the -autoDebug case
    ///  and even when the debugger is toggled off and on multiple times in a single execution of
    ///  the game. So: just ignore the first call we see, and from then on treat any ShowDllForm
    ///  call as a break.
    pub fn show_dll_form(&mut self) -> () {
        if !self.saw_show_dll {
            // This was the first spurious call to show dll. Just remember we saw it but do
            // nothing, this is not a break. If we did launch with -autoDebug we'll get another
            // call after the rest of the debugger state has been sent.
            self.saw_show_dll = true;
        } else {
            // This is a true break. If we're connected send the Stopped event to the adapter. If
            // we're not connected yet set a flag indicating that we're stopped so we can tell
            // the adapter about this state when it does connect.
            if let Some(stream) = &mut self.event_channel {
                if let Err(e) = UnrealEvent::Stopped.serialize(stream) {
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
        match kind {
            WatchKind::Local => self.local_watches.clear(),
            WatchKind::Global => self.global_watches.clear(),
            WatchKind::User => self.user_watches.clear(),
        }
    }

    pub fn add_watch(
        &mut self,
        kind: WatchKind,
        parent: i32,
        name: *const c_char,
        value: *const c_char,
    ) -> i32 {
        let watch = Watch {
            parent,
            name: self.decode_string(name),
            value: self.decode_string(value),
        };
        let vec: &mut Vec<Watch> = match kind {
            WatchKind::Local => self.local_watches.as_mut(),
            WatchKind::Global => self.global_watches.as_mut(),
            WatchKind::User => self.user_watches.as_mut(),
        };

        // The given parent must be a member of our vector already. Note that
        // Unreal indicates root variables with parent -1.
        assert!(parent < vec.len().try_into().unwrap());

        // Add the new entry to the vector and return an identifier for it:
        // the index of this entry in the vector.
        vec.push(watch);
        vec.len() as i32 - 1
    }

    pub fn lock_watchlist(&mut self) -> () {}

    pub fn unlock_watchlist(&mut self) -> () {}

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
            class_name: class_name.to_string(),
            function_name: function_name.to_string(),
            line: self.current_line,
        };

        // If we previously added an entry clear the line since it wasn't the top-most
        // entry.
        if !self.callstack.is_empty() {
            let last = self.callstack.len() - 1;
            // TODO Fixme
            self.callstack[last].line = 66;
        }
        self.callstack.push(frame);
    }

    /// Send the current call stack (or subset of it) to the adapter.
    pub fn handle_stacktrace_request(&mut self, req: &StackTraceRequest) -> StackTraceResponse {
        let start = req.start_frame as usize;
        let levels = req.levels as usize;

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

    pub fn watch_count(&mut self, kind: WatchKind) -> i32 {
        let iter = match kind {
            WatchKind::Local => self.local_watches.iter(),
            WatchKind::Global => self.global_watches.iter(),
            WatchKind::User => self.user_watches.iter(),
        };

        iter.filter(|x| x.parent == -1)
            .count()
            .try_into()
            .unwrap_or(i32::MAX)
    }

    /// Record the current object name. This is updated each time unreal stops.
    pub fn current_object_name(&mut self, obj_name: *const c_char) -> () {
        self.current_object_name = Some(self.decode_string(obj_name));
    }

    /// A line has been added to the log. Send directly to the adapter (if connected).
    pub fn add_line_to_log(&mut self, text: *const c_char) -> () {
        let mut str = self.decode_string(text);
        log::trace!("Add to log: {str}");
        // Unreal does not add newlines to log messages, add one for readability.
        str.push_str("\r\n");
        if let Some(stream) = &mut self.event_channel {
            if let Err(e) = UnrealEvent::Log(str).serialize(stream) {
                log::error!("Sending log failed: {e}");
            }
        } else {
            log::trace!("Skipping log entry: not connected.");
        }
    }

    /// Set the current line.
    pub fn goto_line(&mut self, line: i32) -> () {
        self.current_line = line;
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
}

impl Debugger<TcpStream> {
    /// A new connection has been established from the adapter. Record the tcp stream used to send
    /// events.
    pub fn new_connection(&mut self, stream: TcpStream) -> () {
        self.event_channel = Some(serde_json::Serializer::new(stream));

        // The debugger stopped before we connected (e.g. due to -autoDebug). Send a stopped
        // event to let it know about this.
        if self.pending_break_event {
            log::info!("Sending stored stop event to the new connection.");
            self.pending_break_event = false;
            self.show_dll_form();
        }
    }
}

/// Initialize the debugger instance. This should be called exactly once when
/// Unreal first initializes us. Responsible for building the shared state object
/// the other Unreal entry points will use and spawning the main loop thread
/// that will perform I/O with the debugger adapter.
pub fn initialize(cb: UnrealCallback) -> () {
    if let Ok(dbg) = DEBUGGER.lock().as_mut() {
        assert!(dbg.is_none(), "Initialize already called.");

        // Start the logger. If this fails there isn't much we can do.
        let _ = init_logger();

        // Construct the debugger state.
        dbg.replace(Debugger::new());

        // Start the main loop that will listen for connections so we can
        // communiate the debugger state to the adapter.
        thread::spawn(move || main_loop(cb));
    }
}

/// Initialize the logging interface.
pub fn init_logger() -> Result<(), FlexiLoggerError> {
    let mut logger = LOGGER.lock().unwrap();
    assert!(logger.is_none(), "Already have a logger. Multiple inits?");
    let new_logger = Logger::try_with_env_or_str("trace")?
        .log_to_file(FileSpec::default().directory("DebuggerLogs"))
        .start()?;
    logger.replace(new_logger);
    Ok(())
}

/// The main loop of the debugger interface. This runs in an independent thread from Unreal.
///
/// This thread will process incoming commands from the debugger adapter and dispatch them through
/// the callback to unreal. This thread lives for the entire lifetime of the Unreal process with no
/// mechanism to end it. The Unreal debugger interface API does not have a mechanism to shut down
/// the interface, it'll just kill us when the process ends. This means this thread and loop may
/// survive multiple debugging "sessions". The 'toggledebugger' unreal command can disable an
/// active debugger and then another one can turn it back on again. This loop persists over those
/// stattes, although we will disconnect any active adapter when we shut down.
fn main_loop(cb: UnrealCallback) -> () {
    // Start listening on a socket for connections from the adapter.
    let mut server =
        TcpListener::bind(format!("127.0.0.1:{DEFAULT_PORT}")).expect("Failed to bind port");

    loop {
        match handle_connection(&mut server, cb) {
            Ok(_) => {}
            Err(e) => {
                log::error!("Error communicating with adapter: {e}");
            }
        }
    }
}

/// Accept one connection from the debugger adapter and process commands from it until it
/// disconects.
///
/// We accept only a single connection at a time, if multiple adapters attempt to connect
/// we'll process them in sequence.
fn handle_connection(server: &mut TcpListener, cb: UnrealCallback) -> Result<(), DebuggerError> {
    let (stream, addr) = server.accept().or(Err(DebuggerError::InitializeFailure))?;
    log::info!("Received connection from {addr}");

    // Tell the debugger state we have a new connection for it to send events through.
    {
        let mut hnd = DEBUGGER.lock().unwrap();
        let dbg = hnd.as_mut().unwrap();
        dbg.new_connection(stream.try_clone().unwrap());
    }

    let mut deserializer =
        serde_json::Deserializer::from_reader(stream).into_iter::<UnrealCommand>();
    while let Some(command) = deserializer.next() {
        let vec;
        {
            let mut hnd = DEBUGGER.lock().unwrap();
            let dbg = hnd.as_mut().unwrap();
            vec = dbg.handle_command(command?)?;

            // We must drop the mutex on the debugger instance before invoking the callback.
            // For certain callback commands Unreal will synchronously call back into us
            // on the same thread and we will need to re-acquire the mutex at that point to
            // process the response.
        }
        if let Some(vec) = vec {
            (cb)(vec.as_ptr());
        }
    }
    Ok(())
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
    use serde_json::Deserializer;

    use super::*;

    struct MockStream<'a> {
        logs: &'a mut Vec<String>,
    }

    impl io::Write for MockStream<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.logs.push(String::from_utf8(buf.to_vec()).unwrap());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn adding_to_hierarchy() {
        let cls = "Package.Class\0".as_ptr() as *const i8;
        let mut dbg = Debugger::<MockStream>::new();
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(dbg.class_hierarchy[0], "Package.Class");
    }

    #[test]
    fn clearing_hierarchy() {
        let cls = "Package.Class\0".as_ptr() as *const i8;
        let mut dbg = Debugger::<MockStream>::new();
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(dbg.class_hierarchy.len(), 1);
        dbg.clear_class_hierarchy();
        assert!(dbg.class_hierarchy.is_empty());
    }

    #[test]
    fn add_watches_are_independent() {
        let name = "SomeVar\0".as_ptr() as *const i8;
        let val = "10\0".as_ptr() as *const i8;
        let mut dbg = Debugger::<MockStream>::new();
        assert_eq!(dbg.add_watch(WatchKind::Local, -1, name, val), 0);
        assert_eq!(dbg.local_watches.len(), 1);
        assert_eq!(dbg.global_watches.len(), 0);
        assert_eq!(dbg.user_watches.len(), 0);
        assert_eq!(dbg.add_watch(WatchKind::Global, -1, name, val), 0);
        assert_eq!(dbg.local_watches.len(), 1);
        assert_eq!(dbg.global_watches.len(), 1);
        assert_eq!(dbg.user_watches.len(), 0);
        assert_eq!(dbg.add_watch(WatchKind::User, -1, name, val), 0);
        assert_eq!(dbg.local_watches.len(), 1);
        assert_eq!(dbg.global_watches.len(), 1);
        assert_eq!(dbg.user_watches.len(), 1);
    }

    #[test]
    fn clear_watches_are_independent() {
        let name = "SomeVar\0".as_ptr() as *const i8;
        let val = "10\0".as_ptr() as *const i8;
        let mut dbg = Debugger::<MockStream>::new();
        dbg.add_watch(WatchKind::Local, -1, name, val);
        dbg.add_watch(WatchKind::Global, -1, name, val);
        dbg.add_watch(WatchKind::User, -1, name, val);
        dbg.clear_watch(WatchKind::Local);
        assert_eq!(dbg.local_watches.len(), 0);
        assert_eq!(dbg.global_watches.len(), 1);
        assert_eq!(dbg.user_watches.len(), 1);
    }

    #[test]
    #[should_panic]
    fn add_watch_invalid_parent() {
        let name = "SomeVar\0".as_ptr() as *const i8;
        let val = "10\0".as_ptr() as *const i8;
        let mut dbg = Debugger::<MockStream>::new();
        dbg.add_watch(WatchKind::Local, 0, name, val);
    }

    #[test]
    fn log_sends_line() {
        let mut dbg = Debugger::<MockStream>::new();
        let mut vec = Vec::new();
        let mock_stream = MockStream { logs: &mut vec };
        dbg.event_channel = Some(Serializer::new(mock_stream));
        let str = "This is a log line\0";
        dbg.add_line_to_log(str.as_ptr() as *const i8);

        let concat = vec.iter().fold(String::new(), |mut x, y| {
            x.push_str(y);
            x
        });
        let deserializer = Deserializer::from_str(&concat);
        let destr: UnrealEvent = deserializer.into_iter().next().unwrap().unwrap();
        match destr {
            // Compare the strings. Ignore the null byte in our sending string, and ignore the \r\n
            // appended to the log line in the event.
            UnrealEvent::Log(s) => assert_eq!(str[..str.len() - 1], s[..s.len() - 2]),
            _ => panic!("Expected a log"),
        };
    }

    #[test]
    fn add_frame() {
        let mut dbg = Debugger::<MockStream>::new();
        dbg.add_frame("Function MyPackage.Class:MyFunction\0".as_ptr() as *const i8);
        assert_eq!(dbg.callstack[0].class_name, "MyPackage.Class");
        assert_eq!(dbg.callstack[0].function_name, "MyFunction");
    }

    #[test]
    fn empty_stacktrace() {
        let mut dbg = Debugger::<MockStream>::new();
        let response = dbg.handle_stacktrace_request(&StackTraceRequest {
            start_frame: 0,
            levels: 20,
        });
        assert!(response.frames.is_empty())
    }

    #[test]
    fn with_stacktrace() {
        let mut dbg = Debugger::<MockStream>::new();
        dbg.callstack.push(Frame {
            class_name: "Class1".to_string(),
            function_name: "foo".to_string(),
            line: 20,
        });
        dbg.callstack.push(Frame {
            class_name: "Class2".to_string(),
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
                    class_name: "Class2".to_string(),
                    function_name: "bar".to_string(),
                    line: 84
                },
                Frame {
                    class_name: "Class1".to_string(),
                    function_name: "foo".to_string(),
                    line: 20
                },
            ]
        );
    }

    #[test]
    fn partial_stacktrace_start() {
        let mut dbg = Debugger::<MockStream>::new();
        dbg.callstack.push(Frame {
            class_name: "Class1".to_string(),
            function_name: "foo".to_string(),
            line: 20,
        });
        dbg.callstack.push(Frame {
            class_name: "Class2".to_string(),
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
                class_name: "Class2".to_string(),
                function_name: "bar".to_string(),
                line: 84
            },]
        );
    }

    #[test]
    fn partial_stacktrace_end() {
        let mut dbg = Debugger::<MockStream>::new();
        dbg.callstack.push(Frame {
            class_name: "Class1".to_string(),
            function_name: "foo".to_string(),
            line: 20,
        });
        dbg.callstack.push(Frame {
            class_name: "Class2".to_string(),
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
                class_name: "Class1".to_string(),
                function_name: "foo".to_string(),
                line: 20
            },]
        );
    }

    #[test]
    fn partial_stacktrace_beyond() {
        let mut dbg = Debugger::<MockStream>::new();
        dbg.callstack.push(Frame {
            class_name: "Class1".to_string(),
            function_name: "foo".to_string(),
            line: 20,
        });
        dbg.callstack.push(Frame {
            class_name: "Class2".to_string(),
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
        let mut dbg = Debugger::<MockStream>::new();
        assert_eq!(dbg.watch_count(WatchKind::Local), 0);
        assert_eq!(dbg.watch_count(WatchKind::Global), 0);
        assert_eq!(dbg.watch_count(WatchKind::User), 0);
    }

    #[test]
    fn local_watch_count() {
        let mut dbg = Debugger::<MockStream>::new();
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
        assert_eq!(dbg.watch_count(WatchKind::Local), 2);
        assert_eq!(dbg.watch_count(WatchKind::Local), 2);
        assert_eq!(dbg.watch_count(WatchKind::Global), 0);
        assert_eq!(dbg.watch_count(WatchKind::User), 0);
    }

    #[test]
    fn global_watch_count() {
        let mut dbg = Debugger::<MockStream>::new();
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
        assert_eq!(dbg.watch_count(WatchKind::Local), 0);
        assert_eq!(dbg.watch_count(WatchKind::Global), 2);
        assert_eq!(dbg.watch_count(WatchKind::User), 0);
    }

    #[test]
    fn watch_counts_roots_only() {
        let mut dbg = Debugger::<MockStream>::new();
        dbg.add_watch(
            WatchKind::Global,
            -1,
            "Var1\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        dbg.add_watch(
            WatchKind::Global,
            0,
            "subfield\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        dbg.add_watch(
            WatchKind::Global,
            0,
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
            3,
            "subfield\0".as_ptr() as *const i8,
            "0\0".as_ptr() as *const i8,
        );
        assert_eq!(dbg.watch_count(WatchKind::Global), 2);
    }
}
