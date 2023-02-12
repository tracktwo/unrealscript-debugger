use flexi_logger::{FileSpec, FlexiLoggerError, Logger, LoggerHandle};
use ipmpsc::{Sender, SharedRingBuffer};
use std::ffi::{c_char, CStr};
use std::net::TcpListener;
use std::ptr;
use std::{sync::Mutex, thread};
use textcode::iso8859_1;
use thiserror::Error;

use super::UnrealCallback;
use super::DEBUGGER;
use common::DEFAULT_PORT;
use common::{Breakpoint, UnrealCommand, UnrealResponse};

static LOGGER: Mutex<Option<LoggerHandle>> = Mutex::new(None);

/// A struct representing the debugger state.
pub struct Debugger {
    callback: UnrealCallback,
    class_hierarchy: Vec<String>,
    local_watches: Vec<Watch>,
    global_watches: Vec<Watch>,
    user_watches: Vec<Watch>,
    breakpoints: Vec<Breakpoint>,
    callstack: Vec<Frame>,
    current_object_name: Option<String>,
    response_channel: Option<Sender>,
}

/// A variable watch.
pub struct Watch {
    parent: i32,
    name: String,
    value: String,
}

/// A callstack frame.
pub struct Frame {
    class_name: String,
    line: i32,
}

/// The kind of watch, e.g. scope or user-defined watches.
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

impl Debugger {
    pub fn new(callback: UnrealCallback) -> Debugger {
        Debugger {
            callback,
            class_hierarchy: Vec::new(),
            local_watches: Vec::new(),
            global_watches: Vec::new(),
            user_watches: Vec::new(),
            breakpoints: Vec::new(),
            callstack: Vec::new(),
            current_object_name: None,
            response_channel: None,
        }
    }

    /// Handle a command from the adapter. This may generate responses.
    pub fn handle_command(&mut self, command: UnrealCommand) -> Result<(), DebuggerError> {
        match command {
            UnrealCommand::Initialize(path) => {
                let buf =
                    SharedRingBuffer::open(&path).or(Err(DebuggerError::InitializeFailure))?;
                self.response_channel = Some(Sender::new(buf));
                Ok(())
            }
            UnrealCommand::AddBreakpoint(bp) => {
                let str = format!("addbreakpoint {}", bp.qualified_name);
                self.invoke_callback(&str);
                Ok(())
            }
            UnrealCommand::RemoveBreakpoint(_) => Ok(()),
        }
    }

    /// Invoke the unreal callback with the given string argument. This will be
    /// reencoded to Unreal's format and null terminated before sending.
    fn invoke_callback(&mut self, command: &str) -> () {
        let mut encoded = self.encode_string(command);
        encoded.push(0);
        (self.callback)(encoded.as_ptr());
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

    pub fn add_breakpoint(&mut self, class_name: *const c_char, line: i32) -> () {
        let bp = Breakpoint {
            qualified_name: self.decode_string(class_name),
            line,
        };
        self.breakpoints.push(bp.clone());
        if let Err(e) = self.send_response(&UnrealResponse::BreakpointAdded(bp)) {
            log::error!("Sending BreakpointAdded response failed: {e}");
        }
    }

    pub fn remove_breakpoint(&mut self, name: *const c_char, line: i32) -> () {
        let str = self.decode_string(name);
        if let Some(idx) = self
            .breakpoints
            .iter()
            .position(|val| val.qualified_name == str && val.line == line)
        {
            let bp = self.breakpoints.swap_remove(idx);
            if let Err(e) = self.send_response(&UnrealResponse::BreakpointRemoved(bp)) {
                log::error!("Sending BreakpointRemoved response failed: {e}");
            }
        } else {
            log::error!("Could not find breakpoint {str}:{line}",);
        }
    }

    pub fn clear_callstack(&mut self) -> () {
        self.callstack.clear();
    }

    pub fn add_frame(&mut self, class_name: *const c_char, line: i32) -> () {
        let frame = Frame {
            class_name: self.decode_string(class_name),
            line,
        };
        self.callstack.push(frame);
    }

    pub fn current_object_name(&mut self, obj_name: *const c_char) -> () {
        self.current_object_name = Some(self.decode_string(obj_name));
    }

    /// Decode an Unreal-encoded string to UTF-8.
    fn decode_string(&mut self, ptr: *const c_char) -> String {
        let str = make_cstr(ptr);
        return iso8859_1::decode_to_string(str.to_bytes());
    }

    /// Encode a UTF-8 string to Unreal.
    fn encode_string(&mut self, s: &str) -> Vec<u8> {
        iso8859_1::encode_to_vec(s)
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
        dbg.replace(Debugger::new(cb));

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
fn handle_connection(server: &mut TcpListener, _cb: UnrealCallback) -> Result<(), DebuggerError> {
    let (stream, addr) = server.accept().or(Err(DebuggerError::InitializeFailure))?;
    log::info!("Received connection from {addr}");

    let mut deserializer =
        serde_json::Deserializer::from_reader(stream).into_iter::<UnrealCommand>();
    while let Some(command) = deserializer.next() {
        let mut hnd = DEBUGGER.lock().unwrap();
        let dbg = hnd.as_mut().unwrap();
        dbg.handle_command(command?)?;
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
    use super::*;

    extern "C" fn callback(_s: *const u8) -> () {}

    #[test]
    fn adding_to_hierarchy() {
        let cls = "Package.Class\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new(callback);
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(dbg.class_hierarchy[0], "Package.Class");
    }

    #[test]
    fn clearing_hierarchy() {
        let cls = "Package.Class\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new(callback);
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(dbg.class_hierarchy.len(), 1);
        dbg.clear_class_hierarchy();
        assert!(dbg.class_hierarchy.is_empty());
    }

    #[test]
    fn add_watches_are_independent() {
        let name = "SomeVar\0".as_ptr() as *const i8;
        let val = "10\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new(callback);
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
        let mut dbg = Debugger::new(callback);
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
        let mut dbg = Debugger::new(callback);
        dbg.add_watch(WatchKind::Local, 0, name, val);
    }

    #[test]
    fn adds_breakpoint() {
        let class_name = "SomeClass\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new(callback);
        dbg.add_breakpoint(class_name, 10);
        assert_eq!(dbg.breakpoints.len(), 1);
    }

    #[test]
    fn can_find_breakpoint() {
        let class_name = "SomeClass\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new(callback);
        dbg.add_breakpoint(class_name, 10);
        dbg.remove_breakpoint(class_name, 10);
        assert_eq!(dbg.breakpoints.len(), 0);
    }

    #[test]
    fn remove_unknown_breakpoint() {
        let class_name = "SomeClass\0".as_ptr() as *const i8;
        let another_name = "AnotherClass\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new(callback);
        dbg.add_breakpoint(class_name, 10);
        dbg.remove_breakpoint(another_name, 20);
        assert_eq!(dbg.breakpoints.len(), 1);
        dbg.remove_breakpoint(class_name, 11);
        assert_eq!(dbg.breakpoints.len(), 1);
    }
}
