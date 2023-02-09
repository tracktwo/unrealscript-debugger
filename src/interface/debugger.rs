use core::time;
use flexi_logger::{FileSpec, FlexiLoggerError, Logger, LoggerHandle};
use std::ffi::{c_char, CStr, CString};
use std::net::TcpListener;
use std::{io, ptr};
use std::{sync::Mutex, thread};

use super::UnrealCallback;
use super::DEBUGGER;
use crate::ipc::UnrealCommand;

const PORT: i32 = 18777;

static LOGGER: Mutex<Option<LoggerHandle>> = Mutex::new(None);

/// A struct representing the debugger state.
pub struct Debugger {
    class_hierarchy: Vec<Box<CString>>,
    local_watches: Vec<Watch>,
    global_watches: Vec<Watch>,
    user_watches: Vec<Watch>,
    breakpoints: Vec<Breakpoint>,
    callstack: Vec<Frame>,
    current_object_name: Option<Box<CString>>,
}

/// A variable watch.
struct Watch {
    parent: i32,
    name: Box<CString>,
    value: Box<CString>,
}

/// A breakpoint, verified by Unreal.
struct Breakpoint {
    class_name: Box<CString>,
    line: i32,
}

/// A callstack frame.
struct Frame {
    class_name: Box<CString>,
    line: i32,
}

// The kind of watch, e.g. scope or user-defined watches.
pub enum WatchKind {
    Local,
    Global,
    User,
}

impl WatchKind {
    pub fn from_int(kind: i32) -> Option<WatchKind> {
        match kind {
            0 => Some(WatchKind::Local),
            1 => Some(WatchKind::Global),
            2 => Some(WatchKind::User),
            _ => None,
        }
    }
}

impl Debugger {
    fn new() -> Debugger {
        Debugger {
            class_hierarchy: Vec::new(),
            local_watches: Vec::new(),
            global_watches: Vec::new(),
            user_watches: Vec::new(),
            breakpoints: Vec::new(),
            callstack: Vec::new(),
            current_object_name: None,
        }
    }

    /// Add a class to the debugger's class hierarchy.
    pub fn add_class_to_hierarchy(&mut self, arg: *const c_char) -> () {
        let str = make_cstring(arg);
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
            name: make_cstring(name),
            value: make_cstring(value),
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
            class_name: make_cstring(class_name),
            line,
        };
        self.breakpoints.push(bp);
    }

    pub fn remove_breakpoint(&mut self, name: *const c_char, line: i32) -> () {
        let str = make_cstr(name);
        if let Some(idx) = self
            .breakpoints
            .iter()
            .position(|val| val.class_name.as_c_str() == str && val.line == line)
        {
            self.breakpoints.swap_remove(idx);
        } else {
            log::error!(
                "Could not find breakpoint {:#?}:{line}",
                str.to_string_lossy()
            );
        }
    }

    pub fn clear_callstack(&mut self) -> () {
        self.callstack.clear();
    }

    pub fn add_frame(&mut self, class_name: *const c_char, line: i32) -> () {
        let frame = Frame {
            class_name: make_cstring(class_name),
            line,
        };
        self.callstack.push(frame);
    }

    pub fn current_object_name(&mut self, obj_name: *const c_char) -> () {
        self.current_object_name.replace(make_cstring(obj_name));
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
    let mut server = TcpListener::bind(format!("127.0.0.1:{PORT}")).expect("Failed to bind port");

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
fn handle_connection(server: &mut TcpListener, cb: UnrealCallback) -> Result<(), io::Error> {
    let (stream, addr) = server.accept()?;
    log::info!("Received connection from {addr}");

    let mut deserializer = serde_json::Deserializer::from_reader(stream).into_iter::<UnrealCommand>();
    while let Some(command) = deserializer.next() {
        // TODO Probably move this into the debugger and take a lock here for processing?
        match command? { 
            UnrealCommand::Initialize(path) => (),
            UnrealCommand::SetBreakpoint(bp) => (),
            UnrealCommand::RemoveBreakpoint(bp) => (),
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct UnknownCommandError;

/// Given a pointer to a string from Unreal, return a boxed CStr with the
/// same contents. This interface deals only with CStrs, since Unreal does not
/// give us UTF-8 encoded strings. The format might be locale-dependent, but
/// for INT they are definitely ISO8859-1 encoded. Text conversion is performed
/// in the debugger adapter, not in this interface.
///
/// TODO: What about non-western game locales? What format text do we get?
fn make_cstring(raw: *const c_char) -> Box<CString> {
    // The byte vector to use if we have a null pointer: return as an empty string.
    let mut bytes: Vec<u8> = Vec::new();
    if raw != ptr::null() {
        unsafe {
            let cstr = CStr::from_ptr(raw);
            // Get a copy of the raw bytes from the given pointer.
            bytes = cstr.to_bytes().to_owned();
        }
    }
    // Create a new CString with our bytes. These bytes should never contain
    // interior nulls.
    return Box::new(CString::new(bytes).unwrap());
}

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
    fn cstr_from_null() {
        assert_eq!(make_cstring(ptr::null()).to_str().unwrap(), "");
    }

    #[test]
    fn cstr_from_text() {
        let p = "hello world\0".as_ptr() as *const i8;
        assert_eq!(make_cstring(p).to_str().unwrap(), "hello world");
    }

    #[test]
    fn string_ownership() {
        let mut str = "I'M A STRING\0".to_owned();
        let ptr = str.as_ptr() as *const i8;
        let copy = make_cstring(ptr);
        assert_ne!(ptr, copy.as_ptr());
        str.make_ascii_lowercase();
        assert_eq!(copy.to_str().unwrap(), "I'M A STRING");
    }

    #[test]
    fn adding_to_hierarchy() {
        let cls = "Package.Class\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(
            dbg.class_hierarchy[0].as_ref().to_str().unwrap(),
            "Package.Class"
        );
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
        let mut dbg = Debugger::new();
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
        let mut dbg = Debugger::new();
        dbg.add_watch(WatchKind::Local, 0, name, val);
    }

    #[test]
    fn adds_breakpoint() {
        let class_name = "SomeClass\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_breakpoint(class_name, 10);
        assert_eq!(dbg.breakpoints.len(), 1);
    }

    #[test]
    fn can_find_breakpoint() {
        let class_name = "SomeClass\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_breakpoint(class_name, 10);
        dbg.remove_breakpoint(class_name, 10);
        assert_eq!(dbg.breakpoints.len(), 0);
    }

    #[test]
    fn remove_unknown_breakpoint() {
        let class_name = "SomeClass\0".as_ptr() as *const i8;
        let another_name = "AnotherClass\0".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_breakpoint(class_name, 10);
        dbg.remove_breakpoint(another_name, 20);
        assert_eq!(dbg.breakpoints.len(), 1);
        dbg.remove_breakpoint(class_name, 11);
        assert_eq!(dbg.breakpoints.len(), 1);
    }
}
