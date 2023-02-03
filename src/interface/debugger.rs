use std::ffi::{c_char, CStr};
use std::net::{TcpListener, TcpStream};
use std::{fmt, io, ptr};
use std::{sync::Mutex, thread};
use flexi_logger::{Logger, FileSpec, LoggerHandle, FlexiLoggerError};
use tcp_channel::{ChannelRecv, ChannelSend, ReceiverBuilder, SenderBuilder};
use serde::{Serialize, Deserialize};

use super::UnrealCallback;
use super::DEBUGGER;

const PORT: i32 = 18777;

static LOGGER: Mutex<Option<LoggerHandle>> = Mutex::new(None);

/// A struct representing the debugger state.
pub struct Debugger {
    class_hierarchy: Vec<Box<CStr>>,
}

pub enum WatchKind {
    Local,
    Global,
    User
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
        Debugger { class_hierarchy: Vec::new() }
    }

    /// Add a class to the debugger's class hierarchy.
    pub fn add_class_to_hierarchy(&mut self, arg: *const c_char) -> () {
        let str = make_cstr(arg);
        self.class_hierarchy.push(str);
    }

    /// Clear the class hierarchy.
    pub fn clear_class_hierarchy(&mut self) -> () {
        self.class_hierarchy.clear();
    }

    pub fn clear_watch(&mut self, kind: WatchKind) -> () {
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
    let new_logger = Logger::try_with_env_or_str("info")?
            .log_to_file(FileSpec::default())
            .start()?;
    logger.replace(new_logger);
    Ok(())
}

fn main_loop(cb: UnrealCallback) -> () {

    // Start listening on a socket for connections from the adapter.
    let mut server = TcpListener::bind(format!("127.0.0.1:{PORT}")).expect("Failed to bind port");
    loop {
        match handle_connection(&mut server) {
            // TODO Logging
            Ok(_) => {}
            Err(_) => {}
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum InterfaceMessage {
    Next,
    Continue,
}

fn handle_connection(server: &mut TcpListener) -> Result<(), io::Error> {
    loop {
        let (stream, addr) = server.accept()?;
        let mut rx = ReceiverBuilder::realtime().with_type::<InterfaceMessage>().build(stream.try_clone()?);
        let mut tx = SenderBuilder::realtime().with_type::<InterfaceMessage>().build(stream);
        while let msg  = rx.recv() {
        }
    }
}

/// Given a pointer to a string from Unreal, return a boxed CStr with the
/// same contents. This interface deals only with CStrs, since Unreal does not
/// give us UTF-8 encoded strings. The format might be locale-dependent, but
/// for INT they are definitely ISO8859-1 encoded. Text conversion is performed
/// in the debugger adapter, not in this interface.
///
/// TODO: What about non-western game locales? What format text do we get?
fn make_cstr(raw: *const c_char) -> Box<CStr> {
    if raw != ptr::null() {
        unsafe {
            return CStr::from_ptr(raw).to_owned().into();
        }
    }
    
    CStr::from_bytes_with_nul(b"\0").unwrap().to_owned().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstr_from_null() {
        assert_eq!(make_cstr(ptr::null()).as_ref().to_str().unwrap(), "");
    }

    #[test]
    fn cstr_from_text() {
        let p = "hello world".as_ptr() as *const i8;
        assert_eq!(make_cstr(p).as_ref().to_str().unwrap(), "hello world");
    }

    #[test]
    fn adding_to_hierarchy() {
        let cls = "Package.Class".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(dbg.class_hierarchy[0].as_ref().to_str().unwrap(), "Package.Class");
    }

    #[test]
    fn clearing_hierarchy() {
        let cls = "Package.Class".as_ptr() as *const i8;
        let mut dbg = Debugger::new();
        dbg.add_class_to_hierarchy(cls);
        assert_eq!(dbg.class_hierarchy.len(), 1);
        dbg.clear_class_hierarchy();
        assert!(dbg.class_hierarchy.is_empty());
    }
}
