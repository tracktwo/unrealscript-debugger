//! # Unrealscript Debugger
//! Module for the Unrealscript debugger interface.
//! See https://docs.unrealengine.com/udk/Three/DebuggerInterface.html
//!
//! Unreal controls the lifetime this library, and does not provide much of
//! any error handling or recovery mechanisms. If any of the expected invariants
//! of this interface are violated we will simply panic.
//!
//! The functions in this interface are thin wrappers that simply pass their
//! arguments on to corresponding methods on the debugger state instance.

use common::WatchKind;
use debugger::Debugger;
use log::trace;
use std::{ffi::c_char, sync::Mutex};

/// The debugger state. Calls from Unreal are dispatched into this instance.
static DEBUGGER: Mutex<Option<Debugger>> = Mutex::new(None);

/// The unreal callback type. Note that the debugger specification defines
/// it as accepting a 'const char*' parameter but we use u8 here. This is
/// for convenience since it is primarily passed strings.
type UnrealCallback = extern "C" fn(*const u8) -> ();

/// Called once from Unreal when the debugger interface is initialized, passing the callback
/// function to use.
///
/// This is the primary entry point into the debugger interface and we use this to
/// launch the effective 'main'.
#[no_mangle]
pub extern "C" fn SetCallback(callback: Option<UnrealCallback>) {
    let cb = callback.expect("Unreal should never give us a null callback.");

    debugger::initialize(cb);
}

/// Called each time the debugger breaks, as well as just after SetCallback when the debugger is
/// first initialized.
///
/// Since this implementation doesn't have a UI in-process this does nothing.
#[no_mangle]
pub extern "C" fn ShowDllForm() {
    trace!("ShowDllForm");
}

/// Add the given class to the class hierarchy.
///
/// Tells the debugger the names of all currently loaded classes.
#[no_mangle]
pub extern "C" fn AddClassToHierarchy(class_name: *const c_char) -> () {
    trace!("AddClassToHierarchy");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_class_to_hierarchy(class_name);
}

/// Clear the class hierarchy in the debugger state.
#[no_mangle]
pub extern "C" fn ClearClassHierarchy() -> () {
    trace!("ClearClassHierarchy");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.clear_class_hierarchy();
}

/// ???
#[no_mangle]
pub extern "C" fn BuildClassHierarchy() -> () {
    trace!("BuildClassHierarchy");
}

/// Legacy version of ClearAWatch.
#[no_mangle]
pub extern "C" fn ClearWatch(kind: i32) -> () {
    trace!("ClearWatch {kind}");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.clear_watch(
        WatchKind::from_int(kind).expect("Unreal should never give us a bad watch kind."),
    );
}

/// Removes all watches of the given kind.
///
/// Used when rebuilding the watch list.
/// This occurs each time the debugger breaks to refresh watches.
#[no_mangle]
pub extern "C" fn ClearAWatch(kind: i32) -> () {
    trace!("ClearAWatch {kind}");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.clear_watch(
        WatchKind::from_int(kind).expect("Unreal should never give us a bad watch kind."),
    );
}

/// Adds a watch to the watch list for the given kind.
///
/// This is the only Unreal
/// debugger API that returns a value.
#[no_mangle]
pub extern "C" fn AddAWatch(
    kind: i32,
    parent: i32,
    name: *const c_char,
    value: *const c_char,
) -> i32 {
    trace!("AddAWatch {kind} {parent}");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_watch(
        WatchKind::from_int(kind).expect("Unreal should never give us a bad watch kind."),
        parent,
        name,
        value,
    )
}

/// Locks the given watch list.
///
/// Called before Unreal updates the watchlist of the given kind. This will be
/// followed by some number of 'AddAWatch' calls, followed by 'UnlockList'.
#[no_mangle]
pub extern "C" fn LockList(_kind: i32) -> () {
    trace!("LockList {_kind}");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.lock_watchlist()
}

/// Unlocks the given watch list.
///
/// Called after Unreal has finished updating the watchlist of the given kind.
#[no_mangle]
pub extern "C" fn UnlockList(_kind: i32) -> () {
    trace!("UnlockList {_kind}");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.unlock_watchlist()
}

#[no_mangle]
pub extern "C" fn AddBreakpoint(class_name: *const c_char, line: i32) -> () {
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_breakpoint(class_name, line);
}

#[no_mangle]
pub extern "C" fn RemoveBreakpoint(class_name: *const c_char, line: i32) -> () {
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.remove_breakpoint(class_name, line);
}

#[no_mangle]
pub extern "C" fn EditorLoadClass(_class_name: *const c_char) -> () {
    trace!("EditorLoadClass");
    // TODO Implement
}

#[no_mangle]
pub extern "C" fn EditorGotoLine(_line: i32, _highlight: i32) -> () {
    trace!("EditorGotoLine");
    // TODO Implement
}

#[no_mangle]
pub extern "C" fn AddLineToLog(text: *const c_char) -> () {
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_line_to_log(text);
}

#[no_mangle]
pub extern "C" fn CallStackClear() -> () {
    trace!("CallStackClear");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.clear_callstack();
}

/// Add the given class name to the call stack. Call stacks are built bottom-up.
#[no_mangle]
pub extern "C" fn CallStackAdd(class_name: *const c_char) -> () {
    trace!("CallStackAdd");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_frame(class_name, 0);
}

#[no_mangle]
pub extern "C" fn SetCurrentObjectName(obj_name: *const c_char) -> () {
    trace!("SetCurrentObjectName");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.current_object_name(obj_name);
}

#[no_mangle]
pub extern "C" fn DebugWindowState(code: i32) -> () {
    trace!("DebugWindowState {code}");
}

/// Module that manages the internal debugger state within the interface DLL.
///
/// As Unreal invokes the API entry points of this interface the debugger state
/// is updated. Since the interface module is only a very thin wrapper the
/// functions for handling calls from the DLL are very low-level and deal with
/// C types. These are converted internally to a slightly higher level for
/// convenience, but with only minimal processing.
pub mod debugger;
