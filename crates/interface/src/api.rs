//! Module for API entry points from Unreal to the debugger interface.
//!
//! See: https://docs.unrealengine.com/udk/Three/DebuggerInterface.html
//!
//! This contains all the publicly exported functions defined by the Unrealscript
//! debugger interface.

/// The unreal callback type. Note that the debugger specification defines
/// it as accepting a 'const char*' parameter but we use u8 here. This is
/// for convenience since it is primarily passed strings.
pub type UnrealCallback = extern "C" fn(*const u8) -> ();

use std::ffi::c_char;

use crate::lifetime::initialize;
use common::WatchKind;
use log;

use crate::lifetime::DEBUGGER;

/// Called once from Unreal when the debugger interface is initialized, passing the callback
/// function to use.
///
/// This is the primary entry point into the debugger interface and we use this to
/// launch the effective 'main'.
#[no_mangle]
pub extern "C" fn SetCallback(callback: Option<UnrealCallback>) {
    let cb = callback.expect("Unreal should never give us a null callback.");

    initialize(cb);
}

/// Called each time the debugger breaks, as well as just after SetCallback when the debugger is
/// first initialized.
///
/// Since this implementation doesn't have a UI in-process this does nothing.
#[no_mangle]
pub extern "C" fn ShowDllForm() {
    log::trace!("ShowDllForm");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.show_dll_form();
}

/// Add the given class to the class hierarchy.
///
/// Tells the debugger the names of all currently loaded classes.
#[no_mangle]
pub extern "C" fn AddClassToHierarchy(class_name: *const c_char) {
    log::trace!("AddClassToHierarchy");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_class_to_hierarchy(class_name);
}

/// Clear the class hierarchy in the debugger state.
#[no_mangle]
pub extern "C" fn ClearClassHierarchy() {
    log::trace!("ClearClassHierarchy");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.clear_class_hierarchy();
}

/// ???
#[no_mangle]
pub extern "C" fn BuildClassHierarchy() {
    log::trace!("BuildClassHierarchy");
}

/// Legacy version of ClearAWatch.
#[no_mangle]
pub extern "C" fn ClearWatch(kind: i32) {
    log::trace!("ClearWatch {kind}");
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
pub extern "C" fn ClearAWatch(kind: i32) {
    log::trace!("ClearAWatch {kind}");
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
    log::trace!("AddAWatch {kind} {parent}");
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
pub extern "C" fn LockList(_kind: i32) {
    log::trace!("LockList {_kind}");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.lock_watchlist()
}

/// Unlocks the given watch list.
///
/// Called after Unreal has finished updating the watchlist of the given kind.
#[no_mangle]
pub extern "C" fn UnlockList(kind: i32) {
    log::trace!("UnlockList {kind}");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.unlock_watchlist(
        WatchKind::from_int(kind).expect("Unreal should never give us a bad watch kind."),
    );
}

#[no_mangle]
pub extern "C" fn AddBreakpoint(class_name: *const c_char, line: i32) {
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_breakpoint(class_name, line);
}

#[no_mangle]
pub extern "C" fn RemoveBreakpoint(class_name: *const c_char, line: i32) {
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.remove_breakpoint(class_name, line);
}

#[no_mangle]
pub extern "C" fn EditorLoadClass(_class_name: *const c_char) {
    // For our purposes this API is not necessary. This gets send on a break
    // and any changestack command to indicate what source file to show. But
    // the full filenames of each stack frame are also sent in the CallStackAdd
    // command, and we use this information instead. When switching frames
    // we already know the filename for the frame we switched to.
}

#[no_mangle]
pub extern "C" fn EditorGotoLine(line: i32, _highlight: i32) {
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.goto_line(line);
}

#[no_mangle]
pub extern "C" fn AddLineToLog(text: *const c_char) {
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_line_to_log(text);
}

#[no_mangle]
pub extern "C" fn CallStackClear() {
    log::trace!("CallStackClear");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.clear_callstack();
}

/// Add the given class name to the call stack. Call stacks are built bottom-up.
#[no_mangle]
pub extern "C" fn CallStackAdd(class_name: *const c_char) {
    log::trace!("CallStackAdd");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.add_frame(class_name);
}

#[no_mangle]
pub extern "C" fn SetCurrentObjectName(obj_name: *const c_char) {
    log::trace!("SetCurrentObjectName");
    let mut hnd = DEBUGGER.lock().unwrap();
    let dbg = hnd.as_mut().unwrap();
    dbg.current_object_name(obj_name);
}

#[no_mangle]
pub extern "C" fn DebugWindowState(code: i32) {
    log::trace!("DebugWindowState {code}");
}
