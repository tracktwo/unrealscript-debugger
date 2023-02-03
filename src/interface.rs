// Module for the Unrealscript debugger interface.
// See https://docs.unrealengine.com/udk/Three/DebuggerInterface.html

pub mod debugger;

use std::{sync::Mutex, ffi::{c_char, c_int}};
use debugger::{Debugger, WatchKind};

/// The debugger state. Calls from Unreal are dispatched into this instance.
static DEBUGGER: Mutex<Option<Debugger>> = Mutex::new(None);

/// The unreal callback type. Note that the debugger specification defines
/// it as accepting a 'const char*' parameter but we use u8 here. This is
/// for convenience since it is primarily passed strings.
type UnrealCallback = extern "C" fn(*const u8) -> ();

/// SetCallback: Called once from Unreal when the debugger interface is
/// initialized, passing the callback function to use. This is the primary
/// entry point into the debugger interface and we use this to launch the
/// effective 'main'.
#[no_mangle]
pub extern "C" fn SetCallback(callback: Option<UnrealCallback>) {
    let cb = callback.expect("Unreal should never give us a null callback.");

    debugger::initialize(cb);
}

#[no_mangle]
pub extern "C" fn ShowDllForm() {
}

#[no_mangle]
pub extern "C" fn AddClassToHierarchy(class_name: *const c_char) -> () {
    if let Ok(mut dbg) = DEBUGGER.lock() {
        if let Some(dbg) = dbg.as_mut() {
            dbg.add_class_to_hierarchy(class_name);
        }
    }
}

#[no_mangle]
pub extern "C" fn ClearClassHierarchy() -> () {
    if let Ok(mut dbg) = DEBUGGER.lock() {
        if let Some(dbg) = dbg.as_mut() {
            dbg.clear_class_hierarchy();
        }
    }
}

#[no_mangle]
pub extern "C" fn BuildClassHierarchy() -> () {
}

#[no_mangle]
pub extern "C" fn ClearWatch(kind: i32) -> () {
    if let Ok(mut dbg) = DEBUGGER.lock() {
        if let Some(dbg) = dbg.as_mut() {
            dbg.clear_watch(WatchKind::from_int(kind)
                .expect("Unreal should never give us a bad watch kind."));
        }
    }
}

#[no_mangle]
pub extern "C" fn ClearAWatch(kind: i32) -> () {
    if let Ok(mut dbg) = DEBUGGER.lock() {
        if let Some(dbg) = dbg.as_mut() {
            dbg.clear_watch(WatchKind::from_int(kind)
                .expect("Unreal should never give us a bad watch kind."));
        }
    }
}
