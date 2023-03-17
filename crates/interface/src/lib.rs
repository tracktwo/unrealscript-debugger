//! # Unrealscript Debugger
//! Module for the Unrealscript debugger interface.
//! See <https://docs.unrealengine.com/udk/Three/DebuggerInterface.html>
//!
//! Unreal controls the lifetime this library, and does not provide much of
//! any error handling or recovery mechanisms. If any of the expected invariants
//! of this interface are violated we will simply panic.
//!
//! The functions in this interface are thin wrappers that simply pass their
//! arguments on to corresponding methods on the debugger state instance.
#![warn(missing_docs)]

use std::sync::{Condvar, Mutex};

use common::Version;
use debugger::Debugger;
use flexi_logger::LoggerHandle;
use pkg_version::{pkg_version_major, pkg_version_minor, pkg_version_patch};
pub mod api;
pub mod debugger;
pub mod lifetime;
pub mod stackhack;

/// The debugger state. Calls from Unreal are dispatched into this instance.
static DEBUGGER: Mutex<Option<Debugger>> = Mutex::new(None);
static LOGGER: Mutex<Option<LoggerHandle>> = Mutex::new(None);
static VARIABLE_REQUST_CONDVAR: Condvar = Condvar::new();
static INTERFACE_VERSION: Version = Version {
    major: pkg_version_major!(),
    minor: pkg_version_minor!(),
    patch: pkg_version_patch!(),
};
