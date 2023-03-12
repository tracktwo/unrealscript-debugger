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
#![warn(missing_docs)]

use std::sync::{Condvar, Mutex};

use debugger::Debugger;
use flexi_logger::LoggerHandle;
pub mod lifetime;

pub mod debugger;

pub mod api;

/// The debugger state. Calls from Unreal are dispatched into this instance.
static DEBUGGER: Mutex<Option<Debugger>> = Mutex::new(None);
static LOGGER: Mutex<Option<LoggerHandle>> = Mutex::new(None);
static VARIABLE_REQUST_CONDVAR: Condvar = Condvar::new();
