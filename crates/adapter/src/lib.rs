//! Unrealscript Debugger Adapter
//!
//! This crate implements the 'adapter' portion of the DAP. It is responsible
//! for mediating communication between the DAP client (e.g. an editor) and
//! the Unrealscript Debugger Interface, which runs in the Unreal process.
#![warn(missing_docs)]

use dap::responses::MessageResponseBody;
use thiserror::Error;
pub mod async_client;
pub mod client_config;
pub mod comm;
pub mod connected_adapter;
pub mod disconnected_adapter;
pub mod variable_reference;

/// An error representing failure modes of the adapter. These errors are transmitted
/// to the client and may be displayed to the user, so they will include several
/// specific error cases to give better diagnostics about particular failures
/// especially if they are related to configuration, or indicate some kind of
/// unexpected state communicating with DAP for a particular editor that might be
/// a bug in the adapter.
#[derive(Error, Debug)]
pub enum UnrealscriptAdapterError {
    /// We received a DAP command that is not understood, or is inappropriate for
    /// the current adapter state (e.g. we can't process a 'setBreakpoints' command
    /// until after launching or attaching to the debuggee).
    #[error("Unhandled command: {0}")]
    UnhandledCommand(String),

    /// We received a source filename that is not a valid path.
    #[error("Invalid filename: {0}")]
    InvalidFilename(String),

    /// An I/O error occurred during communications with the client or interface.
    #[error("{0}")]
    IoError(std::io::Error),

    /// The launch configuration did not specify a program to run.
    #[error("No program provided to 'launch' configuration")]
    NoProgram,

    /// The launch configuration specified a program that could not be found or
    /// executed.
    #[error("Failed to launch program {0}")]
    InvalidProgram(String),

    /// A value exceeded the limits of the debugger, e.g. a frame too deep.
    #[error("Limit exceeded: {0}")]
    LimitExceeded(String),

    /// We failed to retreive the watch value for a particular expression.
    ///
    /// This error does not mean that the expression could not be evaluated: that
    /// returns a watch variable with an error string in the "value". This can
    /// only occur when a new watch is registered but Unreal does not actually
    /// give us any watch data, which should be impossible.
    #[error("Error setting watch for: {0}")]
    WatchError(String),
}

impl From<std::io::Error> for UnrealscriptAdapterError {
    fn from(e: std::io::Error) -> Self {
        UnrealscriptAdapterError::IoError(e)
    }
}

impl UnrealscriptAdapterError {
    /// Return a fixed id number for an error. This is used in DAP error
    /// responses to uniquely identify messages.
    fn id(&self) -> i64 {
        match self {
            UnrealscriptAdapterError::UnhandledCommand(_) => 1,
            UnrealscriptAdapterError::InvalidFilename(_) => 2,
            UnrealscriptAdapterError::IoError(_) => 3,
            UnrealscriptAdapterError::NoProgram => 3,
            UnrealscriptAdapterError::InvalidProgram(_) => 3,
            UnrealscriptAdapterError::LimitExceeded(_) => 4,
            UnrealscriptAdapterError::WatchError(_) => 5,
        }
    }

    /// Convet an UnrealScriptAdapterError to a DAP error message suitable
    /// for use as a body in an error response.
    pub fn to_error_message(&self) -> MessageResponseBody {
        MessageResponseBody {
            id: self.id(),
            format: self.to_string(),
            show_user: true,
        }
    }
}
