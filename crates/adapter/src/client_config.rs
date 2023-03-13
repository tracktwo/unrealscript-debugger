//! Client configuration settings.
//!
//! These settings are sent by the client to indicate which features it supports.
//! They are used to determine the format of particular responses to the client.

/// A representation of the client configuration options. These will impact how
/// we send responses. This can include both standard DAP configuration settings
/// as well as debugger-specific ones.
#[derive(Debug)]
pub struct ClientConfig {
    /// If true (the default and Unreal's native mode) the client expects lines to start at 1.
    /// Otherwise they start at 0.
    pub one_based_lines: bool,

    /// If true then we will send type information with variables.
    pub supports_variable_type: bool,

    /// If true then we'll send invalidated events when fetching variables that involves a stack
    /// change.
    pub supports_invalidated_event: bool,

    /// An ordered list of directories in which we may find source files. Used to locate
    /// the source file for a particular package and class.
    pub source_roots: Vec<String>,
}

impl ClientConfig {
    /// Create a new client config with default settings.
    pub fn new() -> Self {
        ClientConfig {
            one_based_lines: true,
            supports_variable_type: false,
            supports_invalidated_event: false,
            source_roots: vec![],
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new()
    }
}
