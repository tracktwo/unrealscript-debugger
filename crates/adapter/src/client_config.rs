/// A representation of the client configuration options. These will impact how
/// we send responses.
#[derive(Debug, Default)]
pub struct ClientConfig {
    // If true (the default and Unreal's native mode) the client expects lines to start at 1.
    // Otherwise they start at 0.
    pub one_based_lines: bool,
    // If true then we will send type information with variables.
    pub supports_variable_type: bool,
    // If true then we'll send invalidated events when fetching variables that involves a stack
    // change.
    pub supports_invalidated_event: bool,
    pub source_roots: Vec<String>,
}

impl ClientConfig {
    pub fn new() -> Self {
        ClientConfig {
            one_based_lines: true,
            supports_variable_type: false,
            supports_invalidated_event: false,
            source_roots: vec![],
        }
    }
}
