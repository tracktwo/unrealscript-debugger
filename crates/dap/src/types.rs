use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub supports_configuration_done_request: bool,
    pub supports_delayed_stack_trace_loading: bool,
}

#[derive(Serialize, Debug)]
#[serde(rename = "breakpoint")]
pub struct Breakpoint {
    pub verified: bool,
    pub source: Source,
    pub line: i64,
}

/// A source file.
///
/// Sent by the client in [`SetBreakpointRequest`] and sent by the
/// adapter in [`SetBreakpointResponse`].
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "source")]
pub struct Source {
    pub name: Option<String>,
    pub path: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct StackFrame {
    pub id: i64,
    pub name: String,
    pub source: Option<Source>,
    pub line: i64,
    pub column: i64,
}

#[derive(Serialize, Debug)]
pub struct Scope {
    pub name: String,
    #[serde(flatten)]
    pub variable_info: VariableReferenceInfo,
    pub expensive: bool,
}

#[derive(Serialize, Debug)]
pub struct Variable {
    pub name: String,
    pub value: String,
    #[serde(rename = "type")]
    pub ty: Option<String>,
    #[serde(flatten)]
    pub variable_info: VariableReferenceInfo,
}

#[derive(Serialize, Debug)]
pub struct Thread {
    pub id: i64,
    pub name: String,
}

#[derive(Deserialize, Debug)]
pub struct SourceBreakpoint {
    pub line: i64,
    // TODO implement log points
}

/// A type to abstract some common parts of DAP responses relating to variables.
///
/// This type does not appear in DAP directly and should always be flattened
/// in any type that uses it. The purpose of this struct is only to make it
/// easier to serialize certain data structures we sent to the client.
#[derive(Serialize, Debug)]
pub struct VariableReferenceInfo {
    #[serde(rename = "variablesReference")]
    pub variables_reference: i64,
    #[serde(rename = "namedVariables")]
    pub named_variables: Option<i64>,
    #[serde(rename = "indexedVariables")]
    pub indexed_variables: Option<i64>,
}

impl VariableReferenceInfo {
    pub fn new_childless(reference: i64) -> Self {
        Self {
            variables_reference: reference,
            named_variables: None,
            indexed_variables: None,
        }
    }
    /// Make a reference for some variable
    pub fn new(reference: i64, count: i64, is_array: bool) -> Self {
        if is_array {
            Self {
                variables_reference: reference,
                named_variables: None,
                indexed_variables: Some(count),
            }
        } else {
            Self {
                variables_reference: reference,
                named_variables: Some(count),
                indexed_variables: None,
            }
        }
    }
}
