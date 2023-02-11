//! Integration tests for communications between the adapter and interface.

use ucdebugger::Thingy;
use ucdebugger::adapter::UnrealscriptAdapter;

/// Set a breakpoint and then mock hitting it, ensuring we get a breakpoint response.
#[test]
fn hit_breakpoint() {
    let mut adapter = UnrealscriptAdapter::new();
}

