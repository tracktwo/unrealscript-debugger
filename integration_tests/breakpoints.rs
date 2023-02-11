//! Integration tests for communications between the adapter and interface.

use adapter::{UnrealscriptAdapter, client::UnrealscriptClient};
use dap::{prelude::*, requests::{Request,Command}, types::{SourceBreakpoint, Source}};

/// Set a breakpoint and then mock hitting it, ensuring we get a breakpoint response.
#[test]
#[allow(deprecated)]
fn hit_breakpoint() {
    let mut adapter = UnrealscriptAdapter::new();
    let mut client = UnrealscriptClient::new(std::io::stdout());

    let response = adapter.accept(
        Request{ 
        seq: 1,
        command: Command::Initialize(
            requests::InitializeArguments {
                client_id: Some("test".to_string()),
                lines_start_at1: Some(true),
                ..Default::default()})
        },&mut client).unwrap();

    match response.body.unwrap() {
        ResponseBody::Initialize(_) => (),
        _o => assert!(false, "Expected an initialize response: {_o:#?}"),
    }

    // Set a breakpoint
    let response = adapter.accept(
    Request {
    seq: 2,
    command: Command::SetBreakpoints(
        requests::SetBreakpointsArguments {
            source: Source{ path: Some("C:\\foo\\Src\\Package\\Classes\\Classname.uc".to_string()), ..Default::default() },
            breakpoints: Some(vec![SourceBreakpoint{ line: 10, ..Default::default() }]),
            ..Default::default()
        } )}, &mut client).unwrap();

    match response.body.unwrap() {
        ResponseBody::SetBreakpoints(_) => (),
        _o => assert!(false, "Expected a setbreakpoints response: {_o:#?}"),
    }
}

