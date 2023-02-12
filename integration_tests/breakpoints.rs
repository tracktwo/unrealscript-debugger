//! Integration tests for communications between the adapter and interface.

use adapter::{client::UnrealscriptClient, UnrealscriptAdapter};
use common::UnrealCommand;
use dap::{
    prelude::*,
    requests::{Command, Request},
    types::{Source, SourceBreakpoint},
};
use interface::debugger::Debugger;
use serde_json::{json, Map, Value};
use std::thread;
use std::{ffi::c_char, net::TcpListener};

const PACKAGE_CLASSNAME: &str = if cfg!(windows) {
    "C:\\foo\\Src\\Package\\Classes\\Classname.uc"
} else {
    "/home/username/src/Package/Classes/Classname.uc"
};

extern "C" fn callback(_s: *const u8) -> () {}

/// Set a breakpoint and then mock hitting it, ensuring we get a break event at the
/// expected position.
#[test]
#[allow(deprecated)]
fn hit_breakpoint() {
    let mut adapter = UnrealscriptAdapter::new();
    let mut client = UnrealscriptClient::new(std::io::stdout());
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();

    let interface_thread = thread::spawn(move || {
        let mut dbg = Debugger::new(callback);
        let (stream, _addr) = server.accept().unwrap();
        let mut deserializer = serde_json::Deserializer::from_reader(stream.try_clone().unwrap())
            .into_iter::<UnrealCommand>();

        // First command should be an initialize
        let command = deserializer.next().unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::Initialize(_)));
        dbg.handle_command(command).unwrap();

        // Next command should be add breakpoint
        let command = deserializer.next().unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::AddBreakpoint(_)));
        dbg.handle_command(command).unwrap();

        // Generate an add breakpoint event from unreal
        dbg.add_breakpoint(PACKAGE_CLASSNAME.as_ptr() as *mut c_char, 10);
    });

    // Send an 'initialize' request
    let response = adapter
        .accept(
            Request {
                seq: 1,
                command: Command::Initialize(requests::InitializeArguments {
                    client_id: Some("test".to_string()),
                    lines_start_at1: Some(true),
                    ..Default::default()
                }),
            },
            &mut client,
        )
        .unwrap();

    match response.body.unwrap() {
        ResponseBody::Initialize(_) => (),
        _o => assert!(false, "Expected an initialize response: {_o:#?}"),
    }

    // Send an 'attach' request
    let mut attach_map = Map::new();
    attach_map.insert("port".to_string(), json!(port));
    let response = adapter
        .accept(
            Request {
                seq: 2,
                command: Command::Attach(requests::AttachRequestArguments {
                    other: Some(Value::Object(attach_map)),
                    ..Default::default()
                }),
            },
            &mut client,
        )
        .unwrap();

    match response.body.unwrap() {
        ResponseBody::Attach => (),
        _o => assert!(false, "Expected an attach response: {_o:#?}"),
    }

    // Set a breakpoint
    let response = adapter
        .accept(
            Request {
                seq: 3,
                command: Command::SetBreakpoints(requests::SetBreakpointsArguments {
                    source: Source {
                        path: Some(PACKAGE_CLASSNAME.to_string()),
                        ..Default::default()
                    },
                    breakpoints: Some(vec![SourceBreakpoint {
                        line: 10,
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            &mut client,
        )
        .unwrap();

    match response.body.unwrap() {
        ResponseBody::SetBreakpoints(_) => (),
        _o => assert!(false, "Expected a setbreakpoints response: {_o:#?}"),
    }

    interface_thread.join().unwrap();
}
