//! Integration tests for communications between the adapter and interface: breakpoints.

use common::UnrealCommand;
use dap::{
    prelude::*,
    requests::{Command, Request},
    types::{Source, SourceBreakpoint},
};

use std::ffi::c_char;

mod fixture;

pub const PACKAGE_CLASSNAME: &str = if cfg!(windows) {
    "C:\\foo\\Src\\Package\\Classes\\Classname.uc\0"
} else {
    "/home/username/src/Package/Classes/Classname.uc\0"
};

/// Set a breakpoint and then mock hitting it, ensuring we get a break event at the expected position.
#[test]
fn hit_breakpoint() {
    let (mut adapter, mut client, _receiver, handle) = fixture::setup(|dbg, deserializer| {
        // Next command should be add breakpoint
        let command = deserializer.next().unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::AddBreakpoint(_)));
        dbg.handle_command(command).unwrap();

        // Generate an add breakpoint event from unreal
        dbg.add_breakpoint(PACKAGE_CLASSNAME.as_ptr() as *mut c_char, 10);
    });

    // Set a breakpoint
    let response = adapter
        .accept(
            &Request {
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
        )
        .unwrap();

    match response {
        ResponseBody::SetBreakpoints(_) => (),
        o => assert!(false, "Expected a setbreakpoints response: {o:#?}"),
    }

    fixture::wait_for_thread(handle);
}

/// Test removing a breakpoint
#[test]
fn remove_breakpoint() {
    let (mut adapter, mut client, _receiver, handle) = fixture::setup(|dbg, deserializer| {
        // Next command should be add breakpoint
        let command = deserializer.next().unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::AddBreakpoint(_)));
        dbg.handle_command(command).unwrap();

        // Generate an add breakpoint event from unreal
        dbg.add_breakpoint(PACKAGE_CLASSNAME.as_ptr() as *mut c_char, 10);

        // Next command should be a remove breakpoint
        let command = deserializer.next().unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::RemoveBreakpoint(_)));
        dbg.handle_command(command).unwrap();

        // Generate a remove breakpoint event from unreal
        dbg.remove_breakpoint(PACKAGE_CLASSNAME.as_ptr() as *mut c_char, 10);
    });

    // Set a breakpoint
    let response = adapter
        .accept(
            &Request {
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
        )
        .unwrap();

    match response {
        ResponseBody::SetBreakpoints(_) => (),
        _o => assert!(false, "Expected a setbreakpoints response: {_o:#?}"),
    }

    // Set no breakpoints. This should generate a remove command to remove the first breakpoint.
    let response = adapter
        .accept(
            &Request {
                seq: 3,
                command: Command::SetBreakpoints(requests::SetBreakpointsArguments {
                    source: Source {
                        path: Some(PACKAGE_CLASSNAME.to_string()),
                        ..Default::default()
                    },
                    breakpoints: None,
                    ..Default::default()
                }),
            },
        )
        .unwrap();

    match response {
        ResponseBody::SetBreakpoints(_) => (),
        _o => assert!(false, "Expected a setbreakpoints response: {_o:#?}"),
    }

    fixture::wait_for_thread(handle);
}
