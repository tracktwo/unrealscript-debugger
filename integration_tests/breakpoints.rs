//! Integration tests for communications between the adapter and interface: breakpoints.

use common::UnrealCommand;
use dap::{
    requests::{Command, Request, SetBreakpointsArguments},
    responses::ResponseBody,
    types::{Source, SourceBreakpoint},
};
use tokio::task::block_in_place;
use tokio_stream::StreamExt;

use std::ffi::c_char;

mod fixture;

pub const PACKAGE_CLASSNAME: &str = if cfg!(windows) {
    "C:\\foo\\Src\\Package\\Classes\\Classname.uc\0"
} else {
    "/home/username/src/Package/Classes/Classname.uc\0"
};

/// Set a breakpoint and then mock hitting it, ensuring we get a break event at the expected position.
#[tokio::test(flavor = "multi_thread")]
async fn hit_breakpoint() {
    let (mut adapter, mut dbg, mut conn) = fixture::setup().await;
    tokio::task::spawn(async move {
        // Next command should be add breakpoint
        let command = conn.next().await.unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::AddBreakpoint(_)));
        dbg.handle_command(command).unwrap();

        // Generate an add breakpoint event from unreal
        dbg.add_breakpoint(PACKAGE_CLASSNAME.as_ptr() as *mut c_char, 10);
    });

    // Set a breakpoint
    let response = adapter
        .accept(&Request {
            seq: 3,
            command: Command::SetBreakpoints(SetBreakpointsArguments {
                source: Source {
                    name: None,
                    path: Some(PACKAGE_CLASSNAME.to_string()),
                },
                breakpoints: Some(vec![SourceBreakpoint { line: 10 }]),
            }),
        })
        .unwrap();

    match response {
        Some(ResponseBody::SetBreakpoints(_)) => (),
        o => panic!("Expected a setbreakpoints response: {o:#?}"),
    }
}

/// Test removing a breakpoint
#[tokio::test(flavor = "multi_thread")]
async fn remove_breakpoint() {
    let (mut adapter, mut dbg, mut conn) = fixture::setup().await;
    tokio::task::spawn(async move {
        log::trace!("Entering fixture async block");
        // Next command should be add breakpoint
        log::trace!("Waiting for breakpoint");
        let command = conn.next().await.unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::AddBreakpoint(_)));
        block_in_place(|| {
            dbg.handle_command(command).unwrap();
            // Generate an add breakpoint event from unreal
            log::trace!("Sending breakpoint to adapter.");
            dbg.add_breakpoint(PACKAGE_CLASSNAME.as_ptr() as *mut c_char, 10);
        });

        // Next command should be a remove breakpoint
        let command = conn.next().await.unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::RemoveBreakpoint(_)));

        block_in_place(|| {
            dbg.handle_command(command).unwrap();
            // Generate a remove breakpoint event from unreal
            dbg.remove_breakpoint(PACKAGE_CLASSNAME.as_ptr() as *mut c_char, 10);
        });
    });

    // Set a breakpoint
    let response = adapter
        .accept(&Request {
            seq: 3,
            command: Command::SetBreakpoints(SetBreakpointsArguments {
                source: Source {
                    name: None,
                    path: Some(PACKAGE_CLASSNAME.to_string()),
                },
                breakpoints: Some(vec![SourceBreakpoint { line: 10 }]),
            }),
        })
        .unwrap();

    match response {
        Some(ResponseBody::SetBreakpoints(_)) => (),
        _o => panic!("Expected a setbreakpoints response: {_o:#?}"),
    }

    // Set no breakpoints. This should generate a remove command to remove the first breakpoint.
    let response = adapter
        .accept(&Request {
            seq: 3,
            command: Command::SetBreakpoints(SetBreakpointsArguments {
                source: Source {
                    name: None,
                    path: Some(PACKAGE_CLASSNAME.to_string()),
                },
                breakpoints: None,
            }),
        })
        .unwrap();

    match response {
        Some(ResponseBody::SetBreakpoints(_)) => (),
        _o => panic!("Expected a setbreakpoints response: {_o:#?}"),
    }
}
