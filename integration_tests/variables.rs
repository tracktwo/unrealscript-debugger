mod fixture;
use adapter::variable_reference::VariableReference;
use common::{FrameIndex, UnrealCommand, VariableIndex, WatchKind};
use dap::prelude::*;
use tokio_stream::StreamExt;

#[tokio::test(flavor = "multi_thread")]
async fn frame_0() {
    let (mut adapter, mut dbg, mut conn) = fixture::setup().await;
    tokio::task::spawn(async move {
        dbg.add_frame("MyPackage.MyClass\0".as_ptr() as *const i8);
        dbg.add_watch(
            WatchKind::Local,
            -1,
            "SomeVar ( Int,02392392,032932 )\0".as_ptr() as *const i8,
            "33\0".as_ptr() as *const i8,
        );
        // Next command should be a variables request.
        let command = conn.next().await.unwrap().unwrap();

        assert!(matches!(command, UnrealCommand::Variables(_, _, _, _, _)));
        dbg.handle_command(command).unwrap();
    });

    // Ask for variable 0 in frame 0.
    let response = adapter
        .accept(&Request {
            seq: 3,
            command: Command::Variables(requests::VariablesArguments {
                variables_reference: VariableReference::new(
                    WatchKind::Local,
                    FrameIndex::TOP_FRAME,
                    VariableIndex::SCOPE,
                )
                .to_int(),
                filter: None,
                start: Some(0),
                count: Some(0),
                format: None,
            }),
        })
        .unwrap();

    match response {
        ResponseBody::Variables(resp) => {
            assert_eq!(resp.variables.len(), 1);
            let v = &resp.variables[0];
            assert_eq!(v.name, "SomeVar");
            assert_eq!(v.type_field.as_ref().unwrap(), "Int");
            assert_eq!(v.value, "33");
        }
        o => panic!("Expected a variables response: {o:#?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
/// Test a variables request for a variable in a frame other than the top-most.
async fn frame_2() {
    let (mut adapter, mut dbg, mut conn) = fixture::setup().await;
    tokio::task::spawn(async move {
        dbg.add_frame("Function MyClass.TopFunction\0".as_ptr() as *const i8);
        dbg.add_frame("Function MyClass.CallingFunction\0".as_ptr() as *const i8);
        dbg.add_frame("Function AnotherClass.AnotherCaller\0".as_ptr() as *const i8);
        // Next command should be a variables request.
        let command = conn.next().await.unwrap().unwrap();

        assert!(matches!(command, UnrealCommand::Variables(_, _, _, _, _)));
        dbg.handle_command(command).unwrap();

        // This should have resulted in a frame switch request. Add the watch
        // and then send an unlock to unblock the caller.
        dbg.add_watch(
            WatchKind::Local,
            -1,
            "SomeVar ( Int,02392392,032932 )\0".as_ptr() as *const i8,
            "33\0".as_ptr() as *const i8,
        );
        dbg.unlock_watchlist(WatchKind::User);
    });

    // Ask for variable 0 in frame 2.
    let response = adapter
        .accept(&Request {
            seq: 3,
            command: Command::Variables(requests::VariablesArguments {
                variables_reference: VariableReference::new(
                    WatchKind::Local,
                    FrameIndex::create(2).unwrap(),
                    VariableIndex::SCOPE,
                )
                .to_int(),
                filter: None,
                start: Some(0),
                count: Some(0),
                format: None,
            }),
        })
        .unwrap();

    match response {
        ResponseBody::Variables(resp) => {
            assert_eq!(resp.variables.len(), 1);
            let v = &resp.variables[0];
            assert_eq!(v.name, "SomeVar");
            assert_eq!(v.type_field.as_ref().unwrap(), "Int");
            assert_eq!(v.value, "33");
        }
        o => panic!("Expected a variables response: {o:#?}"),
    }
}
