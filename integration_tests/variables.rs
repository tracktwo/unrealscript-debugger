mod fixture;
use adapter::variable_reference::VariableReference;
use common::{FrameIndex, UnrealCommand, VariableIndex, WatchKind};
use dap::prelude::*;

#[test]
fn frame_0_is_default() {
    let (mut adapter, mut client, _receiver, handle) = fixture::setup(|dbg, deserializer| {
        dbg.add_frame("MyPackage.MyClass\0".as_ptr() as *const i8);
        dbg.add_watch(
            WatchKind::Local,
            -1,
            "SomeVar ( Int,02392392,032932 )\0".as_ptr() as *const i8,
            "33\0".as_ptr() as *const i8,
        );
        // Next command should be a variables request.
        let command = deserializer.next().unwrap().unwrap();

        assert!(matches!(command, UnrealCommand::Variables(_, _, _, _, _)));
        dbg.handle_command(command).unwrap();
    });

    // Ask for variable 0 in frame 0.
    let response = adapter
        .accept(
            Request {
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
            },
            &mut client,
        )
        .unwrap();

    match response.body.unwrap() {
        ResponseBody::Variables(resp) => {
            assert_eq!(resp.variables.len(), 1);
            let v = &resp.variables[0];
            assert_eq!(v.name, "SomeVar");
            assert_eq!(v.type_field.as_ref().unwrap(), "Int");
            assert_eq!(v.value, "33");
        }
        o => assert!(false, "Expected a variables response: {o:#?}"),
    }

    fixture::wait_for_thread(handle);
}
