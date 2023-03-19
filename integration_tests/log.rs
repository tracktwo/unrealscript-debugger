//! Integration tests for communications between the adapter and interface: logging.

use common::{InitializeResponse, UnrealCommand, UnrealResponse, Version};
use dap::{events::EventBody, events::OutputEventCategory};
use futures::StreamExt;
mod fixture;

/// Test sending a log line from the interface to the adapter.
#[tokio::test(flavor = "multi_thread")]
async fn simple_log() {
    let (client, mut erx, _rtx) = fixture::make_test_client();
    let (mut adapter, mut dbg, mut comm) = fixture::setup_with_client(client).await;

    tokio::task::spawn(async move {
        // Fetch the initialized command and return a response.
        let command = comm.next().await.unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::Initialize(_)));
        dbg.send_response(UnrealResponse::Initialize(InitializeResponse {
            version: Version {
                major: 0,
                minor: 0,
                patch: 0,
            },
        }))
        .unwrap();
        // Send a log event
        dbg.add_line_to_log("Log line!\0".as_ptr() as *const i8);
        // Close the tcp connection. Required so the adapter loop can detect this and stop.
        drop(comm);
    });

    tokio::task::spawn(async move {
        // We should get an initialized event first from construction of the adapter.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Initialized));

        // The adapter should receive the log event and dispatch it to the event sender.
        let evt = erx.recv().await.unwrap();
        match &evt.body {
            EventBody::Output(obody) => {
                assert!(matches!(obody.category, OutputEventCategory::Stdout));
                assert_eq!(obody.output, "Log line!\r\n");
            }
            b => panic!("Expected an output event but got {b:?}"),
        }

        // Finally we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated));
    });

    adapter
        .process_messages(Version {
            major: 0,
            minor: 0,
            patch: 0,
        })
        .await
        .unwrap();
}
