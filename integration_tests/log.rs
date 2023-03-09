//! Integration tests for communications between the adapter and interface: logging.

use dap::{events::EventBody, types::OutputEventCategory};
mod fixture;

/// Test sending a log line from the interface to the adapter.
#[tokio::test(flavor = "multi_thread")]
async fn simple_log() {
    let (_adapter, mut dbg, mut _comm) = fixture::setup().await;

    tokio::task::spawn(async move {
        // Send a log event
        dbg.add_line_to_log("Log line!\0".as_ptr() as *const i8);
    });

    // The adapter should receive the log event and dispatch it to the event sender.
    // let evt = receiver.recv().unwrap();
    // match evt.body {
    //     EventBody::Output(obody) => {
    //         assert!(matches!(
    //             obody.category.unwrap(),
    //             OutputEventCategory::Stdout
    //         ));
    //     }
    //     b => panic!("Expected an output event but got {b:?}"),
    // }
}
