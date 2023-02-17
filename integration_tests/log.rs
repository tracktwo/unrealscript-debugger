//! Integration tests for communications between the adapter and interface: logging.
mod fixture;

/// Test sending a log line from the interface to the adapter.
#[test]
fn simple_log() {
    let (_adapter, _client, handle) = fixture::setup(|dbg, _deserializer| {
        // Send a log event
        dbg.add_line_to_log("Log line!\0".as_ptr() as *const i8);
    });

    // The adapter should receive the log event and dispatch it to the event sender.

    fixture::wait_for_thread(handle);
}
