use std::{
    thread::JoinHandle,
    time::Duration,
};

use adapter::{UnrealscriptAdapter, async_client::AsyncClient, ClientConfig, comm::UnrealChannel};
use common::UnrealCommand;
use dap::{
    requests::{self, Command, Request},
    responses::ResponseBody,
};
use interface::debugger::Debugger;
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;

/// Integration test setup:
/// - construct an adapter and client
/// - Create a channel to receive events and hook this up to the client
/// - open a tcp listener for a mock interface on a random port.
/// - Spawn a thread to process messages on that port and dispatch them to the provided closure
/// - Initialize communication between the two by sending an initialize and attach request.
///
/// Returns the adapter, client, the receiving end of the event channel, and a join handle for the thread.
///
/// Test cases can now send requests and receive responses through the adapter. Events sent from
/// the closure will appear in the event receiver.
pub async fn setup<F>(
    f: F,
) -> 
    UnrealscriptAdapter
where
    F: FnOnce(
            &mut Debugger,
            &mut dyn Iterator<Item = Result<UnrealCommand, serde_json::Error>>,
        ) -> ()
        + Send
        + 'static,
{
    let mut adapter = UnrealscriptAdapter::new(
        AsyncClient::new(tokio::io::stdin(), tokio::io::stdout()),
        ClientConfig::default(),
        UnrealChannel::new()
    );

    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();

    let interface_task = tokio::spawn(async move {
        let mut dbg = Debugger::new();
        let (stream, _addr) = tcp.accept().await.unwrap();
        let mut deserializer = serde_json::Deserializer::from_reader(stream.try_clone().unwrap())
            .into_iter::<UnrealCommand>();

        let (tx, rx) = tokio::sync::mpsc::channel(128);
        dbg.new_connection(tx);

        // First command should be an initialize
        let command = deserializer.next().unwrap().unwrap();
        assert!(matches!(command, UnrealCommand::Initialize(_)));
        dbg.handle_command(command).unwrap();

        f(&mut dbg, &mut deserializer);
    });

    // Send an 'initialize' request
    let response = adapter
        .accept(
            Request {
                seq: 1,
                command: Command::Initialize(requests::InitializeArguments {
                    client_id: Some("test".to_string()),
                    lines_start_at1: Some(true),
                    supports_variable_type: Some(true),
                    ..Default::default()
                }),
            },
            &mut context,
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
            &mut context,
        )
        .unwrap();

    match response.body.unwrap() {
        ResponseBody::Attach => (),
        _o => assert!(false, "Expected an attach response: {_o:#?}"),
    }

    (adapter, context, receiver, interface_thread)
}

/// Helper to wait for the spawned interface thread to end without blocking tests forever if
/// the thread does not complete. Will wait for up to 5 seconds for the thread to become joinable
/// and then panic if not.
pub fn wait_for_thread(handle: JoinHandle<()>) {
    for _ in 0..5 {
        if handle.is_finished() {
            handle.join().unwrap();
            return;
        } else {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    panic!("Thread did not complete after 5 seconds");
}
