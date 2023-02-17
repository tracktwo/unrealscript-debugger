use std::{
    io::Stdout,
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use adapter::{client::UnrealscriptClient, UnrealscriptAdapter};
use common::UnrealCommand;
use dap::{
    prelude::Adapter,
    requests::{self, Command, Request},
    responses::ResponseBody,
};
use interface::debugger::Debugger;
use serde_json::{json, Map, Value};

/// Integration test setup:
/// - construct an adapter and client;
/// - open a tcp listener for a mock interface on a random port.
/// - Spawn a thread to process messages on that port and dispatch them to the provided closure
/// - Initialize communication between the two by sending an initialize and attach request.
///
/// Returns the adapter, client, and a join handle for the thread.
pub fn setup<F>(
    f: F,
) -> (
    UnrealscriptAdapter,
    UnrealscriptClient<Stdout>,
    JoinHandle<()>,
)
where
    F: FnOnce(
            &mut Debugger<TcpStream>,
            &mut dyn Iterator<Item = Result<UnrealCommand, serde_json::Error>>,
        ) -> ()
        + Send
        + 'static,
{
    let mut adapter = UnrealscriptAdapter::new();
    let mut client = UnrealscriptClient::new(std::io::stdout());
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();

    let interface_thread = thread::spawn(move || {
        let mut dbg = Debugger::new();
        let (stream, _addr) = server.accept().unwrap();
        let mut deserializer = serde_json::Deserializer::from_reader(stream.try_clone().unwrap())
            .into_iter::<UnrealCommand>();

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

    (adapter, client, interface_thread)
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
