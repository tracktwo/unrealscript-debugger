use adapter::{
    client::{Client, ClientImpl},
    client_config::ClientConfig,
    comm::tcp::TcpConnection,
    connected_adapter::UnrealscriptAdapter,
    AdapterMessage,
};
use common::{UnrealCommand, UnrealInterfaceMessage};
use dap::events::Event;
use futures::{stream::SplitStream, SinkExt, StreamExt};
use interface::debugger::Debugger;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::unbounded_channel,
};
use tokio_serde::formats::Json;
use tokio_util::codec::LengthDelimitedCodec;

pub type TcpFrame = tokio_serde::Framed<
    tokio_util::codec::Framed<TcpStream, LengthDelimitedCodec>,
    UnrealCommand,
    UnrealInterfaceMessage,
    Json<UnrealCommand, UnrealInterfaceMessage>,
>;

/// Integration test setup:
/// - construct an adapter and client
/// - Create a channel to receive events and hook this up to the client
/// - open a TCP listener for a mock interface on a random port.
/// - Spawns a task that will monitor the debugger object's event channel and
///   push them through the TCP connection.
///
/// Returns the adapter, debugger, and the receiving end of the debugger's TCP channel.
///
/// Test cases can then spawn an async task to process the debugger: this task is
/// responsible for reading commands from the returned TCP stream and feeding them
/// to the debugger instance in the order it wants them to appear, and can also initiate
/// events by interacting with the debugger object.
///
/// Test cases can also interact with the adapter to send requests and inspect responses
/// with the accept function, or can spawn a dedicated thread to interact with the client
/// by writing to the client's input stream and have the test case run the normal adapter
/// event loop.

pub async fn setup_with_client<C: Client>(
    client: C,
    sender: std::sync::mpsc::Sender<AdapterMessage>,
    receiver: std::sync::mpsc::Receiver<AdapterMessage>,
) -> (UnrealscriptAdapter<C>, Debugger, SplitStream<TcpFrame>) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();

    let adapter = UnrealscriptAdapter::new(
        client,
        receiver,
        ClientConfig {
            one_based_lines: true,
            supports_variable_type: true,
            supports_invalidated_event: false,
            source_roots: vec![],
            enable_stack_hack: false,
            auto_resume: false,
        },
        Box::new(TcpConnection::connect(port, sender).unwrap()),
        None,
        None,
    );

    log::trace!("Created adapter");
    let (ctx, _crx) = unbounded_channel();
    let mut dbg = Debugger::new(ctx, None);
    let (stream, _addr) = tcp.accept().await.unwrap();
    log::trace!("Got connection");

    let frame = tokio_util::codec::Framed::new(stream, LengthDelimitedCodec::new());

    // Build a json formatter that can deserialize events and serialize commands.
    let format: Json<UnrealCommand, UnrealInterfaceMessage> = Json::default();

    // Build a source + sink for that json format on top of our framing system.
    let tcp_stream = tokio_serde::Framed::new(frame, format);
    let (mut tcp_tx, tcp_rx) = tcp_stream.split();

    let (tx, mut rx) = unbounded_channel();
    dbg.new_connection(tx);

    // Spawn a task to monitor the receiving side of events and push them through the TCP
    // connection.
    tokio::task::spawn(async move {
        while let Some(msg) = rx.recv().await {
            tcp_tx.send(msg).await.unwrap();
        }
    });

    (adapter, dbg, tcp_rx)
}

#[allow(dead_code)]
pub async fn setup() -> (
    UnrealscriptAdapter<ClientImpl<std::io::Stdout>>,
    Debugger,
    SplitStream<TcpFrame>,
) {
    let (tx, rx) = std::sync::mpsc::channel();
    setup_with_client(
        ClientImpl::new(std::io::stdin(), std::io::stdout(), tx.clone()),
        tx,
        rx,
    )
    .await
}

pub struct TestClient {
    etx: std::sync::mpsc::Sender<Event>,
}

impl TestClient {
    pub fn new(etx: std::sync::mpsc::Sender<Event>) -> Self {
        TestClient { etx }
    }
}

impl Client for TestClient {
    fn respond(&mut self, _: dap::responses::Response) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn send_event(&mut self, event: Event) -> Result<(), std::io::Error> {
        self.etx.send(event).unwrap();
        Ok(())
    }
}

/// Create a test client and return it and a channel to receive events from it.
#[allow(dead_code)]
pub fn make_test_client() -> (TestClient, std::sync::mpsc::Receiver<Event>) {
    let (etx, erx) = std::sync::mpsc::channel();
    let client = TestClient::new(etx);
    (client, erx)
}
