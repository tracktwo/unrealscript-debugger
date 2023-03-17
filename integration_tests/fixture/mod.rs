use adapter::{
    async_client::{AsyncClient, AsyncClientImpl},
    client_config::ClientConfig,
    comm::tcp::TcpConnection,
    connected_adapter::UnrealscriptAdapter,
};
use common::{UnrealCommand, UnrealInterfaceMessage};
use dap::{prelude::Event, requests::Request};
use futures::{executor, stream::SplitStream, SinkExt, StreamExt};
use interface::debugger::Debugger;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        broadcast,
        mpsc::{channel, Receiver, Sender},
    },
};
use tokio_serde::formats::Json;
use tokio_stream::wrappers::ReceiverStream;
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
/// - open a tcp listener for a mock interface on a random port.
/// - Spawn a thread to process messages on that port and dispatch them to the provided closure
/// - Initialize communication between the two by sending an initialize and attach request.
///
/// Returns the adapter, client, the receiving end of the event channel, and a join handle for the thread.
///
/// Test cases can now send requests and receive responses through the adapter. Events sent from
/// the closure will appear in the event receiver.

pub async fn setup_with_client<C: AsyncClient + Unpin>(
    client: C,
) -> (UnrealscriptAdapter<C>, Debugger, SplitStream<TcpFrame>) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();

    let adapter = UnrealscriptAdapter::new(
        client,
        ClientConfig {
            one_based_lines: true,
            supports_variable_type: true,
            supports_invalidated_event: false,
            source_roots: vec![],
            enable_stack_hack: false,
        },
        Box::new(TcpConnection::connect(port).await.unwrap()),
        None,
    );

    log::trace!("Created adapter");
    let (ctx, _crx) = broadcast::channel(1);
    let mut dbg = Debugger::new(ctx, None);
    let (stream, _addr) = tcp.accept().await.unwrap();
    log::trace!("Got connection");

    let frame = tokio_util::codec::Framed::new(stream, LengthDelimitedCodec::new());

    // Build a json formatter that can deserialize events and serialize commands.
    let format: Json<UnrealCommand, UnrealInterfaceMessage> = Json::default();

    // Build a source + sink for that Json format on top of our framing system.
    let tcp_stream = tokio_serde::Framed::new(frame, format);
    let (mut tcp_tx, tcp_rx) = tcp_stream.split();

    let (tx, mut rx) = tokio::sync::mpsc::channel(128);
    dbg.new_connection(tx);

    // Spawn a task to monitor the receiving side of events and push them through the tcp
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
    UnrealscriptAdapter<AsyncClientImpl<tokio::io::Stdin, tokio::io::Stdout>>,
    Debugger,
    SplitStream<TcpFrame>,
) {
    setup_with_client(AsyncClientImpl::new(
        tokio::io::stdin(),
        tokio::io::stdout(),
    ))
    .await
}

pub struct TestClient {
    etx: Sender<Event>,
    rstream: ReceiverStream<Result<Request, std::io::Error>>,
}

impl TestClient {
    pub fn new(etx: Sender<Event>, rrx: Receiver<Result<Request, std::io::Error>>) -> Self {
        TestClient {
            etx,
            rstream: ReceiverStream::new(rrx),
        }
    }
}

impl AsyncClient for TestClient {
    type St = ReceiverStream<Result<Request, std::io::Error>>;

    fn next_request(&mut self) -> futures::stream::Next<'_, Self::St> {
        self.rstream.next()
    }

    fn respond(&mut self, _: dap::responses::Response) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn send_event(&mut self, event: dap::prelude::Event) -> Result<(), std::io::Error> {
        executor::block_on(async { self.etx.send(event).await.unwrap() });
        Ok(())
    }
}

/// Create a test client and return it, a channel to receive events from it, and a channel to send
/// requests to it.
#[allow(dead_code)]
pub fn make_test_client() -> (
    TestClient,
    Receiver<Event>,
    Sender<Result<Request, std::io::Error>>,
) {
    let (etx, erx) = channel(1);
    let (rtx, rrx) = channel(1);
    let client = TestClient::new(etx, rrx);
    (client, erx, rtx)
}
