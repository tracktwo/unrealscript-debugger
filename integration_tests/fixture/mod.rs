use adapter::{
    async_client::AsyncClient, comm::tcp::TcpConnection, ClientConfig, UnrealscriptAdapter,
};
use common::{UnrealCommand, UnrealInterfaceMessage};
use futures::{stream::SplitStream, SinkExt, StreamExt};
use interface::debugger::Debugger;
use tokio::net::{TcpListener, TcpStream};
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
/// - open a tcp listener for a mock interface on a random port.
/// - Spawn a thread to process messages on that port and dispatch them to the provided closure
/// - Initialize communication between the two by sending an initialize and attach request.
///
/// Returns the adapter, client, the receiving end of the event channel, and a join handle for the thread.
///
/// Test cases can now send requests and receive responses through the adapter. Events sent from
/// the closure will appear in the event receiver.

pub async fn setup(//f: F,
) -> (UnrealscriptAdapter, Debugger, SplitStream<TcpFrame>)
where
    // F: FnOnce(
    //         &mut Debugger,
    //         &mut TcpFrame
    //     ) -> ()
    //     + Send
    //     + 'static,
{
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();

    let adapter = UnrealscriptAdapter::new(
        AsyncClient::new(tokio::io::stdin(), tokio::io::stdout()),
        ClientConfig {
            one_based_lines: true,
            supports_variable_type: true,
            supports_invalidated_event: false,
            source_roots: vec![],
        },
        Box::new(TcpConnection::connect(port).await.unwrap()),
        None,
    );

    log::trace!("Created adapter");

    let mut dbg = Debugger::new();
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
