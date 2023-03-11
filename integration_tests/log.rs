//! Integration tests for communications between the adapter and interface: logging.

use adapter::async_client::AsyncClient;
use dap::{events::EventBody, prelude::Event, requests::Request, types::OutputEventCategory};
use futures::{executor, StreamExt};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;
mod fixture;

struct LogClient {
    etx: Sender<Event>,
    rstream: ReceiverStream<Result<Request, std::io::Error>>,
}

impl LogClient {
    pub fn new(etx: Sender<Event>, rrx: Receiver<Result<Request, std::io::Error>>) -> Self {
        LogClient {
            etx,
            rstream: ReceiverStream::new(rrx),
        }
    }
}

impl AsyncClient for LogClient {
    type St = ReceiverStream<Result<Request, std::io::Error>>;

    fn next_request<'a>(&'a mut self) -> futures::stream::Next<'a, Self::St> {
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

/// Test sending a log line from the interface to the adapter.
#[tokio::test(flavor = "multi_thread")]
async fn simple_log() {
    let (etx, mut erx) = channel(1);

    let (_rtx, rrx) = channel(1);
    let (mut adapter, mut dbg, comm) = fixture::setup_with_client(LogClient::new(etx, rrx)).await;

    tokio::task::spawn(async move {
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
                assert!(matches!(
                    obody.category.as_ref().unwrap(),
                    OutputEventCategory::Stdout
                ));
                assert_eq!(obody.output, "Log line!\r\n");
            }
            b => panic!("Expected an output event but got {b:?}"),
        }

        // Finally we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated(_)));
    });

    adapter.process_messages().await.unwrap();
}
