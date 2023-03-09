//! Asynchronous client for DAP

use dap::{
    events::EventProtocolMessage,
    prelude::Event,
    requests::Request,
    responses::{Response, ResponseProtocolMessage},
};
use futures::executor;
use tokio::io::{AsyncWriteExt, BufWriter};

pub struct AsyncClient {
    input: tokio::io::Stdin,
    output: BufWriter<tokio::io::Stdout>,
    seq: i64,
}

impl AsyncClient {
    pub fn new(input: tokio::io::Stdin, output: tokio::io::Stdout) -> Self {
        Self {
            input,
            output: BufWriter::new(output),
            seq: 0,
        }
    }

    pub async fn next(&mut self) -> Request {
        todo!();
    }

    pub fn respond(&mut self, response: Response) -> Result<(), std::io::Error> {
        let response_message = ResponseProtocolMessage {
            seq: self.next_seq(),
            response,
        };
        let mut payload = serde_json::ser::to_vec(&response_message)
            .expect("Response messages are serializable to json");
        executor::block_on(async move {
            self.output.write_all(&mut payload).await?;
            Ok::<(), std::io::Error>(())
        })?;
        Ok(())
    }

    pub fn send_event(&mut self, event: Event) -> Result<(), std::io::Error> {
        let event_message = EventProtocolMessage {
            seq: self.next_seq(),
            event,
        };
        let mut payload = serde_json::ser::to_vec(&event_message)
            .expect("Event messages are serializable to json");
        executor::block_on(async move {
            self.output.write_all(&mut payload).await?;
            Ok::<(), std::io::Error>(())
        })?;
        Ok(())
    }

    fn next_seq(&mut self) -> i64 {
        self.seq += 1;
        self.seq
    }
}
