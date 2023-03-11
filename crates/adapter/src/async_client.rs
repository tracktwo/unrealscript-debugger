//! Asynchronous client for DAP

use std::io::{Error, ErrorKind};

use bytes::BytesMut;
use dap::{
    events::EventProtocolMessage,
    prelude::Event,
    requests::Request,
    responses::{Response, ResponseProtocolMessage},
};
use futures::{executor, stream::Next, Stream, StreamExt};
use memmem::{Searcher, TwoWaySearcher};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio_util::codec::{Decoder, FramedRead};

pub trait AsyncClient {
    type St: Unpin + Stream<Item = Result<Request, Error>>;

    fn next_request<'a>(&'a mut self) -> Next<'a, Self::St>;
    fn respond(&mut self, response: Response) -> Result<(), Error>;
    fn send_event(&mut self, event: Event) -> Result<(), Error>;
}

pub struct AsyncClientImpl<R, W>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    pub input: FramedRead<R, AsyncClientDecoder>,
    output: BufWriter<W>,
    seq: i64,
}

/// A Decoder struct for DAP requests.
pub struct AsyncClientDecoder {
    state: State,
    body_start: usize,
    body_len: usize,
}

/// A representation of the current client reader state. Each request message
/// is made up of three parts: A header, a body, and a separator between them.
enum State {
    Header,
    Body,
}

impl<R, W> AsyncClientImpl<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(input: R, output: W) -> Self {
        Self {
            input: FramedRead::new(input, AsyncClientDecoder::new()),
            output: BufWriter::new(output),
            seq: 0,
        }
    }

    fn next_seq(&mut self) -> i64 {
        self.seq += 1;
        self.seq
    }

    fn send_message(&mut self, msg: &[u8]) -> Result<(), Error> {
        let len = msg.len();
        let header = format!("Content-Length: {len}\r\n\r\n");
        log::trace!(
            "Sending: {header}{}",
            std::str::from_utf8(msg).expect("Message must be valid utf8")
        );
        executor::block_on(async move {
            self.output.write_all(header.as_bytes()).await?;
            self.output.write_all(msg).await?;
            self.output.flush().await?;
            log::trace!("Finished writing response");
            Ok::<(), Error>(())
        })?;
        Ok(())
    }
}

impl<R, W> AsyncClient for AsyncClientImpl<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    type St = FramedRead<R, AsyncClientDecoder>;

    fn next_request<'a>(&'a mut self) -> Next<'a, Self::St> {
        self.input.next()
    }

    fn respond(&mut self, response: Response) -> Result<(), Error> {
        let response_message = ResponseProtocolMessage {
            seq: self.next_seq(),
            response,
        };
        let payload = serde_json::ser::to_vec(&response_message)
            .expect("Response messages are serializable to json");
        self.send_message(&payload)
    }

    fn send_event(&mut self, event: Event) -> Result<(), Error> {
        let event_message = EventProtocolMessage {
            seq: self.next_seq(),
            event,
        };
        let payload = serde_json::ser::to_vec(&event_message)
            .expect("Event messages are serializable to json");
        self.send_message(&payload)
    }
}

impl AsyncClientDecoder {
    pub fn new() -> Self {
        Self {
            state: State::Header,
            body_start: 0,
            body_len: 0,
        }
    }
    /// Parse a DAP header from the given buffer and record the expected offset of the body
    /// and its length, then move to the 'body' state.
    ///
    /// 'src' is the input buffer so far
    fn process_header(&mut self, src: &[u8]) -> Result<(), Error> {
        // The buffer should be a well-formed utf-8 string.
        let str =
            std::str::from_utf8(&src).or_else(|e| Err(Error::new(ErrorKind::InvalidData, e)))?;

        assert!(str.ends_with("\r\n\r\n"));
        let spl: Vec<&str> = str.trim_end().split(':').collect();
        if spl.len() == 2 {
        } else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Unexpected header format",
            ));
        }
        let len: usize = match spl[0] {
            "Content-Length" => match spl[1].trim().parse() {
                Ok(val) => Ok(val),
                Err(e) => Err(Error::new(ErrorKind::InvalidData, e)),
            },
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Expected 'Content-Length' header",
            )),
        }?;

        self.state = State::Body;
        self.body_start = src.len();
        self.body_len = len;
        Ok(())
    }

    /// Process a message.
    fn process_message(&mut self, src: &[u8]) -> Result<Request, Error> {
        // We should have a full message to parse. Note that 'src' still contains
        // the header bytes as we don't consume them until the entire frame is complete.
        assert!(src.len() >= self.body_start + self.body_len);
        let req = serde_json::from_slice(&src[self.body_start..self.body_start + self.body_len])
            .or_else(|e| Err(Error::new(ErrorKind::InvalidData, e)));
        self.state = State::Header;
        self.body_start = 0;
        self.body_len = 0;
        return req;
    }
}

impl Decoder for AsyncClientDecoder {
    type Item = Request;
    type Error = std::io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match &self.state {
                State::Header => {
                    let search = TwoWaySearcher::new(b"\r\n\r\n");
                    match search.search_in(src) {
                        Some(pos) => {
                            self.process_header(&src.as_ref()[..pos + 4])?;
                            src.reserve(self.body_len);
                            // Do not return here since we might have enough bytes in
                            // 'src' to complete the message. We're now in the Body
                            // state so we'll loop and try to process the body if we
                            // can.
                        }
                        None => return Ok(None),
                    };
                }
                State::Body => {
                    if src.len() >= self.body_start + self.body_len {
                        // Remove the packet bytes from the stream: we will never return
                        // these again.
                        let packet = src.split_to(self.body_len + self.body_start);
                        // Process the packet and return the message if successful.
                        let msg = self.process_message(&packet)?;
                        return Ok(Some(msg));
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use dap::requests::Command;

    use super::*;

    #[tokio::test]
    async fn read_partial() {
        let input = Cursor::new("Content-Length: ");
        let output: Vec<u8> = vec![];
        let mut client = AsyncClientImpl::new(input, output);
        // The stream should end before we successfully read the full packet. This is an error.
        match client.next_request().await {
            Some(Err(_)) => (),
            _ => panic!("Unexpected result"),
        }
    }

    #[tokio::test]
    async fn a_packet() {
        let payload = r#"{"seq": 1, "command": "initialize", "arguments": { "clientId": "test client", "adapterID": "unrealscript"}}"#;
        let str = format!("Content-Length: {}\r\n\r\n{payload}", payload.len());
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let mut client = AsyncClientImpl::new(input, output);
        match client.next_request().await {
            Some(Ok(req)) => assert!(matches!(req.command, Command::Initialize(_))),
            other => panic!("Expected valid request but got {other:?}"),
        }

        // We should now be at the end of the stream.
        match client.next_request().await {
            None => (),
            other => panic!("Expected end of stream but got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_packet_with_extra() {
        let payload = r#"{"seq": 1, "command": "initialize", "arguments": { "clientId": "test client", "adapterID": "unrealscript"}}"#;
        // Stick the start of the next packet immediately after the body one.
        let str = format!(
            "Content-Length: {}\r\n\r\n{payload}Content-Length: 300",
            payload.len()
        );
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let mut client = AsyncClientImpl::new(input, output);
        match client.next_request().await {
            Some(Ok(req)) => assert!(matches!(req.command, Command::Initialize(_))),
            other => panic!("Expected valid request but got {other:?}"),
        }
    }
}
