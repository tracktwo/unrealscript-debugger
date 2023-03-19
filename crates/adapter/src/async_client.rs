//! Asynchronous client for DAP
//!
//! This module defines the [`AsyncClient`] trait representing a connection to
//! a DAP client that can communicate with the adapter in a partially
//! asynchronous way.
//!
//! It also provides an implementation of this trait that can communicate via
//! a pair of objects that implement [`AsyncRead`] and [`AsyncWrite`].

use std::io::{Error, ErrorKind};

use bytes::BytesMut;
use dap::{
    events::{Event, EventMessage},
    requests::Request,
    responses::{Response, ResponseMessage},
};
use futures::{executor, stream::Next, Stream, StreamExt};
use memmem::{Searcher, TwoWaySearcher};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio_util::codec::{Decoder, FramedRead};

/// The primary trait for communicating with a DAP client.
///
/// This defines the protocol for communicating with the client to send and
/// receive DAP messages. This protocol receives asynchronously but implements
/// blocking sends. The blocking send behavior is helpful both to limit the
/// async scope of the adapter as well as to help ensure we do not have any
/// interleaved messages.
pub trait AsyncClient {
    /// The stream type for requests.
    type St: Unpin + Stream<Item = Result<Request, Error>>;

    /// Asynchronously receive the next request.
    ///
    /// Returns a future that will resolve to the next request.
    /// Effectively: `async fn next_request(&mut self) -> Option<Result<Request,Error>>`
    ///
    /// # Errors
    ///
    /// Returns a [`std::io::Error`] if an i/o error occurs while reading from the
    /// underlying transport.
    fn next_request(&mut self) -> Next<'_, Self::St>;
    /// Synchronously send a response to the client. This will block until the
    /// message is sent.
    ///
    /// # Errors
    ///
    /// Returns a [`std::io::Error`] if an i/o error occurs while writing to the
    /// underlying transport.
    fn respond(&mut self, response: Response) -> Result<(), Error>;
    /// Synchronously send an event to the client. This will block until the
    /// message is sent.
    ///
    /// # Errors
    ///
    /// Returns a [`std::io::Error`] if an i/o error occurs while writing to the
    /// underlying transport.
    fn send_event(&mut self, event: Event) -> Result<(), Error>;
}

/// An implementation of [`AsyncClient`] for arbitrary asynchronous read/write
/// streams.
///
/// Since the [`AsyncClient`] protocol is synchronous for sends the output side
/// will be wrapped to block.
pub struct AsyncClientImpl<R, W>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    input: FramedRead<R, AsyncClientDecoder>,
    output: BufWriter<W>,
    seq: i64,
}

/// A [`tokio_util::codec::Decoder`] for DAP requests.
pub struct AsyncClientDecoder {
    state: State,
    body_start: usize,
    body_len: usize,
}

// A representation of the current client reader state.
enum State {
    Header,
    Body,
}

impl<R, W> AsyncClientImpl<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Construct a new [`AsyncClient`] from the given input reader and output writer.
    pub fn new(input: R, output: W) -> Self {
        Self {
            input: FramedRead::new(input, AsyncClientDecoder::new()),
            output: BufWriter::new(output),
            seq: 0,
        }
    }

    // Return the next sequence number to use in messages to the client, updating
    // the internal state.
    fn next_seq(&mut self) -> i64 {
        self.seq += 1;
        self.seq
    }

    // Synchronously end a message to the client.
    //
    // `msg` is a json-encoded DAP message. This function will prepend the required
    // header.
    //
    // # Errors
    //
    // Returns an io::Error if the message cannot be written to the client's output
    // stream.
    //
    // # Panics
    //
    // May panic if the given message is not valid UTF-8.
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

    fn next_request(&mut self) -> Next<'_, Self::St> {
        self.input.next()
    }

    fn respond(&mut self, response: Response) -> Result<(), Error> {
        let response_message = ResponseMessage {
            seq: self.next_seq(),
            response,
        };
        let payload = serde_json::ser::to_vec(&response_message)
            .expect("Response messages are serializable to json");
        self.send_message(&payload)
    }

    fn send_event(&mut self, event: Event) -> Result<(), Error> {
        let event_message = EventMessage {
            seq: self.next_seq(),
            event,
        };
        let payload = serde_json::ser::to_vec(&event_message)
            .expect("Event messages are serializable to json");
        self.send_message(&payload)
    }
}

impl Default for AsyncClientDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncClientDecoder {
    fn new() -> Self {
        Self {
            state: State::Header,
            body_start: 0,
            body_len: 0,
        }
    }

    // Parse a DAP header from the given buffer and record the expected offset of the body
    // and its length, then move to the 'body' state.
    //
    // 'src' is the input buffer so far
    fn process_header(&self, src: &[u8]) -> Result<usize, Error> {
        // The buffer should be a well-formed utf-8 string.
        let str = std::str::from_utf8(src).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        // We should only be called if we have seen the full header.
        assert!(str.ends_with("\r\n\r\n"));

        // The header is of the form:
        //
        // Content-Length: <len>
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

        Ok(len)
    }

    // Process a message.
    fn process_message(&self, src: &[u8]) -> Result<Request, Error> {
        // We should have a full message to parse. Note that 'src' still contains
        // the header bytes as we don't consume them until the entire frame is complete.
        assert!(src.len() >= self.body_start + self.body_len);
        serde_json::from_slice(&src[self.body_start..self.body_start + self.body_len])
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))
    }
}

impl Decoder for AsyncClientDecoder {
    type Item = Request;
    type Error = std::io::Error;

    // Decode a DAP protocol message.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match &self.state {
                State::Header => {
                    // Check to see if we have seen the entire header yet. This is uniquely
                    // identified by the byte sequence "\r\n\r\n".
                    let search = TwoWaySearcher::new(b"\r\n\r\n");
                    match search.search_in(src) {
                        Some(pos) => {
                            let len = self.process_header(&src.as_ref()[..pos + 4])?;
                            self.state = State::Body;
                            self.body_start = pos + 4;
                            self.body_len = len;
                            src.reserve(len);
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
                        self.state = State::Header;
                        self.body_start = 0;
                        self.body_len = 0;
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

    use dap::{
        events::{EventBody, OutputEventBody, OutputEventCategory},
        requests::Command,
        responses::ResponseBody,
        types::{Scope, VariableReferenceInfo},
    };

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

    #[tokio::test]
    async fn bad_header_kind() {
        let str = "Misunderstood: 20\r\n\r\n";
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let mut client = AsyncClientImpl::new(input, output);
        match client.next_request().await {
            Some(Err(e)) => assert_eq!(e.kind(), ErrorKind::InvalidData),
            _ => panic!("Expected a bad header error response"),
        }
    }

    #[tokio::test]
    async fn bad_header_line() {
        let str = "Not a valid header\r\n\r\n";
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let mut client = AsyncClientImpl::new(input, output);
        match client.next_request().await {
            Some(Err(e)) => assert_eq!(e.kind(), ErrorKind::InvalidData),
            _ => panic!("Expected a bad header error response"),
        }
    }

    #[tokio::test]
    async fn bad_length() {
        let str = "Content-Length: nine thousand\r\n\r\n";
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let mut client = AsyncClientImpl::new(input, output);
        match client.next_request().await {
            Some(Err(e)) => assert_eq!(e.kind(), ErrorKind::InvalidData),
            _ => panic!("Expected a bad header error response"),
        }
    }

    #[tokio::test]
    async fn not_json() {
        let str = "Content-Length: 11\r\n\r\nHello World";
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let mut client = AsyncClientImpl::new(input, output);
        match client.next_request().await {
            Some(Err(e)) => assert_eq!(e.kind(), ErrorKind::InvalidData),
            _ => panic!("Expected a bad body error response"),
        }
    }

    #[test]
    fn sending_raw_message() {
        let str = "A message";
        let input = Cursor::new(str);
        let mut buf: Vec<u8> = vec![];
        let output = Cursor::new(&mut buf);
        let mut client = AsyncClientImpl::new(input, output);
        client.send_message(str.as_bytes()).unwrap();
        let out = std::str::from_utf8(&buf).unwrap();
        assert_eq!(format!("Content-Length: 9\r\n\r\n{str}"), out);
    }

    #[test]
    fn sending_response() {
        let str = "A message";
        let input = Cursor::new(str);
        let mut buf: Vec<u8> = vec![];
        let output = Cursor::new(&mut buf);
        let mut client = AsyncClientImpl::new(input, output);
        let response = Response {
            command: "scopes".to_string(),
            request_seq: 1,
            success: true,
            message: None,
            body: Some(ResponseBody::Scopes(dap::responses::ScopesResponseBody {
                scopes: vec![Scope {
                    name: "Globals".to_string(),
                    expensive: false,
                    variable_info: VariableReferenceInfo::new_childless(1),
                }],
            })),
        };
        client.respond(response).unwrap();
        let out = std::str::from_utf8(&buf).unwrap();
        assert_eq!(out,
        "Content-Length: 203\r\n\r\n{\"type\":\"response\",\"seq\":1,\"request_seq\":1,\"success\":true,\"command\":\"scopes\",\"body\":{\"scopes\":[{\"name\":\"Globals\",\"variablesReference\":1,\"namedVariables\":null,\"indexedVariables\":null,\"expensive\":false}]}}");
    }

    #[test]
    fn sending_event() {
        let str = "A message";
        let input = Cursor::new(str);
        let mut buf: Vec<u8> = vec![];
        let output = Cursor::new(&mut buf);
        let mut client = AsyncClientImpl::new(input, output);
        let event = Event {
            body: EventBody::Output(OutputEventBody {
                category: OutputEventCategory::Stdout,
                output: "A log line".to_string(),
            }),
        };
        client.send_event(event).unwrap();
        let out = std::str::from_utf8(&buf).unwrap();
        assert_eq!(out,
        "Content-Length: 92\r\n\r\n{\"seq\":1,\"type\":\"event\",\"event\":\"output\",\"body\":{\"category\":\"stdout\",\"output\":\"A log line\"}}");
    }
}
