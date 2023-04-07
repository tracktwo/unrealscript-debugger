//! Asynchronous client for DAP
//!
//! This module defines the [`AsyncClient`] trait representing a connection to
//! a DAP client that can communicate with the adapter in a partially
//! asynchronous way.
//!
//! It also provides an implementation of this trait that can communicate via
//! a pair of objects that implement [`AsyncRead`] and [`AsyncWrite`].

use std::{
    io::{BufRead, BufReader, BufWriter, Error, Read, Write},
    sync::mpsc::Sender,
};

use dap::{
    events::{Event, EventMessage},
    responses::{Response, ResponseMessage},
};

use crate::AdapterMessage;

/// The primary trait for communicating with a DAP client.
///
/// This defines the protocol for communicating with the client to send and
/// receive DAP messages. This protocol receives asynchronously but implements
/// blocking sends. The blocking send behavior is helpful both to limit the
/// async scope of the adapter as well as to help ensure we do not have any
/// interleaved messages.
pub trait Client {
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
pub struct ClientImpl<W>
where
    W: Write,
{
    output: BufWriter<W>,
    seq: i64,
}

impl<W> ClientImpl<W>
where
    W: Write,
{
    /// Construct a new [`AsyncClient`] from the given input reader and output writer.
    pub fn new<R: Read + Send + 'static>(
        input: R,
        output: W,
        sender: Sender<AdapterMessage>,
    ) -> Self {
        let input = BufReader::new(input);
        std::thread::spawn(|| {
            match client_loop(input, sender) {
                Ok(()) => (),
                Err(e) => {
                    log::error!("Client loop exitedi with error: {e}");
                }
            };
        });
        Self {
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
        self.output.write_all(header.as_bytes())?;
        self.output.write_all(msg)?;
        self.output.flush()?;
        log::trace!("Finished writing response");
        Ok(())
    }
}

impl<W> Client for ClientImpl<W>
where
    W: Write,
{
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

fn client_loop<R: Read>(
    mut input: BufReader<R>,
    sender: Sender<AdapterMessage>,
) -> Result<(), Error> {
    let mut hdr = String::new();
    loop {
        // Read the header.
        hdr.clear();
        match input.read_line(&mut hdr) {
            Ok(0) => {
                log::info!("EOF from client: shutting down.");
                return Ok(());
            }
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        // The header is of the form:
        //
        // Content-Length: <len>
        let spl: Vec<&str> = hdr.trim_end().split(':').collect();
        if spl.len() == 2 {
        } else {
            log::error!("Unexpected header format: got {hdr}");
            continue;
        }

        let len: usize = match spl[0] {
            "Content-Length" => match spl[1].trim().parse() {
                Ok(val) => val,
                Err(_) => {
                    log::error!("Error parsing header length: got {hdr}");
                    continue;
                }
            },
            _ => {
                log::error!("Expected 'Content-Length' header; got {hdr}");
                continue;
            }
        };

        // Read the separator.
        match input.read_line(&mut hdr) {
            Ok(0) => {
                log::info!("EOF from client: shutting down.");
                return Ok(());
            }
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        // Read the message body.
        let mut buf = vec![0; len];
        match input.read_exact(&mut buf) {
            Ok(()) => (),
            Err(e) => return Err(e),
        };

        // Convert the message to JSON
        match serde_json::from_slice(&buf) {
            Ok(request) => {
                log::trace!("Got request: {request:?}");
                sender
                    .send(AdapterMessage::Request(request))
                    .expect("Receiver should still be alive.");
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Deserialization of request failed: {e}"),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::{io::Cursor, sync::mpsc::channel};

    use dap::{
        events::{EventBody, OutputEventBody, OutputEventCategory},
        requests::Command,
        responses::ResponseBody,
        types::{Scope, VariableReferenceInfo},
    };

    use super::*;

    #[test]
    fn a_packet() {
        let payload = r#"{"seq": 1, "command": "initialize", "arguments": { "clientId": "test client", "adapterID": "unrealscript"}}"#;
        let str = format!("Content-Length: {}\r\n\r\n{payload}", payload.len());
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let (tx, rx) = channel();
        let _ = ClientImpl::new(input, output, tx);
        match rx.recv() {
            Ok(AdapterMessage::Request(req)) => {
                assert!(matches!(req.command, Command::Initialize(_)))
            }
            other => panic!("Expected valid request but got {other:?}"),
        }
    }

    #[test]
    fn a_packet_with_extra() {
        let payload = r#"{"seq": 1, "command": "initialize", "arguments": { "clientId": "test client", "adapterID": "unrealscript"}}"#;
        // Stick the start of the next packet immediately after the body one.
        let str = format!(
            "Content-Length: {}\r\n\r\n{payload}Content-Length: 300",
            payload.len()
        );
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let (tx, rx) = channel();
        let _ = ClientImpl::new(input, output, tx);
        match rx.recv() {
            Ok(AdapterMessage::Request(req)) => {
                assert!(matches!(req.command, Command::Initialize(_)))
            }
            other => panic!("Expected valid request but got {other:?}"),
        }
    }

    #[test]
    fn sending_raw_message() {
        let str = "A message";
        let input = Cursor::new(str);
        let mut buf: Vec<u8> = vec![];
        {
            let output = Cursor::new(&mut buf);
            let (tx, _) = channel();
            let mut client = ClientImpl::new(input, output, tx);
            client.send_message(str.as_bytes()).unwrap();
        }
        let out = std::str::from_utf8(&buf).unwrap();
        assert_eq!(format!("Content-Length: 9\r\n\r\n{str}"), out);
    }

    #[test]
    fn sending_response() {
        let str = "A message";
        let input = Cursor::new(str);
        let mut buf: Vec<u8> = vec![];
        {
            let output = Cursor::new(&mut buf);
            let (tx, _) = channel();
            let mut client = ClientImpl::new(input, output, tx);
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
        }
        let out = std::str::from_utf8(&buf).unwrap();
        assert_eq!(out,
        "Content-Length: 203\r\n\r\n{\"type\":\"response\",\"seq\":1,\"request_seq\":1,\"success\":true,\"command\":\"scopes\",\"body\":{\"scopes\":[{\"name\":\"Globals\",\"variablesReference\":1,\"namedVariables\":null,\"indexedVariables\":null,\"expensive\":false}]}}");
    }

    #[test]
    fn sending_event() {
        let str = "A message";
        let input = Cursor::new(str);
        let mut buf: Vec<u8> = vec![];
        {
            let output = Cursor::new(&mut buf);
            let (tx, _) = channel();
            let mut client = ClientImpl::new(input, output, tx);
            let event = Event {
                body: EventBody::Output(OutputEventBody {
                    category: OutputEventCategory::Stdout,
                    output: "A log line".to_string(),
                }),
            };
            client.send_event(event).unwrap();
        }
        let out = std::str::from_utf8(&buf).unwrap();
        assert_eq!(out,
        "Content-Length: 92\r\n\r\n{\"seq\":1,\"type\":\"event\",\"event\":\"output\",\"body\":{\"category\":\"stdout\",\"output\":\"A log line\"}}");
    }
}
