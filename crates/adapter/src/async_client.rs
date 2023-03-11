//! Asynchronous client for DAP

use std::io::{Error, ErrorKind};

use dap::{
    events::EventProtocolMessage,
    prelude::Event,
    requests::Request,
    responses::{Response, ResponseProtocolMessage},
};
use futures::executor;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};

pub struct AsyncClient<R, W>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    input: BufReader<R>,
    output: BufWriter<W>,
    seq: i64,
    state: State,
    next_msg_size: usize,
    buf: Vec<u8>,
}

/// A representation of the current client reader state. Each request message
/// is made up of three parts: A header, a body, and a separator between them.
enum State {
    Header,
    Sep,
    Body,
}

impl<R, W> AsyncClient<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(input: R, output: W) -> Self {
        Self {
            input: BufReader::new(input),
            output: BufWriter::new(output),
            seq: 0,
            state: State::Header,
            next_msg_size: 0,
            buf: Vec::new(),
        }
    }

    /// Read the next request from the stream.
    ///
    /// This function must be cancelation safe.
    pub async fn next(&mut self) -> Result<Option<Request>, Error> {
        loop {
            match &self.state {
                State::Header => match self.input.read_until(b'\n', &mut self.buf).await {
                    Ok(0) => return Ok(None),
                    Ok(_) => self.process_header()?,
                    Err(e) => return Err(e),
                },
                State::Sep => match self.input.read_until(b'\n', &mut self.buf).await {
                    Ok(0) => return Ok(None),
                    Ok(_) => self.process_separator()?,
                    Err(e) => return Err(e),
                },
                State::Body => {
                    // Pull some bytes from the reader's buffer, and move them into
                    // our buffer.
                    let num_consumed = match self.input.fill_buf().await {
                        Ok(s) if s.len() == 0 => return Ok(None),
                        Ok(s) => {
                            // If the returned buf size is not big enough to complete
                            // our message then move all bytes into our buf.
                            if self.buf.len() + s.len() <= self.next_msg_size {
                                self.buf.extend_from_slice(s);
                                dbg!(s);
                                s.len()
                            } else {
                                // We've internally buffered more bytes than necessary for
                                // the next message. Consume only the amount we need.
                                let bytes_used = self.next_msg_size - self.buf.len();
                                self.buf.extend_from_slice(&s[..bytes_used]);
                                dbg!(s);
                                bytes_used
                            }
                            // Otherwise we'll stay in the same state and try to read more.
                        }
                        Err(e) => return Err(e),
                    };
                    self.input.consume(num_consumed);
                    // If our buffer now holds a full message it's time to process it.
                    if self.buf.len() == self.next_msg_size {
                        return Ok(Some(self.process_message()?));
                    }
                }
            }
        }
    }

    pub fn respond(&mut self, response: Response) -> Result<(), Error> {
        let response_message = ResponseProtocolMessage {
            seq: self.next_seq(),
            response,
        };
        let mut payload = serde_json::ser::to_vec(&response_message)
            .expect("Response messages are serializable to json");
        executor::block_on(async move {
            self.output.write_all(&mut payload).await?;
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    pub fn send_event(&mut self, event: Event) -> Result<(), Error> {
        let event_message = EventProtocolMessage {
            seq: self.next_seq(),
            event,
        };
        let mut payload = serde_json::ser::to_vec(&event_message)
            .expect("Event messages are serializable to json");
        executor::block_on(async move {
            self.output.write_all(&mut payload).await?;
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    fn next_seq(&mut self) -> i64 {
        self.seq += 1;
        self.seq
    }

    /// Parse a DAP header and move self to the next state or return an error.
    ///
    /// `self.buf` should contain a single line representing a DAP header,
    /// and the only supported DAP header is 'Content-Length'.
    fn process_header(&mut self) -> Result<(), Error> {
        // The buffer should be a well-formed utf-8 string.
        let str = std::str::from_utf8(&self.buf)
            .or_else(|e| Err(Error::new(ErrorKind::InvalidData, e)))?;

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

        self.buf.clear();
        self.state = State::Sep;
        self.next_msg_size = len;
        if self.buf.capacity() < len {
            self.buf.reserve(len - self.buf.capacity());
        }
        Ok(())
    }

    /// Parse the end of the DAP header and move self to the next state, or error.
    fn process_separator(&mut self) -> Result<(), Error> {
        let str = std::str::from_utf8(&self.buf)
            .or_else(|e| Err(Error::new(ErrorKind::InvalidData, e)))?;

        if str == "\r\n" {
            self.buf.clear();
            self.state = State::Body;
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Expected empty header separator: {str}",
            ))
        }
    }

    /// Process a message.
    fn process_message(&mut self) -> Result<Request, Error> {
        // We should never move more bytes from the reader's buffer into our own buffer
        // than we needed for the next message.
        assert!(self.buf.len() == self.next_msg_size);
        dbg!(&self.buf);
        let req = serde_json::from_slice(&self.buf)
            .or_else(|e| Err(Error::new(ErrorKind::InvalidData, e)));
        // Consume the bytes from our buffer and return to the header state.
        self.buf.clear();
        self.state = State::Header;
        return req;
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
        let mut client = AsyncClient::new(input, output);
        // The stream should end before we successfully read the full packet. This is an error.
        match client.next().await {
            Err(e) => assert!(e.kind() == ErrorKind::InvalidData),
            _ => panic!("Unexpected result"),
        }
    }

    #[tokio::test]
    async fn a_packet() {
        let payload = r#"{"seq": 1, "command": "initialize", "arguments": { "clientId": "test client", "adapterID": "unrealscript"}}"#;
        let str = format!("Content-Length: {}\r\n\r\n{payload}", payload.len());
        let input = Cursor::new(str);
        let output: Vec<u8> = vec![];
        let mut client = AsyncClient::new(input, output);
        match client.next().await {
            Ok(Some(req)) => assert!(matches!(req.command, Command::Initialize(_))),
            other => panic!("Expected valid request but got {other:?}"),
        }

        // We should now be at the end of the stream.
        match client.next().await {
            Ok(None) => (),
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
        let mut client = AsyncClient::new(input, output);
        match client.next().await {
            Ok(Some(req)) => assert!(matches!(req.command, Command::Initialize(_))),
            other => panic!("Expected valid request but got {other:?}"),
        }

        // The client's buffer should be empty, even if the input's buffer isn't.
        assert!(client.buf.is_empty());
    }
}
