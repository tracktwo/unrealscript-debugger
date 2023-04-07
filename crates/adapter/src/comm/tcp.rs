//! TCP-based connection to Unreal

use std::{
    io::{Error, ErrorKind, Read, Write},
    net::TcpStream,
    sync::mpsc::{channel, Receiver, Sender},
    time::Duration,
};

use common::{UnrealCommand, UnrealInterfaceMessage, UnrealResponse};

use crate::AdapterMessage;

use super::Connection;

/// The number of connection attempts to make
const CONNECT_ATTEMPTS: i32 = 10;
// The amount of time to wait between each connection
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// A TCP-based connection between the debug adapter and the Unreal debugger
/// interface.
pub struct TcpConnection {
    tcp_stream: TcpStream,
    response_receiver: Receiver<UnrealResponse>,
}

impl TcpConnection {
    /// Connect to an unreal debugger adapter running at the given port number on the local computer.
    pub fn connect(
        port: u16,
        event_sender: Sender<AdapterMessage>,
    ) -> Result<TcpConnection, Error> {
        let mut tcp: Option<TcpStream> = None;

        // Try to connect, sleeping between attempts. This sleep is intended to give
        // enough time for a launched Unreal process to get to the point where the
        // interface has opened the listening socket.
        for _ in 0..CONNECT_ATTEMPTS {
            match TcpStream::connect(format!("127.0.0.1:{port}")) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(_) => {
                    std::thread::sleep(CONNECT_TIMEOUT);
                }
            }
        }

        // If we failed to connect we can't go any further.
        let tcp = tcp.ok_or(Error::new(ErrorKind::NotConnected, "Failed to connect. Ensure the debug interface has been installed to the game directory."))?;

        log::trace!("Connected to interface");

        // Create channels to manage sending commands to and receiving events from the
        // interface TCP connection.
        let (rtx, rrx) = channel();

        let tcp_clone = tcp.try_clone().unwrap();
        // Spawn a new thread to manage these channels and the TCP connection.
        std::thread::spawn(|| debuggee_tcp_loop(tcp_clone, rtx, event_sender));
        Ok(TcpConnection {
            response_receiver: rrx,
            tcp_stream: tcp,
        })
    }
}

impl Connection for TcpConnection {
    fn send_command(&mut self, command: UnrealCommand) -> Result<(), Error> {
        log::trace!("Sending command {command:?}");
        let buf = serde_json::ser::to_vec(&command)?;
        let msg_len = buf.len() as u32;
        let size_buf = msg_len.to_be_bytes();
        log::trace!("{} bytes became prefix {size_buf:?}", buf.len());
        self.tcp_stream.write_all(&size_buf)?;
        self.tcp_stream.write_all(&buf).map(|_| ())
    }

    fn next_response(&mut self) -> Result<UnrealResponse, Error> {
        log::trace!("Waiting for next response...");
        match self.response_receiver.recv() {
            Ok(resp) => {
                log::trace!("Got response {resp:?}");
                Ok(resp)
            }
            Err(_) => Err(std::io::Error::new(
                ErrorKind::ConnectionReset,
                "Error reading next response",
            )),
        }
    }
}

/// Task for managing a TCP connection to the debugger interface.
///
/// This is intended to be spawned as an independent task which will coordinate
/// communication between the interface's socket and the main debugger adapter.
/// This communication is done via channels.
fn debuggee_tcp_loop(
    mut tcp: TcpStream,
    response_sender: Sender<UnrealResponse>,
    event_sender: Sender<AdapterMessage>,
) {
    // Adapt the tcp socket into an asymmetrical source + sink for Json objects.
    // Across this TCP socket we will send UnrealCommands to the interface, and
    // receive UnrealEvents from that interface. These will always be length-delimited.

    loop {
        let mut size_buf = [0u8; 4];
        match tcp.read_exact(&mut size_buf) {
            Ok(()) => {
                log::trace!("Read size bytes from socket: {size_buf:?}");
            }
            Err(_) => {
                // Failed to read bytes from the TCP socket. This is not necessarily
                // an error, the interface will close the connection when it disconnects.
                log::info!("Received EOF from interface. Closing connection.");
                if event_sender.send(AdapterMessage::Shutdown).is_err() {
                    log::error!("Failed to send shutdown event to adapter.");
                }
                return;
            }
        };
        let sz = u32::from_be_bytes(size_buf);
        let mut msg_buf = vec![0; sz as usize];
        match tcp.read_exact(&mut msg_buf) {
            Ok(()) => (),
            Err(e) => {
                log::error!("Error reading msg from interface: {e}");
            }
        };
        match serde_json::from_slice(&msg_buf) {
            Ok(UnrealInterfaceMessage::Event(event)) => {
                if event_sender.send(AdapterMessage::Event(event)).is_err() {
                    log::error!("Failed to send event to adapter.");
                    return;
                }
            }
            Ok(UnrealInterfaceMessage::Response(resp)) => {
                if response_sender.send(resp).is_err() {
                    log::error!("Failed to send response to adapter.");
                    return;
                }
            }
            Err(e) => {
                log::error!("Error from Unreal connection: {e}");
                if event_sender.send(AdapterMessage::Shutdown).is_err() {
                    log::error!("Failed to send shutdown event to adapter.");
                }
                return;
            }
        }
    }
}
