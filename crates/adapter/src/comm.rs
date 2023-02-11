use std::net::TcpStream;

use common::Breakpoint;

pub struct ConnectionError;

/// A representation for communications between the adapter and interface.
///
// TODO: Currently the adapter is sent across a thread boundary, and the adapter
// holds the channel so this must be Send + 'static. This could be eliminated if
// we restructure things so that the adapter can be constructed inside the thread
// instead of being moved into it.
pub trait UnrealChannel : Send + 'static {

    /// Add a breakpoint, receiving the verified breakpoint from unreal.
    fn add_breakpoint(&mut self, bp: Breakpoint) -> Breakpoint;

    // Remove a breakpoint, receiving the removed breakpoint from unreal.
    fn remove_breakpoint(&mut self, bp: Breakpoint) -> Breakpoint;
}

/// The DefaultChannel uses two communications modes for talking to the debugger interface.
///
/// A TCP socket is used to send commands from the adapter to the interface. This socket
/// can also receive asynchronous events from the interface to the adapter.
///
/// It also has a separate shared memory channel to send responses from the
/// interface to the adapter. These are guaranteed to arrive in a specific order in response
/// to commands, and some of the responses can be very large (e.g. watch data).
///
/// This split model allows for a simpler communications scheme between the adapter and the
/// interface:
///
///  - The adapter can spin up a thread responsible only for monitoring the TCP socket for
///  asynchronous events. These can occur at any time in unpredictable orders.
///  - Synchronous communication of command to one or more responses can be done on the adapter's
///  main message processing thread.
pub struct DefaultChannel {
    pub tcp: TcpStream,
}

impl UnrealChannel for DefaultChannel {

    fn add_breakpoint(&mut self, bp: Breakpoint) -> Breakpoint {
        bp
    }
    fn remove_breakpoint(&mut self, bp: Breakpoint) -> Breakpoint {
        bp
    }
}

/// Connect to an unreal debugger adapter running at the given port number on the local computer.
pub fn connect(port: i32) -> Result<Box<dyn UnrealChannel>,ConnectionError> {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).or(Err(ConnectionError{}))?;

    Ok(Box::new(DefaultChannel{tcp: stream}))
}
