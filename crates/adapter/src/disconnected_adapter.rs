//! A builder pattern for managing a debugging session.
//!
//! This module provides the ['DisconnectedAdapter'] which manages the first part
//! of a debugging session before we launch/attach to the debuggee. Once communications
//! with the debuggee are established this transforms to a ['ConnectedAdapter'] to
//! manage the rest of the debugging session.

use std::process::Child;

use common::{DEFAULT_PORT, PORT_VAR};
use dap::{
    requests::{AttachArguments, Command, InitializeArguments, LaunchArguments, Request},
    responses::{Response, ResponseBody},
    types::Capabilities,
};
use flexi_logger::LogSpecification;
use tokio::select;

use crate::{
    async_client::AsyncClient, client_config::ClientConfig, comm::tcp::TcpConnection,
    connected_adapter::UnrealscriptAdapter, UnrealscriptAdapterError, _LOGGER,
};

/// A representation of a disconnected adapter. This manages the portion of the
/// protocol up to the point where a connection to the debuggee is established.
pub struct DisconnectedAdapter<C: AsyncClient + Unpin> {
    client: C,
    config: ClientConfig,
}

/// Error cases for a disconnected adapter.
///
/// The disconnected adapter attempts to transform itself into a connected adapter.
/// This can fail in either a recoverable or unrecoverable way:
///
/// - If we fail to read or write from the client connection the error is fatal and we
/// cannot recover since there is no communications channel with the client to give us
/// future instructions.
/// - If we fail to launch or attach, receive a disconnect request from the client, or
/// receive unexpected protocol messages from the client we may fail to connect but
/// can continue processing messages and may be able to connect in the future.
pub enum DisconnectedAdapterError<C: AsyncClient + Unpin> {
    /// Represents a fatal error communicating with the client. There is no way to
    /// continue to attempt connection since no more instructions will come from the
    /// client or we can't send any responses. The adapter should give up when
    /// receiving this error.
    IoError(std::io::Error),

    /// We failed to connect, but still have valid commmunications with the client.
    /// We may be able to retry, so this error mode returns the same disconnected
    /// adapter so we can try again.
    NoConnection(DisconnectedAdapter<C>),
}

impl<C: AsyncClient + Unpin> From<std::io::Error> for DisconnectedAdapterError<C> {
    fn from(e: std::io::Error) -> Self {
        DisconnectedAdapterError::IoError(e)
    }
}

impl<C: AsyncClient + Unpin> DisconnectedAdapter<C> {
    /// Create a new disconnected adapter for the given client.
    pub fn new(client: C) -> Self {
        DisconnectedAdapter {
            client,
            config: ClientConfig {
                one_based_lines: true,
                supports_variable_type: false,
                supports_invalidated_event: false,
                source_roots: vec![],
                enable_stack_hack: false,
            },
        }
    }

    /// Process protocol messages until we have launched or connected to
    /// the debuggee process, then return an UnrealscriptAdapter instance to
    /// manage the rest of the session.
    pub async fn connect(mut self) -> Result<UnrealscriptAdapter<C>, DisconnectedAdapterError<C>> {
        loop {
            select! {
                request = self.client.next_request() => {
                    log::trace!("Received request: {request:?}");
                    match request {
                        Some(Ok(request)) => {
                            match &request.command {
                                Command::Initialize(args) => self.initialize(&request, args)?,
                                Command::Attach(args) => return self.attach(&request, args).await,
                                Command::Launch(args) => return self.launch(&request, args).await,
                                Command::Disconnect(_) => {
                                    log::info!("Received disconnect message during connection phase.");
                                    return Err(DisconnectedAdapterError::NoConnection(self));
                                },
                                // No other requests are expected in the disconnected state.
                                cmd => {
                                    log::error!("Unexpected command {} in disconnected state.", cmd.to_string());
                                    //
                                    self.client.respond(Response::make_error(&request, "Unhandled Command".to_string(),
                                            UnrealscriptAdapterError::UnhandledCommand(cmd.to_string()).to_error_message()
                                    ))?;
                                }
                            }
                        },
                        Some(Err(e)) => return Err(DisconnectedAdapterError::IoError(e)),
                        None => return Err(DisconnectedAdapterError::IoError(
                            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Client closed connection."))),
                    }
                }
            }
        }
    }

    /// Handle an initialize request
    ///
    /// Sets up the client configuration and returns a response.
    fn initialize(
        &mut self,
        req: &Request,
        args: &InitializeArguments,
    ) -> Result<(), DisconnectedAdapterError<C>> {
        // Build our client config.
        self.config = ClientConfig {
            one_based_lines: args.lines_start_at1.unwrap_or(true),
            supports_variable_type: args.supports_variable_type.unwrap_or(false),
            supports_invalidated_event: args.supports_invalidated_event.unwrap_or(false),
            source_roots: vec![],
            enable_stack_hack: false,
        };

        // Send the response.
        self.client.respond(Response::make_success(
            req,
            ResponseBody::Initialize(Some(Capabilities {
                supports_configuration_done_request: true,
                supports_delayed_stack_trace_loading: true,
            })),
        ))?;
        Ok(())
    }

    /// Connect to the debugger interface. When connected this will send an 'initialized' event to
    /// DAP. This is shared by both the 'launch' and 'attach' requests.
    async fn connect_to_interface(
        &self,
        port: u16,
    ) -> Result<TcpConnection, UnrealscriptAdapterError> {
        log::info!("Connecting to port {port}");

        // Connect to the unrealscript interface and set up the communications channel between
        // it and this adapter.
        Ok(TcpConnection::connect(port).await?)
    }

    /// Attach to a running unreal process.
    ///
    /// Consumes the disconnected adapter and returns a connected one if it can connect,
    /// or returns self if connection fails.
    ///
    /// # Errors
    ///
    /// Returns an io error if we are unable to send a response to the client's output
    /// channel.
    async fn attach(
        mut self,
        req: &Request,
        args: &AttachArguments,
    ) -> Result<UnrealscriptAdapter<C>, DisconnectedAdapterError<C>> {
        log::info!("Attach request");

        if let Some(loglevel) = &args.log_level {
            match LogSpecification::try_from(loglevel) {
                Ok(newspec) => {
                    log::info!("Replacing log spec with {loglevel}");
                    _LOGGER
                        .write()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .set_new_spec(newspec)
                }
                Err(e) => log::error!(
                    "Failed to set new log level from attach arg {}: {e}",
                    loglevel
                ),
            }
        }
        let port = DEFAULT_PORT;
        self.config.source_roots = args.source_roots.clone().unwrap_or_default();
        self.config.enable_stack_hack = args.enable_stack_hack.unwrap_or(true);
        match self.connect_to_interface(port).await {
            Ok(connection) => {
                // Connection succeeded: Respond with a success response and return
                // the conneted adapter.
                self.client.respond(Response::make_ack(req))?;

                Ok(UnrealscriptAdapter::new(
                    self.client,
                    self.config,
                    Box::new(connection),
                    None,
                    args.log_level.as_ref().cloned(),
                ))
            }
            Err(e) => {
                // Connection failed.
                self.client.respond(Response::make_error(
                    req,
                    "Connection Failed".to_string(),
                    e.to_error_message(),
                ))?;
                Err(DisconnectedAdapterError::NoConnection(self))
            }
        }
    }

    /// Spawn the debuggee process according to the arguments given.
    fn spawn_debuggee(
        &self,
        args: &LaunchArguments,
        auto_debug: bool,
    ) -> Result<Child, UnrealscriptAdapterError> {
        // Find the program to run
        let program = args
            .program
            .as_ref()
            .ok_or(UnrealscriptAdapterError::NoProgram)?;

        let program_args = args.args.as_ref();

        let mut command = &mut std::process::Command::new(program);
        if let Some(a) = program_args {
            command = command.args(a);
        }

        // Append '-autoDebug' if we're launching so we can be sure the interface will launch and
        // we can connect.
        if auto_debug {
            command = command.arg("-autoDebug");
        }

        log::info!(
            "Launching {} with arguments {:#?}",
            program,
            command.get_args()
        );

        // Spawn the process.
        //
        // Note we must disconnect all streams (or we could pipe them elsewhere...). By
        // default in/out/err streams are inherited from the parent process, and we do _not_ want
        // unreal writing to stdout or reading from stdin since those are our communication
        // channel with the DAP client.
        let child = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .or(Err(UnrealscriptAdapterError::InvalidProgram(format!(
                "Failed to launch {0}",
                program
            ))))?;

        Ok(child)
    }

    // Determine the port number to use.
    //
    // - If the given argument is Some, use it if valid or emit an error. This
    //   is expected to be a number from DAP. If this number is valid also set
    //   the port env var to this value so the adapter can find it when we launch.
    // - Check the environment for a value, parse that and use it
    //   if valid or emit an error if not.
    // - If neither of the above are valid, return none.
    fn determine_port(arg: Option<i64>) -> Option<u16> {
        // Check for a port override.
        match arg {
            Some(p) => match p.try_into() {
                Ok(p) => {
                    std::env::set_var(PORT_VAR, format!("{p}"));
                    Some(p)
                }
                Err(_) => {
                    log::error!("Bad port in launch arguments: {p}");
                    None
                }
            },
            None => {
                // No port specified in the arguments, try the environment.
                if let Ok(str) = std::env::var(PORT_VAR) {
                    match str.parse::<u16>() {
                        Ok(v) => Some(v),
                        Err(_) => {
                            log::error!("Bad port value in {}: {str}", PORT_VAR);
                            None
                        }
                    }
                } else {
                    None
                }
            }
        }
    }

    /// Launch a process and optionally attach to it.
    ///
    /// If we are in autodebug mode we will immediately attach, and on success
    /// return the connected adapter. If we are not in autodebug mode or if we
    /// fail to connect then we're return the existing disconnected adapter. If
    /// the connection was a failure we will also send the appropriate response
    /// error to the client, but these two states are indistinguishable to the
    /// caller.
    async fn launch(
        mut self,
        req: &Request,
        args: &LaunchArguments,
    ) -> Result<UnrealscriptAdapter<C>, DisconnectedAdapterError<C>> {
        // Override the default log level if specified.
        if let Some(loglevel) = &args.log_level {
            match LogSpecification::try_from(loglevel) {
                Ok(newspec) => {
                    log::info!("Replacing log spec with {loglevel}");
                    _LOGGER
                        .write()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .set_new_spec(newspec)
                }
                Err(e) => log::error!(
                    "Failed to set new log level from launch arg {}: {e}",
                    loglevel
                ),
            }
        }

        let port = Self::determine_port(args.port).unwrap_or(DEFAULT_PORT);

        // Unless instructed otherwise we're going to debug the launched process, so pass
        // '-autoDebug' and try to connect. If 'no_debug' is 'true' then we're just launching and
        // will not try to debug. We could get a later 'attach' request, in which case we can
        // attach, but that also requires the user to enable the debugger from the unreal side with
        // 'toggledebugger'.
        let auto_debug = !matches!(args.no_debug, Some(true));

        match self.spawn_debuggee(args, auto_debug) {
            Ok(child) => {
                // If we're auto-debugging we can now connect to the interface.
                if auto_debug {
                    match self.connect_to_interface(port).await {
                        Ok(connection) => {
                            // Send a response ack for the launch request.
                            self.client.respond(Response::make_ack(req))?;
                            self.config.source_roots =
                                args.source_roots.clone().unwrap_or_default();
                            self.config.enable_stack_hack = args.enable_stack_hack.unwrap_or(true);

                            Ok(UnrealscriptAdapter::new(
                                self.client,
                                self.config,
                                Box::new(connection),
                                Some(child),
                                args.log_level.as_ref().cloned(),
                            ))
                        }
                        Err(e) => {
                            // We launched, but failed to connect.
                            log::error!("Successfully launched program but failed to connect: {e}");
                            self.client.respond(Response::make_error(
                                req,
                                "Connection failed".to_string(),
                                e.to_error_message(),
                            ))?;
                            Err(DisconnectedAdapterError::NoConnection(self))
                        }
                    }
                } else {
                    // We launched, but were not asked to connect. Send a success response to the
                    // client, but stay in the disconnected state.
                    log::info!("Launch request succeeded but autodebug is disabled. Remaining disconnected.");
                    self.client.respond(Response::make_ack(req))?;
                    Err(DisconnectedAdapterError::NoConnection(self))
                }
            }
            Err(e) => {
                // We failed to launch the debuggee. Send an error response
                self.client.respond(Response::make_error(
                    req,
                    "Launch Failed".to_string(),
                    e.to_error_message(),
                ))?;
                Err(DisconnectedAdapterError::NoConnection(self))
            }
        }
    }
}
