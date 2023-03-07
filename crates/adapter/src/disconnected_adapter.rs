//! A builder pattern for managing a debugging session.
//!
//! This module provides the 'DisconnectedAdapter' which manages the first part
//! of a debugging session before we launch/attach to the debuggee. Once communications
//! with the debuggee are established this transforms to a 'ConnectedAdapter' to
//! manage the rest of the debugging session.

use std::process::Child;

use common::DEFAULT_PORT;
use dap::{
    requests::{
        AttachRequestArguments, Command, InitializeArguments, LaunchRequestArguments, Request,
    },
    responses::{Response, ResponseBody},
    types::Capabilities,
};
use serde_json::Value;
use tokio::select;

use crate::{
    async_client::AsyncClient,
    comm::{self, UnrealChannel},
    ClientConfig, UnrealscriptAdapter, UnrealscriptAdapterError,
};

/// A representation of a disconnected adapter. This manages the portion of the
/// protocol up to the point where a connection to the debuggee is established.
pub struct DisconnectedAdapter {
    client: AsyncClient,
    config: ClientConfig,
}

impl DisconnectedAdapter {
    /// Create a new disconnected adapter for the given client.
    pub fn new(client: AsyncClient) -> Self {
        DisconnectedAdapter {
            client,
            config: ClientConfig {
                one_based_lines: true,
                supports_variable_type: false,
                supports_invalidated_event: false,
                source_roots: vec![],
            },
        }
    }

    /// Process protocol messages until we have launched or connected to
    /// the debuggee process, then return an UnrealscriptAdapter instance to
    /// manage the rest of the session.
    pub async fn connect(mut self) -> Result<UnrealscriptAdapter, DisconnectedAdapter> {
        loop {
            select! {
                request = self.client.next() => {
                    match &request.command {
                        Command::Initialize(args) => self.initialize(&request, &args).await,
                        Command::Attach(args) => return self.attach(&request, &args).await,
                        Command::Launch(args) => return self.launch(&request, &args).await,
                        Command::Disconnect(_) => {
                            log::info!("Received disconnect message during connection phase.");
                            return Err(self);
                        },
                        // No other requests are expected in the disconnected state.
                        cmd => {
                            log::error!("Unexpected command {} in disconnected state.", cmd.name().to_string());
                            self.client.respond(Response::make_error(&request,
                                    UnrealscriptAdapterError::UnhandledCommand(cmd.name().to_string()).to_error_message()
                            )).await;
                        }
                    };
                }
            }
        }
    }

    /// Handle an initialize request
    ///
    /// Sets up the client configuration and returns a response.
    async fn initialize(&mut self, req: &Request, args: &InitializeArguments) -> () {
        // Build our client config.
        self.config = ClientConfig {
            one_based_lines: args.lines_start_at1.unwrap_or(true),
            supports_variable_type: args.supports_variable_type.unwrap_or(false),
            supports_invalidated_event: args.supports_invalidated_event.unwrap_or(false),
            source_roots: vec![],
        };

        // Send the response.
        self.client
            .respond(Response::make_success(
                &req,
                ResponseBody::Initialize(Some(Capabilities {
                    supports_configuration_done_request: Some(true),
                    supports_delayed_stack_trace_loading: Some(true),
                    supports_value_formatting_options: Some(false),
                    ..Default::default()
                })),
            ))
            .await;
    }

    /// Connect to the debugger interface. When connected this will send an 'initialized' event to
    /// DAP. This is shared by both the 'launch' and 'attach' requests.
    async fn connect_to_interface(
        &self,
        port: u16,
        child: Option<Child>,
    ) -> Result<UnrealChannel, UnrealscriptAdapterError> {
        log::info!("Connecting to port {port}");

        // Connect to the unrealscript interface and set up the communications channel between
        // it and this adapter.
        Ok(comm::connect(port).await?)
    }

    /// Attach to a running unreal process.
    ///
    /// Consumes the disconnected adapter and returns a connected one if it can connect,
    /// or returns self if connection fails.
    async fn attach(
        mut self,
        req: &Request,
        args: &AttachRequestArguments,
    ) -> Result<UnrealscriptAdapter, DisconnectedAdapter> {
        log::info!("Attach request");
        let port = Self::extract_port(&args.other).unwrap_or(DEFAULT_PORT);
        self.config.source_roots =
            Self::extract_source_roots(&args.other).unwrap_or_else(|| vec![]);
        // TODO this early return is wrong: we have to send a response.
        match self.connect_to_interface(port, None).await {
            Ok(channel) => {
                // Connection succeeded: Respond with a success response and return
                // the conneted adapter.
                self.client
                    .respond(Response::make_success(&req, ResponseBody::Attach))
                    .await;

                return Ok(UnrealscriptAdapter::new(self.client, self.config, channel));
            }
            Err(e) => {
                // Connection failed.
                self.client
                    .respond(Response::make_error(&req, e.to_error_message()))
                    .await;
                return Err(self);
            }
        }
    }

    /// Spawn the debuggee process according to the arguments given.
    fn spawn_debuggee(
        &self,
        args: &LaunchRequestArguments,
        auto_debug: bool,
    ) -> Result<Child, UnrealscriptAdapterError> {
        // Find the program to run
        let program = Self::extract_program(&args.other).ok_or(
            UnrealscriptAdapterError::InvalidProgram("No program provided".to_string()),
        )?;

        let program_args = Self::extract_args(&args.other);

        let mut command = &mut std::process::Command::new(program);
        if program_args.is_some() {
            command = command.args(program_args.unwrap());
            log::info!("Program args are {:#?}", command.get_args());
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
        args: &LaunchRequestArguments,
    ) -> Result<UnrealscriptAdapter, DisconnectedAdapter> {
        // Unless instructed otherwise we're going to debug the launched process, so pass
        // '-autoDebug' and try to connect. If 'no_debug' is 'true' then we're just launching and
        // will not try to debug. We could get a later 'attach' request, in which case we can
        // attach, but that also requires the user to enable the debugger from the unreal side with
        // 'toggledebugger'.
        let auto_debug = match args.no_debug {
            Some(true) => false,
            _ => true,
        };

        match self.spawn_debuggee(args, auto_debug) {
            Ok(child) => {
                // If we're auto-debugging we can now connect to the interface.
                if auto_debug {
                    let port = Self::extract_port(&args.other).unwrap_or(DEFAULT_PORT);
                    match self.connect_to_interface(port, Some(child)).await {
                        Ok(channel) => {
                            // Send a response ack for the launch request.
                            self.client
                                .respond(Response::make_success(req, ResponseBody::Launch))
                                .await;
                            self.config.source_roots =
                                Self::extract_source_roots(&args.other).unwrap_or_else(|| vec![]);

                            return Ok(UnrealscriptAdapter::new(self.client, self.config, channel));
                        }
                        Err(e) => {
                            // We launched, but failed to connect.
                            log::error!("Successfully launched program but failed to connect: {e}");
                            self.client
                                .respond(Response::make_error(&req, e.to_error_message()))
                                .await;
                            return Err(self);
                        }
                    }
                } else {
                    // We launched, but were not asked to connect. Send a success response to the
                    // client, but stay in the disconnected state.
                    log::info!("Launch request succeeded but autodebug is disabled. Remaining disconnected.");
                    self.client
                        .respond(Response::make_success(req, ResponseBody::Launch))
                        .await;
                    return Err(self);
                }
            }
            Err(e) => {
                // We failed to launch the debuggee. Send an error response
                self.client
                    .respond(Response::make_error(&req, e.to_error_message()))
                    .await;
                return Err(self);
            }
        }
    }

    /// Extract the port number from a launch/attach arguments value map.
    fn extract_port(value: &Option<Value>) -> Option<u16> {
        value.as_ref()?["port"].as_i64()?.try_into().ok()
    }

    /// Extract the program from launch arguments.
    fn extract_program(value: &Option<Value>) -> Option<&str> {
        value.as_ref()?["program"].as_str()
    }

    /// Extract the argument list from launch arguments.
    fn extract_args(value: &Option<Value>) -> Option<impl Iterator<Item = &str>> {
        let arr = value.as_ref()?["args"].as_array()?;
        Some(
            arr.iter()
                .filter(|e| e.is_string())
                .map(|e| e.as_str().unwrap()),
        )
    }

    /// Extract the source roots list from the launch/attach arguments.
    fn extract_source_roots(value: &Option<Value>) -> Option<Vec<String>> {
        let arr = value.as_ref()?["sourceRoots"].as_array()?;
        Some(
            arr.iter()
                .filter(|e| e.is_string())
                .map(|e| e.as_str().unwrap().to_string())
                .collect(),
        )
    }
}
