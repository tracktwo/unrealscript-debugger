
use dap::{prelude::*, requests::InitializeArguments, types::Capabilities};
use thiserror::Error;

pub struct UnrealscriptAdapter;

#[derive(Error, Debug)]
pub enum UnrealscriptAdapterError {
    #[error("Unhandled command")]
    UnhandledCommandError,
}

impl Adapter for UnrealscriptAdapter {
    type Error = UnrealscriptAdapterError;
    fn accept(&mut self, request: Request, ctx: &mut dyn Context) -> Result<Response,Self::Error> {
        log::info!("Got request {request:#?}");
        match &request.command {
            Command::Initialize(args) => Ok(Response::make_success(ctx.next_seq(), &request, initialize(args))),
            _ => Err(UnrealscriptAdapterError::UnhandledCommandError),
        }
    }
}

fn initialize(args: &InitializeArguments) -> ResponseBody {
    log::info!("Initialize Request from client {}", args.client_name.as_ref().unwrap());
    ResponseBody::Initialize(Some(Capabilities {
            supports_configuration_done_request: Some(true),
            supports_delayed_stack_trace_loading: Some(true),
            supports_value_formatting_options: Some(true),
            ..Default::default()
        }))
}
