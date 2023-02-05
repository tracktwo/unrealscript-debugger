
use dap::{prelude::*, requests::{InitializeArguments, SetBreakpointsArguments, AttachRequestArguments}, types::Capabilities, responses::ErrorMessage};
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
            Command::Initialize(args) => Ok(initialize(args, &request, ctx)),
            Command::SetBreakpoints(args) => Ok(set_breakpoints(args, &request, ctx)),
            Command::Attach(args) => Ok(attach(args, &request, ctx)),
            _ => Ok(Response::make_error(ctx.next_seq(), &request, ErrorMessage::new(1, "Unsupported Command", true)))
        }
    }
}

fn initialize(_args: &InitializeArguments, request: &Request, ctx: &mut dyn Context) -> Response {
    Response::make_success(ctx.next_seq(), request, ResponseBody::Initialize(Some(Capabilities {
        supports_configuration_done_request: Some(true),
        supports_delayed_stack_trace_loading: Some(true),
        supports_value_formatting_options: Some(true),
        ..Default::default()
    })))
}

fn set_breakpoints(args: &SetBreakpointsArguments, request: &Request, ctx: &mut dyn Context) -> Response {
    log::info!("Set breakpoints request");
    if let Some(breakpoints) = &args.breakpoints {
        for bp in breakpoints {
            // Ask the debugger to set each breapoint in turn, and wait for the corresponding
            // response message to be delivered.
        }
    }
    Response::make_error(ctx.next_seq(), request, ErrorMessage::new(2, "Not implemented", true) )
}

fn attach(_args: &AttachRequestArguments, request: &Request, ctx: &mut dyn Context) -> Response {
    log::info!("Attach request");
    Response::make_ack(ctx.next_seq(), &request).expect("Attach can be acked")
}
