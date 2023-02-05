use dap::{
    prelude::*,
    requests::{InitializeArguments, SetBreakpointsArguments},
    responses::ErrorMessage,
    types::Capabilities,
};
use thiserror::Error;

pub struct UnrealscriptAdapter;

#[derive(Error, Debug)]
pub enum UnrealscriptAdapterError {
    #[error("Unhandled command: {0}")]
    UnhandledCommandError(String),
}

impl UnrealscriptAdapterError {
    fn id(&self) -> i64 {
        match self {
            UnrealscriptAdapterError::UnhandledCommandError(_) => 1,
        }
    }

    pub fn to_error_message(&self) -> ErrorMessage {
        ErrorMessage {
            id: self.id(),
            format: self.to_string(),
            show_user: true,
        }
    }
}

impl Adapter for UnrealscriptAdapter {
    type Error = UnrealscriptAdapterError;
    fn accept(&mut self, request: Request, ctx: &mut dyn Context) -> Result<Response, Self::Error> {
        log::info!("Got request {request:#?}");
        let response = match &request.command {
            Command::Initialize(args) => self.initialize(args),
            Command::SetBreakpoints(args) => self.set_breakpoints(args),
            Command::Attach(_) => {
                return Ok(
                    Response::make_ack(ctx.next_seq(), &request).expect("attach can be acked")
                )
            }
            _ => Err(UnrealscriptAdapterError::UnhandledCommandError(
                request.command.name().to_string(),
            )),
        };

        match response {
            Ok(body) => Ok(Response::make_success(ctx.next_seq(), &request, body)),
            Err(e) => Ok(Response::make_error(
                ctx.next_seq(),
                &request,
                e.to_error_message(),
            )),
        }
    }
}

impl UnrealscriptAdapter {
    fn initialize(
        &self,
        _args: &InitializeArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        Ok(ResponseBody::Initialize(Some(Capabilities {
            supports_configuration_done_request: Some(true),
            supports_delayed_stack_trace_loading: Some(true),
            supports_value_formatting_options: Some(true),
            ..Default::default()
        })))
    }

    fn set_breakpoints(
        &self,
        args: &SetBreakpointsArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Set breakpoints request");
        if let Some(breakpoints) = &args.breakpoints {
            for bp in breakpoints {
                // Ask the debugger to set each breapoint in turn, and wait for the corresponding
                // response message to be delivered.
            }
        }
        Err(UnrealscriptAdapterError::UnhandledCommandError(
            "setBreakpoints".to_string(),
        ))
    }
}
