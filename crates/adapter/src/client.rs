use std::io::Write;

use dap::{
    client,
    events::EventBody,
    prelude::{BasicClient, Client, Context, Event},
    responses::{Response, ResponseBody},
};

pub struct UnrealscriptClient<'a, W: Write> {
    client: BasicClient<'a, W>,
}

impl<'a ,W: Write> UnrealscriptClient<'a, W> {
    pub fn new(writer: W) -> UnrealscriptClient<'a, W> {
        return UnrealscriptClient {
            client: BasicClient::new(writer),
        };
    }
}

impl<W: Write> Client for UnrealscriptClient<W> {
    fn respond(&mut self, response: Response) -> dap::client::Result<()> {
        log::info!("Sending response");
        let mut evt: Option<Event> = None;
        if response.success {
            if let Some(ResponseBody::Initialize(_)) = response.body {
                evt = Some(Event::new(self.client.next_seq(), EventBody::Initialized));
            }
        }

        self.client.respond(response)?;
        if let Some(evt) = evt {
            log::info!("Sending initialized event");
            self.client.send_event(evt)?;
        }
        Ok(())
    }
}

impl<W: Write> Context for UnrealscriptClient<W> {
    fn send_event(&mut self, event: Event) -> client::Result<()> {
        self.client.send_event(event)
    }

    fn send_reverse_request(
        &mut self,
        request: dap::reverse_requests::ReverseRequest,
    ) -> dap::client::Result<()> {
        self.client.send_reverse_request(request)
    }

    fn request_exit(&mut self) {
        self.client.request_exit()
    }

    fn cancel_exit(&mut self) {
        self.client.cancel_exit()
    }

    fn get_exit_state(&self) -> bool {
        self.client.get_exit_state()
    }

    fn next_seq(&mut self) -> i64 {
        self.client.next_seq()
    }
}
