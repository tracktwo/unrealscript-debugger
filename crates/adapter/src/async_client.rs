//! Asynchronous client for DAP

use dap::{prelude::Event, requests::Request, responses::Response};

pub struct AsyncClient {
    input: tokio::io::Stdin,
    output: tokio::io::Stdout,
}

impl AsyncClient {
    pub fn new(input: tokio::io::Stdin, output: tokio::io::Stdout) -> Self {
        Self { input, output }
    }

    pub async fn next(&mut self) -> Request {
        todo!();
    }

    pub async fn respond(&mut self, response: Response) -> () {
        todo!();
    }

    pub async fn send_event(&mut self, event: Event) -> () {
        todo!();
    }
}
