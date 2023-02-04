use std::io::{BufReader, BufRead, Read};

use adapter::UnrealscriptAdapter;
use dap::prelude::*;
use flexi_logger::{Logger, FileSpec};

pub mod adapter;
pub mod client;

use client::UnrealscriptClient;

fn main() {
    let adapter = UnrealscriptAdapter {};
    let client = UnrealscriptClient::new(std::io::stdout()); 
    let mut server = Server::new(adapter, client);
    let _logger = Logger::try_with_env_or_str("trace").unwrap()
        .log_to_file(FileSpec::default().directory("C:\\users\\jonat\\projects\\debugger\\unrealscript-debugger-interface\\logs"))
        .start().unwrap();
    log::info!("Ready to start!");
    let mut reader = BufReader::new(std::io::stdin());
    match server.run(&mut reader) {
        Ok(()) => std::process::exit(0),
        Err(err) => {
            log::error!("Debugger failed with error {err}");
            eprintln!("Debugger failed with error {err:#?}");
            std::process::exit(1);
        }
    };
}
