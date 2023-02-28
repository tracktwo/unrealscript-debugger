use std::io::BufReader;

use adapter::UnrealscriptAdapter;
use dap::prelude::*;
use flexi_logger::{Duplicate, FileSpec, Logger};

fn main() {
    let _logger = Logger::try_with_env_or_str("trace")
        .unwrap()
        .log_to_file(FileSpec::default().directory("logs"))
        .duplicate_to_stderr(Duplicate::All)
        .start()
        .unwrap();

    // Clients don't always connect stderr to anything so hook panics and write them to the log.
    std::panic::set_hook(Box::new(|p| {
        log::error!("Panic: {p:#?}");
    }));

    let adapter = UnrealscriptAdapter::new();
    let mut server = Server::new(adapter, std::io::stdout());

    log::info!("Ready to start!");

    let reader = BufReader::new(std::io::stdin());
    server.run(reader).unwrap_or_else(|e| {
        log::error!("Debugger failed with error {e}");
        std::process::exit(1);
    });
}
