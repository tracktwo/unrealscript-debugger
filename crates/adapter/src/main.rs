use std::io::BufReader;

use adapter::UnrealscriptAdapter;
use dap::prelude::*;
use flexi_logger::{FileSpec, Logger, Duplicate};

fn main() {
    let _logger = Logger::try_with_env_or_str("trace")
        .unwrap()
        .log_to_file(FileSpec::default().directory("logs"))
        .duplicate_to_stderr(Duplicate::All)
        .start()
        .unwrap();

    let adapter = UnrealscriptAdapter::new();
    let mut server = Server::new(adapter, std::io::stdout());

    log::info!("Ready to start!");

    // Spawn a new thread for the server to process messages in. This will loop
    // until the debugger quits.
    let server_thread = std::thread::spawn(move || {
        let reader = BufReader::new(std::io::stdin());
        server.run(reader)
    });

    // Wait for the server to finish processing. We may not necessarily get back here at
    // all: the client may kill the adapter process if it hits certain errors.
    match server_thread.join().unwrap() {
        Ok(()) => std::process::exit(0),
        Err(err) => {
            log::error!("Debugger failed with error {err}");
            eprintln!("Debugger failed with error {err:#?}");
            std::process::exit(1);
        }
    };
}
