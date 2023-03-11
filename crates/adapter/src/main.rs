use adapter::{
    async_client::AsyncClientImpl,
    disconnected_adapter::{DisconnectedAdapter, DisconnectedAdapterError},
};
use flexi_logger::{Duplicate, FileSpec, Logger};

#[tokio::main]
async fn main() {
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

    let client = AsyncClientImpl::new(tokio::io::stdin(), tokio::io::stdout());
    let mut adapter = DisconnectedAdapter::new(client);

    log::info!("Ready to start!");
    let return_code = loop {
        match adapter.connect().await {
            Ok(mut connected) => {
                log::info!("Connection established!");
                match connected.process_messages().await {
                    Ok(()) => {
                        log::info!("Debugger session ended.");
                        break 0;
                    }
                    Err(e) => {
                        log::error!("Adapter exiting with error {e}");
                        break 1;
                    }
                };
            }
            Err(DisconnectedAdapterError::NoConnection(a)) => {
                // We failed to connect, or launched without attempting connection.
                // If the former the client will just kill this process. If the
                // latter then loop again and wait for an attach message.
                adapter = a;
            }
            Err(DisconnectedAdapterError::IoError(e)) => {
                log::error!("Received fatal error {e} while connecting. Aborting");
                break 1;
            }
        }
    };

    std::process::exit(return_code);
}
