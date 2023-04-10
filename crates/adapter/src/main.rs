use std::sync::mpsc::channel;

use adapter::{
    client::ClientImpl,
    disconnected_adapter::{DisconnectedAdapter, DisconnectedAdapterError},
    _LOGGER,
};
use common::{create_logger, Version};
use pkg_version::{pkg_version_major, pkg_version_minor, pkg_version_patch};

const ADAPTER_VERSION: Version = Version {
    major: pkg_version_major!(),
    minor: pkg_version_minor!(),
    patch: pkg_version_patch!(),
};

fn main() {
    // Create the logging instance.
    _LOGGER.write().unwrap().replace(create_logger("adapter"));

    // Clients don't always connect stderr to anything so hook panics and write them to the log.
    std::panic::set_hook(Box::new(|p| {
        log::error!("Panic: {p:#?}");
    }));

    let (tx, rx) = channel();
    let client = ClientImpl::new(std::io::stdin(), std::io::stdout(), tx.clone());
    let mut adapter = DisconnectedAdapter::new(client, tx, rx);

    log::info!("Ready to start!");
    let return_code = loop {
        match adapter.connect() {
            Ok(mut connected) => {
                log::info!("Connection established!");
                match connected.process_messages(ADAPTER_VERSION) {
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
