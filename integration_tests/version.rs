use common::{InitializeResponse, UnrealCommand, UnrealResponse, Version};
use dap::{events::EventBody, types::OutputEventCategory};
use tokio_stream::StreamExt;

mod fixture;

#[tokio::test(flavor = "multi_thread")]
async fn equal_version() {
    let (client, mut erx, _rtx) = fixture::make_test_client();
    let (mut adapter, mut dbg, mut comm) = fixture::setup_with_client(client).await;

    tokio::task::spawn(async move {
        // Fetch the initialized command and return a response.
        let command = comm.next().await.unwrap().unwrap();
        if let UnrealCommand::Initialize(init) = command {
            // Send a response with the same version we were given.
            dbg.send_response(UnrealResponse::Initialize(InitializeResponse {
                version: init.version,
            }))
            .unwrap();
        } else {
            panic!("Expected an initialize request but got {command:?}");
        }
        // Close the tcp connection. Required so the adapter loop can detect this and stop.
        drop(comm);
    });

    tokio::task::spawn(async move {
        // We should get an initialized event first from construction of the adapter.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Initialized));

        // Then we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated(_)));
    });

    adapter
        .process_messages(Version {
            major: 0,
            minor: 1,
            patch: 0,
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn larger_major() {
    let (client, mut erx, _rtx) = fixture::make_test_client();
    let (mut adapter, mut dbg, mut comm) = fixture::setup_with_client(client).await;

    tokio::task::spawn(async move {
        // Fetch the initialized command and return a response.
        let command = comm.next().await.unwrap().unwrap();
        if let UnrealCommand::Initialize(init) = command {
            // Send a response with a larger major version
            dbg.send_response(UnrealResponse::Initialize(InitializeResponse {
                version: Version {
                    major: init.version.major + 1,
                    minor: init.version.minor,
                    patch: init.version.patch,
                },
            }))
            .unwrap();
        } else {
            panic!("Expected an initialize request but got {command:?}");
        }
        // Close the tcp connection. Required so the adapter loop can detect this and stop.
        drop(comm);
    });

    tokio::task::spawn(async move {
        // We should get an output event telling us there is a version mismatch
        let evt = erx.recv().await.unwrap();
        match evt.body {
            EventBody::Output(o) => {
                assert!(matches!(o.category.unwrap(), OutputEventCategory::Console));
            }
            e => panic!("Expected output event for version mismatch but got {e:?}"),
        };

        // We should get an initialized event from construction of the adapter.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Initialized));

        // Then we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated(_)));
    });

    adapter
        .process_messages(Version {
            major: 0,
            minor: 1,
            patch: 0,
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn larger_minor() {
    let (client, mut erx, _rtx) = fixture::make_test_client();
    let (mut adapter, mut dbg, mut comm) = fixture::setup_with_client(client).await;

    tokio::task::spawn(async move {
        // Fetch the initialized command and return a response.
        let command = comm.next().await.unwrap().unwrap();
        if let UnrealCommand::Initialize(init) = command {
            // Send a response with a larger major version
            dbg.send_response(UnrealResponse::Initialize(InitializeResponse {
                version: Version {
                    major: init.version.major,
                    minor: init.version.minor + 1,
                    patch: init.version.patch,
                },
            }))
            .unwrap();
        } else {
            panic!("Expected an initialize request but got {command:?}");
        }
        // Close the tcp connection. Required so the adapter loop can detect this and stop.
        drop(comm);
    });

    tokio::task::spawn(async move {
        // We should get an output event telling us there is a version mismatch
        let evt = erx.recv().await.unwrap();
        match evt.body {
            EventBody::Output(o) => {
                assert!(matches!(o.category.unwrap(), OutputEventCategory::Console));
            }
            e => panic!("Expected output event for version mismatch but got {e:?}"),
        };

        // We should get an initialized event from construction of the adapter.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Initialized));

        // Then we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated(_)));
    });

    adapter
        .process_messages(Version {
            major: 0,
            minor: 1,
            patch: 0,
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn larger_patch() {
    let (client, mut erx, _rtx) = fixture::make_test_client();
    let (mut adapter, mut dbg, mut comm) = fixture::setup_with_client(client).await;

    tokio::task::spawn(async move {
        // Fetch the initialized command and return a response.
        let command = comm.next().await.unwrap().unwrap();
        if let UnrealCommand::Initialize(init) = command {
            // Send a response with a larger major version
            dbg.send_response(UnrealResponse::Initialize(InitializeResponse {
                version: Version {
                    major: init.version.major,
                    minor: init.version.minor,
                    patch: init.version.patch + 1,
                },
            }))
            .unwrap();
        } else {
            panic!("Expected an initialize request but got {command:?}");
        }
        // Close the tcp connection. Required so the adapter loop can detect this and stop.
        drop(comm);
    });

    tokio::task::spawn(async move {
        // We should get an output event telling us there is a version mismatch
        let evt = erx.recv().await.unwrap();
        match evt.body {
            EventBody::Output(o) => {
                assert!(matches!(o.category.unwrap(), OutputEventCategory::Console));
            }
            e => panic!("Expected output event for version mismatch but got {e:?}"),
        };

        // We should get an initialized event from construction of the adapter.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Initialized));

        // Then we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated(_)));
    });

    adapter
        .process_messages(Version {
            major: 0,
            minor: 1,
            patch: 0,
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn smaller_major() {
    let (client, mut erx, _rtx) = fixture::make_test_client();
    let (mut adapter, mut dbg, mut comm) = fixture::setup_with_client(client).await;

    tokio::task::spawn(async move {
        // Fetch the initialized command and return a response.
        let command = comm.next().await.unwrap().unwrap();
        if let UnrealCommand::Initialize(init) = command {
            // Send a response with a larger major version
            dbg.send_response(UnrealResponse::Initialize(InitializeResponse {
                version: Version {
                    major: init.version.major - 1,
                    minor: init.version.minor,
                    patch: init.version.patch,
                },
            }))
            .unwrap();
        } else {
            panic!("Expected an initialize request but got {command:?}");
        }
        // Close the tcp connection. Required so the adapter loop can detect this and stop.
        drop(comm);
    });

    tokio::task::spawn(async move {
        // We should get an output event telling us there is a version mismatch
        let evt = erx.recv().await.unwrap();
        match evt.body {
            EventBody::Output(o) => {
                assert!(matches!(o.category.unwrap(), OutputEventCategory::Console));
            }
            e => panic!("Expected output event for version mismatch but got {e:?}"),
        };

        // We should get an initialized event from construction of the adapter.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Initialized));

        // Then we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated(_)));
    });

    adapter
        .process_messages(Version {
            major: 2,
            minor: 1,
            patch: 0,
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn smaller_minor() {
    let (client, mut erx, _rtx) = fixture::make_test_client();
    let (mut adapter, mut dbg, mut comm) = fixture::setup_with_client(client).await;

    tokio::task::spawn(async move {
        // Fetch the initialized command and return a response.
        let command = comm.next().await.unwrap().unwrap();
        if let UnrealCommand::Initialize(init) = command {
            // Send a response with a larger major version
            dbg.send_response(UnrealResponse::Initialize(InitializeResponse {
                version: Version {
                    major: init.version.major,
                    minor: init.version.minor - 1,
                    patch: init.version.patch,
                },
            }))
            .unwrap();
        } else {
            panic!("Expected an initialize request but got {command:?}");
        }
        // Close the tcp connection. Required so the adapter loop can detect this and stop.
        drop(comm);
    });

    tokio::task::spawn(async move {
        // We should get an output event telling us there is a version mismatch
        let evt = erx.recv().await.unwrap();
        match evt.body {
            EventBody::Output(o) => {
                assert!(matches!(o.category.unwrap(), OutputEventCategory::Console));
            }
            e => panic!("Expected output event for version mismatch but got {e:?}"),
        };

        // We should get an initialized event from construction of the adapter.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Initialized));

        // Then we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated(_)));
    });

    adapter
        .process_messages(Version {
            major: 1,
            minor: 1,
            patch: 0,
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn smaller_patch() {
    let (client, mut erx, _rtx) = fixture::make_test_client();
    let (mut adapter, mut dbg, mut comm) = fixture::setup_with_client(client).await;

    tokio::task::spawn(async move {
        // Fetch the initialized command and return a response.
        let command = comm.next().await.unwrap().unwrap();
        if let UnrealCommand::Initialize(init) = command {
            // Send a response with a larger major version
            dbg.send_response(UnrealResponse::Initialize(InitializeResponse {
                version: Version {
                    major: init.version.major,
                    minor: init.version.minor,
                    patch: init.version.patch - 1,
                },
            }))
            .unwrap();
        } else {
            panic!("Expected an initialize request but got {command:?}");
        }
        // Close the tcp connection. Required so the adapter loop can detect this and stop.
        drop(comm);
    });

    tokio::task::spawn(async move {
        // We should get an output event telling us there is a version mismatch
        let evt = erx.recv().await.unwrap();
        match evt.body {
            EventBody::Output(o) => {
                assert!(matches!(o.category.unwrap(), OutputEventCategory::Console));
            }
            e => panic!("Expected output event for version mismatch but got {e:?}"),
        };

        // We should get an initialized event from construction of the adapter.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Initialized));

        // Then we'll get a terminated event because we closed the interface connection.
        let evt = erx.recv().await.unwrap();
        assert!(matches!(evt.body, EventBody::Terminated(_)));
    });

    adapter
        .process_messages(Version {
            major: 0,
            minor: 1,
            patch: 3,
        })
        .await
        .unwrap();
}
