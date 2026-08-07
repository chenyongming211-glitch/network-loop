use std::process::ExitCode;

use l2_loop_agent::{
    PreflightService,
    daemon::{BoundedUnixServer, DEFAULT_SOCKET_PATH, DaemonDispatcher, DaemonError},
    linux::inspector::SystemLinuxInspector,
};
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), DaemonError> {
    let mut terminate = signal(SignalKind::terminate()).map_err(|source| DaemonError::Io {
        operation: "register termination signal",
        source,
    })?;
    let server = BoundedUnixServer::bind(DEFAULT_SOCKET_PATH).await?;
    let dispatcher = DaemonDispatcher::new(PreflightService::new(SystemLinuxInspector::system()));
    server
        .serve(
            move |request| {
                let dispatcher = dispatcher.clone();
                async move { dispatcher.dispatch(request).await }
            },
            async move {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            },
        )
        .await
}
