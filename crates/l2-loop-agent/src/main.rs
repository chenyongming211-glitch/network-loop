use std::process::ExitCode;

use l2_loop_agent::{
    AttachmentTransaction, PreflightService,
    daemon::{
        BoundedUnixServer, DEFAULT_SOCKET_PATH, DaemonDispatcher, DaemonError,
        TransactionIsolatedControl,
    },
    linux::{
        bpf_object::AyaObjectRuntime,
        inspector::SystemLinuxInspector,
        limits::ProcessResourceLimits,
        tc::{RtnetlinkTcIo, SafeTc},
        xdp::{RtnetlinkXdpIo, SafeXdp},
    },
    ownership::FileOwnershipRepository,
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
    let executable = std::env::current_exe().map_err(|source| DaemonError::Io {
        operation: "resolve daemon executable",
        source,
    })?;
    let object_path = executable
        .parent()
        .ok_or_else(|| DaemonError::Io {
            operation: "resolve daemon bundle directory",
            source: std::io::Error::other("daemon executable has no parent directory"),
        })?
        .join("l2-loop-ebpf.o");
    let runtime = AyaObjectRuntime::new(object_path);
    let transaction = AttachmentTransaction::new(
        SystemLinuxInspector::system(),
        ProcessResourceLimits,
        runtime.loader(),
        SafeXdp::new(RtnetlinkXdpIo),
        SafeTc::new(RtnetlinkTcIo),
        runtime.map_publisher(),
        FileOwnershipRepository,
    );
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(SystemLinuxInspector::system()),
        TransactionIsolatedControl::new(transaction),
    );
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
