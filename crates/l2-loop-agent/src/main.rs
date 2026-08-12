use std::{path::Path, process::ExitCode, time::Duration};

use l2_loop_agent::{
    AttachmentTransaction, IncidentOutputBackend, IncidentOutputWorker, LinuxEvidenceStore,
    PreflightService, StdEvidenceIo, UnavailableIncidentOutputBackend,
    daemon::{
        BoundedUnixServer, DEFAULT_SOCKET_PATH, DaemonDispatcher, DaemonError,
        TransactionIsolatedControl, coordinate_daemon, run_sampling_loop,
    },
    linux::{
        acceptance_fault::{
            ACCEPTANCE_FAULT_ENV, AcceptanceFault, FaultInjectingMaps, FaultInjectingObservation,
            FaultInjectingObservationReader, FaultInjectingTc,
        },
        bpf_object::AyaObjectRuntime,
        inspector::SystemLinuxInspector,
        limits::ProcessResourceLimits,
        observation::{AyaObservationIo, LinuxObservationReader},
        tc::{RtnetlinkTcIo, SafeTc},
        xdp::{RtnetlinkXdpIo, SafeXdp},
    },
    ownership::FileOwnershipRepository,
};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

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
    let acceptance_fault_value = match std::env::var(ACCEPTANCE_FAULT_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(DaemonError::InvalidAcceptanceFault);
        }
    };
    let acceptance_fault = AcceptanceFault::parse(acceptance_fault_value.as_deref())
        .map_err(|_| DaemonError::InvalidAcceptanceFault)?;
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
        FaultInjectingTc::new(SafeTc::new(RtnetlinkTcIo), acceptance_fault),
        FaultInjectingMaps::new(runtime.map_publisher(), acceptance_fault),
        FileOwnershipRepository,
    );
    let backend: Box<dyn IncidentOutputBackend> = LinuxEvidenceStore::open(
        StdEvidenceIo,
        Path::new("/var/lib/l2-loop/evidence/v1"),
        env!("CARGO_PKG_VERSION"),
    )
    .map(|store| Box::new(store) as Box<dyn IncidentOutputBackend>)
    .unwrap_or_else(|_| Box::new(UnavailableIncidentOutputBackend));
    let (incident_output, incident_worker) = IncidentOutputWorker::start(backend);
    let isolated = TransactionIsolatedControl::new(
        transaction,
        FaultInjectingObservationReader::new(
            LinuxObservationReader::new(FaultInjectingObservation::new(
                AyaObservationIo::new(),
                acceptance_fault,
            )),
            acceptance_fault,
        ),
    )
    .with_incident_output(incident_output);
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(SystemLinuxInspector::system()),
        isolated,
    );
    let (shutdown, shutdown_receiver) = watch::channel(false);
    let request_dispatcher = dispatcher.clone();
    let mut server_shutdown = shutdown_receiver.clone();
    let server = server.serve(
        move |request| {
            let dispatcher = request_dispatcher.clone();
            async move { dispatcher.dispatch(request).await }
        },
        async move {
            loop {
                if *server_shutdown.borrow() || server_shutdown.changed().await.is_err() {
                    break;
                }
            }
        },
    );
    let sampler = tokio::spawn(run_sampling_loop(dispatcher.clone(), shutdown_receiver));
    let shutdown_signal = async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    };

    let daemon_result =
        coordinate_daemon(dispatcher, server, sampler, shutdown, shutdown_signal).await;
    let _ = incident_worker.shutdown(Duration::from_secs(5)).await;
    daemon_result
}
