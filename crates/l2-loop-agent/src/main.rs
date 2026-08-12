use std::{path::Path, process::ExitCode, time::Duration};

use l2_loop_agent::{
    AttachmentTransaction, EvidenceStore, IncidentOutputBackend, IncidentOutputWorker,
    LinuxAlertSink, LinuxEvidenceStore, PreflightService, SharedEvidenceStore, StdEvidenceIo,
    StoredIncidentOutputBackend, SystemAlertIo,
    daemon::{
        BoundedUnixServer, DEFAULT_SOCKET_PATH, DaemonDispatcher, DaemonError,
        TransactionIsolatedControl, coordinate_daemon, run_sampling_loop,
    },
    linux::{
        acceptance_fault::{
            ACCEPTANCE_EVIDENCE_FAILURE_ENV, ACCEPTANCE_EVIDENCE_ROOT_ENV, ACCEPTANCE_FAULT_ENV,
            AcceptanceAlertIo, AcceptanceEvidenceFailure, AcceptanceFault,
            FaultInjectingIncidentOutput, FaultInjectingMaps, FaultInjectingObservation,
            FaultInjectingObservationReader, FaultInjectingTc, parse_acceptance_evidence_root,
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
use l2_loop_core::{AlertSinkMode, OutputHealth, OutputHealthState};
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
    let acceptance_evidence_root_value = read_optional_unicode_env(ACCEPTANCE_EVIDENCE_ROOT_ENV)?;
    let acceptance_evidence_root =
        parse_acceptance_evidence_root(acceptance_evidence_root_value.as_deref())
            .map_err(|_| DaemonError::InvalidAcceptanceFault)?;
    if let Some(root) = acceptance_evidence_root.as_ref() {
        let canonical =
            std::fs::canonicalize(root).map_err(|_| DaemonError::InvalidAcceptanceFault)?;
        if canonical != *root {
            return Err(DaemonError::InvalidAcceptanceFault);
        }
    }
    let acceptance_evidence_failure = AcceptanceEvidenceFailure::parse(
        read_optional_unicode_env(ACCEPTANCE_EVIDENCE_FAILURE_ENV)?.as_deref(),
    )
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
    let evidence_root = acceptance_evidence_root
        .as_deref()
        .unwrap_or_else(|| Path::new("/var/lib/l2-loop/evidence/v1"));
    let acceptance_alerts = acceptance_evidence_root.is_some();
    let configured_alert_sink = if acceptance_alerts {
        AlertSinkMode::StderrJson
    } else {
        AlertSinkMode::Journald
    };
    let evidence_store =
        LinuxEvidenceStore::open(StdEvidenceIo, evidence_root, env!("CARGO_PKG_VERSION"));
    let (backend, evidence_control, initial_output_health) = match evidence_store {
        Ok(store) => {
            let store_health = store.health();
            let recovery_issue = store_health.corrupt_object_count > 0
                || store_health.incomplete_object_count > 0
                || store_health.unknown_object_count > 0;
            let output_health = OutputHealth {
                state: if store_health.available && !recovery_issue {
                    OutputHealthState::Healthy
                } else {
                    OutputHealthState::Degraded
                },
                store_available: store_health.available,
                corrupt_object_count: store_health.corrupt_object_count,
                incomplete_object_count: store_health.incomplete_object_count,
                unknown_object_count: store_health.unknown_object_count,
                alert_sink: configured_alert_sink,
                last_error_code: recovery_issue
                    .then(|| "OUTPUT_STORE_RECOVERY_ISSUES".to_owned()),
                dropped_job_count: 0,
            };
            let shared = SharedEvidenceStore::new(store);
            (
                Box::new(StoredIncidentOutputBackend::new(
                    shared.clone(),
                    LinuxAlertSink::new(AcceptanceAlertIo::new(SystemAlertIo, acceptance_alerts)),
                )) as Box<dyn IncidentOutputBackend>,
                Some(shared),
                output_health,
            )
        }
        Err(_) => {
            let mut output_health = OutputHealth::unavailable("OUTPUT_STORE_UNAVAILABLE");
            output_health.alert_sink = configured_alert_sink;
            (
                Box::new(LinuxAlertSink::new(AcceptanceAlertIo::new(
                    SystemAlertIo,
                    acceptance_alerts,
                ))) as Box<dyn IncidentOutputBackend>,
                None,
                output_health,
            )
        }
    };
    let backend: Box<dyn IncidentOutputBackend> = match acceptance_evidence_failure {
        AcceptanceEvidenceFailure::None => backend,
        AcceptanceEvidenceFailure::OnePersist => Box::new(FaultInjectingIncidentOutput::new(
            backend,
            acceptance_evidence_failure,
        )),
    };
    let (incident_output, incident_worker) =
        IncidentOutputWorker::start_with_health(backend, initial_output_health);
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
    let preflight = PreflightService::new(SystemLinuxInspector::system());
    let dispatcher = match evidence_control {
        Some(evidence) => DaemonDispatcher::with_controls(preflight, isolated, evidence),
        None => DaemonDispatcher::with_isolated_control(preflight, isolated),
    };
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

fn read_optional_unicode_env(name: &str) -> Result<Option<String>, DaemonError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(DaemonError::InvalidAcceptanceFault),
    }
}
