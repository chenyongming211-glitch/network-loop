use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use l2_loop_core::{
    AlertSinkMode, EVIDENCE_MAX_REVISION_BYTES, EvidenceStatus, INCIDENT_OUTPUT_QUEUE_CAPACITY,
    OutputHealth, OutputHealthState,
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::{
    AlertSink, EvidenceIo, EvidenceStore, IncidentWriteJob, LinuxAlertSink, LinuxEvidenceStore,
    SanitizedAlertV1, StdFilesystemCapacity,
};

const OUTPUT_STORE_UNAVAILABLE: &str = "OUTPUT_STORE_UNAVAILABLE";
const OUTPUT_QUEUE_FULL: &str = "OUTPUT_QUEUE_FULL";
const OUTPUT_WORKER_FAILED: &str = "OUTPUT_WORKER_FAILED";

pub trait IncidentOutputBackend: Send + 'static {
    fn persist(&mut self, job: &IncidentWriteJob) -> Result<(), IncidentOutputError>;

    fn alert(&mut self, job: &IncidentWriteJob, evidence_status: EvidenceStatus) -> AlertSinkMode;
}

pub trait IncidentEvidenceSink: Send + 'static {
    fn persist_revision(
        &mut self,
        revision: &l2_loop_core::IncidentRevisionV1,
    ) -> Result<(), IncidentOutputError>;
}

impl<S: IncidentEvidenceSink> IncidentEvidenceSink for crate::SharedEvidenceStore<S> {
    fn persist_revision(
        &mut self,
        revision: &l2_loop_core::IncidentRevisionV1,
    ) -> Result<(), IncidentOutputError> {
        self.with_locked(|store| store.persist_revision(revision))
            .map_err(|_| IncidentOutputError::StoreUnavailable)?
    }
}

impl<T: IncidentOutputBackend + ?Sized> IncidentOutputBackend for Box<T> {
    fn persist(&mut self, job: &IncidentWriteJob) -> Result<(), IncidentOutputError> {
        (**self).persist(job)
    }

    fn alert(&mut self, job: &IncidentWriteJob, evidence_status: EvidenceStatus) -> AlertSinkMode {
        (**self).alert(job, evidence_status)
    }
}

impl<I> IncidentEvidenceSink for LinuxEvidenceStore<I>
where
    I: EvidenceIo + Send + 'static,
{
    fn persist_revision(
        &mut self,
        revision: &l2_loop_core::IncidentRevisionV1,
    ) -> Result<(), IncidentOutputError> {
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(IncidentOutputError::StoreUnavailable)?;
        self.enforce_retention(
            now_unix_ms,
            EVIDENCE_MAX_REVISION_BYTES,
            &StdFilesystemCapacity,
        )
        .map_err(|_| IncidentOutputError::StoreUnavailable)?;
        self.put(revision)
            .map(|_| ())
            .map_err(|_| IncidentOutputError::StoreUnavailable)
    }
}

impl<I> IncidentOutputBackend for LinuxEvidenceStore<I>
where
    I: EvidenceIo + Send + 'static,
{
    fn persist(&mut self, job: &IncidentWriteJob) -> Result<(), IncidentOutputError> {
        self.persist_revision(&job.revision)
    }

    fn alert(
        &mut self,
        _job: &IncidentWriteJob,
        _evidence_status: EvidenceStatus,
    ) -> AlertSinkMode {
        AlertSinkMode::StderrJson
    }
}

pub struct StoredIncidentOutputBackend<S, A> {
    store: S,
    alerts: A,
}

impl<S, A> StoredIncidentOutputBackend<S, A> {
    pub const fn new(store: S, alerts: A) -> Self {
        Self { store, alerts }
    }
}

impl<S, A> IncidentOutputBackend for StoredIncidentOutputBackend<S, A>
where
    S: IncidentEvidenceSink,
    A: AlertSink + Send + 'static,
{
    fn persist(&mut self, job: &IncidentWriteJob) -> Result<(), IncidentOutputError> {
        self.store.persist_revision(&job.revision)
    }

    fn alert(&mut self, job: &IncidentWriteJob, evidence_status: EvidenceStatus) -> AlertSinkMode {
        let revision = &job.revision;
        let alert = SanitizedAlertV1 {
            event_id: revision.event_id,
            evidence_status,
            revision: revision.revision,
            transition_sequence: revision.transition_sequence,
            code: revision.alert_code,
            severity: revision.severity,
            previous_state: revision.previous_state,
            current_state: revision.current_state,
            transition_reason: revision.transition_reason,
            interface: revision.interface.clone(),
            ifindex: revision.ifindex,
            generation: revision.interface_generation,
            message: alert_message(revision.alert_code).to_owned(),
        };
        match self.alerts.publish(&alert) {
            Ok(crate::AlertPublishOutcome::Journald) => AlertSinkMode::Journald,
            Ok(crate::AlertPublishOutcome::StderrJson) | Err(_) => AlertSinkMode::StderrJson,
        }
    }
}

impl<I: crate::AlertIo> IncidentOutputBackend for LinuxAlertSink<I>
where
    I: Send + 'static,
{
    fn persist(&mut self, _job: &IncidentWriteJob) -> Result<(), IncidentOutputError> {
        Err(IncidentOutputError::StoreUnavailable)
    }

    fn alert(&mut self, job: &IncidentWriteJob, evidence_status: EvidenceStatus) -> AlertSinkMode {
        let revision = &job.revision;
        let alert = SanitizedAlertV1 {
            event_id: revision.event_id,
            evidence_status,
            revision: revision.revision,
            transition_sequence: revision.transition_sequence,
            code: revision.alert_code,
            severity: revision.severity,
            previous_state: revision.previous_state,
            current_state: revision.current_state,
            transition_reason: revision.transition_reason,
            interface: revision.interface.clone(),
            ifindex: revision.ifindex,
            generation: revision.interface_generation,
            message: alert_message(revision.alert_code).to_owned(),
        };
        match self.publish(&alert) {
            Ok(crate::AlertPublishOutcome::Journald) => AlertSinkMode::Journald,
            Ok(crate::AlertPublishOutcome::StderrJson) | Err(_) => AlertSinkMode::StderrJson,
        }
    }
}

const fn alert_message(code: l2_loop_core::AlertCode) -> &'static str {
    match code {
        l2_loop_core::AlertCode::StormConfirmed => "passive L2 storm confirmed",
        l2_loop_core::AlertCode::ExternalLoopSuspected => "passive L2 loop relationship suspected",
        l2_loop_core::AlertCode::ExternalLoopHighConfidence => {
            "passive L2 loop relationship high confidence"
        }
        l2_loop_core::AlertCode::IncidentCooldown => "passive L2 incident cooling down",
        l2_loop_core::AlertCode::IncidentClosed => "passive L2 incident closed",
        l2_loop_core::AlertCode::GenerationEnded => "passive L2 observation generation ended",
        l2_loop_core::AlertCode::OutputDegraded => "passive L2 incident output degraded",
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableIncidentOutputBackend;

impl IncidentOutputBackend for UnavailableIncidentOutputBackend {
    fn persist(&mut self, _job: &IncidentWriteJob) -> Result<(), IncidentOutputError> {
        Err(IncidentOutputError::StoreUnavailable)
    }

    fn alert(
        &mut self,
        _job: &IncidentWriteJob,
        _evidence_status: EvidenceStatus,
    ) -> AlertSinkMode {
        AlertSinkMode::StderrJson
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum IncidentOutputError {
    #[error("incident evidence store is unavailable")]
    StoreUnavailable,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum IncidentOutputSubmitError {
    #[error("incident output queue is full")]
    QueueFull,
    #[error("incident output worker is closed")]
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentOutputShutdown {
    Drained,
    TimedOut,
    WorkerFailed,
}

#[derive(Clone)]
pub struct IncidentOutputHandle {
    sender: mpsc::Sender<IncidentWriteJob>,
    health: Arc<Mutex<OutputHealth>>,
}

impl IncidentOutputHandle {
    pub fn try_submit(&self, job: IncidentWriteJob) -> Result<(), IncidentOutputSubmitError> {
        match self.sender.try_send(job) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                update_health(&self.health, false, Some(OUTPUT_QUEUE_FULL), true);
                Err(IncidentOutputSubmitError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                update_health(&self.health, false, Some(OUTPUT_WORKER_FAILED), true);
                Err(IncidentOutputSubmitError::Closed)
            }
        }
    }

    pub fn health(&self) -> OutputHealth {
        self.health
            .lock()
            .map(|health| health.clone())
            .unwrap_or_else(|_| unavailable_health(OUTPUT_WORKER_FAILED))
    }
}

pub struct IncidentOutputWorker {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
    health: Arc<Mutex<OutputHealth>>,
}

impl IncidentOutputWorker {
    pub fn start<B>(backend: B) -> (IncidentOutputHandle, Self)
    where
        B: IncidentOutputBackend,
    {
        Self::start_with_health(
            backend,
            OutputHealth {
                state: OutputHealthState::Healthy,
                store_available: true,
                corrupt_object_count: 0,
                incomplete_object_count: 0,
                unknown_object_count: 0,
                alert_sink: AlertSinkMode::StderrJson,
                last_error_code: None,
                dropped_job_count: 0,
            },
        )
    }

    pub fn start_with_health<B>(
        backend: B,
        initial_health: OutputHealth,
    ) -> (IncidentOutputHandle, Self)
    where
        B: IncidentOutputBackend,
    {
        let (sender, mut receiver) =
            mpsc::channel::<IncidentWriteJob>(INCIDENT_OUTPUT_QUEUE_CAPACITY);
        let (shutdown, mut shutdown_receiver) = watch::channel(false);
        let backend = Arc::new(Mutex::new(backend));
        let health = Arc::new(Mutex::new(initial_health));
        let task_health = health.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    changed = shutdown_receiver.changed() => {
                        if changed.is_err() || *shutdown_receiver.borrow() {
                            receiver.close();
                            while let Some(job) = receiver.recv().await {
                                process_job(backend.clone(), task_health.clone(), job).await;
                            }
                            return;
                        }
                    }
                    job = receiver.recv() => {
                        let Some(job) = job else {
                            return;
                        };
                        process_job(backend.clone(), task_health.clone(), job).await;
                    }
                }
            }
        });
        (
            IncidentOutputHandle {
                sender,
                health: health.clone(),
            },
            Self {
                shutdown,
                task,
                health,
            },
        )
    }

    pub async fn shutdown(mut self, timeout: Duration) -> IncidentOutputShutdown {
        let _ = self.shutdown.send(true);
        match tokio::time::timeout(timeout, &mut self.task).await {
            Ok(Ok(())) => IncidentOutputShutdown::Drained,
            Ok(Err(_)) => {
                update_health(&self.health, false, Some(OUTPUT_WORKER_FAILED), false);
                IncidentOutputShutdown::WorkerFailed
            }
            Err(_) => {
                self.task.abort();
                update_health(&self.health, false, Some(OUTPUT_WORKER_FAILED), false);
                IncidentOutputShutdown::TimedOut
            }
        }
    }
}

async fn process_job<B>(
    backend: Arc<Mutex<B>>,
    health: Arc<Mutex<OutputHealth>>,
    job: IncidentWriteJob,
) where
    B: IncidentOutputBackend,
{
    let result = tokio::task::spawn_blocking(move || {
        let mut backend = backend
            .lock()
            .map_err(|_| IncidentOutputError::StoreUnavailable)?;
        let persisted = backend.persist(&job);
        let status = if persisted.is_ok() {
            EvidenceStatus::Stored
        } else {
            EvidenceStatus::Unavailable
        };
        let alert_sink = backend.alert(&job, status);
        (persisted, alert_sink)
    })
    .await;

    match result {
        Ok((persisted, alert_sink)) => {
            if let Ok(mut health) = health.lock() {
                health.alert_sink = alert_sink;
            }
            if persisted.is_err() {
                update_health(&health, false, Some(OUTPUT_STORE_UNAVAILABLE), false);
            }
        }
        Err(_) => update_health(&health, false, Some(OUTPUT_STORE_UNAVAILABLE), false),
    }
}

fn update_health(
    health: &Arc<Mutex<OutputHealth>>,
    store_available: bool,
    error_code: Option<&str>,
    dropped: bool,
) {
    let Ok(mut health) = health.lock() else {
        return;
    };
    health.state = OutputHealthState::Degraded;
    health.store_available = store_available;
    health.last_error_code = error_code.map(str::to_owned);
    if dropped {
        health.dropped_job_count = health.dropped_job_count.saturating_add(1);
    }
}

fn unavailable_health(error_code: &str) -> OutputHealth {
    OutputHealth {
        state: OutputHealthState::Degraded,
        store_available: false,
        corrupt_object_count: 0,
        incomplete_object_count: 0,
        unknown_object_count: 0,
        alert_sink: AlertSinkMode::StderrJson,
        last_error_code: Some(error_code.to_owned()),
        dropped_job_count: 0,
    }
}
