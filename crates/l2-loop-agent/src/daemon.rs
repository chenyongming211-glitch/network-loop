use std::{
    fs,
    future::Future,
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{Instant, MissedTickBehavior},
};

use crate::{
    AttachmentSession, EvidenceStore, EvidenceStoreError, IncidentOutputHandle,
    IsolatedAttachmentDriver, OBS_OWNERSHIP_MISMATCH, OBS_SESSION_NOT_FOUND, ObservationReader,
    PlatformInspector, PortError, PreflightService, SamplingService, SamplingTickOutcome,
    SharedEvidenceStore, SystemClock,
    linux::acceptance_fault::ACCEPTANCE_DIAGNOSTICS_ENV,
    ownership::{FileOwnershipRepository, OwnershipRecord, RunId},
    protocol::{
        ControlRequest, ControlResponse, ERROR_COMMAND_NOT_IMPLEMENTED, ERROR_EARLY_EOF,
        ERROR_INTERNAL, ERROR_INVALID_REQUEST, ERROR_PAYLOAD_TOO_LARGE, ERROR_REQUEST_TIMEOUT,
        ERROR_RESPONSE_TOO_LARGE, ERROR_TRANSPORT, ERROR_UNSUPPORTED_PROTOCOL_VERSION,
        ProtocolError, decode_request, encode_response,
    },
    transport::{TransportError, read_frame, write_frame},
};
use l2_loop_core::{
    AgentCommand, AgentResult, EvidenceCursor, EvidenceDetailV1, EvidenceListPageV1,
    EvidenceListQuery, EventId, InterfaceName, InterfaceStatus, ObservationSnapshot,
    PF_OWNERSHIP_MISMATCH,
};

pub const DEFAULT_SOCKET_PATH: &str = "/run/l2-loop/agent.sock";
pub const MAX_ACTIVE_HANDLERS: usize = 16;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const EVIDENCE_INVALID_REQUEST: &str = "EVIDENCE_INVALID_REQUEST";
pub const EVIDENCE_NOT_FOUND: &str = "EVIDENCE_NOT_FOUND";
pub const EVIDENCE_UNAVAILABLE: &str = "EVIDENCE_UNAVAILABLE";

pub struct DaemonDispatcher<P> {
    preflight: Arc<Mutex<PreflightService<P>>>,
    isolated: Option<Arc<Mutex<Box<dyn IsolatedControl>>>>,
    evidence: Option<Arc<Mutex<Box<dyn EvidenceControl>>>>,
}

impl<P> Clone for DaemonDispatcher<P> {
    fn clone(&self) -> Self {
        Self {
            preflight: self.preflight.clone(),
            isolated: self.isolated.clone(),
            evidence: self.evidence.clone(),
        }
    }
}

impl<P> DaemonDispatcher<P>
where
    P: PlatformInspector + Send + 'static,
{
    pub fn new(preflight: PreflightService<P>) -> Self {
        Self {
            preflight: Arc::new(Mutex::new(preflight)),
            isolated: None,
            evidence: None,
        }
    }

    pub fn with_isolated_control<C>(preflight: PreflightService<P>, isolated: C) -> Self
    where
        C: IsolatedControl + 'static,
    {
        Self {
            preflight: Arc::new(Mutex::new(preflight)),
            isolated: Some(Arc::new(Mutex::new(Box::new(isolated)))),
            evidence: None,
        }
    }

    pub fn with_controls<C, E>(preflight: PreflightService<P>, isolated: C, evidence: E) -> Self
    where
        C: IsolatedControl + 'static,
        E: EvidenceControl + 'static,
    {
        Self {
            preflight: Arc::new(Mutex::new(preflight)),
            isolated: Some(Arc::new(Mutex::new(Box::new(isolated)))),
            evidence: Some(Arc::new(Mutex::new(Box::new(evidence)))),
        }
    }

    pub async fn dispatch(&self, request: ControlRequest) -> ControlResponse {
        match request.command {
            AgentCommand::Preflight { interface } => {
                let preflight = self.preflight.clone();
                let inspected = tokio::task::spawn_blocking(move || {
                    let mut service = preflight.lock().map_err(|_| ())?;
                    service.execute(&interface).map_err(|_| ())
                })
                .await;
                match inspected {
                    Ok(Ok(result)) => ControlResponse::success(result),
                    Ok(Err(())) | Err(_) => {
                        ControlResponse::error(ERROR_INTERNAL, "preflight inspection failed")
                    }
                }
            }
            AgentCommand::IsolatedAttach { interface, run_id } => {
                let Some(run_id) = parse_run_id(&run_id) else {
                    return ControlResponse::error(
                        ERROR_INVALID_REQUEST,
                        "invalid isolated run ID",
                    );
                };
                let Some(isolated) = self.isolated.clone() else {
                    return ControlResponse::error(
                        ERROR_COMMAND_NOT_IMPLEMENTED,
                        "isolated control is not enabled",
                    );
                };
                let controlled = tokio::task::spawn_blocking(move || {
                    let mut control = isolated.lock().map_err(|_| IsolatedDispatchFailure::Lock)?;
                    control
                        .attach(&interface, &run_id)
                        .map_err(IsolatedDispatchFailure::Control)
                })
                .await;
                isolated_response(controlled)
            }
            AgentCommand::IsolatedDetach { run_id } => {
                let Some(run_id) = parse_run_id(&run_id) else {
                    return ControlResponse::error(
                        ERROR_INVALID_REQUEST,
                        "invalid isolated run ID",
                    );
                };
                let Some(isolated) = self.isolated.clone() else {
                    return ControlResponse::error(
                        ERROR_COMMAND_NOT_IMPLEMENTED,
                        "isolated control is not enabled",
                    );
                };
                let controlled = tokio::task::spawn_blocking(move || {
                    let mut control = isolated.lock().map_err(|_| IsolatedDispatchFailure::Lock)?;
                    control
                        .detach(&run_id)
                        .map_err(IsolatedDispatchFailure::Control)
                })
                .await;
                isolated_response(controlled)
            }
            AgentCommand::Observe { interface } => {
                let Some(isolated) = self.isolated.clone() else {
                    return ControlResponse::error(
                        ERROR_COMMAND_NOT_IMPLEMENTED,
                        "command is not implemented",
                    );
                };
                let controlled = tokio::task::spawn_blocking(move || {
                    let mut control = isolated.lock().map_err(|_| IsolatedDispatchFailure::Lock)?;
                    control
                        .observe(&interface)
                        .map_err(IsolatedDispatchFailure::Control)
                })
                .await;
                observation_response(controlled, |snapshot| AgentResult::Observation { snapshot })
            }
            AgentCommand::Status { interface } => {
                let Some(isolated) = self.isolated.clone() else {
                    return ControlResponse::error(
                        ERROR_COMMAND_NOT_IMPLEMENTED,
                        "command is not implemented",
                    );
                };
                let controlled = tokio::task::spawn_blocking(move || {
                    let mut control = isolated.lock().map_err(|_| IsolatedDispatchFailure::Lock)?;
                    control
                        .status(interface.as_ref())
                        .map_err(IsolatedDispatchFailure::Control)
                })
                .await;
                observation_response(controlled, |interfaces| AgentResult::Status { interfaces })
            }
            AgentCommand::EvidenceList {
                interface,
                limit,
                cursor,
            } => {
                let Some(evidence) = self.evidence.clone() else {
                    return ControlResponse::error(EVIDENCE_UNAVAILABLE, "evidence is unavailable");
                };
                let controlled = tokio::task::spawn_blocking(move || {
                    let evidence = evidence.lock().map_err(|_| EvidenceControlError::Unavailable)?;
                    evidence.list(interface, limit, cursor.as_deref())
                })
                .await;
                evidence_response(controlled, |page| AgentResult::EvidenceList { page })
            }
            AgentCommand::EvidenceShow { event_id } => {
                let Some(evidence) = self.evidence.clone() else {
                    return ControlResponse::error(EVIDENCE_UNAVAILABLE, "evidence is unavailable");
                };
                let controlled = tokio::task::spawn_blocking(move || {
                    let evidence = evidence.lock().map_err(|_| EvidenceControlError::Unavailable)?;
                    evidence.show(event_id)
                })
                .await;
                evidence_response(controlled, |detail| AgentResult::Evidence { detail })
            }
            _ => {
                ControlResponse::error(ERROR_COMMAND_NOT_IMPLEMENTED, "command is not implemented")
            }
        }
    }

    pub async fn shutdown_isolated(&self) -> Result<(), IsolatedControlError> {
        let Some(isolated) = self.isolated.clone() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || {
            let mut control = isolated
                .lock()
                .map_err(|_| IsolatedControlError::internal("ISOLATED_CONTROL_LOCK"))?;
            control.shutdown()
        })
        .await
        .map_err(|_| IsolatedControlError::internal("ISOLATED_CONTROL_JOIN"))?
    }

    pub async fn sample_isolated(&self) -> Result<IsolatedSamplingOutcome, DaemonError> {
        let Some(isolated) = self.isolated.clone() else {
            return Ok(IsolatedSamplingOutcome::Idle);
        };
        tokio::task::spawn_blocking(move || {
            let mut control = isolated.lock().map_err(|_| DaemonError::Sampler)?;
            control.sample_tick().map_err(|_| DaemonError::Sampler)
        })
        .await
        .map_err(|_| DaemonError::Sampler)?
    }
}

pub trait EvidenceControl: Send {
    fn list(
        &self,
        interface: Option<InterfaceName>,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<EvidenceListPageV1, EvidenceControlError>;

    fn show(&self, event_id: EventId) -> Result<EvidenceDetailV1, EvidenceControlError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceControlError {
    InvalidRequest,
    NotFound,
    Unavailable,
}

impl<S> EvidenceControl for SharedEvidenceStore<S>
where
    S: EvidenceStore + Send + 'static,
{
    fn list(
        &self,
        interface: Option<InterfaceName>,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<EvidenceListPageV1, EvidenceControlError> {
        let cursor = cursor
            .map(|value| EvidenceCursor::parse_for(value, interface.as_ref()))
            .transpose()
            .map_err(|_| EvidenceControlError::InvalidRequest)?;
        let query = EvidenceListQuery::new(interface, Some(limit), cursor)
            .map_err(|_| EvidenceControlError::InvalidRequest)?;
        let page = EvidenceStore::list(self, &query).map_err(map_evidence_error)?;
        Ok(EvidenceListPageV1 {
            items: page.items,
            next_cursor: page.next_cursor.map(|cursor| cursor.to_string()),
        })
    }

    fn show(&self, event_id: EventId) -> Result<EvidenceDetailV1, EvidenceControlError> {
        EvidenceStore::get(self, event_id).map_err(map_evidence_error)
    }
}

fn map_evidence_error(error: EvidenceStoreError) -> EvidenceControlError {
    if error == EvidenceStoreError::NotFound {
        EvidenceControlError::NotFound
    } else {
        EvidenceControlError::Unavailable
    }
}

fn evidence_response<T, F>(
    controlled: Result<Result<T, EvidenceControlError>, tokio::task::JoinError>,
    success: F,
) -> ControlResponse
where
    F: FnOnce(T) -> AgentResult,
{
    match controlled {
        Ok(Ok(value)) => ControlResponse::success(success(value)),
        Ok(Err(EvidenceControlError::InvalidRequest)) => {
            ControlResponse::error(EVIDENCE_INVALID_REQUEST, "invalid bounded evidence query")
        }
        Ok(Err(EvidenceControlError::NotFound)) => {
            ControlResponse::error(EVIDENCE_NOT_FOUND, "evidence event was not found")
        }
        Ok(Err(EvidenceControlError::Unavailable)) | Err(_) => {
            ControlResponse::error(EVIDENCE_UNAVAILABLE, "evidence is unavailable")
        }
    }
}

pub async fn run_sampling_loop<P>(
    dispatcher: DaemonDispatcher<P>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), DaemonError>
where
    P: PlatformInspector + Send + 'static,
{
    run_sampling_loop_with_period(dispatcher, shutdown, Duration::from_secs(1)).await
}

#[doc(hidden)]
pub async fn run_sampling_loop_with_period<P>(
    dispatcher: DaemonDispatcher<P>,
    mut shutdown: watch::Receiver<bool>,
    period: Duration,
) -> Result<(), DaemonError>
where
    P: PlatformInspector + Send + 'static,
{
    if period.is_zero() {
        return Err(DaemonError::Sampler);
    }

    let mut interval = tokio::time::interval_at(Instant::now() + period, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            _ = interval.tick() => {}
        }

        if *shutdown.borrow() {
            return Ok(());
        }
        dispatcher.sample_isolated().await?;
        interval.reset();
    }
}

pub async fn coordinate_daemon<P, Server, Signal>(
    dispatcher: DaemonDispatcher<P>,
    server: Server,
    mut sampler: tokio::task::JoinHandle<Result<(), DaemonError>>,
    shutdown: watch::Sender<bool>,
    signal: Signal,
) -> Result<(), DaemonError>
where
    P: PlatformInspector + Send + 'static,
    Server: Future<Output = Result<(), DaemonError>> + Send,
    Signal: Future<Output = ()> + Send,
{
    enum FirstExit {
        Signal,
        Server(Result<(), DaemonError>),
        Sampler(Result<Result<(), DaemonError>, tokio::task::JoinError>),
    }

    let mut server = Box::pin(server);
    let mut signal = Box::pin(signal);
    let first = tokio::select! {
        _ = &mut signal => FirstExit::Signal,
        result = &mut server => FirstExit::Server(result),
        result = &mut sampler => FirstExit::Sampler(result),
    };

    let _ = shutdown.send(true);

    let (server_result, sampler_result, sampler_exited_first) = match first {
        FirstExit::Signal => (server.await, sampler.await, false),
        FirstExit::Server(result) => (result, sampler.await, false),
        FirstExit::Sampler(result) => (server.await, result, true),
    };
    let cleanup_result = dispatcher
        .shutdown_isolated()
        .await
        .map_err(|_| DaemonError::IsolatedCleanup);

    match sampler_result {
        Ok(Ok(())) if !sampler_exited_first => {}
        Ok(Ok(())) | Ok(Err(_)) | Err(_) => return Err(DaemonError::Sampler),
    }
    server_result?;
    cleanup_result
}

pub trait IsolatedControl: Send {
    fn attach(
        &mut self,
        interface: &l2_loop_core::InterfaceName,
        run_id: &RunId,
    ) -> Result<(), IsolatedControlError>;

    fn detach(&mut self, run_id: &RunId) -> Result<(), IsolatedControlError>;

    fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError>;

    fn observe(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<ObservationSnapshot, IsolatedControlError>;

    fn status(
        &mut self,
        interface: Option<&InterfaceName>,
    ) -> Result<Vec<InterfaceStatus>, IsolatedControlError>;

    fn shutdown(&mut self) -> Result<(), IsolatedControlError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolatedSamplingOutcome {
    Idle,
    Sampled,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolatedControlError {
    code: String,
    blocked: bool,
}

impl IsolatedControlError {
    pub fn blocked(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            blocked: true,
        }
    }

    pub fn internal(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            blocked: false,
        }
    }
}

trait ControlAttachmentDriver: Send {
    fn attach(
        &mut self,
        interface: &InterfaceName,
        run_id: &RunId,
        created_at_unix_seconds: u64,
    ) -> Result<AttachmentSession, IsolatedControlError>;

    fn detach_exact(&mut self, session: &AttachmentSession) -> Result<(), IsolatedControlError>;
}

impl<T> ControlAttachmentDriver for T
where
    T: IsolatedAttachmentDriver,
{
    fn attach(
        &mut self,
        interface: &InterfaceName,
        run_id: &RunId,
        created_at_unix_seconds: u64,
    ) -> Result<AttachmentSession, IsolatedControlError> {
        IsolatedAttachmentDriver::attach(self, interface, run_id, created_at_unix_seconds)
            .map_err(attachment_control_error)
    }

    fn detach_exact(&mut self, session: &AttachmentSession) -> Result<(), IsolatedControlError> {
        IsolatedAttachmentDriver::detach_exact(self, session).map_err(attachment_control_error)
    }
}

trait CanonicalOwnershipReader: Send {
    fn load(&self, run_id: &RunId) -> Result<OwnershipRecord, PortError>;
}

impl CanonicalOwnershipReader for FileOwnershipRepository {
    fn load(&self, run_id: &RunId) -> Result<OwnershipRecord, PortError> {
        FileOwnershipRepository::load(self, run_id)
    }
}

pub struct TransactionIsolatedControl {
    driver: Box<dyn ControlAttachmentDriver>,
    ownership: Box<dyn CanonicalOwnershipReader>,
    sampling: SamplingService<Box<dyn ObservationReader>, SystemClock>,
    incident_output: Option<IncidentOutputHandle>,
    active: Option<ActiveIsolatedSession>,
}

struct ActiveIsolatedSession {
    run_id: RunId,
    interface: InterfaceName,
    attachment: AttachmentSession,
    sampling_paused: bool,
}

impl TransactionIsolatedControl {
    pub fn new<D, R>(driver: D, reader: R) -> Self
    where
        D: IsolatedAttachmentDriver + 'static,
        R: ObservationReader + 'static,
    {
        Self {
            driver: Box::new(driver),
            ownership: Box::new(FileOwnershipRepository),
            sampling: SamplingService::new(Box::new(reader), SystemClock::new()),
            incident_output: None,
            active: None,
        }
    }

    pub fn with_incident_output(mut self, output: IncidentOutputHandle) -> Self {
        self.incident_output = Some(output);
        self
    }

    fn canonical_ownership(
        &self,
        active: &ActiveIsolatedSession,
    ) -> Result<crate::ownership::OwnershipRecord, IsolatedControlError> {
        let committed = self
            .ownership
            .load(&active.run_id)
            .map_err(|_| IsolatedControlError::internal(OBS_OWNERSHIP_MISMATCH))?;
        if committed != active.attachment.ownership {
            return Err(IsolatedControlError::internal(OBS_OWNERSHIP_MISMATCH));
        }
        Ok(committed)
    }

    fn flush_incident_jobs(&mut self) {
        let jobs = self.sampling.take_incident_jobs();
        let Some(output) = self.incident_output.as_ref() else {
            return;
        };
        for job in jobs {
            let _ = output.try_submit(job);
        }
    }
}

impl IsolatedControl for TransactionIsolatedControl {
    fn attach(
        &mut self,
        interface: &l2_loop_core::InterfaceName,
        run_id: &RunId,
    ) -> Result<(), IsolatedControlError> {
        if self.active.is_some() {
            return Err(IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH));
        }
        let created_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IsolatedControlError::internal("SYSTEM_CLOCK_INVALID"))?
            .as_secs();
        let session = self
            .driver
            .attach(interface, run_id, created_at_unix_seconds)?;
        self.sampling
            .start(&session.ownership)
            .map_err(observation_control_error)?;
        self.sampling
            .start_incident_generation(interface, &session.ownership)
            .map_err(observation_control_error)?;
        self.active = Some(ActiveIsolatedSession {
            run_id: run_id.clone(),
            interface: interface.clone(),
            attachment: session,
            sampling_paused: false,
        });
        Ok(())
    }

    fn detach(&mut self, run_id: &RunId) -> Result<(), IsolatedControlError> {
        let Some(active) = self.active.as_ref() else {
            return Err(IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH));
        };
        if &active.run_id != run_id {
            return Err(IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH));
        }
        let committed = self
            .ownership
            .load(run_id)
            .map_err(|_| IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH))?;
        if committed != active.attachment.ownership {
            return Err(IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH));
        }
        self.sampling.pause();
        self.flush_incident_jobs();
        self.active
            .as_mut()
            .expect("active session was validated")
            .sampling_paused = true;
        let active = self.active.as_ref().expect("active session was validated");
        self.driver.detach_exact(&active.attachment)?;
        self.sampling.generation_ended();
        self.flush_incident_jobs();
        self.sampling.clear();
        self.active = None;
        Ok(())
    }

    fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError> {
        let Some(active) = self.active.as_ref() else {
            return Ok(IsolatedSamplingOutcome::Idle);
        };
        if active.sampling_paused {
            return Ok(IsolatedSamplingOutcome::Rejected);
        }
        let ownership = self.canonical_ownership(active)?;
        let outcome = match self.sampling.sample_tick(&ownership) {
            SamplingTickOutcome::Sampled => IsolatedSamplingOutcome::Sampled,
            SamplingTickOutcome::Rejected => IsolatedSamplingOutcome::Rejected,
        };
        self.flush_incident_jobs();
        Ok(outcome)
    }

    fn observe(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<ObservationSnapshot, IsolatedControlError> {
        let Some(active) = self.active.as_ref() else {
            return Err(IsolatedControlError::internal(OBS_SESSION_NOT_FOUND));
        };
        let ownership = self.canonical_ownership(active)?;
        self.sampling
            .observe(interface, &active.interface, &ownership)
            .map_err(observation_control_error)
    }

    fn status(
        &mut self,
        interface: Option<&InterfaceName>,
    ) -> Result<Vec<InterfaceStatus>, IsolatedControlError> {
        let Some(active) = self.active.as_ref() else {
            return self
                .sampling
                .status(interface, None, None)
                .map_err(observation_control_error);
        };
        if interface.is_some_and(|requested| requested != &active.interface) {
            return Err(IsolatedControlError::internal(OBS_SESSION_NOT_FOUND));
        }
        let ownership = self.canonical_ownership(active)?;
        let mut statuses = self
            .sampling
            .status(interface, Some(&active.interface), Some(&ownership))
            .map_err(observation_control_error)?;
        let output_health = self.incident_output.as_ref().map_or_else(
            || l2_loop_core::OutputHealth::unavailable("OUTPUT_NOT_CONFIGURED"),
            IncidentOutputHandle::health,
        );
        let active_incident = self.sampling.active_incident();
        for status in &mut statuses {
            status.output_health = output_health.clone();
            status.active_incident = active_incident;
        }
        Ok(statuses)
    }

    fn shutdown(&mut self) -> Result<(), IsolatedControlError> {
        let Some(active) = self.active.as_ref() else {
            return Ok(());
        };
        let run_id = active.run_id.clone();
        self.detach(&run_id)
    }
}

fn attachment_control_error(error: crate::AttachmentError) -> IsolatedControlError {
    if std::env::var_os(ACCEPTANCE_DIAGNOSTICS_ENV).is_some() {
        eprintln!(
            "isolated acceptance detail: {}: {}",
            error.code(),
            error.evidence()
        );
    }
    if error.code().starts_with("PF_") {
        IsolatedControlError::blocked(error.code())
    } else {
        IsolatedControlError::internal(error.code())
    }
}

fn observation_control_error(error: crate::ObservationError) -> IsolatedControlError {
    IsolatedControlError::internal(error.code())
}

fn parse_run_id(value: &str) -> Option<RunId> {
    RunId::parse(value).ok()
}

#[derive(Debug)]
enum IsolatedDispatchFailure {
    Lock,
    Control(IsolatedControlError),
}

fn isolated_response(
    controlled: Result<Result<(), IsolatedDispatchFailure>, tokio::task::JoinError>,
) -> ControlResponse {
    match controlled {
        Ok(Ok(())) => ControlResponse::success(l2_loop_core::AgentResult::Accepted),
        Ok(Err(IsolatedDispatchFailure::Control(error))) if error.blocked => {
            ControlResponse::error(error.code, "isolated attachment was blocked")
        }
        Ok(Err(IsolatedDispatchFailure::Control(error))) => {
            ControlResponse::error(error.code, "isolated control failed")
        }
        Ok(Err(IsolatedDispatchFailure::Lock)) | Err(_) => {
            ControlResponse::error(ERROR_INTERNAL, "isolated control failed")
        }
    }
}

fn observation_response<T, F>(
    controlled: Result<Result<T, IsolatedDispatchFailure>, tokio::task::JoinError>,
    result: F,
) -> ControlResponse
where
    F: FnOnce(T) -> AgentResult,
{
    match controlled {
        Ok(Ok(value)) => ControlResponse::success(result(value)),
        Ok(Err(IsolatedDispatchFailure::Control(error))) => {
            ControlResponse::error(error.code, "observation failed")
        }
        Ok(Err(IsolatedDispatchFailure::Lock)) | Err(_) => {
            ControlResponse::error(ERROR_INTERNAL, "observation failed")
        }
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("control socket parent directory is missing or invalid")]
    InvalidParent,
    #[error("control socket parent directory has unsafe ownership")]
    UnsafeParentOwner,
    #[error("control socket parent directory is group/world writable")]
    UnsafeParentPermissions,
    #[error("control socket path exists and is not a socket")]
    SocketPathNotSocket,
    #[error("control socket is already in use")]
    SocketInUse,
    #[error("exact isolated cleanup failed during daemon shutdown")]
    IsolatedCleanup,
    #[error("daemon sampler failed")]
    Sampler,
    #[error("isolated acceptance fault configuration is invalid")]
    InvalidAcceptanceFault,
    #[error("control socket operation failed: {operation}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug)]
pub struct BoundedUnixServer {
    listener: UnixListener,
    owned_path: OwnedSocketPath,
}

impl BoundedUnixServer {
    pub async fn bind(path: impl AsRef<Path>) -> Result<Self, DaemonError> {
        let path = path.as_ref();
        validate_parent(path)?;
        clear_stale_socket(path).await?;

        let listener = UnixListener::bind(path).map_err(|source| DaemonError::Io {
            operation: "bind",
            source,
        })?;
        if let Err(source) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(path);
            return Err(DaemonError::Io {
                operation: "set permissions",
                source,
            });
        }
        let owned_path = match OwnedSocketPath::capture(path) {
            Ok(owned_path) => owned_path,
            Err(error) => {
                let _ = fs::remove_file(path);
                return Err(error);
            }
        };

        Ok(Self {
            listener,
            owned_path,
        })
    }

    pub async fn serve<H, Fut, S>(self, handler: H, shutdown: S) -> Result<(), DaemonError>
    where
        H: Fn(ControlRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = ControlResponse> + Send + 'static,
        S: Future<Output = ()> + Send,
    {
        let semaphore = Arc::new(Semaphore::new(MAX_ACTIVE_HANDLERS));
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);

        loop {
            reap_finished_connections(&mut tasks);
            let permit = tokio::select! {
                _ = &mut shutdown => break,
                permit = semaphore.clone().acquire_owned() => {
                    permit.map_err(|_| DaemonError::Io {
                        operation: "acquire handler permit",
                        source: io::Error::other("handler semaphore closed"),
                    })?
                }
            };
            let stream = tokio::select! {
                _ = &mut shutdown => {
                    drop(permit);
                    break;
                }
                accepted = self.listener.accept() => {
                    accepted.map_err(|source| DaemonError::Io {
                        operation: "accept",
                        source,
                    })?.0
                }
            };
            let connection_handler = handler.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let _ = serve_connection(stream, connection_handler).await;
            });
        }

        while tasks.join_next().await.is_some() {}
        drop(self.owned_path);
        Ok(())
    }
}

async fn serve_connection<H, Fut>(mut stream: UnixStream, handler: H) -> Result<(), TransportError>
where
    H: Fn(ControlRequest) -> Fut,
    Fut: Future<Output = ControlResponse>,
{
    let response =
        match tokio::time::timeout(REQUEST_TIMEOUT, response_for(&mut stream, handler)).await {
            Ok(response) => response,
            Err(_) => ControlResponse::error(ERROR_REQUEST_TIMEOUT, "request timed out"),
        };
    let frame = encode_bounded_response(response);
    write_response_with_timeout(&mut stream, &frame, REQUEST_TIMEOUT).await
}

async fn write_response_with_timeout<W>(
    writer: &mut W,
    frame: &[u8],
    timeout: Duration,
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, async {
        write_frame(writer, frame).await?;
        writer.shutdown().await.map_err(TransportError::Io)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(TransportError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "response write timed out",
        ))),
    }
}

fn reap_finished_connections(tasks: &mut JoinSet<()>) {
    while tasks.try_join_next().is_some() {}
}

async fn response_for<H, Fut>(stream: &mut UnixStream, handler: H) -> ControlResponse
where
    H: Fn(ControlRequest) -> Fut,
    Fut: Future<Output = ControlResponse>,
{
    let frame = match read_frame(stream).await {
        Ok(frame) => frame,
        Err(error) => return transport_error_response(error),
    };
    let request = match decode_request(&frame) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(error),
    };
    handler(request).await
}

fn transport_error_response(error: TransportError) -> ControlResponse {
    match error {
        TransportError::EarlyEof { .. } => {
            ControlResponse::error(ERROR_EARLY_EOF, "request frame ended early")
        }
        TransportError::PayloadTooLarge { .. } => {
            ControlResponse::error(ERROR_PAYLOAD_TOO_LARGE, "request payload is too large")
        }
        TransportError::Io(_) => {
            ControlResponse::error(ERROR_TRANSPORT, "request transport failed")
        }
    }
}

fn protocol_error_response(error: ProtocolError) -> ControlResponse {
    match error {
        ProtocolError::UnsupportedVersion(_) => ControlResponse::error(
            ERROR_UNSUPPORTED_PROTOCOL_VERSION,
            "unsupported protocol version",
        ),
        ProtocolError::PayloadTooLarge { .. } => {
            ControlResponse::error(ERROR_PAYLOAD_TOO_LARGE, "request payload is too large")
        }
        _ => ControlResponse::error(ERROR_INVALID_REQUEST, "request is malformed"),
    }
}

fn encode_bounded_response(response: ControlResponse) -> Vec<u8> {
    match encode_response(&response) {
        Ok(frame) => frame,
        Err(ProtocolError::PayloadTooLarge { .. }) => encode_response(&ControlResponse::error(
            ERROR_RESPONSE_TOO_LARGE,
            "response payload is too large",
        ))
        .expect("fixed response-too-large error must fit the frame limit"),
        Err(_) => encode_response(&ControlResponse::error(
            ERROR_INTERNAL,
            "response encoding failed",
        ))
        .expect("fixed internal error must fit the frame limit"),
    }
}

fn validate_parent(path: &Path) -> Result<(), DaemonError> {
    let parent = path.parent().ok_or(DaemonError::InvalidParent)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| DaemonError::InvalidParent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DaemonError::InvalidParent);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(DaemonError::UnsafeParentPermissions);
    }

    let required_uid = if path == Path::new(DEFAULT_SOCKET_PATH) {
        0
    } else {
        nix::unistd::geteuid().as_raw()
    };
    if metadata.uid() != required_uid {
        return Err(DaemonError::UnsafeParentOwner);
    }
    Ok(())
}

async fn clear_stale_socket(path: &Path) -> Result<(), DaemonError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(DaemonError::Io {
                operation: "inspect existing socket path",
                source,
            });
        }
    };
    if !metadata.file_type().is_socket() {
        return Err(DaemonError::SocketPathNotSocket);
    }
    let device = metadata.dev();
    let inode = metadata.ino();

    match UnixStream::connect(path).await {
        Ok(_) => return Err(DaemonError::SocketInUse),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(_) => return Err(DaemonError::SocketInUse),
    }
    remove_stale_socket_if_unchanged(path, device, inode)
}

fn remove_stale_socket_if_unchanged(
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), DaemonError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(DaemonError::Io {
                operation: "reinspect stale socket",
                source,
            });
        }
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
    {
        return Err(DaemonError::SocketInUse);
    }
    fs::remove_file(path).map_err(|source| DaemonError::Io {
        operation: "remove stale socket",
        source,
    })
}

#[derive(Debug)]
struct OwnedSocketPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl OwnedSocketPath {
    fn capture(path: &Path) -> Result<Self, DaemonError> {
        let metadata = fs::symlink_metadata(path).map_err(|source| DaemonError::Io {
            operation: "record socket identity",
            source,
        })?;
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for OwnedSocketPath {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        os::unix::net::UnixListener as StdUnixListener,
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use l2_loop_common::ABI_VERSION;
    use l2_loop_core::{
        ClassObservation, HookObservation, HookRole, InterfaceState, OBSERVED_CLASS_COUNT,
        ObservationCounters, RateWindowState, TrafficClass, VlanVisibility,
    };

    use super::*;
    use crate::{
        LoadedBpfObject, ObservationReadPurpose, RawObservation,
        linux::{tc::LoadedTc, xdp::LoadedXdp},
        ownership::{OWNED_MAP_NAMES, OWNERSHIP_SCHEMA_VERSION, OwnedMapPin},
    };

    const FIRST_RUN_ID: &str = "0123456789abcdef0123456789abcdef";
    const SECOND_RUN_ID: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn tick_without_active_session_is_idle_and_does_not_read() {
        let (mut control, state) = lifecycle_control(0);

        assert_eq!(
            control.sample_tick().unwrap(),
            IsolatedSamplingOutcome::Idle
        );
        assert_eq!(state.reader_reads.load(Ordering::SeqCst), 0);
        assert!(state.events.lock().unwrap().is_empty());
    }

    #[test]
    fn attach_starts_an_empty_history_for_committed_identity() {
        let (mut control, _) = lifecycle_control(0);
        let run_id = run_id(FIRST_RUN_ID);
        let interface = lifecycle_interface();

        control.attach(&interface, &run_id).unwrap();
        let snapshot = control.observe(&interface).unwrap();

        assert_eq!(snapshot.generation, 7);
        assert_eq!(snapshot.sampling, l2_loop_core::SamplingStatus::default());
        assert_eq!(
            snapshot.baseline.state,
            l2_loop_core::BaselineState::Learning
        );
        assert_eq!(
            snapshot.detection.state,
            l2_loop_core::DetectionState::WarmingUp
        );
        assert!(
            snapshot
                .baseline
                .subjects
                .iter()
                .all(|subject| subject.sample_count == 0)
        );
        assert!(
            snapshot
                .rate_windows
                .iter()
                .all(|window| window.state == RateWindowState::WarmingUp)
        );
    }

    #[test]
    fn tick_uses_the_canonical_journal_before_reader_io() {
        let (mut control, state) = lifecycle_control(0);
        let run_id = run_id(FIRST_RUN_ID);
        control.attach(&lifecycle_interface(), &run_id).unwrap();
        state.events.lock().unwrap().clear();

        assert_eq!(
            control.sample_tick().unwrap(),
            IsolatedSamplingOutcome::Sampled
        );
        assert_eq!(
            state.events.lock().unwrap().as_slice(),
            [
                format!("journal:{}", run_id.as_str()),
                "read:background".to_owned(),
            ]
        );
    }

    #[test]
    fn successful_detach_clears_sampling_state() {
        let (mut control, state) = lifecycle_control(0);
        let run_id = run_id(FIRST_RUN_ID);
        control.attach(&lifecycle_interface(), &run_id).unwrap();
        assert_eq!(
            control.sample_tick().unwrap(),
            IsolatedSamplingOutcome::Sampled
        );

        control.detach(&run_id).unwrap();

        assert_eq!(
            control.sample_tick().unwrap(),
            IsolatedSamplingOutcome::Idle
        );
        assert_eq!(state.reader_reads.load(Ordering::SeqCst), 1);
        assert!(control.status(None).unwrap().is_empty());
    }

    #[test]
    fn failed_detach_pauses_and_clears_but_preserves_active_ownership() {
        let (mut control, state) = lifecycle_control(1);
        let run_id = run_id(FIRST_RUN_ID);
        control.attach(&lifecycle_interface(), &run_id).unwrap();

        assert!(control.detach(&run_id).is_err());
        let snapshot = control.observe(&lifecycle_interface()).unwrap();
        assert_eq!(
            snapshot.detection.state,
            l2_loop_core::DetectionState::Unavailable
        );
        assert_eq!(
            control.sample_tick().unwrap(),
            IsolatedSamplingOutcome::Rejected
        );
        assert_eq!(state.reader_reads.load(Ordering::SeqCst), 1);

        control.detach(&run_id).unwrap();
        let detach_calls = state
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.starts_with("detach:"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            detach_calls,
            [
                format!("detach:{}", run_id.as_str()),
                format!("detach:{}", run_id.as_str()),
            ]
        );
    }

    #[test]
    fn reattach_uses_a_new_empty_generation() {
        let (mut control, _) = lifecycle_control(0);
        let first_run = run_id(FIRST_RUN_ID);
        let second_run = run_id(SECOND_RUN_ID);
        let interface = lifecycle_interface();
        control.attach(&interface, &first_run).unwrap();
        assert_eq!(
            control.sample_tick().unwrap(),
            IsolatedSamplingOutcome::Sampled
        );
        control.detach(&first_run).unwrap();

        control.attach(&interface, &second_run).unwrap();
        let snapshot = control.observe(&interface).unwrap();

        assert_eq!(snapshot.generation, 8);
        assert_eq!(snapshot.sampling, l2_loop_core::SamplingStatus::default());
        assert_eq!(
            snapshot.baseline.state,
            l2_loop_core::BaselineState::Learning
        );
        assert!(
            snapshot
                .baseline
                .subjects
                .iter()
                .all(|subject| subject.sample_count == 0)
        );
        assert!(
            snapshot
                .rate_windows
                .iter()
                .all(|window| window.state == RateWindowState::WarmingUp)
        );
    }

    #[test]
    fn shutdown_serializes_sampling_before_exact_cleanup() {
        let (mut control, state) = lifecycle_control(0);
        let run_id = run_id(FIRST_RUN_ID);
        control.attach(&lifecycle_interface(), &run_id).unwrap();
        state.events.lock().unwrap().clear();

        assert_eq!(
            control.sample_tick().unwrap(),
            IsolatedSamplingOutcome::Sampled
        );
        control.shutdown().unwrap();

        assert_eq!(
            state.events.lock().unwrap().as_slice(),
            [
                format!("journal:{}", run_id.as_str()),
                "read:background".to_owned(),
                format!("journal:{}", run_id.as_str()),
                format!("detach:{}", run_id.as_str()),
            ]
        );
    }

    struct LifecycleState {
        events: Arc<Mutex<Vec<String>>>,
        reader_reads: Arc<AtomicUsize>,
    }

    fn lifecycle_control(detach_failures: usize) -> (TransactionIsolatedControl, LifecycleState) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let reader_reads = Arc::new(AtomicUsize::new(0));
        let records = [
            (
                FIRST_RUN_ID.to_owned(),
                lifecycle_ownership(FIRST_RUN_ID, 7),
            ),
            (
                SECOND_RUN_ID.to_owned(),
                lifecycle_ownership(SECOND_RUN_ID, 8),
            ),
        ]
        .into_iter()
        .collect();
        let control = TransactionIsolatedControl {
            driver: Box::new(FakeControlAttachmentDriver {
                events: events.clone(),
                detach_failures,
            }),
            ownership: Box::new(FakeCanonicalOwnershipReader {
                events: events.clone(),
                records,
            }),
            sampling: SamplingService::new(
                Box::new(LifecycleObservationReader {
                    events: events.clone(),
                    reads: reader_reads.clone(),
                }),
                SystemClock::new(),
            ),
            incident_output: None,
            active: None,
        };
        (
            control,
            LifecycleState {
                events,
                reader_reads,
            },
        )
    }

    struct FakeControlAttachmentDriver {
        events: Arc<Mutex<Vec<String>>>,
        detach_failures: usize,
    }

    impl ControlAttachmentDriver for FakeControlAttachmentDriver {
        fn attach(
            &mut self,
            interface: &InterfaceName,
            run_id: &RunId,
            _: u64,
        ) -> Result<AttachmentSession, IsolatedControlError> {
            self.events.lock().unwrap().push(format!(
                "attach:{}:{}",
                interface.as_str(),
                run_id.as_str()
            ));
            let generation = if run_id.as_str() == FIRST_RUN_ID {
                7
            } else {
                8
            };
            Ok(lifecycle_session(run_id.as_str(), generation))
        }

        fn detach_exact(
            &mut self,
            session: &AttachmentSession,
        ) -> Result<(), IsolatedControlError> {
            let run_id = session
                .ownership
                .map_pins
                .first()
                .and_then(|pin| pin.path.parent())
                .and_then(Path::file_name)
                .and_then(|value| value.to_str())
                .unwrap();
            self.events.lock().unwrap().push(format!("detach:{run_id}"));
            if self.detach_failures > 0 {
                self.detach_failures -= 1;
                Err(IsolatedControlError::internal("OWNED_CLEANUP_INCOMPLETE"))
            } else {
                Ok(())
            }
        }
    }

    struct FakeCanonicalOwnershipReader {
        events: Arc<Mutex<Vec<String>>>,
        records: HashMap<String, OwnershipRecord>,
    }

    impl CanonicalOwnershipReader for FakeCanonicalOwnershipReader {
        fn load(&self, run_id: &RunId) -> Result<OwnershipRecord, PortError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("journal:{}", run_id.as_str()));
            self.records
                .get(run_id.as_str())
                .cloned()
                .ok_or_else(|| PortError::Adapter("missing canonical ownership".to_owned()))
        }
    }

    struct LifecycleObservationReader {
        events: Arc<Mutex<Vec<String>>>,
        reads: Arc<AtomicUsize>,
    }

    impl ObservationReader for LifecycleObservationReader {
        fn read_exact(
            &mut self,
            ownership: &OwnershipRecord,
            purpose: ObservationReadPurpose,
        ) -> Result<RawObservation, PortError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.events.lock().unwrap().push(match purpose {
                ObservationReadPurpose::Request => "read:request".to_owned(),
                ObservationReadPurpose::BackgroundSample => "read:background".to_owned(),
                ObservationReadPurpose::BackgroundAnalysis => "read:analysis".to_owned(),
            });
            Ok(lifecycle_raw(ownership))
        }
    }

    fn lifecycle_session(run_id: &str, generation: u64) -> AttachmentSession {
        let ownership = lifecycle_ownership(run_id, generation);
        AttachmentSession {
            state: InterfaceState::Observing,
            generation,
            loaded: LoadedBpfObject {
                xdp: LoadedXdp {
                    program_fd: -1,
                    program_id: 101,
                    program_tag: [1; 8],
                },
                tc_egress: LoadedTc {
                    program_fd: -1,
                    program_id: 102,
                },
                map_pins: ownership.map_pins.clone(),
            },
            ownership,
        }
    }

    fn lifecycle_ownership(run_id: &str, generation: u64) -> OwnershipRecord {
        OwnershipRecord {
            schema_version: OWNERSHIP_SCHEMA_VERSION,
            abi_version: ABI_VERSION,
            generation,
            ifindex: 41,
            xdp: None,
            tc: Vec::new(),
            map_pins: OWNED_MAP_NAMES
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    OwnedMapPin::new(
                        *name,
                        PathBuf::from(format!("/sys/fs/bpf/l2-loop/test/{run_id}/{name}")),
                        301 + u32::try_from(index).unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
            created_at_unix_seconds: 1_787_000_000,
        }
    }

    fn lifecycle_raw(ownership: &OwnershipRecord) -> RawObservation {
        RawObservation {
            ifindex: ownership.ifindex,
            generation: ownership.generation,
            vlan_visibility: VlanVisibility::VerifiedVisible,
            hooks: [
                lifecycle_hook(HookRole::ExternalXdpIngress),
                lifecycle_hook(HookRole::PhysicalTcEgress),
            ],
            fingerprints: crate::RawFingerprints::NotRequested,
        }
    }

    fn lifecycle_hook(role: HookRole) -> HookObservation {
        const CLASS_ORDER: [TrafficClass; OBSERVED_CLASS_COUNT] = [
            TrafficClass::L2Broadcast,
            TrafficClass::Ipv4Multicast,
            TrafficClass::Ipv6Multicast,
            TrafficClass::OtherL2Multicast,
            TrafficClass::LinkLocalControl,
            TrafficClass::UnicastOrUnclassified,
        ];
        HookObservation {
            role,
            total: ObservationCounters {
                packets: 10,
                bytes: 600,
            },
            classes: CLASS_ORDER.map(|traffic_class| ClassObservation {
                traffic_class,
                counters: ObservationCounters {
                    packets: 1,
                    bytes: 60,
                },
            }),
            parse_errors: ObservationCounters {
                packets: 0,
                bytes: 0,
            },
        }
    }

    fn lifecycle_interface() -> InterfaceName {
        InterfaceName::new("l2h0123456789").unwrap()
    }

    fn run_id(value: &str) -> RunId {
        RunId::parse(value).unwrap()
    }

    #[test]
    fn never_unlinks_a_replacement_at_a_stale_socket_path() {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "l2-loop-stale-replacement-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("agent.sock");
        let listener = StdUnixListener::bind(&path).unwrap();
        let stale_metadata = fs::symlink_metadata(&path).unwrap();
        drop(listener);

        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement must survive").unwrap();

        let result =
            remove_stale_socket_if_unchanged(&path, stale_metadata.dev(), stale_metadata.ino());

        assert!(matches!(result, Err(DaemonError::SocketInUse)));
        assert_eq!(fs::read(&path).unwrap(), b"replacement must survive");
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[tokio::test]
    async fn response_write_stops_at_its_deadline() {
        let (mut writer, _reader) = tokio::io::duplex(1);

        let error = write_response_with_timeout(
            &mut writer,
            &[0_u8; 128],
            std::time::Duration::from_millis(10),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(error) if error.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[tokio::test]
    async fn completed_connection_tasks_are_reaped() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async {});
        tokio::task::yield_now().await;

        reap_finished_connections(&mut tasks);

        assert!(tasks.is_empty());
    }
}
