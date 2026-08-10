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
    sync::Semaphore,
    task::JoinSet,
};

use crate::{
    AttachmentSession, IsolatedAttachmentDriver, PlatformInspector, PreflightService,
    ownership::{FileOwnershipRepository, RunId},
    protocol::{
        ControlRequest, ControlResponse, ERROR_COMMAND_NOT_IMPLEMENTED, ERROR_EARLY_EOF,
        ERROR_INTERNAL, ERROR_INVALID_REQUEST, ERROR_PAYLOAD_TOO_LARGE, ERROR_REQUEST_TIMEOUT,
        ERROR_RESPONSE_TOO_LARGE, ERROR_TRANSPORT, ERROR_UNSUPPORTED_PROTOCOL_VERSION,
        ProtocolError, decode_request, encode_response,
    },
    transport::{TransportError, read_frame, write_frame},
};
use l2_loop_core::{AgentCommand, PF_OWNERSHIP_MISMATCH};

pub const DEFAULT_SOCKET_PATH: &str = "/run/l2-loop/agent.sock";
pub const MAX_ACTIVE_HANDLERS: usize = 16;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DaemonDispatcher<P> {
    preflight: Arc<Mutex<PreflightService<P>>>,
    isolated: Option<Arc<Mutex<Box<dyn IsolatedControl>>>>,
}

impl<P> Clone for DaemonDispatcher<P> {
    fn clone(&self) -> Self {
        Self {
            preflight: self.preflight.clone(),
            isolated: self.isolated.clone(),
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
        }
    }

    pub fn with_isolated_control<C>(preflight: PreflightService<P>, isolated: C) -> Self
    where
        C: IsolatedControl + 'static,
    {
        Self {
            preflight: Arc::new(Mutex::new(preflight)),
            isolated: Some(Arc::new(Mutex::new(Box::new(isolated)))),
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
}

pub trait IsolatedControl: Send {
    fn attach(
        &mut self,
        interface: &l2_loop_core::InterfaceName,
        run_id: &RunId,
    ) -> Result<(), IsolatedControlError>;

    fn detach(&mut self, run_id: &RunId) -> Result<(), IsolatedControlError>;

    fn shutdown(&mut self) -> Result<(), IsolatedControlError>;
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

pub struct TransactionIsolatedControl {
    driver: Box<dyn IsolatedAttachmentDriver>,
    ownership: FileOwnershipRepository,
    active: Option<(RunId, AttachmentSession)>,
}

impl TransactionIsolatedControl {
    pub fn new<D>(driver: D) -> Self
    where
        D: IsolatedAttachmentDriver + 'static,
    {
        Self {
            driver: Box::new(driver),
            ownership: FileOwnershipRepository,
            active: None,
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
            .attach(interface, run_id, created_at_unix_seconds)
            .map_err(attachment_control_error)?;
        self.active = Some((run_id.clone(), session));
        Ok(())
    }

    fn detach(&mut self, run_id: &RunId) -> Result<(), IsolatedControlError> {
        let Some((active_run, session)) = self.active.as_ref() else {
            return Err(IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH));
        };
        if active_run != run_id {
            return Err(IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH));
        }
        let committed = self
            .ownership
            .load(run_id)
            .map_err(|_| IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH))?;
        if committed != session.ownership {
            return Err(IsolatedControlError::blocked(PF_OWNERSHIP_MISMATCH));
        }
        self.driver
            .detach_exact(session)
            .map_err(attachment_control_error)?;
        self.active = None;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), IsolatedControlError> {
        let Some((run_id, _)) = self.active.as_ref() else {
            return Ok(());
        };
        let run_id = run_id.clone();
        self.detach(&run_id)
    }
}

fn attachment_control_error(error: crate::AttachmentError) -> IsolatedControlError {
    if error.code().starts_with("PF_") {
        IsolatedControlError::blocked(error.code())
    } else {
        IsolatedControlError::internal(error.code())
    }
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
        os::unix::net::UnixListener as StdUnixListener,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

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
