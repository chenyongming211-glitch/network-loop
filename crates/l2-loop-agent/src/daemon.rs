use std::{
    fs,
    future::Future,
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
};

use crate::{
    protocol::{
        ControlRequest, ControlResponse, ERROR_EARLY_EOF, ERROR_INTERNAL, ERROR_INVALID_REQUEST,
        ERROR_PAYLOAD_TOO_LARGE, ERROR_REQUEST_TIMEOUT, ERROR_RESPONSE_TOO_LARGE, ERROR_TRANSPORT,
        ERROR_UNSUPPORTED_PROTOCOL_VERSION, ProtocolError, decode_request, encode_response,
    },
    transport::{TransportError, read_frame, write_frame},
};

pub const DEFAULT_SOCKET_PATH: &str = "/run/l2-loop/agent.sock";
pub const MAX_ACTIVE_HANDLERS: usize = 16;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

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
    write_frame(&mut stream, &frame).await?;
    stream.shutdown().await.map_err(TransportError::Io)
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
