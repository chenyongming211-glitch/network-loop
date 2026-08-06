#![cfg(target_os = "linux")]

use std::{
    future::{Future, pending},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use l2_loop_agent::{
    daemon::{BoundedUnixServer, DaemonError, MAX_ACTIVE_HANDLERS, REQUEST_TIMEOUT},
    protocol::{
        ControlRequest, ControlResponse, ERROR_EARLY_EOF, ERROR_INVALID_REQUEST,
        ERROR_PAYLOAD_TOO_LARGE, ERROR_REQUEST_TIMEOUT, ERROR_UNSUPPORTED_PROTOCOL_VERSION,
        MAX_PAYLOAD_LEN, ResponseBody, decode_response, encode_request,
    },
    transport::{TransportError, read_frame, write_frame},
};
use l2_loop_core::{AgentCommand, AgentResult};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::oneshot,
    task::JoinHandle,
};

#[tokio::test]
async fn serves_exactly_one_request_and_response_per_connection() {
    let socket = SocketFixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = calls.clone();
    let server = RunningServer::start(&socket.path, move |_request| {
        let handler_calls = handler_calls.clone();
        async move {
            handler_calls.fetch_add(1, Ordering::SeqCst);
            ControlResponse::success(AgentResult::Accepted)
        }
    })
    .await;
    let request = request_frame();
    let mut bytes = request.clone();
    bytes.extend_from_slice(&request);
    let mut stream = UnixStream::connect(&socket.path).await.unwrap();

    stream.write_all(&bytes).await.unwrap();
    let response = decode_response(&read_frame(&mut stream).await.unwrap()).unwrap();
    let mut trailing = [0_u8; 1];
    let connection_closed = match stream.read(&mut trailing).await {
        Ok(0) => true,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => true,
        result => panic!("expected the server to close after one response, got {result:?}"),
    };

    assert_eq!(response, ControlResponse::success(AgentResult::Accepted));
    assert!(connection_closed);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.stop().await;
}

#[tokio::test]
async fn reads_big_endian_frames_and_rejects_sizes_before_payload_allocation() {
    let payload = br#"{"small":true}"#;
    let expected = raw_frame(payload);
    let (mut writer, mut reader) = tokio::io::duplex(128);
    writer.write_all(&expected).await.unwrap();

    assert_eq!(read_frame(&mut reader).await.unwrap(), expected);

    let (mut writer, mut reader) = tokio::io::duplex(16);
    writer
        .write_all(&((MAX_PAYLOAD_LEN + 1) as u32).to_be_bytes())
        .await
        .unwrap();

    assert!(matches!(
        read_frame(&mut reader).await,
        Err(TransportError::PayloadTooLarge { declared, maximum })
            if declared == MAX_PAYLOAD_LEN + 1 && maximum == MAX_PAYLOAD_LEN
    ));
}

#[tokio::test]
async fn reports_early_eof_with_declared_and_received_lengths() {
    let (mut writer, mut reader) = tokio::io::duplex(16);
    writer.write_all(&5_u32.to_be_bytes()).await.unwrap();
    writer.write_all(b"ab").await.unwrap();
    writer.shutdown().await.unwrap();

    assert!(matches!(
        read_frame(&mut reader).await,
        Err(TransportError::EarlyEof {
            declared: 5,
            received: 2,
        })
    ));
}

#[tokio::test]
async fn converts_client_controlled_failures_to_stable_responses() {
    let socket = SocketFixture::new();
    let server = RunningServer::start(&socket.path, |_request| async {
        ControlResponse::success(AgentResult::Accepted)
    })
    .await;

    let cases = [
        (raw_frame(b"{"), ERROR_INVALID_REQUEST),
        (
            raw_frame(br#"{"protocol_version":2,"kind":"status","interface":null}"#),
            ERROR_UNSUPPORTED_PROTOCOL_VERSION,
        ),
        (
            ((MAX_PAYLOAD_LEN + 1) as u32).to_be_bytes().to_vec(),
            ERROR_PAYLOAD_TOO_LARGE,
        ),
    ];

    for (frame, expected_code) in cases {
        let response = exchange(&socket.path, &frame).await;
        assert_eq!(error_code(&response), expected_code);
    }

    let mut stream = UnixStream::connect(&socket.path).await.unwrap();
    stream.write_all(&8_u32.to_be_bytes()).await.unwrap();
    stream.write_all(b"{}").await.unwrap();
    stream.shutdown().await.unwrap();
    let response = decode_response(&read_frame(&mut stream).await.unwrap()).unwrap();
    assert_eq!(error_code(&response), ERROR_EARLY_EOF);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caps_active_handlers_at_sixteen() {
    let socket = SocketFixture::new();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let handler_active = active.clone();
    let handler_maximum = maximum.clone();
    let server = RunningServer::start(&socket.path, move |_request| {
        let handler_active = handler_active.clone();
        let handler_maximum = handler_maximum.clone();
        async move {
            let now_active = handler_active.fetch_add(1, Ordering::SeqCst) + 1;
            handler_maximum.fetch_max(now_active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(250)).await;
            handler_active.fetch_sub(1, Ordering::SeqCst);
            ControlResponse::success(AgentResult::Accepted)
        }
    })
    .await;

    let mut clients = Vec::new();
    for _ in 0..(MAX_ACTIVE_HANDLERS * 2) {
        let path = socket.path.clone();
        clients.push(tokio::spawn(async move {
            exchange(&path, &request_frame()).await
        }));
    }
    for client in clients {
        assert_eq!(
            client.await.unwrap(),
            ControlResponse::success(AgentResult::Accepted)
        );
    }

    assert_eq!(maximum.load(Ordering::SeqCst), MAX_ACTIVE_HANDLERS);
    server.stop().await;
}

#[tokio::test]
async fn returns_request_timeout_after_five_seconds() {
    let socket = SocketFixture::new();
    let server = RunningServer::start(&socket.path, |_request| async {
        pending::<ControlResponse>().await
    })
    .await;
    let started = tokio::time::Instant::now();

    let response = tokio::time::timeout(
        REQUEST_TIMEOUT + Duration::from_secs(2),
        exchange(&socket.path, &request_frame()),
    )
    .await
    .expect("server did not enforce its request timeout");

    assert_eq!(error_code(&response), ERROR_REQUEST_TIMEOUT);
    assert!(started.elapsed() >= REQUEST_TIMEOUT);
    server.stop().await;
}

#[tokio::test]
async fn never_unlinks_a_stale_non_socket_path() {
    let socket = SocketFixture::new();
    std::fs::write(&socket.path, b"preserve me").unwrap();

    let error = BoundedUnixServer::bind(&socket.path).await.unwrap_err();

    assert!(matches!(error, DaemonError::SocketPathNotSocket));
    assert_eq!(std::fs::read(&socket.path).unwrap(), b"preserve me");
}

#[tokio::test]
async fn creates_a_private_socket_and_rejects_an_unsafe_parent() {
    let socket = SocketFixture::new();
    let server = BoundedUnixServer::bind(&socket.path).await.unwrap();
    let mode = std::fs::metadata(&socket.path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    drop(server);

    let unsafe_socket = SocketFixture::with_parent_mode(0o777);
    let error = BoundedUnixServer::bind(&unsafe_socket.path)
        .await
        .unwrap_err();
    assert!(matches!(error, DaemonError::UnsafeParentPermissions));
    assert!(!unsafe_socket.path.exists());
}

struct RunningServer {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), DaemonError>>,
}

impl RunningServer {
    async fn start<H, Fut>(path: &Path, handler: H) -> Self
    where
        H: Fn(ControlRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = ControlResponse> + Send + 'static,
    {
        let server = BoundedUnixServer::bind(path).await.unwrap();
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(server.serve(handler, async move {
            let _ = receiver.await;
        }));
        Self { shutdown, task }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        self.task.await.unwrap().unwrap();
    }
}

struct SocketFixture {
    root: PathBuf,
    path: PathBuf,
}

impl SocketFixture {
    fn new() -> Self {
        Self::with_parent_mode(0o700)
    }

    fn with_parent_mode(mode: u32) -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("l2-loop-{}-{id}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).unwrap();
        let path = root.join("agent.sock");
        Self { root, path }
    }
}

impl Drop for SocketFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.root);
    }
}

async fn exchange(path: &Path, frame: &[u8]) -> ControlResponse {
    let mut stream = UnixStream::connect(path).await.unwrap();
    write_frame(&mut stream, frame).await.unwrap();
    decode_response(&read_frame(&mut stream).await.unwrap()).unwrap()
}

fn request_frame() -> Vec<u8> {
    encode_request(&ControlRequest::new(AgentCommand::Status {
        interface: None,
    }))
    .unwrap()
}

fn raw_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn error_code(response: &ControlResponse) -> &str {
    match &response.body {
        ResponseBody::Error { code, .. } => code,
        ResponseBody::Success { .. } => panic!("expected error response, got {response:?}"),
    }
}
