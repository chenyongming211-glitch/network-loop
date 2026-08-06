#![cfg(target_os = "linux")]

use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use l2_loop_agent::{
    protocol::{ControlRequest, ControlResponse, decode_request, encode_response},
    transport::{read_frame, write_frame},
};
use l2_loop_cli::{ClientError, EXIT_FAILURE, RenderedOutput, UnixControlClient};
use l2_loop_core::{AgentCommand, AgentResult, InterfaceName};
use tokio::{io::AsyncReadExt, net::UnixListener};

#[tokio::test]
async fn sends_one_framed_request_and_reads_one_framed_response() {
    let socket = SocketFixture::new();
    let listener = UnixListener::bind(&socket.path).unwrap();
    let expected = AgentCommand::Preflight {
        interface: InterfaceName::new("veth-test").unwrap(),
    };
    let server_expected = expected.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = decode_request(&read_frame(&mut stream).await.unwrap()).unwrap();
        assert_eq!(request, ControlRequest::new(server_expected));
        let response = encode_response(&ControlResponse::success(AgentResult::Accepted)).unwrap();
        write_frame(&mut stream, &response).await.unwrap();

        let mut trailing = [0_u8; 1];
        assert_eq!(stream.read(&mut trailing).await.unwrap(), 0);
    });

    let response = UnixControlClient::new(&socket.path)
        .execute(expected)
        .await
        .unwrap();

    assert_eq!(response, ControlResponse::success(AgentResult::Accepted));
    server.await.unwrap();
}

#[tokio::test]
async fn transport_failures_render_with_exit_code_one() {
    let socket = SocketFixture::new();
    let error = UnixControlClient::new(&socket.path)
        .execute(AgentCommand::Preflight {
            interface: InterfaceName::new("veth-test").unwrap(),
        })
        .await
        .unwrap_err();

    assert!(matches!(error, ClientError::Connect(_)));
    let rendered = RenderedOutput::failure(error.to_string());
    assert_eq!(rendered.exit_code, EXIT_FAILURE);
    assert!(rendered.stdout.is_empty());
    assert!(!rendered.stderr.is_empty());
}

struct SocketFixture {
    root: PathBuf,
    path: PathBuf,
}

impl SocketFixture {
    fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "l2-loop-cli-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
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
