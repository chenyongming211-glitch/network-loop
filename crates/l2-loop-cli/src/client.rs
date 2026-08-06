use std::{io, path::PathBuf};

use l2_loop_agent::{
    daemon::DEFAULT_SOCKET_PATH,
    protocol::{ControlRequest, ControlResponse, ProtocolError, decode_response, encode_request},
    transport::{TransportError, read_frame, write_frame},
};
use l2_loop_core::AgentCommand;
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::UnixStream};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("failed to connect to the control socket")]
    Connect(#[source] io::Error),
    #[error("failed to encode the control request")]
    Encode(#[source] ProtocolError),
    #[error("failed to write the control request")]
    Write(#[source] TransportError),
    #[error("failed to finish the control request")]
    FinishRequest(#[source] io::Error),
    #[error("failed to read the control response")]
    Read(#[source] TransportError),
    #[error("failed to decode the control response")]
    Decode(#[source] ProtocolError),
}

#[derive(Debug, Clone)]
pub struct UnixControlClient {
    socket_path: PathBuf,
}

impl Default for UnixControlClient {
    fn default() -> Self {
        Self::new(DEFAULT_SOCKET_PATH)
    }
}

impl UnixControlClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn execute(&self, command: AgentCommand) -> Result<ControlResponse, ClientError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(ClientError::Connect)?;
        let frame = encode_request(&ControlRequest::new(command)).map_err(ClientError::Encode)?;
        write_frame(&mut stream, &frame)
            .await
            .map_err(ClientError::Write)?;
        stream
            .shutdown()
            .await
            .map_err(ClientError::FinishRequest)?;
        let response = read_frame(&mut stream).await.map_err(ClientError::Read)?;
        decode_response(&response).map_err(ClientError::Decode)
    }
}
