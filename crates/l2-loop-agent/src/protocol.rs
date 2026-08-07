use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use l2_loop_core::{AgentCommand, AgentResult};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;
pub const ERROR_COMMAND_NOT_IMPLEMENTED: &str = "COMMAND_NOT_IMPLEMENTED";
pub const ERROR_EARLY_EOF: &str = "EARLY_EOF";
pub const ERROR_INTERNAL: &str = "INTERNAL_ERROR";
pub const ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const ERROR_PAYLOAD_TOO_LARGE: &str = "PAYLOAD_TOO_LARGE";
pub const ERROR_REQUEST_TIMEOUT: &str = "REQUEST_TIMEOUT";
pub const ERROR_RESPONSE_TOO_LARGE: &str = "RESPONSE_TOO_LARGE";
pub const ERROR_TRANSPORT: &str = "TRANSPORT_ERROR";
pub const ERROR_UNSUPPORTED_PROTOCOL_VERSION: &str = "UNSUPPORTED_PROTOCOL_VERSION";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRequest {
    pub protocol_version: u16,
    #[serde(flatten)]
    pub command: AgentCommand,
}

impl ControlRequest {
    pub fn new(command: AgentCommand) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            command,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlResponse {
    pub protocol_version: u16,
    #[serde(flatten)]
    pub body: ResponseBody,
}

impl ControlResponse {
    pub fn success(result: AgentResult) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            body: ResponseBody::Success {
                result: Box::new(result),
            },
        }
    }

    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            body: ResponseBody::Error {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseBody {
    Success { result: Box<AgentResult> },
    Error { code: String, message: String },
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame is missing its four-byte length prefix")]
    MissingLengthPrefix,
    #[error("payload length {declared} exceeds maximum {maximum}")]
    PayloadTooLarge { declared: usize, maximum: usize },
    #[error("frame declares {declared} payload bytes but contains {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("invalid protocol JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
}

pub fn encode_request(request: &ControlRequest) -> Result<Vec<u8>, ProtocolError> {
    ensure_version(request.protocol_version)?;
    encode_frame(request)
}

pub fn decode_request(frame: &[u8]) -> Result<ControlRequest, ProtocolError> {
    let request: ControlRequest = decode_frame(frame)?;
    ensure_version(request.protocol_version)?;
    Ok(request)
}

pub fn encode_response(response: &ControlResponse) -> Result<Vec<u8>, ProtocolError> {
    ensure_version(response.protocol_version)?;
    encode_frame(response)
}

pub fn decode_response(frame: &[u8]) -> Result<ControlResponse, ProtocolError> {
    let response: ControlResponse = decode_frame(frame)?;
    ensure_version(response.protocol_version)?;
    Ok(response)
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(ProtocolError::PayloadTooLarge {
            declared: payload.len(),
            maximum: MAX_PAYLOAD_LEN,
        });
    }

    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, ProtocolError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(ProtocolError::MissingLengthPrefix)?
        .try_into()
        .map_err(|_| ProtocolError::MissingLengthPrefix)?;
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared > MAX_PAYLOAD_LEN {
        return Err(ProtocolError::PayloadTooLarge {
            declared,
            maximum: MAX_PAYLOAD_LEN,
        });
    }

    let actual = frame.len() - 4;
    if actual != declared {
        return Err(ProtocolError::LengthMismatch { declared, actual });
    }

    Ok(serde_json::from_slice(&frame[4..])?)
}

const fn ensure_version(version: u16) -> Result<(), ProtocolError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion(version))
    }
}
