//! Acceptance-only request and lifecycle boundary; no kernel operations here.

use serde::{Deserialize, Serialize};

use crate::diagnostic::{DiagnosticProfile, lower_hex};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRequest {
    pub schema_version: u16,
    pub run_id: String,
    pub profile: DiagnosticProfile,
    pub ifindex: u32,
    pub peer_ifindex: u32,
    pub host_mac: String,
    pub peer_mac: String,
    pub namespace_device: u64,
    pub namespace_inode: u64,
    pub duration_seconds: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStep {
    Prepare,
    AttachXdp,
    AttachTc,
    Verify,
    Activate,
    Observe,
    DetachTc,
    DetachXdp,
    Release,
    Finish,
}

pub trait DiagnosticBackend {
    fn perform(&mut self, step: SessionStep) -> Result<(), String>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct DiagnosticSessionError {
    pub primary: Option<String>,
    pub cleanup: Vec<String>,
}

pub fn validate_request(_bytes: &[u8]) -> Result<DiagnosticRequest, DiagnosticSessionError> {
    let invalid = || DiagnosticSessionError {
        primary: Some("DX_REQUEST".into()),
        cleanup: vec![],
    };
    if _bytes.len() > 65_536 {
        return Err(invalid());
    }
    let request: DiagnosticRequest = serde_json::from_slice(_bytes).map_err(|_| invalid())?;
    if request.schema_version != 1
        || !lower_hex(&request.run_id, 32)
        || request.ifindex == 0
        || request.peer_ifindex == 0
        || !unicast_mac(&request.host_mac)
        || !unicast_mac(&request.peer_mac)
        || request.host_mac == request.peer_mac
        || request.namespace_device == 0
        || request.namespace_inode == 0
        || !(1..=120).contains(&request.duration_seconds)
    {
        return Err(invalid());
    }
    Ok(request)
}

fn unicast_mac(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts.iter().all(|part| lower_hex(part, 2))
        && value != "00:00:00:00:00:00"
        && u8::from_str_radix(parts[0], 16).is_ok_and(|byte| byte & 1 == 0)
}

pub fn run_session(backend: &mut impl DiagnosticBackend) -> Result<(), DiagnosticSessionError> {
    use SessionStep::*;
    let mut primary = None;
    for step in [Prepare, AttachXdp, AttachTc, Verify, Activate, Observe] {
        if let Err(error) = backend.perform(step) {
            primary = Some(error);
            break;
        }
    }
    let mut cleanup = Vec::new();
    for step in [DetachTc, DetachXdp, Release] {
        if let Err(error) = backend.perform(step) {
            cleanup.push(error);
        }
    }
    if cleanup.is_empty()
        && let Err(error) = backend.perform(Finish)
    {
        cleanup.push(error);
    }
    if primary.is_none() && cleanup.is_empty() {
        Ok(())
    } else {
        Err(DiagnosticSessionError { primary, cleanup })
    }
}
