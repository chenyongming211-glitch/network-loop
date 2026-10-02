//! Acceptance-only request and lifecycle boundary; no kernel operations here.

use serde::{Deserialize, Serialize};
use crate::diagnostic::DiagnosticProfile;

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
    Err(DiagnosticSessionError { primary: Some("not implemented".into()), cleanup: vec![] })
}

pub fn run_session(_backend: &mut impl DiagnosticBackend) -> Result<(), DiagnosticSessionError> {
    Err(DiagnosticSessionError { primary: Some("not implemented".into()), cleanup: vec![] })
}
