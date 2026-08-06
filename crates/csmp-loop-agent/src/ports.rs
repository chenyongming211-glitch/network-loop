use std::time::SystemTime;

use csmp_loop_core::{HookRole, InterfaceName, PolicyRequest, ProbeRequest};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PortError {
    #[error("adapter error: {0}")]
    Adapter(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceIdentity {
    pub name: InterfaceName,
    pub ifindex: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookHandle {
    pub id: u8,
    pub role: HookRole,
}

pub trait InterfaceResolver {
    fn resolve(&mut self, name: &InterfaceName) -> Result<InterfaceIdentity, PortError>;
}

pub trait HookManager {
    fn attach(
        &mut self,
        interface: &InterfaceIdentity,
        role: HookRole,
    ) -> Result<HookHandle, PortError>;

    fn verify(&mut self, handle: HookHandle) -> Result<(), PortError>;
    fn detach(&mut self, handle: HookHandle) -> Result<(), PortError>;
    fn publish_observe(
        &mut self,
        interface: &InterfaceIdentity,
        generation: u64,
    ) -> Result<(), PortError>;
    fn publish_policy(&mut self, policy: &PolicyRequest) -> Result<(), PortError>;
    fn clear_policy(&mut self) -> Result<(), PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub captured_at_ns: u64,
}

pub trait MetricsReader {
    fn read(&mut self, interface: &InterfaceIdentity) -> Result<MetricsSnapshot, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReceipt {
    pub returned_frames: u64,
}

pub trait ProbeTransport {
    fn send_one(&mut self, request: &ProbeRequest) -> Result<ProbeReceipt, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBundle {
    pub id: String,
    pub payload: Vec<u8>,
}

pub trait EvidenceStore {
    fn persist(&mut self, bundle: &EvidenceBundle) -> Result<(), PortError>;
}

pub trait Clock {
    fn monotonic_ns(&self) -> u64;
    fn wall_time(&self) -> SystemTime;
}
