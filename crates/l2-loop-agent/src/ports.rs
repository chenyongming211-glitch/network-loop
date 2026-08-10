use std::time::SystemTime;

use l2_loop_core::{HookRole, InterfaceName, PolicyRequest, PreflightReport, ProbeRequest};
use thiserror::Error;

#[cfg(target_os = "linux")]
use l2_loop_core::{HookObservation, OBSERVED_HOOK_COUNT, VlanVisibility};
#[cfg(target_os = "linux")]
use crate::{
    linux::{tc::LoadedTc, xdp::LoadedXdp},
    ownership::{
        OwnedMapPin, OwnedTc, OwnedXdp, OwnershipRecord, TcHook, TestPinRoot, XdpAttachMode,
    },
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PortError {
    #[error("adapter error: {0}")]
    Adapter(String),
    #[error("adapter error: {code}: {evidence}")]
    CodedAdapter {
        code: &'static str,
        evidence: String,
    },
    #[error("invalid preflight report: {0}")]
    InvalidReport(String),
}

impl PortError {
    pub fn coded_adapter(code: &'static str, evidence: impl Into<String>) -> Self {
        Self::CodedAdapter {
            code,
            evidence: evidence.into(),
        }
    }

    pub const fn stable_code(&self) -> Option<&'static str> {
        match self {
            Self::CodedAdapter { code, .. } => Some(code),
            Self::Adapter(_) | Self::InvalidReport(_) => None,
        }
    }
}

pub trait PlatformInspector {
    fn inspect(&mut self, interface: &InterfaceName) -> Result<PreflightReport, PortError>;
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

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawObservation {
    pub ifindex: u32,
    pub generation: u64,
    pub vlan_visibility: VlanVisibility,
    pub hooks: [HookObservation; OBSERVED_HOOK_COUNT],
}

#[cfg(target_os = "linux")]
pub trait ObservationReader: Send {
    fn read_exact(&mut self, ownership: &OwnershipRecord) -> Result<RawObservation, PortError>;
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedBpfObject {
    pub xdp: LoadedXdp,
    pub tc_egress: LoadedTc,
    pub map_pins: Vec<OwnedMapPin>,
}

#[cfg(target_os = "linux")]
pub trait ResourceLimits {
    fn raise_memlock_to_infinity(&mut self) -> Result<(), PortError>;
}

#[cfg(target_os = "linux")]
pub trait BpfObjectLoader {
    /// Load the object and validate its complete public ABI before returning it.
    /// An error must leave no loaded or pinned object behind.
    fn load_and_validate_abi(&mut self, pins: &TestPinRoot) -> Result<LoadedBpfObject, PortError>;

    /// Release only resources represented by `loaded`.
    fn unload_exact(&mut self, loaded: &LoadedBpfObject) -> Result<(), PortError>;
}

#[cfg(target_os = "linux")]
pub trait SafeXdpPort {
    /// Attach atomically with no-replace semantics. Errors must not retain an
    /// unreported link; the adapter owns any rollback needed inside this call.
    fn attach_no_replace(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        loaded: LoadedXdp,
    ) -> Result<OwnedXdp, PortError>;

    fn verify_exact(&mut self, owned: &OwnedXdp) -> Result<(), PortError>;
    fn detach_exact(&mut self, owned: &OwnedXdp) -> Result<(), PortError>;
}

#[cfg(target_os = "linux")]
pub trait SafeTcPort {
    /// Attach at an explicit hook, priority, and handle without replacement.
    /// Errors must not retain an unreported filter.
    fn attach_explicit(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        loaded: LoadedTc,
    ) -> Result<OwnedTc, PortError>;

    fn verify_exact(&mut self, owned: &OwnedTc) -> Result<(), PortError>;
    fn detach_exact(&mut self, owned: &OwnedTc) -> Result<(), PortError>;
}

#[cfg(target_os = "linux")]
pub trait MapPublisher {
    /// Initialize entries that are not activation gates. Errors must leave no
    /// completed initialization that is not represented to the transaction.
    fn initialize_dependent(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError>;

    /// Publish the activation gate last. An error guarantees that the entry is
    /// absent, so rollback never guesses whether observation became active.
    fn publish_iface_config(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError>;

    fn rollback_initialized_exact(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError>;
}

#[cfg(target_os = "linux")]
pub trait EphemeralOwnershipStore {
    /// Persist atomically. An error guarantees that no committed journal for
    /// this record exists.
    fn save(&mut self, record: &OwnershipRecord) -> Result<(), PortError>;

    /// Remove only the exact committed record after revalidating its identity.
    fn remove_exact(&mut self, record: &OwnershipRecord) -> Result<(), PortError>;
}
