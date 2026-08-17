use std::{
    collections::BTreeMap,
    path::Path,
    time::{Instant, SystemTime},
};

use l2_loop_core::{
    DeploymentArtifactIdentityV1, DeploymentAuthorizationV1, DeploymentHostCompatibilityV1,
    HookRole, InterfaceKind, InterfaceName, PerformanceEvidenceV1, PolicyRequest, PreflightReport,
    ProbeRequest,
};
use thiserror::Error;

#[cfg(target_os = "linux")]
use std::fs::File;

use crate::{
    InstallActionV1, InstallDestinationSnapshotV1, InstallJournalSnapshotV1, InstallPlanV1,
    InstallSourceSnapshotV1,
};

#[cfg(target_os = "linux")]
use crate::{
    linux::{tc::LoadedTc, xdp::LoadedXdp},
    ownership::{
        OwnedMapPin, OwnedTc, OwnedXdp, OwnershipRecord, TcHook, TestPinRoot, XdpAttachMode,
    },
};
#[cfg(target_os = "linux")]
use l2_loop_core::{FingerprintEvidence, HookObservation, OBSERVED_HOOK_COUNT, VlanVisibility};

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawFingerprints {
    NotRequested,
    Available(Vec<FingerprintEvidence>),
    Unavailable { code: &'static str },
}

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

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentIoError {
    #[error("deployment input is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSnapshotV1 {
    pub artifact: DeploymentArtifactIdentityV1,
    pub files: BTreeMap<String, BundleFileIdentityV1>,
}

impl BundleSnapshotV1 {
    pub fn new(artifact: DeploymentArtifactIdentityV1) -> Self {
        Self {
            artifact,
            files: BTreeMap::new(),
        }
    }

    pub fn with_files(
        artifact: DeploymentArtifactIdentityV1,
        files: BTreeMap<String, BundleFileIdentityV1>,
    ) -> Self {
        Self { artifact, files }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFileIdentityV1 {
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub device: u64,
    pub inode: u64,
    pub hard_links: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentEntryKindV1 {
    Directory,
    Regular,
    Symlink,
    Socket,
    Fifo,
    Device,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentEntrySnapshotV1 {
    pub relative_path: String,
    pub canonical_path: std::path::PathBuf,
    pub kind: DeploymentEntryKindV1,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub device: u64,
    pub inode: u64,
    pub hard_links: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutSnapshotV1 {
    pub artifact: DeploymentArtifactIdentityV1,
    pub files: BTreeMap<String, DeploymentEntrySnapshotV1>,
    pub runtime_occupied: bool,
}

impl LayoutSnapshotV1 {
    pub fn new(artifact: DeploymentArtifactIdentityV1) -> Self {
        Self {
            artifact,
            files: BTreeMap::new(),
            runtime_occupied: false,
        }
    }

    pub fn with_files(
        artifact: DeploymentArtifactIdentityV1,
        files: BTreeMap<String, DeploymentEntrySnapshotV1>,
        runtime_occupied: bool,
    ) -> Self {
        Self {
            artifact,
            files,
            runtime_occupied,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceUnitSnapshotV1 {
    contract_valid: bool,
}

impl ServiceUnitSnapshotV1 {
    pub const fn new(contract_valid: bool) -> Self {
        Self { contract_valid }
    }

    pub const fn valid() -> Self {
        Self::new(true)
    }

    pub const fn is_valid(self) -> bool {
        self.contract_valid
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentPrerequisitesV1 {
    evidence_root_ready: bool,
    runtime_contract_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledOwnershipSnapshotV1 {
    pub transaction_id: String,
    pub authorization_id: String,
    pub artifact: DeploymentArtifactIdentityV1,
}

impl InstalledOwnershipSnapshotV1 {
    pub fn new(
        transaction_id: impl Into<String>,
        authorization_id: impl Into<String>,
        artifact: DeploymentArtifactIdentityV1,
    ) -> Result<Self, DeploymentIoError> {
        let snapshot = Self {
            transaction_id: transaction_id.into(),
            authorization_id: authorization_id.into(),
            artifact,
        };
        if !is_lower_hex(&snapshot.transaction_id, 32)
            || !is_lower_hex(&snapshot.authorization_id, 32)
            || snapshot.artifact.validate().is_err()
        {
            return Err(DeploymentIoError::Unavailable);
        }
        Ok(snapshot)
    }
}

impl DeploymentPrerequisitesV1 {
    pub const fn new(evidence_root_ready: bool, runtime_contract_ready: bool) -> Self {
        Self {
            evidence_root_ready,
            runtime_contract_ready,
        }
    }

    pub const fn ready() -> Self {
        Self::new(true, true)
    }

    pub const fn is_ready(self) -> bool {
        self.evidence_root_ready && self.runtime_contract_ready
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentPlatformSnapshotV1 {
    pub preflight: PreflightReport,
    pub interface_name: InterfaceName,
    pub ifindex: u32,
    pub kind: InterfaceKind,
    pub administrative_up: bool,
    pub operational_up: bool,
    pub master_ifindex: Option<u32>,
    pub mac_address_sha256: String,
    pub driver: String,
    pub device_identity_sha256: String,
    pub network_namespace_sha256: String,
    pub tc_clsact_present: bool,
    pub address_present: bool,
    pub route_present: bool,
    pub neighbor_present: bool,
    pub service_present: bool,
    pub other_consumer_present: bool,
    pub capabilities_sufficient: bool,
    pub native_xdp_driver_ready: bool,
    pub receive_queue_count: u32,
    pub offload_state_known: bool,
    pub host: DeploymentHostCompatibilityV1,
}

pub trait DeploymentFilesystem {
    fn validate_staging_root(&mut self, root: &Path) -> Result<(), DeploymentIoError>;
    fn inspect_bundle(&mut self, bundle: &Path) -> Result<BundleSnapshotV1, DeploymentIoError>;
    fn inspect_staged_layout(&mut self, root: &Path)
    -> Result<LayoutSnapshotV1, DeploymentIoError>;
    fn inspect_staged_service(
        &mut self,
        root: &Path,
    ) -> Result<ServiceUnitSnapshotV1, DeploymentIoError>;
    fn load_staged_authorization(
        &mut self,
        root: &Path,
    ) -> Result<DeploymentAuthorizationV1, DeploymentIoError>;
    fn load_staged_performance(
        &mut self,
        root: &Path,
    ) -> Result<PerformanceEvidenceV1, DeploymentIoError>;
    fn inspect_staged_prerequisites(
        &mut self,
        root: &Path,
    ) -> Result<DeploymentPrerequisitesV1, DeploymentIoError>;
    fn inspect_installed_ownership(
        &mut self,
    ) -> Result<InstalledOwnershipSnapshotV1, DeploymentIoError>;
    fn inspect_installed_layout(&mut self) -> Result<LayoutSnapshotV1, DeploymentIoError>;
    fn inspect_installed_service(&mut self) -> Result<ServiceUnitSnapshotV1, DeploymentIoError>;
    fn load_installed_authorization(
        &mut self,
    ) -> Result<DeploymentAuthorizationV1, DeploymentIoError>;
    fn load_installed_performance(&mut self) -> Result<PerformanceEvidenceV1, DeploymentIoError>;
    fn inspect_installed_prerequisites(
        &mut self,
    ) -> Result<DeploymentPrerequisitesV1, DeploymentIoError>;
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub trait DeploymentPlatformInspector {
    fn inspect_authorized_interface(
        &mut self,
        authorization: &DeploymentAuthorizationV1,
    ) -> Result<DeploymentPlatformSnapshotV1, DeploymentIoError>;
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InstallIoError {
    #[error("installation adapter input is unavailable")]
    Unavailable,
    #[cfg(target_os = "linux")]
    #[error("installation adapter rejected an unsafe filesystem object")]
    UnsafeObject,
    #[cfg(target_os = "linux")]
    #[error("installation filesystem identity changed")]
    IdentityChanged,
    #[cfg(target_os = "linux")]
    #[error("installation filesystem metadata is unsupported")]
    UnsupportedMetadata,
    #[cfg(target_os = "linux")]
    #[error("installation fault injected at {0:?}")]
    FaultInjected(InstallFaultPointV1),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallFaultPointV1 {
    DirectoryCreate,
    SiblingCreate,
    PayloadWrite,
    Ownership,
    Mode,
    Hash,
    FileSync,
    BackupRename,
    FinalRename,
    DirectorySync,
    JournalSync,
    JournalMove,
    Verify,
    Rollback,
}

#[cfg(target_os = "linux")]
pub trait InstallFaultInjector {
    fn check(&mut self, point: InstallFaultPointV1) -> Result<(), InstallIoError>;
}

/// Supplies an already opened installation namespace root. Production uses
/// `/`; generated-root acceptance injects a different directory descriptor
/// without adding a destination override to the installer command surface.
#[cfg(target_os = "linux")]
pub trait InstallRootDirectory {
    fn open_root(&self) -> Result<File, InstallIoError>;
}

pub trait InstallSourceReader {
    fn load_source(&mut self) -> Result<InstallSourceSnapshotV1, InstallIoError>;
}

pub trait HostIdentityReader {
    fn host_identity_sha256(&mut self) -> Result<String, InstallIoError>;
}

pub trait InstallStateReader {
    fn inspect_destinations(
        &mut self,
        source: &InstallSourceSnapshotV1,
    ) -> Result<Vec<InstallDestinationSnapshotV1>, InstallIoError>;

    fn inspect_prior_journal(
        &mut self,
        transaction_id: &str,
    ) -> Result<Option<InstallJournalSnapshotV1>, InstallIoError>;
}

pub trait InstallTransactionWriter {
    fn begin_transaction(&mut self, plan: &InstallPlanV1) -> Result<(), InstallIoError>;
    fn apply_action(&mut self, action: &InstallActionV1) -> Result<(), InstallIoError>;
    fn record_completed(&mut self, action: &InstallActionV1) -> Result<(), InstallIoError>;
    fn complete_transaction(&mut self, plan: &InstallPlanV1) -> Result<(), InstallIoError>;
    fn begin_rollback(&mut self, journal: &InstallJournalSnapshotV1) -> Result<(), InstallIoError>;
    fn rollback_action(&mut self, action: &InstallActionV1) -> Result<(), InstallIoError>;
    fn record_rolled_back(&mut self, action: &InstallActionV1) -> Result<(), InstallIoError>;
    fn complete_rollback(
        &mut self,
        journal: &InstallJournalSnapshotV1,
    ) -> Result<(), InstallIoError>;
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

pub trait Clock {
    fn monotonic_ns(&self) -> u64;
    fn wall_time(&self) -> SystemTime;
}

#[derive(Debug)]
pub struct SystemClock {
    monotonic_origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            monotonic_origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn monotonic_ns(&self) -> u64 {
        u64::try_from(self.monotonic_origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn wall_time(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawObservation {
    pub ifindex: u32,
    pub generation: u64,
    pub vlan_visibility: VlanVisibility,
    pub hooks: [HookObservation; OBSERVED_HOOK_COUNT],
    pub fingerprints: RawFingerprints,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationReadPurpose {
    Request,
    BackgroundSample,
    BackgroundAnalysis,
}

#[cfg(target_os = "linux")]
pub trait ObservationReader: Send {
    fn read_exact(
        &mut self,
        ownership: &OwnershipRecord,
        purpose: ObservationReadPurpose,
    ) -> Result<RawObservation, PortError>;
}

#[cfg(target_os = "linux")]
impl<T> ObservationReader for Box<T>
where
    T: ObservationReader + ?Sized,
{
    fn read_exact(
        &mut self,
        ownership: &OwnershipRecord,
        purpose: ObservationReadPurpose,
    ) -> Result<RawObservation, PortError> {
        (**self).read_exact(ownership, purpose)
    }
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
