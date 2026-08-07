use l2_loop_common::ABI_VERSION;
use l2_loop_core::{
    FindingSeverity, InterfaceKind, InterfaceName, InterfaceState, PF_LIVE_INTERFACE,
    PF_MEMLOCK_TOO_LOW, PreflightDecision,
};

use crate::{
    BpfObjectLoader, EphemeralOwnershipStore, LoadedBpfObject, MapPublisher, PlatformInspector,
    PortError, ResourceLimits, SafeTcPort, SafeXdpPort,
    ownership::{
        OWNERSHIP_SCHEMA_VERSION, OwnedTc, OwnedXdp, OwnershipRecord, RunId, TcHook, TestPinRoot,
        XdpAttachMode,
    },
};

const ATTACH_PREFLIGHT_FAILED: &str = "ATTACH_PREFLIGHT_FAILED";
const PREFLIGHT_BLOCKED: &str = "PREFLIGHT_BLOCKED";
const BPF_LOAD_FAILED: &str = "BPF_LOAD_FAILED";
const XDP_ATTACH_FAILED: &str = "XDP_ATTACH_FAILED";
const XDP_VERIFY_FAILED: &str = "XDP_VERIFY_FAILED";
const TC_ATTACH_FAILED: &str = "TC_ATTACH_FAILED";
const TC_VERIFY_FAILED: &str = "TC_VERIFY_FAILED";
const MAP_INITIALIZE_FAILED: &str = "MAP_INITIALIZE_FAILED";
const OWNERSHIP_JOURNAL_FAILED: &str = "OWNERSHIP_JOURNAL_FAILED";
const IFACE_CONFIG_PUBLISH_FAILED: &str = "IFACE_CONFIG_PUBLISH_FAILED";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentSession {
    pub state: InterfaceState,
    pub generation: u64,
    pub ownership: OwnershipRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentError {
    code: String,
    evidence: String,
    cleanup_evidence: Vec<String>,
}

impl AttachmentError {
    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn evidence(&self) -> &str {
        &self.evidence
    }

    pub fn cleanup_evidence(&self) -> &[String] {
        &self.cleanup_evidence
    }

    fn without_cleanup(code: impl Into<String>, error: impl ToString) -> Self {
        Self {
            code: code.into(),
            evidence: error.to_string(),
            cleanup_evidence: Vec::new(),
        }
    }
}

#[derive(Default)]
struct RollbackState {
    loaded: Option<LoadedBpfObject>,
    xdp: Option<OwnedXdp>,
    tc: Option<OwnedTc>,
    maps_initialized: bool,
    journal: Option<OwnershipRecord>,
}

pub struct AttachmentTransaction<P, R, L, X, T, M, O> {
    preflight: P,
    limits: R,
    loader: L,
    xdp: X,
    tc: T,
    maps: M,
    ownership: O,
    generation: u64,
}

impl<P, R, L, X, T, M, O> AttachmentTransaction<P, R, L, X, T, M, O>
where
    P: PlatformInspector,
    R: ResourceLimits,
    L: BpfObjectLoader,
    X: SafeXdpPort,
    T: SafeTcPort,
    M: MapPublisher,
    O: EphemeralOwnershipStore,
{
    pub const fn new(
        preflight: P,
        limits: R,
        loader: L,
        xdp: X,
        tc: T,
        maps: M,
        ownership: O,
    ) -> Self {
        Self {
            preflight,
            limits,
            loader,
            xdp,
            tc,
            maps,
            ownership,
            generation: 0,
        }
    }

    pub fn execute(
        &mut self,
        interface: &InterfaceName,
        run_id: &RunId,
        created_at_unix_seconds: u64,
    ) -> Result<AttachmentSession, AttachmentError> {
        let report = self
            .preflight
            .inspect(interface)
            .map_err(|error| AttachmentError::without_cleanup(ATTACH_PREFLIGHT_FAILED, error))?;
        validate_isolated_target(interface, &report)?;

        self.limits
            .raise_memlock_to_infinity()
            .map_err(|error| AttachmentError::without_cleanup(PF_MEMLOCK_TOO_LOW, error))?;

        let pins = TestPinRoot::new(run_id.clone())
            .map_err(|error| AttachmentError::without_cleanup(BPF_LOAD_FAILED, error))?;
        let loaded = self
            .loader
            .load_and_validate_abi(&pins)
            .map_err(|error| AttachmentError::without_cleanup(BPF_LOAD_FAILED, error))?;
        let mut rollback = RollbackState {
            loaded: Some(loaded),
            ..RollbackState::default()
        };

        let ifindex = report.interface.requested.ifindex;
        let loaded = rollback.loaded.as_ref().expect("loaded object is present");
        rollback.xdp = match self
            .xdp
            .attach_no_replace(ifindex, XdpAttachMode::Generic, loaded.xdp)
        {
            Ok(owned) => Some(owned),
            Err(error) => {
                return Err(self.rollback(XDP_ATTACH_FAILED, error, rollback, ifindex, 0));
            }
        };
        if let Err(error) = self
            .xdp
            .verify_exact(rollback.xdp.as_ref().expect("owned XDP is present"))
        {
            return Err(self.rollback(XDP_VERIFY_FAILED, error, rollback, ifindex, 0));
        }

        rollback.tc = match self
            .tc
            .attach_explicit(ifindex, TcHook::Egress, loaded.tc_egress)
        {
            Ok(owned) => Some(owned),
            Err(error) => return Err(self.rollback(TC_ATTACH_FAILED, error, rollback, ifindex, 0)),
        };
        if let Err(error) = self
            .tc
            .verify_exact(rollback.tc.as_ref().expect("owned TC is present"))
        {
            return Err(self.rollback(TC_VERIFY_FAILED, error, rollback, ifindex, 0));
        }

        let generation = self.generation.saturating_add(1).max(1);
        if let Err(error) = self.maps.initialize_dependent(loaded, ifindex, generation) {
            return Err(self.rollback(MAP_INITIALIZE_FAILED, error, rollback, ifindex, generation));
        }
        rollback.maps_initialized = true;

        let record = OwnershipRecord {
            schema_version: OWNERSHIP_SCHEMA_VERSION,
            abi_version: ABI_VERSION,
            generation,
            ifindex,
            xdp: rollback.xdp,
            tc: vec![rollback.tc.expect("owned TC is present")],
            pin_paths: loaded.pin_paths.clone(),
            created_at_unix_seconds,
        };
        if let Err(error) = self.ownership.save(&record) {
            return Err(self.rollback(
                OWNERSHIP_JOURNAL_FAILED,
                error,
                rollback,
                ifindex,
                generation,
            ));
        }
        rollback.journal = Some(record.clone());

        if let Err(error) = self.maps.publish_iface_config(loaded, ifindex, generation) {
            return Err(self.rollback(
                IFACE_CONFIG_PUBLISH_FAILED,
                error,
                rollback,
                ifindex,
                generation,
            ));
        }

        self.generation = generation;
        Ok(AttachmentSession {
            state: InterfaceState::Observing,
            generation,
            ownership: record,
        })
    }

    fn rollback(
        &mut self,
        code: &'static str,
        error: PortError,
        rollback: RollbackState,
        ifindex: u32,
        generation: u64,
    ) -> AttachmentError {
        let mut cleanup_evidence = Vec::new();

        if let Some(record) = rollback.journal.as_ref() {
            collect_cleanup(
                &mut cleanup_evidence,
                "ephemeral ownership journal",
                self.ownership.remove_exact(record),
            );
        }
        if rollback.maps_initialized {
            let loaded = rollback.loaded.as_ref().expect("loaded object is present");
            collect_cleanup(
                &mut cleanup_evidence,
                "initialized maps",
                self.maps
                    .rollback_initialized_exact(loaded, ifindex, generation),
            );
        }
        if let Some(owned) = rollback.tc.as_ref() {
            collect_cleanup(
                &mut cleanup_evidence,
                "TC egress filter",
                self.tc.detach_exact(owned),
            );
        }
        if let Some(owned) = rollback.xdp.as_ref() {
            collect_cleanup(
                &mut cleanup_evidence,
                "XDP link",
                self.xdp.detach_exact(owned),
            );
        }
        if let Some(loaded) = rollback.loaded.as_ref() {
            collect_cleanup(
                &mut cleanup_evidence,
                "loaded eBPF object",
                self.loader.unload_exact(loaded),
            );
        }

        AttachmentError {
            code: code.to_owned(),
            evidence: error.to_string(),
            cleanup_evidence,
        }
    }
}

fn validate_isolated_target(
    requested: &InterfaceName,
    report: &l2_loop_core::PreflightReport,
) -> Result<(), AttachmentError> {
    let interface = &report.interface;
    if &interface.requested.name != requested
        || interface.requested.ifindex == 0
        || interface.kind != InterfaceKind::Veth
        || !interface.isolated
        || interface.live_shared
    {
        return Err(AttachmentError::without_cleanup(
            PF_LIVE_INTERFACE,
            "attachment is restricted to the exact isolated veth target",
        ));
    }

    if report.decision == PreflightDecision::Blocked {
        let code = report
            .findings
            .iter()
            .find(|finding| finding.severity == FindingSeverity::Blocker)
            .map_or(PREFLIGHT_BLOCKED, |finding| finding.code.as_str());
        return Err(AttachmentError::without_cleanup(
            code,
            "preflight blocked isolated attachment",
        ));
    }
    Ok(())
}

fn collect_cleanup(evidence: &mut Vec<String>, resource: &str, result: Result<(), PortError>) {
    if let Err(error) = result {
        evidence.push(format!("{resource}: {error}"));
    }
}
