use serde::{Deserialize, Serialize};

use crate::{
    BaselineSummary, DetectionSummary, FingerprintSummary, InterfaceName, ObservationCounters,
    ObservationHealth, ObservationSnapshot, PolicyRequest, PreflightReport, ProbeRequest,
    RATE_WINDOW_COUNT, SamplingStatus, StatusRateWindow, VlanVisibility,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentCommand {
    Preflight {
        interface: InterfaceName,
    },
    IsolatedAttach {
        interface: InterfaceName,
        run_id: String,
    },
    IsolatedDetach {
        run_id: String,
    },
    Observe {
        interface: InterfaceName,
    },
    Status {
        interface: Option<InterfaceName>,
    },
    Probe {
        request: ProbeRequest,
    },
    ApplyPolicy {
        request: PolicyRequest,
    },
    DisablePolicy {
        rule_id: String,
    },
    EvidenceList {
        interface: Option<InterfaceName>,
    },
    EvidenceShow {
        evidence_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
// Keep the approved flat domain API; control results are short-lived and concurrency is bounded.
#[allow(clippy::large_enum_variant)]
pub enum AgentResult {
    Preflight { report: PreflightReport },
    Accepted,
    Observation { snapshot: ObservationSnapshot },
    Status { interfaces: Vec<InterfaceStatus> },
    Probe { returned_frames: u64 },
    PolicyApplied { rule_id: String },
    PolicyDisabled,
    EvidenceList { evidence_ids: Vec<String> },
    Evidence { evidence_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub interface: InterfaceName,
    pub state: crate::InterfaceState,
    pub generation: u64,
    pub captured_at_unix_ms: u64,
    pub health: ObservationHealth,
    pub vlan_visibility: VlanVisibility,
    pub xdp_ingress: ObservationCounters,
    pub tc_egress: ObservationCounters,
    pub sampling: SamplingStatus,
    pub rate_windows: [StatusRateWindow; RATE_WINDOW_COUNT],
    pub baseline: BaselineSummary,
    pub fingerprints: FingerprintSummary,
    pub detection: DetectionSummary,
}
