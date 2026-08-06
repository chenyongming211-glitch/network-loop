use serde::{Deserialize, Serialize};

use crate::{InterfaceName, PolicyRequest, PreflightReport, ProbeRequest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentCommand {
    Preflight { interface: InterfaceName },
    Observe { interface: InterfaceName },
    Status { interface: Option<InterfaceName> },
    Probe { request: ProbeRequest },
    ApplyPolicy { request: PolicyRequest },
    DisablePolicy { rule_id: String },
    EvidenceList { interface: Option<InterfaceName> },
    EvidenceShow { evidence_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
// Keep the approved flat domain API; control results are short-lived and concurrency is bounded.
#[allow(clippy::large_enum_variant)]
pub enum AgentResult {
    Preflight { report: PreflightReport },
    Accepted,
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
}
