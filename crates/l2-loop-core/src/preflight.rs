use serde::{Deserialize, Serialize};

use crate::{Direction, HookRole, InterfaceName};

pub const PF_INTERFACE_MISSING: &str = "PF_INTERFACE_MISSING";
pub const PF_INTERFACE_UNSUPPORTED: &str = "PF_INTERFACE_UNSUPPORTED";
pub const PF_BOND_NO_ACTIVE_SLAVE: &str = "PF_BOND_NO_ACTIVE_SLAVE";
pub const PF_XDP_STATE_UNKNOWN: &str = "PF_XDP_STATE_UNKNOWN";
pub const PF_XDP_OCCUPIED: &str = "PF_XDP_OCCUPIED";
pub const PF_TC_STATE_UNKNOWN: &str = "PF_TC_STATE_UNKNOWN";
pub const PF_TC_HANDLE_COLLISION: &str = "PF_TC_HANDLE_COLLISION";
pub const PF_PIN_ROOT_FOREIGN: &str = "PF_PIN_ROOT_FOREIGN";
pub const PF_MEMLOCK_TOO_LOW: &str = "PF_MEMLOCK_TOO_LOW";
pub const PF_KERNEL_CAPABILITY: &str = "PF_KERNEL_CAPABILITY";
pub const PF_LIVE_INTERFACE: &str = "PF_LIVE_INTERFACE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightDecision {
    Ready,
    ReadyWithWarnings,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Blocker,
    Warning,
    Information,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightFinding {
    pub code: String,
    pub severity: FindingSeverity,
    pub message: String,
}

impl PreflightFinding {
    pub fn information(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, FindingSeverity::Information, message)
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, FindingSeverity::Warning, message)
    }

    pub fn blocker(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, FindingSeverity::Blocker, message)
    }

    fn new(code: impl Into<String>, severity: FindingSeverity, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Physical,
    Bond,
    Veth,
    Bridge,
    OvsInternal,
    Tap,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BondMode {
    ActiveBackup,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceRef {
    pub name: InterfaceName,
    pub ifindex: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondInspection {
    pub mode: BondMode,
    pub slaves: Vec<InterfaceRef>,
    pub active_slave: Option<InterfaceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentTarget {
    pub interface: InterfaceRef,
    pub role: HookRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInspection {
    pub requested: InterfaceRef,
    pub kind: InterfaceKind,
    pub admin_up: bool,
    pub oper_up: bool,
    pub master: Option<InterfaceRef>,
    pub bond: Option<BondInspection>,
    pub proposed_targets: Vec<AttachmentTarget>,
    pub isolated: bool,
    pub live_shared: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentState {
    Empty,
    Owned { program_id: u32 },
    Occupied { program_id: u32 },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinRootState {
    Absent,
    Empty,
    Owned,
    Foreign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcAttachment {
    pub direction: Direction,
    pub priority: u16,
    pub handle: u32,
    pub program_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemlockInspection {
    pub soft_bytes: Option<u64>,
    pub hard_bytes: Option<u64>,
    pub required_bytes: u64,
    pub can_raise: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelInspection {
    pub architecture: String,
    pub release: String,
    pub bpf_syscall: bool,
    pub bpf_jit: bool,
    pub btf_readable: bool,
    pub tc_clsact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfInspection {
    pub bpffs_mounted: bool,
    pub relevant_objects_enumerable: bool,
    pub pin_root: PinRootState,
    pub xdp_native: AttachmentState,
    pub xdp_generic: AttachmentState,
    pub tc_ingress: Vec<TcAttachment>,
    pub tc_egress: Vec<TcAttachment>,
    pub memlock: MemlockInspection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    pub decision: PreflightDecision,
    pub interface: InterfaceInspection,
    pub kernel: KernelInspection,
    pub bpf: BpfInspection,
    pub findings: Vec<PreflightFinding>,
}

impl PreflightReport {
    pub fn new(
        interface: InterfaceInspection,
        kernel: KernelInspection,
        bpf: BpfInspection,
        mut findings: Vec<PreflightFinding>,
    ) -> Self {
        findings.sort_by(|left, right| {
            left.severity
                .cmp(&right.severity)
                .then_with(|| left.code.cmp(&right.code))
        });

        let decision = if findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Blocker)
        {
            PreflightDecision::Blocked
        } else if findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Warning)
        {
            PreflightDecision::ReadyWithWarnings
        } else {
            PreflightDecision::Ready
        };

        Self {
            decision,
            interface,
            kernel,
            bpf,
            findings,
        }
    }
}
