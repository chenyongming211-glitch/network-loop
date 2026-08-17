use std::{
    path::Path,
    time::{SystemTimeError, UNIX_EPOCH},
};

use l2_loop_core::{
    AttachmentState, CanaryPlanV1, DG_ARTIFACT_INVENTORY, DG_ARTIFACT_MANIFEST, DG_AUTH_ARTIFACT,
    DG_AUTH_EXPIRED, DG_AUTH_IDENTITY, DG_AUTH_SCHEMA, DG_EVIDENCE_ROOT, DG_INTERFACE_UNSUPPORTED,
    DG_LAYOUT_TYPE, DG_NATIVE_XDP_UNVERIFIED, DG_PERFORMANCE_REGRESSION,
    DG_PERFORMANCE_UNAVAILABLE, DG_PLATFORM_BLOCKED, DG_REAL_JOURNALD_UNVERIFIED, DG_STAGING_ROOT,
    DG_SYSTEMD_CONTRACT, DG_TC_NOT_EMPTY, DG_WORKLOAD_PERFORMANCE_UNVERIFIED, DG_XDP_NOT_EMPTY,
    DeploymentArtifactIdentityV1, DeploymentAuthorizationV1, DeploymentCommandV1,
    DeploymentContractError, DeploymentFindingV1, DeploymentGateReportV1, DeploymentGateStateV1,
    DeploymentGateSummariesV1, DeploymentGateSummaryV1, DeploymentHostCompatibilityV1,
    DeploymentInterfaceSummaryV1, FindingSeverity, InterfaceKind, PF_LIVE_INTERFACE,
    PerformanceEvidenceV1, PerformanceResultV1,
};
use thiserror::Error;

use crate::{
    Clock, DeploymentFilesystem, DeploymentPlatformInspector, DeploymentPlatformSnapshotV1,
};

const UNVERIFIED_COMMIT_SHA: &str = "0000000000000000000000000000000000000000";
const UNVERIFIED_PACKAGE_VERSION: &str = "unverified";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentServiceError {
    #[error("deployment gate report could not be derived")]
    InvalidReport,
    #[error("deployment gate clock is invalid")]
    InvalidClock,
}

impl From<DeploymentContractError> for DeploymentServiceError {
    fn from(_: DeploymentContractError) -> Self {
        Self::InvalidReport
    }
}

impl From<SystemTimeError> for DeploymentServiceError {
    fn from(_: SystemTimeError) -> Self {
        Self::InvalidClock
    }
}

pub struct DeploymentGateService<F, P, C> {
    filesystem: F,
    platform: P,
    clock: C,
}

impl<F, P, C> DeploymentGateService<F, P, C>
where
    F: DeploymentFilesystem,
    P: DeploymentPlatformInspector,
    C: Clock,
{
    pub fn new(filesystem: F, platform: P, clock: C) -> Self {
        Self {
            filesystem,
            platform,
            clock,
        }
    }

    pub fn staging(
        &mut self,
        bundle_path: &Path,
        staging_root: &Path,
    ) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
        let captured_at_unix_ms = self.captured_at_unix_ms()?;
        if self.filesystem.validate_staging_root(staging_root).is_err() {
            return blocked_report(
                DeploymentCommandV1::Staging,
                None,
                GateSlot::Layout,
                DG_STAGING_ROOT,
                captured_at_unix_ms,
            );
        }

        let bundle = match self.filesystem.inspect_bundle(bundle_path) {
            Ok(bundle) => bundle,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Staging,
                    None,
                    GateSlot::Bundle,
                    DG_ARTIFACT_INVENTORY,
                    captured_at_unix_ms,
                );
            }
        };
        let artifact = bundle.artifact;
        if artifact.validate().is_err() {
            return blocked_report(
                DeploymentCommandV1::Staging,
                None,
                GateSlot::Bundle,
                DG_ARTIFACT_MANIFEST,
                captured_at_unix_ms,
            );
        }

        let layout = match self.filesystem.inspect_staged_layout(staging_root) {
            Ok(layout) => layout,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Staging,
                    Some(artifact),
                    GateSlot::Layout,
                    DG_LAYOUT_TYPE,
                    captured_at_unix_ms,
                );
            }
        };
        if layout.artifact != artifact {
            return blocked_report(
                DeploymentCommandV1::Staging,
                Some(artifact),
                GateSlot::Layout,
                DG_ARTIFACT_MANIFEST,
                captured_at_unix_ms,
            );
        }

        let service = match self.filesystem.inspect_staged_service(staging_root) {
            Ok(service) => service,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Staging,
                    Some(artifact),
                    GateSlot::Service,
                    DG_SYSTEMD_CONTRACT,
                    captured_at_unix_ms,
                );
            }
        };
        if !service.is_valid() {
            return blocked_report(
                DeploymentCommandV1::Staging,
                Some(artifact),
                GateSlot::Service,
                DG_SYSTEMD_CONTRACT,
                captured_at_unix_ms,
            );
        }

        let authorization = match self.filesystem.load_staged_authorization(staging_root) {
            Ok(authorization) => authorization,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Staging,
                    Some(artifact),
                    GateSlot::Authorization,
                    DG_AUTH_SCHEMA,
                    captured_at_unix_ms,
                );
            }
        };
        if let Some(code) = authorization_failure(&authorization, &artifact, captured_at_unix_ms) {
            return blocked_report(
                DeploymentCommandV1::Staging,
                Some(artifact),
                GateSlot::Authorization,
                code,
                captured_at_unix_ms,
            );
        }

        let performance = match self.filesystem.load_staged_performance(staging_root) {
            Ok(performance) => performance,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Staging,
                    Some(artifact),
                    GateSlot::Performance,
                    DG_PERFORMANCE_UNAVAILABLE,
                    captured_at_unix_ms,
                );
            }
        };
        if let Some(code) = staged_performance_failure(&performance, &artifact, captured_at_unix_ms)
        {
            return blocked_report(
                DeploymentCommandV1::Staging,
                Some(artifact),
                GateSlot::Performance,
                code,
                captured_at_unix_ms,
            );
        }

        let prerequisites = match self.filesystem.inspect_staged_prerequisites(staging_root) {
            Ok(prerequisites) => prerequisites,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Staging,
                    Some(artifact),
                    GateSlot::Evidence,
                    DG_EVIDENCE_ROOT,
                    captured_at_unix_ms,
                );
            }
        };
        if !prerequisites.is_ready() {
            return blocked_report(
                DeploymentCommandV1::Staging,
                Some(artifact),
                GateSlot::Evidence,
                DG_EVIDENCE_ROOT,
                captured_at_unix_ms,
            );
        }

        Ok(DeploymentGateReportV1::derive(
            DeploymentCommandV1::Staging,
            artifact,
            None,
            DeploymentGateSummariesV1::staging_passed(),
            Vec::new(),
            None,
            captured_at_unix_ms,
        )?)
    }

    pub fn inspect(&mut self) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
        let captured_at_unix_ms = self.captured_at_unix_ms()?;
        let ownership = match self.filesystem.inspect_installed_ownership() {
            Ok(ownership) => ownership,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Inspect,
                    None,
                    GateSlot::Layout,
                    DG_LAYOUT_TYPE,
                    captured_at_unix_ms,
                );
            }
        };
        let layout = match self.filesystem.inspect_installed_layout() {
            Ok(layout) => layout,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Inspect,
                    None,
                    GateSlot::Layout,
                    DG_LAYOUT_TYPE,
                    captured_at_unix_ms,
                );
            }
        };
        let artifact = layout.artifact;
        if artifact.validate().is_err() || artifact != ownership.artifact {
            return blocked_report(
                DeploymentCommandV1::Inspect,
                None,
                GateSlot::Layout,
                DG_ARTIFACT_MANIFEST,
                captured_at_unix_ms,
            );
        }

        let service = match self.filesystem.inspect_installed_service() {
            Ok(service) => service,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Inspect,
                    Some(artifact),
                    GateSlot::Service,
                    DG_SYSTEMD_CONTRACT,
                    captured_at_unix_ms,
                );
            }
        };
        if !service.is_valid() {
            return blocked_report(
                DeploymentCommandV1::Inspect,
                Some(artifact),
                GateSlot::Service,
                DG_SYSTEMD_CONTRACT,
                captured_at_unix_ms,
            );
        }

        let authorization = match self.filesystem.load_installed_authorization() {
            Ok(authorization) => authorization,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Inspect,
                    Some(artifact),
                    GateSlot::Authorization,
                    DG_AUTH_SCHEMA,
                    captured_at_unix_ms,
                );
            }
        };
        if authorization.authorization_id != ownership.authorization_id {
            return blocked_report(
                DeploymentCommandV1::Inspect,
                Some(artifact),
                GateSlot::Authorization,
                DG_AUTH_IDENTITY,
                captured_at_unix_ms,
            );
        }
        if let Some(code) = authorization_failure(&authorization, &artifact, captured_at_unix_ms) {
            return blocked_report(
                DeploymentCommandV1::Inspect,
                Some(artifact),
                GateSlot::Authorization,
                code,
                captured_at_unix_ms,
            );
        }

        let performance = match self.filesystem.load_installed_performance() {
            Ok(performance) => performance,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Inspect,
                    Some(artifact),
                    GateSlot::Performance,
                    DG_PERFORMANCE_UNAVAILABLE,
                    captured_at_unix_ms,
                );
            }
        };

        let platform = match self.platform.inspect_authorized_interface(&authorization) {
            Ok(platform) => platform,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Inspect,
                    Some(artifact),
                    GateSlot::Platform,
                    DG_PLATFORM_BLOCKED,
                    captured_at_unix_ms,
                );
            }
        };
        if let Some(code) = platform_failure(&platform, &authorization) {
            return blocked_report(
                DeploymentCommandV1::Inspect,
                Some(artifact),
                GateSlot::Platform,
                code,
                captured_at_unix_ms,
            );
        }

        if let Some(code) =
            performance_failure(&performance, &artifact, &platform.host, captured_at_unix_ms)
        {
            return blocked_report(
                DeploymentCommandV1::Inspect,
                Some(artifact),
                GateSlot::Performance,
                code,
                captured_at_unix_ms,
            );
        }

        let prerequisites = match self.filesystem.inspect_installed_prerequisites() {
            Ok(prerequisites) => prerequisites,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Inspect,
                    Some(artifact),
                    GateSlot::Evidence,
                    DG_EVIDENCE_ROOT,
                    captured_at_unix_ms,
                );
            }
        };
        if !prerequisites.is_ready() {
            return blocked_report(
                DeploymentCommandV1::Inspect,
                Some(artifact),
                GateSlot::Evidence,
                DG_EVIDENCE_ROOT,
                captured_at_unix_ms,
            );
        }

        let interface = DeploymentInterfaceSummaryV1::new(
            platform.interface_name.as_str(),
            platform.ifindex,
            platform.kind,
            platform.administrative_up,
            platform.operational_up,
        )?;
        let canary_plan = CanaryPlanV1::new(&authorization, &interface)?;
        let findings = [
            DG_REAL_JOURNALD_UNVERIFIED,
            DG_NATIVE_XDP_UNVERIFIED,
            DG_WORKLOAD_PERFORMANCE_UNVERIFIED,
        ]
        .into_iter()
        .map(DeploymentFindingV1::warning)
        .collect::<Result<Vec<_>, _>>()?;

        Ok(DeploymentGateReportV1::derive(
            DeploymentCommandV1::Inspect,
            artifact,
            Some(interface),
            DeploymentGateSummariesV1::inspect_passed(),
            findings,
            Some(canary_plan),
            captured_at_unix_ms,
        )?)
    }

    pub fn installed(&mut self) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
        let captured_at_unix_ms = self.captured_at_unix_ms()?;
        let ownership = match self.filesystem.inspect_installed_ownership() {
            Ok(ownership) => ownership,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Installed,
                    None,
                    GateSlot::Layout,
                    DG_LAYOUT_TYPE,
                    captured_at_unix_ms,
                );
            }
        };
        let layout = match self.filesystem.inspect_installed_layout() {
            Ok(layout) => layout,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Installed,
                    Some(ownership.artifact),
                    GateSlot::Layout,
                    DG_LAYOUT_TYPE,
                    captured_at_unix_ms,
                );
            }
        };
        let artifact = layout.artifact;
        if artifact.validate().is_err() || artifact != ownership.artifact {
            return blocked_report(
                DeploymentCommandV1::Installed,
                Some(artifact),
                GateSlot::Layout,
                DG_ARTIFACT_MANIFEST,
                captured_at_unix_ms,
            );
        }

        let service = match self.filesystem.inspect_installed_service() {
            Ok(service) => service,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Installed,
                    Some(artifact),
                    GateSlot::Service,
                    DG_SYSTEMD_CONTRACT,
                    captured_at_unix_ms,
                );
            }
        };
        if !service.is_valid() {
            return blocked_report(
                DeploymentCommandV1::Installed,
                Some(artifact),
                GateSlot::Service,
                DG_SYSTEMD_CONTRACT,
                captured_at_unix_ms,
            );
        }

        let authorization = match self.filesystem.load_installed_authorization() {
            Ok(authorization) => authorization,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Installed,
                    Some(artifact),
                    GateSlot::Authorization,
                    DG_AUTH_SCHEMA,
                    captured_at_unix_ms,
                );
            }
        };
        if authorization.authorization_id != ownership.authorization_id {
            return blocked_report(
                DeploymentCommandV1::Installed,
                Some(artifact),
                GateSlot::Authorization,
                DG_AUTH_IDENTITY,
                captured_at_unix_ms,
            );
        }
        if let Some(code) = authorization_failure(&authorization, &artifact, captured_at_unix_ms) {
            return blocked_report(
                DeploymentCommandV1::Installed,
                Some(artifact),
                GateSlot::Authorization,
                code,
                captured_at_unix_ms,
            );
        }

        let performance = match self.filesystem.load_installed_performance() {
            Ok(performance) => performance,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Installed,
                    Some(artifact),
                    GateSlot::Performance,
                    DG_PERFORMANCE_UNAVAILABLE,
                    captured_at_unix_ms,
                );
            }
        };
        if let Some(code) = staged_performance_failure(&performance, &artifact, captured_at_unix_ms)
        {
            return blocked_report(
                DeploymentCommandV1::Installed,
                Some(artifact),
                GateSlot::Performance,
                code,
                captured_at_unix_ms,
            );
        }

        let prerequisites = match self.filesystem.inspect_installed_prerequisites() {
            Ok(prerequisites) => prerequisites,
            Err(_) => {
                return blocked_report(
                    DeploymentCommandV1::Installed,
                    Some(artifact),
                    GateSlot::Evidence,
                    DG_EVIDENCE_ROOT,
                    captured_at_unix_ms,
                );
            }
        };
        if !prerequisites.is_ready() {
            return blocked_report(
                DeploymentCommandV1::Installed,
                Some(artifact),
                GateSlot::Evidence,
                DG_EVIDENCE_ROOT,
                captured_at_unix_ms,
            );
        }

        Ok(DeploymentGateReportV1::derive(
            DeploymentCommandV1::Installed,
            artifact,
            None,
            DeploymentGateSummariesV1::installed_passed(),
            Vec::new(),
            None,
            captured_at_unix_ms,
        )?)
    }

    fn captured_at_unix_ms(&self) -> Result<u64, DeploymentServiceError> {
        let elapsed = self.clock.wall_time().duration_since(UNIX_EPOCH)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| DeploymentServiceError::InvalidClock)
    }
}

fn authorization_failure(
    authorization: &DeploymentAuthorizationV1,
    artifact: &DeploymentArtifactIdentityV1,
    captured_at_unix_ms: u64,
) -> Option<&'static str> {
    if authorization.validate_at(captured_at_unix_ms).is_err() {
        if captured_at_unix_ms < authorization.issued_at_unix_ms
            || captured_at_unix_ms > authorization.expires_at_unix_ms
        {
            return Some(DG_AUTH_EXPIRED);
        }
        return Some(DG_AUTH_SCHEMA);
    }
    if authorization.artifact_commit_sha != artifact.commit_sha {
        return Some(DG_AUTH_ARTIFACT);
    }
    authorization
        .validate_for(captured_at_unix_ms, artifact)
        .err()
        .map(|_| DG_AUTH_SCHEMA)
}

fn staged_performance_failure(
    performance: &PerformanceEvidenceV1,
    artifact: &DeploymentArtifactIdentityV1,
    captured_at_unix_ms: u64,
) -> Option<&'static str> {
    let host = match DeploymentHostCompatibilityV1::new(
        performance.architecture.as_str(),
        performance.kernel_release.as_str(),
        performance.logical_cpu_count,
    ) {
        Ok(host) => host,
        Err(_) => return Some(DG_PERFORMANCE_UNAVAILABLE),
    };
    performance_failure(performance, artifact, &host, captured_at_unix_ms)
}

fn performance_failure(
    performance: &PerformanceEvidenceV1,
    artifact: &DeploymentArtifactIdentityV1,
    host: &DeploymentHostCompatibilityV1,
    captured_at_unix_ms: u64,
) -> Option<&'static str> {
    let result_code = match performance.result {
        PerformanceResultV1::Passed => DG_PERFORMANCE_UNAVAILABLE,
        PerformanceResultV1::Failed => DG_PERFORMANCE_REGRESSION,
        PerformanceResultV1::Unavailable => DG_PERFORMANCE_UNAVAILABLE,
    };
    let assessment = match performance.assess_for(captured_at_unix_ms, artifact, host) {
        Ok(assessment) => assessment,
        Err(_) => return Some(result_code),
    };
    match assessment.result {
        PerformanceResultV1::Passed => None,
        PerformanceResultV1::Failed => Some(DG_PERFORMANCE_REGRESSION),
        PerformanceResultV1::Unavailable => Some(DG_PERFORMANCE_UNAVAILABLE),
    }
}

fn platform_failure(
    platform: &DeploymentPlatformSnapshotV1,
    authorization: &DeploymentAuthorizationV1,
) -> Option<&'static str> {
    let authorized = &authorization.interface;
    let preflight = &platform.preflight;
    if platform.interface_name.as_str() != authorized.name
        || platform.ifindex != authorized.ifindex
        || platform.mac_address_sha256 != authorized.mac_address_sha256
        || platform.driver != authorized.driver
        || platform.device_identity_sha256 != authorized.device_identity_sha256
        || platform.network_namespace_sha256 != authorized.network_namespace_sha256
        || platform.administrative_up != preflight.interface.admin_up
        || platform.operational_up != preflight.interface.oper_up
        || platform.master_ifindex
            != preflight
                .interface
                .master
                .as_ref()
                .map(|master| master.ifindex)
        || preflight.interface.requested.name != platform.interface_name
        || preflight.interface.requested.ifindex != platform.ifindex
    {
        return Some(DG_AUTH_IDENTITY);
    }
    if platform.kind != InterfaceKind::Physical
        || platform.kind != authorized.kind
        || preflight.interface.kind != InterfaceKind::Physical
        || !platform.administrative_up
        || !platform.operational_up
        || platform.master_ifindex.is_some()
        || preflight.interface.bond.is_some()
    {
        return Some(DG_INTERFACE_UNSUPPORTED);
    }
    if preflight.bpf.xdp_native != AttachmentState::Empty
        || preflight.bpf.xdp_generic != AttachmentState::Empty
    {
        return Some(DG_XDP_NOT_EMPTY);
    }
    if platform.tc_clsact_present
        || !preflight.bpf.tc_ingress.is_empty()
        || !preflight.bpf.tc_egress.is_empty()
    {
        return Some(DG_TC_NOT_EMPTY);
    }
    let blocker_codes = preflight
        .findings
        .iter()
        .filter(|finding| finding.severity == FindingSeverity::Blocker)
        .map(|finding| finding.code.as_str())
        .collect::<Vec<_>>();
    if blocker_codes.len() != 1
        || blocker_codes.first().copied() != Some(PF_LIVE_INTERFACE)
        || platform.address_present
        || platform.route_present
        || platform.neighbor_present
        || platform.service_present
        || platform.other_consumer_present
        || !platform.capabilities_sufficient
        || !platform.native_xdp_driver_ready
        || platform.receive_queue_count == 0
        || !platform.offload_state_known
        || !preflight.kernel.bpf_syscall
        || !preflight.kernel.bpf_jit
        || !preflight.kernel.btf_readable
        || !preflight.kernel.tc_clsact
        || !preflight.bpf.bpffs_mounted
        || !preflight.bpf.relevant_objects_enumerable
        || preflight.bpf.memlock.soft_bytes.unwrap_or(0) < preflight.bpf.memlock.required_bytes
            && !preflight.bpf.memlock.can_raise
        || preflight.kernel.architecture != platform.host.architecture
        || preflight.kernel.release != platform.host.kernel_release
    {
        return Some(DG_PLATFORM_BLOCKED);
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateSlot {
    Bundle,
    Layout,
    Service,
    Authorization,
    Platform,
    Evidence,
    Performance,
}

fn blocked_report(
    command: DeploymentCommandV1,
    artifact: Option<DeploymentArtifactIdentityV1>,
    slot: GateSlot,
    code: &'static str,
    captured_at_unix_ms: u64,
) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
    let artifact = match artifact {
        Some(artifact) => artifact,
        None => {
            DeploymentArtifactIdentityV1::new(UNVERIFIED_COMMIT_SHA, UNVERIFIED_PACKAGE_VERSION)?
        }
    };
    Ok(DeploymentGateReportV1::derive(
        command,
        artifact,
        None,
        blocked_gates(slot, code),
        vec![DeploymentFindingV1::blocker(code)?],
        None,
        captured_at_unix_ms,
    )?)
}

fn blocked_gates(slot: GateSlot, code: &'static str) -> DeploymentGateSummariesV1 {
    DeploymentGateSummariesV1 {
        bundle: gate_summary(slot, GateSlot::Bundle, code),
        layout: gate_summary(slot, GateSlot::Layout, code),
        service: gate_summary(slot, GateSlot::Service, code),
        authorization: gate_summary(slot, GateSlot::Authorization, code),
        platform: gate_summary(slot, GateSlot::Platform, code),
        evidence: gate_summary(slot, GateSlot::Evidence, code),
        performance: gate_summary(slot, GateSlot::Performance, code),
    }
}

fn gate_summary(
    slot: GateSlot,
    candidate: GateSlot,
    code: &'static str,
) -> DeploymentGateSummaryV1 {
    if slot == candidate {
        DeploymentGateSummaryV1 {
            state: DeploymentGateStateV1::Blocked,
            finding_codes: vec![code.to_owned()],
        }
    } else {
        DeploymentGateSummaryV1 {
            state: DeploymentGateStateV1::NotApplicable,
            finding_codes: Vec::new(),
        }
    }
}
