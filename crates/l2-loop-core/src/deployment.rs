use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{InterfaceKind, InterfaceName};

pub const DEPLOYMENT_SCHEMA_VERSION: u16 = 1;
pub const AUTHORIZATION_MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
pub const PERFORMANCE_EVIDENCE_MAX_LIFETIME_MS: u64 = AUTHORIZATION_MAX_LIFETIME_MS;
pub const CANARY_MAX_OBSERVATION_MS: u64 = 15 * 60 * 1_000;
pub const PERFORMANCE_TRIALS_PER_MODE: usize = 5;
pub const PERFORMANCE_TOTAL_TRIALS: usize = PERFORMANCE_TRIALS_PER_MODE * 3;
pub const PERFORMANCE_FIXED_FRAME_SIZES: [u16; 3] = [64, 512, 1_514];
pub const PERFORMANCE_FRAMES_PER_SIZE: u32 = 65_536;
pub const PERFORMANCE_PASS_THROUGH_MIN_PERMILLE: u16 = 950;
pub const PERFORMANCE_OBSERVE_MIN_PERMILLE: u16 = 900;
pub const PERFORMANCE_MAX_DAEMON_RSS_BYTES: u64 = 256 * 1024 * 1024;
pub const PERFORMANCE_MAX_RSS_GROWTH_BYTES: u64 = 16 * 1024 * 1024;
pub const PERFORMANCE_MAX_DAEMON_CPU_PERMILLE: u16 = 1_000;

pub const DG_ARTIFACT_INVENTORY: &str = "DG_ARTIFACT_INVENTORY";
pub const DG_ARTIFACT_MANIFEST: &str = "DG_ARTIFACT_MANIFEST";
pub const DG_ARTIFACT_CHECKSUM: &str = "DG_ARTIFACT_CHECKSUM";
pub const DG_STAGING_ROOT: &str = "DG_STAGING_ROOT";
pub const DG_LAYOUT_TYPE: &str = "DG_LAYOUT_TYPE";
pub const DG_LAYOUT_MODE: &str = "DG_LAYOUT_MODE";
pub const DG_LAYOUT_SYMLINK: &str = "DG_LAYOUT_SYMLINK";
pub const DG_SYSTEMD_CONTRACT: &str = "DG_SYSTEMD_CONTRACT";
pub const DG_AUTH_SCHEMA: &str = "DG_AUTH_SCHEMA";
pub const DG_AUTH_EXPIRED: &str = "DG_AUTH_EXPIRED";
pub const DG_AUTH_ARTIFACT: &str = "DG_AUTH_ARTIFACT";
pub const DG_AUTH_IDENTITY: &str = "DG_AUTH_IDENTITY";
pub const DG_INTERFACE_UNSUPPORTED: &str = "DG_INTERFACE_UNSUPPORTED";
pub const DG_XDP_NOT_EMPTY: &str = "DG_XDP_NOT_EMPTY";
pub const DG_TC_NOT_EMPTY: &str = "DG_TC_NOT_EMPTY";
pub const DG_PLATFORM_BLOCKED: &str = "DG_PLATFORM_BLOCKED";
pub const DG_EVIDENCE_ROOT: &str = "DG_EVIDENCE_ROOT";
pub const DG_PERFORMANCE_UNAVAILABLE: &str = "DG_PERFORMANCE_UNAVAILABLE";
pub const DG_PERFORMANCE_REGRESSION: &str = "DG_PERFORMANCE_REGRESSION";
pub const DG_INTERNAL: &str = "DG_INTERNAL";
pub const DG_REAL_JOURNALD_UNVERIFIED: &str = "DG_REAL_JOURNALD_UNVERIFIED";
pub const DG_NATIVE_XDP_UNVERIFIED: &str = "DG_NATIVE_XDP_UNVERIFIED";
pub const DG_WORKLOAD_PERFORMANCE_UNVERIFIED: &str = "DG_WORKLOAD_PERFORMANCE_UNVERIFIED";

const BLOCKER_CODES: [&str; 20] = [
    DG_ARTIFACT_INVENTORY,
    DG_ARTIFACT_MANIFEST,
    DG_ARTIFACT_CHECKSUM,
    DG_STAGING_ROOT,
    DG_LAYOUT_TYPE,
    DG_LAYOUT_MODE,
    DG_LAYOUT_SYMLINK,
    DG_SYSTEMD_CONTRACT,
    DG_AUTH_SCHEMA,
    DG_AUTH_EXPIRED,
    DG_AUTH_ARTIFACT,
    DG_AUTH_IDENTITY,
    DG_INTERFACE_UNSUPPORTED,
    DG_XDP_NOT_EMPTY,
    DG_TC_NOT_EMPTY,
    DG_PLATFORM_BLOCKED,
    DG_EVIDENCE_ROOT,
    DG_PERFORMANCE_UNAVAILABLE,
    DG_PERFORMANCE_REGRESSION,
    DG_INTERNAL,
];

const WARNING_CODES: [&str; 3] = [
    DG_REAL_JOURNALD_UNVERIFIED,
    DG_NATIVE_XDP_UNVERIFIED,
    DG_WORKLOAD_PERFORMANCE_UNVERIFIED,
];

const PERFORMANCE_TRIAL_MODE_ORDER: [PerformanceModeV1; PERFORMANCE_TOTAL_TRIALS] = [
    PerformanceModeV1::Baseline,
    PerformanceModeV1::PassThrough,
    PerformanceModeV1::Observe,
    PerformanceModeV1::PassThrough,
    PerformanceModeV1::Observe,
    PerformanceModeV1::Baseline,
    PerformanceModeV1::Observe,
    PerformanceModeV1::Baseline,
    PerformanceModeV1::PassThrough,
    PerformanceModeV1::Baseline,
    PerformanceModeV1::Observe,
    PerformanceModeV1::PassThrough,
    PerformanceModeV1::PassThrough,
    PerformanceModeV1::Baseline,
    PerformanceModeV1::Observe,
];

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentContractError {
    #[error("deployment artifact identity is invalid")]
    InvalidArtifactIdentity,
    #[error("deployment host compatibility identity is invalid")]
    InvalidHostCompatibility,
    #[error("deployment authorization is invalid")]
    InvalidAuthorization,
    #[error("performance evidence is invalid")]
    InvalidPerformanceEvidence,
    #[error("deployment finding is invalid")]
    InvalidFinding,
    #[error("deployment gate summary is invalid")]
    InvalidGateSummary,
    #[error("canary plan is invalid")]
    InvalidCanaryPlan,
    #[error("deployment gate report is invalid")]
    InvalidReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentDecisionV1 {
    Blocked,
    StagingReady,
    CanaryCandidate,
}

impl fmt::Display for DeploymentDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Blocked => "blocked",
            Self::StagingReady => "staging_ready",
            Self::CanaryCandidate => "canary_candidate",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentCommandV1 {
    Staging,
    Inspect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentArtifactIdentityV1 {
    #[serde(deserialize_with = "deserialize_commit_sha")]
    pub commit_sha: String,
    pub package_version: String,
}

impl DeploymentArtifactIdentityV1 {
    pub fn new(
        commit_sha: impl Into<String>,
        package_version: impl Into<String>,
    ) -> Result<Self, DeploymentContractError> {
        let identity = Self {
            commit_sha: commit_sha.into(),
            package_version: package_version.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), DeploymentContractError> {
        if !is_lower_hex(&self.commit_sha, 40) || !is_safe_text(&self.package_version, 64) {
            return Err(DeploymentContractError::InvalidArtifactIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentHostCompatibilityV1 {
    pub architecture: String,
    pub kernel_release: String,
    pub logical_cpu_count: u32,
}

impl DeploymentHostCompatibilityV1 {
    pub fn new(
        architecture: impl Into<String>,
        kernel_release: impl Into<String>,
        logical_cpu_count: u32,
    ) -> Result<Self, DeploymentContractError> {
        let identity = Self {
            architecture: architecture.into(),
            kernel_release: kernel_release.into(),
            logical_cpu_count,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), DeploymentContractError> {
        if !is_safe_text(&self.architecture, 32)
            || !is_safe_text(&self.kernel_release, 128)
            || self.logical_cpu_count == 0
        {
            return Err(DeploymentContractError::InvalidHostCompatibility);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentAuthorizationModeV1 {
    ReadOnlyCanaryCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentLinkStateV1 {
    Up,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentHookStateV1 {
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAuthorizedInterfaceV1 {
    pub name: String,
    pub ifindex: u32,
    pub kind: InterfaceKind,
    pub administrative_state: DeploymentLinkStateV1,
    pub operational_state: DeploymentLinkStateV1,
    pub master_ifindex: Option<u32>,
    pub xdp_native: DeploymentHookStateV1,
    pub xdp_generic: DeploymentHookStateV1,
    pub tc_clsact: bool,
    pub tc_ingress: Vec<String>,
    pub tc_egress: Vec<String>,
}

impl DeploymentAuthorizedInterfaceV1 {
    fn validate(&self) -> Result<(), DeploymentContractError> {
        if InterfaceName::new(self.name.as_str()).is_err()
            || self.ifindex == 0
            || self.kind != InterfaceKind::Physical
            || self.master_ifindex.is_some()
            || self.tc_clsact
            || !self.tc_ingress.is_empty()
            || !self.tc_egress.is_empty()
        {
            return Err(DeploymentContractError::InvalidAuthorization);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAuthorizationV1 {
    pub schema_version: u16,
    #[serde(deserialize_with = "deserialize_128_bit_id")]
    pub authorization_id: String,
    #[serde(deserialize_with = "deserialize_commit_sha")]
    pub artifact_commit_sha: String,
    pub mode: DeploymentAuthorizationModeV1,
    pub interface: DeploymentAuthorizedInterfaceV1,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl DeploymentAuthorizationV1 {
    pub fn validate_at(&self, captured_at_unix_ms: u64) -> Result<(), DeploymentContractError> {
        self.validate_structure()?;
        if !(self.issued_at_unix_ms..=self.expires_at_unix_ms).contains(&captured_at_unix_ms) {
            return Err(DeploymentContractError::InvalidAuthorization);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        captured_at_unix_ms: u64,
        artifact: &DeploymentArtifactIdentityV1,
    ) -> Result<(), DeploymentContractError> {
        self.validate_at(captured_at_unix_ms)?;
        artifact.validate()?;
        if self.artifact_commit_sha != artifact.commit_sha {
            return Err(DeploymentContractError::InvalidAuthorization);
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), DeploymentContractError> {
        let lifetime = self
            .expires_at_unix_ms
            .checked_sub(self.issued_at_unix_ms)
            .ok_or(DeploymentContractError::InvalidAuthorization)?;
        if self.schema_version != DEPLOYMENT_SCHEMA_VERSION
            || !is_lower_hex(&self.authorization_id, 32)
            || !is_lower_hex(&self.artifact_commit_sha, 40)
            || self.issued_at_unix_ms == 0
            || lifetime == 0
            || lifetime > AUTHORIZATION_MAX_LIFETIME_MS
        {
            return Err(DeploymentContractError::InvalidAuthorization);
        }
        self.interface.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceModeV1 {
    Baseline,
    PassThrough,
    Observe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceXdpModeV1 {
    Native,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceResultV1 {
    Passed,
    Failed,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceTrialV1 {
    pub trial_number: u8,
    pub mode: PerformanceModeV1,
    pub frame_sizes: [u16; 3],
    pub frames_per_size: u32,
    pub duration_ns: u64,
    pub packets_per_second: u64,
    pub bytes_per_second: u64,
    pub daemon_cpu_time_ns: u64,
    pub peak_resident_memory_bytes: u64,
    pub packet_drop_delta: u64,
    pub packet_error_delta: u64,
}

impl PerformanceTrialV1 {
    fn validate(&self) -> Result<(), DeploymentContractError> {
        if self.frame_sizes != PERFORMANCE_FIXED_FRAME_SIZES
            || self.frames_per_size != PERFORMANCE_FRAMES_PER_SIZE
            || self.duration_ns == 0
            || self.packets_per_second == 0
            || self.bytes_per_second == 0
        {
            return Err(DeploymentContractError::InvalidPerformanceEvidence);
        }

        let sent_packets = u128::from(self.frames_per_size)
            .checked_mul(self.frame_sizes.len() as u128)
            .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
        let sent_bytes = self
            .frame_sizes
            .iter()
            .try_fold(0_u128, |total, size| total.checked_add(u128::from(*size)))
            .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
        let sent_bytes = sent_bytes
            .checked_mul(u128::from(self.frames_per_size))
            .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
        let expected_packets_per_second = sent_packets
            .checked_mul(1_000_000_000)
            .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?
            / u128::from(self.duration_ns);
        let expected_bytes_per_second = sent_bytes
            .checked_mul(1_000_000_000)
            .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?
            / u128::from(self.duration_ns);
        if u128::from(self.packets_per_second) != expected_packets_per_second
            || u128::from(self.bytes_per_second) != expected_bytes_per_second
        {
            return Err(DeploymentContractError::InvalidPerformanceEvidence);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceRateV1 {
    pub packets_per_second: u64,
    pub bytes_per_second: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceMediansV1 {
    pub baseline: PerformanceRateV1,
    pub pass_through: PerformanceRateV1,
    pub observe: PerformanceRateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceEvidenceV1 {
    pub schema_version: u16,
    #[serde(deserialize_with = "deserialize_128_bit_id")]
    pub evidence_id: String,
    #[serde(deserialize_with = "deserialize_commit_sha")]
    pub artifact_commit_sha: String,
    pub package_version: String,
    pub architecture: String,
    pub kernel_release: String,
    pub logical_cpu_count: u32,
    pub veth_xdp_mode: PerformanceXdpModeV1,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub warm_up_complete: bool,
    pub measurement_complete: bool,
    pub measurement_noisy: bool,
    pub host_identity_stable: bool,
    pub trials: Vec<PerformanceTrialV1>,
    pub medians: PerformanceMediansV1,
    pub pass_through_baseline_ratio_permille: u16,
    pub observe_baseline_ratio_permille: u16,
    pub daemon_cpu_time_ns: u64,
    pub daemon_cpu_permille: u16,
    pub peak_resident_memory_bytes: u64,
    pub rss_growth_bytes: u64,
    pub packet_drop_delta: u64,
    pub packet_error_delta: u64,
    pub process_count_before: u32,
    pub process_count_after: u32,
    pub map_count_before: u32,
    pub map_count_after: u32,
    pub program_count_before: u32,
    pub program_count_after: u32,
    pub pin_count_before: u32,
    pub pin_count_after: u32,
    pub namespace_count_before: u32,
    pub namespace_count_after: u32,
    pub forwarding_intact: bool,
    pub owned_cleanup_complete: bool,
    pub network_identity_restored: bool,
    pub ebpf_identity_restored: bool,
    pub result: PerformanceResultV1,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceAssessmentV1 {
    pub medians: PerformanceMediansV1,
    pub pass_through_baseline_ratio_permille: u16,
    pub observe_baseline_ratio_permille: u16,
    pub daemon_cpu_time_ns: u64,
    pub daemon_cpu_permille: u16,
    pub peak_resident_memory_bytes: u64,
    pub rss_growth_bytes: u64,
    pub result: PerformanceResultV1,
    pub outstanding_warning_codes: Vec<String>,
}

impl PerformanceEvidenceV1 {
    pub fn assess_for(
        &self,
        captured_at_unix_ms: u64,
        artifact: &DeploymentArtifactIdentityV1,
        host: &DeploymentHostCompatibilityV1,
    ) -> Result<PerformanceAssessmentV1, DeploymentContractError> {
        artifact.validate()?;
        host.validate()?;
        let assessment = self.assess_structure(captured_at_unix_ms)?;
        if self.artifact_commit_sha != artifact.commit_sha
            || self.package_version != artifact.package_version
            || self.architecture != host.architecture
            || self.kernel_release != host.kernel_release
            || self.logical_cpu_count != host.logical_cpu_count
        {
            return Err(DeploymentContractError::InvalidPerformanceEvidence);
        }
        Ok(assessment)
    }

    pub fn validate_for(
        &self,
        captured_at_unix_ms: u64,
        artifact: &DeploymentArtifactIdentityV1,
        host: &DeploymentHostCompatibilityV1,
    ) -> Result<(), DeploymentContractError> {
        self.assess_for(captured_at_unix_ms, artifact, host)
            .map(|_| ())
    }

    fn assess_structure(
        &self,
        captured_at_unix_ms: u64,
    ) -> Result<PerformanceAssessmentV1, DeploymentContractError> {
        let lifetime = self
            .expires_at_unix_ms
            .checked_sub(self.issued_at_unix_ms)
            .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
        if self.schema_version != DEPLOYMENT_SCHEMA_VERSION
            || !is_lower_hex(&self.evidence_id, 32)
            || !is_lower_hex(&self.artifact_commit_sha, 40)
            || !is_safe_text(&self.package_version, 64)
            || !is_safe_text(&self.architecture, 32)
            || !is_safe_text(&self.kernel_release, 128)
            || self.logical_cpu_count == 0
            || self.issued_at_unix_ms == 0
            || lifetime == 0
            || lifetime > PERFORMANCE_EVIDENCE_MAX_LIFETIME_MS
            || !(self.issued_at_unix_ms..=self.expires_at_unix_ms).contains(&captured_at_unix_ms)
            || self.trials.len() != PERFORMANCE_TOTAL_TRIALS
        {
            return Err(DeploymentContractError::InvalidPerformanceEvidence);
        }

        let mut total_cpu_time_ns = 0_u64;
        let mut total_duration_ns = 0_u128;
        let mut total_drop_delta = 0_u64;
        let mut total_error_delta = 0_u64;
        let mut peak_resident_memory_bytes = 0_u64;
        for (index, trial) in self.trials.iter().enumerate() {
            trial.validate()?;
            let expected_trial_number = u8::try_from(index / 3 + 1)
                .map_err(|_| DeploymentContractError::InvalidPerformanceEvidence)?;
            if trial.trial_number != expected_trial_number
                || trial.mode != PERFORMANCE_TRIAL_MODE_ORDER[index]
            {
                return Err(DeploymentContractError::InvalidPerformanceEvidence);
            }
            total_cpu_time_ns = total_cpu_time_ns
                .checked_add(trial.daemon_cpu_time_ns)
                .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
            total_duration_ns = total_duration_ns
                .checked_add(u128::from(trial.duration_ns))
                .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
            total_drop_delta = total_drop_delta
                .checked_add(trial.packet_drop_delta)
                .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
            total_error_delta = total_error_delta
                .checked_add(trial.packet_error_delta)
                .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
            peak_resident_memory_bytes =
                peak_resident_memory_bytes.max(trial.peak_resident_memory_bytes);
        }

        let baseline = self.median_for(PerformanceModeV1::Baseline)?;
        let pass_through = self.median_for(PerformanceModeV1::PassThrough)?;
        let observe = self.median_for(PerformanceModeV1::Observe)?;
        let pass_through_ratio = conservative_ratio_permille(pass_through, baseline)?;
        let observe_ratio = conservative_ratio_permille(observe, baseline)?;
        let daemon_cpu_permille = u16::try_from(
            u128::from(total_cpu_time_ns)
                .checked_mul(1_000)
                .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?
                / total_duration_ns,
        )
        .map_err(|_| DeploymentContractError::InvalidPerformanceEvidence)?;
        let first_observe_rss = self.observe_rss_for_trial(1)?;
        let fifth_observe_rss = self.observe_rss_for_trial(5)?;
        let rss_growth_bytes = fifth_observe_rss.saturating_sub(first_observe_rss);
        if self.medians.baseline != baseline
            || self.medians.pass_through != pass_through
            || self.medians.observe != observe
            || self.pass_through_baseline_ratio_permille != pass_through_ratio
            || self.observe_baseline_ratio_permille != observe_ratio
            || self.daemon_cpu_time_ns != total_cpu_time_ns
            || self.daemon_cpu_permille != daemon_cpu_permille
            || self.peak_resident_memory_bytes != peak_resident_memory_bytes
            || self.rss_growth_bytes != rss_growth_bytes
            || self.packet_drop_delta != total_drop_delta
            || self.packet_error_delta != total_error_delta
            || !codes_are_sorted_unique(&self.findings)
            || self.findings.iter().any(|code| {
                !matches!(
                    code.as_str(),
                    DG_PERFORMANCE_REGRESSION | DG_PERFORMANCE_UNAVAILABLE
                )
            })
        {
            return Err(DeploymentContractError::InvalidPerformanceEvidence);
        }

        let unavailable = !self.warm_up_complete
            || !self.measurement_complete
            || self.measurement_noisy
            || !self.host_identity_stable;
        let regression = self.pass_through_baseline_ratio_permille
            < PERFORMANCE_PASS_THROUGH_MIN_PERMILLE
            || self.observe_baseline_ratio_permille < PERFORMANCE_OBSERVE_MIN_PERMILLE
            || self.daemon_cpu_permille > PERFORMANCE_MAX_DAEMON_CPU_PERMILLE
            || self.peak_resident_memory_bytes > PERFORMANCE_MAX_DAEMON_RSS_BYTES
            || self.rss_growth_bytes > PERFORMANCE_MAX_RSS_GROWTH_BYTES
            || self.packet_drop_delta != 0
            || self.packet_error_delta != 0
            || self.process_count_before != self.process_count_after
            || self.map_count_before != self.map_count_after
            || self.program_count_before != self.program_count_after
            || self.pin_count_before != self.pin_count_after
            || self.namespace_count_before != self.namespace_count_after
            || !self.forwarding_intact
            || !self.owned_cleanup_complete
            || !self.network_identity_restored
            || !self.ebpf_identity_restored;
        let expected_result = if unavailable {
            PerformanceResultV1::Unavailable
        } else if regression {
            PerformanceResultV1::Failed
        } else {
            PerformanceResultV1::Passed
        };
        let expected_findings = match expected_result {
            PerformanceResultV1::Passed => Vec::new(),
            PerformanceResultV1::Failed => vec![DG_PERFORMANCE_REGRESSION.to_owned()],
            PerformanceResultV1::Unavailable => vec![DG_PERFORMANCE_UNAVAILABLE.to_owned()],
        };
        if self.result != expected_result || self.findings != expected_findings {
            return Err(DeploymentContractError::InvalidPerformanceEvidence);
        }
        let mut outstanding_warning_codes = WARNING_CODES.map(str::to_owned).to_vec();
        outstanding_warning_codes.sort();
        Ok(PerformanceAssessmentV1 {
            medians: PerformanceMediansV1 {
                baseline,
                pass_through,
                observe,
            },
            pass_through_baseline_ratio_permille: pass_through_ratio,
            observe_baseline_ratio_permille: observe_ratio,
            daemon_cpu_time_ns: total_cpu_time_ns,
            daemon_cpu_permille,
            peak_resident_memory_bytes,
            rss_growth_bytes,
            result: expected_result,
            outstanding_warning_codes,
        })
    }

    fn median_for(
        &self,
        mode: PerformanceModeV1,
    ) -> Result<PerformanceRateV1, DeploymentContractError> {
        let mut packet_rates = [0_u64; PERFORMANCE_TRIALS_PER_MODE];
        let mut byte_rates = [0_u64; PERFORMANCE_TRIALS_PER_MODE];
        let mut count = 0_usize;
        for trial in &self.trials {
            if trial.mode == mode {
                if count == PERFORMANCE_TRIALS_PER_MODE {
                    return Err(DeploymentContractError::InvalidPerformanceEvidence);
                }
                packet_rates[count] = trial.packets_per_second;
                byte_rates[count] = trial.bytes_per_second;
                count += 1;
            }
        }
        if count != PERFORMANCE_TRIALS_PER_MODE {
            return Err(DeploymentContractError::InvalidPerformanceEvidence);
        }
        packet_rates.sort_unstable();
        byte_rates.sort_unstable();
        Ok(PerformanceRateV1 {
            packets_per_second: packet_rates[PERFORMANCE_TRIALS_PER_MODE / 2],
            bytes_per_second: byte_rates[PERFORMANCE_TRIALS_PER_MODE / 2],
        })
    }

    fn observe_rss_for_trial(&self, trial_number: u8) -> Result<u64, DeploymentContractError> {
        let mut matches = self.trials.iter().filter(|trial| {
            trial.trial_number == trial_number && trial.mode == PerformanceModeV1::Observe
        });
        let rss = matches
            .next()
            .map(|trial| trial.peak_resident_memory_bytes)
            .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?;
        if matches.next().is_some() {
            return Err(DeploymentContractError::InvalidPerformanceEvidence);
        }
        Ok(rss)
    }
}

fn conservative_ratio_permille(
    measured: PerformanceRateV1,
    baseline: PerformanceRateV1,
) -> Result<u16, DeploymentContractError> {
    if baseline.packets_per_second == 0 || baseline.bytes_per_second == 0 {
        return Err(DeploymentContractError::InvalidPerformanceEvidence);
    }
    let packet_ratio = u128::from(measured.packets_per_second)
        .checked_mul(1_000)
        .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?
        / u128::from(baseline.packets_per_second);
    let byte_ratio = u128::from(measured.bytes_per_second)
        .checked_mul(1_000)
        .ok_or(DeploymentContractError::InvalidPerformanceEvidence)?
        / u128::from(baseline.bytes_per_second);
    u16::try_from(packet_ratio.min(byte_ratio))
        .map_err(|_| DeploymentContractError::InvalidPerformanceEvidence)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentInterfaceSummaryV1 {
    pub name: String,
    pub ifindex: u32,
    pub kind: InterfaceKind,
    pub administrative_state: DeploymentLinkStateV1,
    pub operational_state: DeploymentLinkStateV1,
}

impl DeploymentInterfaceSummaryV1 {
    pub fn new(
        name: impl Into<String>,
        ifindex: u32,
        kind: InterfaceKind,
        administrative_up: bool,
        operational_up: bool,
    ) -> Result<Self, DeploymentContractError> {
        let summary = Self {
            name: name.into(),
            ifindex,
            kind,
            administrative_state: DeploymentLinkStateV1::Up,
            operational_state: DeploymentLinkStateV1::Up,
        };
        if !administrative_up || !operational_up {
            return Err(DeploymentContractError::InvalidCanaryPlan);
        }
        summary.validate()?;
        Ok(summary)
    }

    fn validate(&self) -> Result<(), DeploymentContractError> {
        if InterfaceName::new(self.name.as_str()).is_err() || self.ifindex == 0 {
            return Err(DeploymentContractError::InvalidCanaryPlan);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanarySnapshotRequirementV1 {
    Network,
    Xdp,
    Tc,
    LoadedPrograms,
    Maps,
    Pins,
    TrafficHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryStopConditionV1 {
    IdentityChange,
    ObservationDegradation,
    TrafficHealthDegradation,
    OwnershipMismatch,
    CleanupUncertainty,
    Signal,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryRollbackRequirementV1 {
    DetachOwnedTc,
    DetachOwnedXdp,
    UnpinOwnedMaps,
    UnloadOwnedPrograms,
    RemoveOwnedJournal,
    RestoreNetworkIdentity,
}

const REQUIRED_SNAPSHOTS: [CanarySnapshotRequirementV1; 7] = [
    CanarySnapshotRequirementV1::Network,
    CanarySnapshotRequirementV1::Xdp,
    CanarySnapshotRequirementV1::Tc,
    CanarySnapshotRequirementV1::LoadedPrograms,
    CanarySnapshotRequirementV1::Maps,
    CanarySnapshotRequirementV1::Pins,
    CanarySnapshotRequirementV1::TrafficHealth,
];

const STOP_CONDITIONS: [CanaryStopConditionV1; 7] = [
    CanaryStopConditionV1::IdentityChange,
    CanaryStopConditionV1::ObservationDegradation,
    CanaryStopConditionV1::TrafficHealthDegradation,
    CanaryStopConditionV1::OwnershipMismatch,
    CanaryStopConditionV1::CleanupUncertainty,
    CanaryStopConditionV1::Signal,
    CanaryStopConditionV1::Deadline,
];

const ROLLBACK_REQUIREMENTS: [CanaryRollbackRequirementV1; 6] = [
    CanaryRollbackRequirementV1::DetachOwnedTc,
    CanaryRollbackRequirementV1::DetachOwnedXdp,
    CanaryRollbackRequirementV1::UnpinOwnedMaps,
    CanaryRollbackRequirementV1::UnloadOwnedPrograms,
    CanaryRollbackRequirementV1::RemoveOwnedJournal,
    CanaryRollbackRequirementV1::RestoreNetworkIdentity,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryPlanV1 {
    pub schema_version: u16,
    pub executable: bool,
    pub authorization_id: String,
    pub artifact_commit_sha: String,
    pub interface: DeploymentInterfaceSummaryV1,
    pub xdp_ingress_mode: PerformanceXdpModeV1,
    pub tc_egress_hook: bool,
    pub no_replace: bool,
    pub reject_foreign_or_unknown_state: bool,
    pub required_snapshots: Vec<CanarySnapshotRequirementV1>,
    pub maximum_observation_duration_ms: u64,
    pub stop_conditions: Vec<CanaryStopConditionV1>,
    pub rollback_requirements: Vec<CanaryRollbackRequirementV1>,
    pub blocker_codes: Vec<String>,
    pub warning_codes: Vec<String>,
}

impl CanaryPlanV1 {
    pub fn new(
        authorization: &DeploymentAuthorizationV1,
        interface: &DeploymentInterfaceSummaryV1,
    ) -> Result<Self, DeploymentContractError> {
        authorization.validate_structure()?;
        interface.validate()?;
        if interface.kind != InterfaceKind::Physical
            || authorization.interface.name != interface.name
            || authorization.interface.ifindex != interface.ifindex
            || authorization.interface.kind != interface.kind
        {
            return Err(DeploymentContractError::InvalidCanaryPlan);
        }
        let mut warning_codes = WARNING_CODES.map(str::to_owned).to_vec();
        warning_codes.sort();
        let plan = Self {
            schema_version: DEPLOYMENT_SCHEMA_VERSION,
            executable: false,
            authorization_id: authorization.authorization_id.clone(),
            artifact_commit_sha: authorization.artifact_commit_sha.clone(),
            interface: interface.clone(),
            xdp_ingress_mode: PerformanceXdpModeV1::Native,
            tc_egress_hook: true,
            no_replace: true,
            reject_foreign_or_unknown_state: true,
            required_snapshots: REQUIRED_SNAPSHOTS.to_vec(),
            maximum_observation_duration_ms: CANARY_MAX_OBSERVATION_MS,
            stop_conditions: STOP_CONDITIONS.to_vec(),
            rollback_requirements: ROLLBACK_REQUIREMENTS.to_vec(),
            blocker_codes: Vec::new(),
            warning_codes,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), DeploymentContractError> {
        let mut warning_codes = WARNING_CODES.map(str::to_owned).to_vec();
        warning_codes.sort();
        if self.schema_version != DEPLOYMENT_SCHEMA_VERSION
            || self.executable
            || !is_lower_hex(&self.authorization_id, 32)
            || !is_lower_hex(&self.artifact_commit_sha, 40)
            || self.interface.kind != InterfaceKind::Physical
            || self.interface.validate().is_err()
            || self.xdp_ingress_mode != PerformanceXdpModeV1::Native
            || !self.tc_egress_hook
            || !self.no_replace
            || !self.reject_foreign_or_unknown_state
            || self.required_snapshots.as_slice() != REQUIRED_SNAPSHOTS.as_slice()
            || self.maximum_observation_duration_ms != CANARY_MAX_OBSERVATION_MS
            || self.stop_conditions.as_slice() != STOP_CONDITIONS.as_slice()
            || self.rollback_requirements.as_slice() != ROLLBACK_REQUIREMENTS.as_slice()
            || !self.blocker_codes.is_empty()
            || self.warning_codes != warning_codes
        {
            return Err(DeploymentContractError::InvalidCanaryPlan);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentFindingSeverityV1 {
    Blocker,
    Warning,
    Information,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentFindingV1 {
    pub code: String,
    pub severity: DeploymentFindingSeverityV1,
}

impl DeploymentFindingV1 {
    pub fn blocker(code: &str) -> Result<Self, DeploymentContractError> {
        if !BLOCKER_CODES.contains(&code) {
            return Err(DeploymentContractError::InvalidFinding);
        }
        Ok(Self {
            code: code.to_owned(),
            severity: DeploymentFindingSeverityV1::Blocker,
        })
    }

    pub fn warning(code: &str) -> Result<Self, DeploymentContractError> {
        if !WARNING_CODES.contains(&code) {
            return Err(DeploymentContractError::InvalidFinding);
        }
        Ok(Self {
            code: code.to_owned(),
            severity: DeploymentFindingSeverityV1::Warning,
        })
    }

    fn validate(&self) -> Result<(), DeploymentContractError> {
        let valid = match self.severity {
            DeploymentFindingSeverityV1::Blocker => BLOCKER_CODES.contains(&self.code.as_str()),
            DeploymentFindingSeverityV1::Warning => WARNING_CODES.contains(&self.code.as_str()),
            DeploymentFindingSeverityV1::Information => false,
        };
        if !valid {
            return Err(DeploymentContractError::InvalidFinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentGateStateV1 {
    Passed,
    Blocked,
    Unavailable,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentGateSummaryV1 {
    pub state: DeploymentGateStateV1,
    pub finding_codes: Vec<String>,
}

impl DeploymentGateSummaryV1 {
    fn passed() -> Self {
        Self {
            state: DeploymentGateStateV1::Passed,
            finding_codes: Vec::new(),
        }
    }

    fn not_applicable() -> Self {
        Self {
            state: DeploymentGateStateV1::NotApplicable,
            finding_codes: Vec::new(),
        }
    }

    fn blocked(code: &str) -> Result<Self, DeploymentContractError> {
        if !BLOCKER_CODES.contains(&code) {
            return Err(DeploymentContractError::InvalidGateSummary);
        }
        Ok(Self {
            state: DeploymentGateStateV1::Blocked,
            finding_codes: vec![code.to_owned()],
        })
    }

    fn validate(&self) -> Result<(), DeploymentContractError> {
        let codes_valid = codes_are_sorted_unique(&self.finding_codes)
            && self
                .finding_codes
                .iter()
                .all(|code| BLOCKER_CODES.contains(&code.as_str()));
        let shape_valid = match self.state {
            DeploymentGateStateV1::Passed | DeploymentGateStateV1::NotApplicable => {
                self.finding_codes.is_empty()
            }
            DeploymentGateStateV1::Blocked | DeploymentGateStateV1::Unavailable => {
                !self.finding_codes.is_empty()
            }
        };
        if !codes_valid || !shape_valid {
            return Err(DeploymentContractError::InvalidGateSummary);
        }
        Ok(())
    }

    fn prevents_positive_decision(&self) -> bool {
        matches!(
            self.state,
            DeploymentGateStateV1::Blocked | DeploymentGateStateV1::Unavailable
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentGateSummariesV1 {
    pub bundle: DeploymentGateSummaryV1,
    pub layout: DeploymentGateSummaryV1,
    pub service: DeploymentGateSummaryV1,
    pub authorization: DeploymentGateSummaryV1,
    pub platform: DeploymentGateSummaryV1,
    pub evidence: DeploymentGateSummaryV1,
    pub performance: DeploymentGateSummaryV1,
}

impl DeploymentGateSummariesV1 {
    pub fn staging_passed() -> Self {
        Self {
            bundle: DeploymentGateSummaryV1::passed(),
            layout: DeploymentGateSummaryV1::passed(),
            service: DeploymentGateSummaryV1::passed(),
            authorization: DeploymentGateSummaryV1::passed(),
            platform: DeploymentGateSummaryV1::not_applicable(),
            evidence: DeploymentGateSummaryV1::passed(),
            performance: DeploymentGateSummaryV1::passed(),
        }
    }

    pub fn inspect_passed() -> Self {
        Self {
            bundle: DeploymentGateSummaryV1::passed(),
            layout: DeploymentGateSummaryV1::passed(),
            service: DeploymentGateSummaryV1::passed(),
            authorization: DeploymentGateSummaryV1::passed(),
            platform: DeploymentGateSummaryV1::passed(),
            evidence: DeploymentGateSummaryV1::passed(),
            performance: DeploymentGateSummaryV1::passed(),
        }
    }

    pub fn inspect_blocked(code: &str) -> Result<Self, DeploymentContractError> {
        let mut summaries = Self::inspect_passed();
        summaries.platform = DeploymentGateSummaryV1::blocked(code)?;
        Ok(summaries)
    }

    fn validate(&self) -> Result<(), DeploymentContractError> {
        for gate in self.all() {
            gate.validate()?;
        }
        Ok(())
    }

    fn all(&self) -> [&DeploymentGateSummaryV1; 7] {
        [
            &self.bundle,
            &self.layout,
            &self.service,
            &self.authorization,
            &self.platform,
            &self.evidence,
            &self.performance,
        ]
    }

    fn prevents_positive_decision(&self) -> bool {
        self.all()
            .iter()
            .any(|gate| gate.prevents_positive_decision())
    }

    fn is_staging_positive(&self) -> bool {
        self.bundle.state == DeploymentGateStateV1::Passed
            && self.layout.state == DeploymentGateStateV1::Passed
            && self.service.state == DeploymentGateStateV1::Passed
            && self.authorization.state == DeploymentGateStateV1::Passed
            && self.platform.state == DeploymentGateStateV1::NotApplicable
            && self.evidence.state == DeploymentGateStateV1::Passed
            && self.performance.state == DeploymentGateStateV1::Passed
    }

    fn is_inspect_positive(&self) -> bool {
        self.all()
            .iter()
            .all(|gate| gate.state == DeploymentGateStateV1::Passed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentGateReportV1 {
    pub schema_version: u16,
    pub decision: DeploymentDecisionV1,
    pub artifact: DeploymentArtifactIdentityV1,
    pub interface: Option<DeploymentInterfaceSummaryV1>,
    pub gates: DeploymentGateSummariesV1,
    pub findings: Vec<DeploymentFindingV1>,
    pub canary_plan: Option<CanaryPlanV1>,
    pub captured_at_unix_ms: u64,
    pub mutations_performed: bool,
}

impl DeploymentGateReportV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        command: DeploymentCommandV1,
        artifact: DeploymentArtifactIdentityV1,
        interface: Option<DeploymentInterfaceSummaryV1>,
        gates: DeploymentGateSummariesV1,
        mut findings: Vec<DeploymentFindingV1>,
        canary_plan: Option<CanaryPlanV1>,
        captured_at_unix_ms: u64,
    ) -> Result<Self, DeploymentContractError> {
        artifact.validate()?;
        gates.validate()?;
        if captured_at_unix_ms == 0 {
            return Err(DeploymentContractError::InvalidReport);
        }
        for finding in &findings {
            finding.validate()?;
        }
        findings.sort_by(|left, right| {
            left.severity
                .cmp(&right.severity)
                .then_with(|| left.code.cmp(&right.code))
        });
        findings.dedup();

        let has_blocker = findings
            .iter()
            .any(|finding| finding.severity == DeploymentFindingSeverityV1::Blocker)
            || gates.prevents_positive_decision();
        let decision = match command {
            DeploymentCommandV1::Staging => {
                if interface.is_some() || canary_plan.is_some() {
                    return Err(DeploymentContractError::InvalidReport);
                }
                if has_blocker {
                    DeploymentDecisionV1::Blocked
                } else if gates.is_staging_positive() {
                    DeploymentDecisionV1::StagingReady
                } else {
                    return Err(DeploymentContractError::InvalidReport);
                }
            }
            DeploymentCommandV1::Inspect => {
                if has_blocker {
                    if canary_plan.is_some() {
                        return Err(DeploymentContractError::InvalidReport);
                    }
                    DeploymentDecisionV1::Blocked
                } else {
                    let interface = interface
                        .as_ref()
                        .ok_or(DeploymentContractError::InvalidReport)?;
                    interface.validate()?;
                    let plan = canary_plan
                        .as_ref()
                        .ok_or(DeploymentContractError::InvalidReport)?;
                    plan.validate()?;
                    if !gates.is_inspect_positive()
                        || plan.artifact_commit_sha != artifact.commit_sha
                        || plan.interface != *interface
                    {
                        return Err(DeploymentContractError::InvalidReport);
                    }
                    DeploymentDecisionV1::CanaryCandidate
                }
            }
        };

        Ok(Self {
            schema_version: DEPLOYMENT_SCHEMA_VERSION,
            decision,
            artifact,
            interface,
            gates,
            findings,
            canary_plan,
            captured_at_unix_ms,
            mutations_performed: false,
        })
    }

    pub fn validate(&self, command: DeploymentCommandV1) -> Result<(), DeploymentContractError> {
        if self.schema_version != DEPLOYMENT_SCHEMA_VERSION || self.mutations_performed {
            return Err(DeploymentContractError::InvalidReport);
        }
        let expected = Self::derive(
            command,
            self.artifact.clone(),
            self.interface.clone(),
            self.gates.clone(),
            self.findings.clone(),
            self.canary_plan.clone(),
            self.captured_at_unix_ms,
        )?;
        if &expected != self {
            return Err(DeploymentContractError::InvalidReport);
        }
        Ok(())
    }
}

fn deserialize_128_bit_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if !is_lower_hex(&value, 32) {
        return Err(D::Error::custom(
            "ID must be 32 lowercase hexadecimal characters",
        ));
    }
    Ok(value)
}

fn deserialize_commit_sha<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if !is_lower_hex(&value, 40) {
        return Err(D::Error::custom(
            "commit SHA must be 40 lowercase hexadecimal characters",
        ));
    }
    Ok(value)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_safe_text(value: &str, maximum_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
}

fn codes_are_sorted_unique(codes: &[String]) -> bool {
    codes.windows(2).all(|pair| pair[0] < pair[1])
}
