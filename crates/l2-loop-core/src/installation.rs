use std::{cmp::Ordering, fmt};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::DeploymentArtifactIdentityV1;

pub const INSTALLATION_SCHEMA_VERSION: u16 = 1;
pub const INSTALL_AUTHORIZATION_MAX_LIFETIME_MS: u64 = 60 * 60 * 1_000;

pub const GI_AUTH_SCHEMA: &str = "GI_AUTH_SCHEMA";
pub const GI_AUTH_EXPIRED: &str = "GI_AUTH_EXPIRED";
pub const GI_AUTH_HOST: &str = "GI_AUTH_HOST";
pub const GI_AUTH_ARTIFACT: &str = "GI_AUTH_ARTIFACT";
pub const GI_BUNDLE_INVALID: &str = "GI_BUNDLE_INVALID";
pub const GI_DESTINATION_FOREIGN: &str = "GI_DESTINATION_FOREIGN";
pub const GI_METADATA_UNSAFE: &str = "GI_METADATA_UNSAFE";
pub const GI_TRANSACTION_CONFLICT: &str = "GI_TRANSACTION_CONFLICT";
pub const GI_WRITE_FAILED: &str = "GI_WRITE_FAILED";
pub const GI_ROLLBACK_IDENTITY: &str = "GI_ROLLBACK_IDENTITY";
pub const GI_LAYOUT_VERIFY: &str = "GI_LAYOUT_VERIFY";
pub const GI_SERVICE_STATE: &str = "GI_SERVICE_STATE";
pub const GI_SERVICE_LIFECYCLE: &str = "GI_SERVICE_LIFECYCLE";
pub const GI_PHYSICAL_BLOCKED: &str = "GI_PHYSICAL_BLOCKED";
pub const GI_INTERNAL: &str = "GI_INTERNAL";

const INSTALL_FINDING_CODES: [&str; 15] = [
    GI_AUTH_SCHEMA,
    GI_AUTH_EXPIRED,
    GI_AUTH_HOST,
    GI_AUTH_ARTIFACT,
    GI_BUNDLE_INVALID,
    GI_DESTINATION_FOREIGN,
    GI_METADATA_UNSAFE,
    GI_TRANSACTION_CONFLICT,
    GI_WRITE_FAILED,
    GI_ROLLBACK_IDENTITY,
    GI_LAYOUT_VERIFY,
    GI_SERVICE_STATE,
    GI_SERVICE_LIFECYCLE,
    GI_PHYSICAL_BLOCKED,
    GI_INTERNAL,
];

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum InstallContractError {
    #[error("installation authorization is invalid")]
    InvalidAuthorization,
    #[error("installation finding is invalid")]
    InvalidFinding,
    #[error("installation report is invalid")]
    InvalidReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallOperationV1 {
    Install,
    Upgrade,
    Rollback,
}

impl fmt::Display for InstallOperationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
            Self::Rollback => "rollback",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallCommandV1 {
    Plan,
    Apply,
    Status,
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallDecisionV1 {
    Blocked,
    InstallPlanReady,
    InstalledVerified,
    RolledBack,
}

impl fmt::Display for InstallDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Blocked => "blocked",
            Self::InstallPlanReady => "install_plan_ready",
            Self::InstalledVerified => "installed_verified",
            Self::RolledBack => "rolled_back",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallAuthorizationV1 {
    pub schema_version: u16,
    #[serde(deserialize_with = "deserialize_128_bit_id")]
    pub authorization_id: String,
    #[serde(deserialize_with = "deserialize_128_bit_id")]
    pub transaction_id: String,
    pub operation: InstallOperationV1,
    #[serde(deserialize_with = "deserialize_commit_sha")]
    pub artifact_commit_sha: String,
    #[serde(deserialize_with = "deserialize_sha256")]
    pub bundle_manifest_sha256: String,
    #[serde(deserialize_with = "deserialize_sha256")]
    pub host_identity_sha256: String,
    #[serde(deserialize_with = "deserialize_sha256")]
    pub deployment_authorization_sha256: String,
    #[serde(deserialize_with = "deserialize_sha256")]
    pub performance_evidence_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub service_enable: bool,
    pub service_start: bool,
    pub physical_attach: bool,
}

impl InstallAuthorizationV1 {
    pub fn validate_at(&self, captured_at_unix_ms: u64) -> Result<(), InstallContractError> {
        self.validate_structure()?;
        if !(self.issued_at_unix_ms..=self.expires_at_unix_ms).contains(&captured_at_unix_ms) {
            return Err(InstallContractError::InvalidAuthorization);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        captured_at_unix_ms: u64,
        operation: InstallOperationV1,
        artifact: &DeploymentArtifactIdentityV1,
        bundle_manifest_sha256: &str,
        host_identity_sha256: &str,
        deployment_authorization_sha256: &str,
        performance_evidence_sha256: &str,
    ) -> Result<(), InstallContractError> {
        self.validate_at(captured_at_unix_ms)?;
        artifact
            .validate()
            .map_err(|_| InstallContractError::InvalidAuthorization)?;
        if self.operation != operation
            || self.artifact_commit_sha != artifact.commit_sha
            || self.bundle_manifest_sha256 != bundle_manifest_sha256
            || self.host_identity_sha256 != host_identity_sha256
            || self.deployment_authorization_sha256 != deployment_authorization_sha256
            || self.performance_evidence_sha256 != performance_evidence_sha256
            || !is_lower_hex(bundle_manifest_sha256, 64)
            || !is_lower_hex(host_identity_sha256, 64)
            || !is_lower_hex(deployment_authorization_sha256, 64)
            || !is_lower_hex(performance_evidence_sha256, 64)
        {
            return Err(InstallContractError::InvalidAuthorization);
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), InstallContractError> {
        let lifetime = self
            .expires_at_unix_ms
            .checked_sub(self.issued_at_unix_ms)
            .ok_or(InstallContractError::InvalidAuthorization)?;
        if self.schema_version != INSTALLATION_SCHEMA_VERSION
            || !is_lower_hex(&self.authorization_id, 32)
            || !is_lower_hex(&self.transaction_id, 32)
            || !is_lower_hex(&self.artifact_commit_sha, 40)
            || !is_lower_hex(&self.bundle_manifest_sha256, 64)
            || !is_lower_hex(&self.host_identity_sha256, 64)
            || !is_lower_hex(&self.deployment_authorization_sha256, 64)
            || !is_lower_hex(&self.performance_evidence_sha256, 64)
            || self.issued_at_unix_ms == 0
            || lifetime == 0
            || lifetime > INSTALL_AUTHORIZATION_MAX_LIFETIME_MS
            || self.service_enable
            || self.service_start
            || self.physical_attach
        {
            return Err(InstallContractError::InvalidAuthorization);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallFindingSeverityV1 {
    Blocker,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallFindingV1 {
    #[serde(deserialize_with = "deserialize_finding_code")]
    pub code: String,
    pub severity: InstallFindingSeverityV1,
}

impl InstallFindingV1 {
    pub fn blocker(code: impl Into<String>) -> Result<Self, InstallContractError> {
        Self::new(code, InstallFindingSeverityV1::Blocker)
    }

    pub fn warning(code: impl Into<String>) -> Result<Self, InstallContractError> {
        Self::new(code, InstallFindingSeverityV1::Warning)
    }

    pub fn sort_and_deduplicate(findings: &mut Vec<Self>) {
        findings.sort_by(|left, right| match left.severity.cmp(&right.severity) {
            Ordering::Equal => left.code.cmp(&right.code),
            ordering => ordering,
        });
        findings.dedup();
    }

    fn new(
        code: impl Into<String>,
        severity: InstallFindingSeverityV1,
    ) -> Result<Self, InstallContractError> {
        let finding = Self {
            code: code.into(),
            severity,
        };
        finding.validate()?;
        Ok(finding)
    }

    fn validate(&self) -> Result<(), InstallContractError> {
        if !INSTALL_FINDING_CODES.contains(&self.code.as_str()) {
            return Err(InstallContractError::InvalidFinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReportV1 {
    pub schema_version: u16,
    pub decision: InstallDecisionV1,
    pub command: InstallCommandV1,
    pub operation: InstallOperationV1,
    #[serde(deserialize_with = "deserialize_128_bit_id")]
    pub authorization_id: String,
    #[serde(deserialize_with = "deserialize_128_bit_id")]
    pub transaction_id: String,
    pub artifact: DeploymentArtifactIdentityV1,
    pub findings: Vec<InstallFindingV1>,
    pub captured_at_unix_ms: u64,
    pub mutations_performed: bool,
}

impl InstallReportV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        command: InstallCommandV1,
        operation: InstallOperationV1,
        authorization_id: impl Into<String>,
        transaction_id: impl Into<String>,
        artifact: DeploymentArtifactIdentityV1,
        mut findings: Vec<InstallFindingV1>,
        captured_at_unix_ms: u64,
        mutations_performed: bool,
    ) -> Result<Self, InstallContractError> {
        if !command_matches_operation(command, operation) {
            return Err(InstallContractError::InvalidReport);
        }
        for finding in &findings {
            finding.validate()?;
        }
        InstallFindingV1::sort_and_deduplicate(&mut findings);
        let blocked = findings
            .iter()
            .any(|finding| finding.severity == InstallFindingSeverityV1::Blocker);
        let decision = if blocked {
            InstallDecisionV1::Blocked
        } else {
            positive_decision(command, mutations_performed)?
        };
        let report = Self {
            schema_version: INSTALLATION_SCHEMA_VERSION,
            decision,
            command,
            operation,
            authorization_id: authorization_id.into(),
            transaction_id: transaction_id.into(),
            artifact,
            findings,
            captured_at_unix_ms,
            mutations_performed,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), InstallContractError> {
        if self.schema_version != INSTALLATION_SCHEMA_VERSION
            || !is_lower_hex(&self.authorization_id, 32)
            || !is_lower_hex(&self.transaction_id, 32)
            || self.artifact.validate().is_err()
            || self.captured_at_unix_ms == 0
            || !command_matches_operation(self.command, self.operation)
        {
            return Err(InstallContractError::InvalidReport);
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        let mut normalized = self.findings.clone();
        InstallFindingV1::sort_and_deduplicate(&mut normalized);
        if normalized != self.findings {
            return Err(InstallContractError::InvalidReport);
        }

        let blocked = self
            .findings
            .iter()
            .any(|finding| finding.severity == InstallFindingSeverityV1::Blocker);
        if blocked {
            if self.decision != InstallDecisionV1::Blocked {
                return Err(InstallContractError::InvalidReport);
            }
        } else if self.decision != positive_decision(self.command, self.mutations_performed)? {
            return Err(InstallContractError::InvalidReport);
        }
        Ok(())
    }
}

fn command_matches_operation(command: InstallCommandV1, operation: InstallOperationV1) -> bool {
    match command {
        InstallCommandV1::Plan | InstallCommandV1::Apply | InstallCommandV1::Status => {
            matches!(
                operation,
                InstallOperationV1::Install | InstallOperationV1::Upgrade
            )
        }
        InstallCommandV1::Rollback => operation == InstallOperationV1::Rollback,
    }
}

fn positive_decision(
    command: InstallCommandV1,
    mutations_performed: bool,
) -> Result<InstallDecisionV1, InstallContractError> {
    match (command, mutations_performed) {
        (InstallCommandV1::Plan, false) => Ok(InstallDecisionV1::InstallPlanReady),
        (InstallCommandV1::Apply, true) | (InstallCommandV1::Status, false) => {
            Ok(InstallDecisionV1::InstalledVerified)
        }
        (InstallCommandV1::Rollback, true) => Ok(InstallDecisionV1::RolledBack),
        _ => Err(InstallContractError::InvalidReport),
    }
}

fn deserialize_128_bit_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_lower_hex(deserializer, 32, "ID")
}

fn deserialize_commit_sha<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_lower_hex(deserializer, 40, "commit SHA")
}

fn deserialize_sha256<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_lower_hex(deserializer, 64, "SHA-256 digest")
}

fn deserialize_lower_hex<'de, D>(
    deserializer: D,
    length: usize,
    label: &str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if !is_lower_hex(&value, length) {
        return Err(D::Error::custom(format_args!(
            "{label} must contain exactly {length} lowercase hexadecimal characters"
        )));
    }
    Ok(value)
}

fn deserialize_finding_code<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if !INSTALL_FINDING_CODES.contains(&value.as_str()) {
        return Err(D::Error::custom("installation finding code is invalid"));
    }
    Ok(value)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
