use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{DeploymentArtifactIdentityV1, InstallFindingV1};

pub const INSTALL_JOURNAL_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InstallJournalError {
    #[error("installation journal is invalid")]
    InvalidJournal,
    #[error("installation journal transition is invalid")]
    InvalidTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallRoleV1 {
    EvidenceRoot,
    Daemon,
    Cli,
    UsrRoot,
    UsrBinRoot,
    UsrLibRoot,
    UsrLibexecRoot,
    ProductLibexecRoot,
    UsrLibSystemdRoot,
    SystemdUnitRoot,
    UsrShareRoot,
    UsrShareDocRoot,
    ProductDocRoot,
    EtcRoot,
    ConfigRoot,
    VarRoot,
    VarLibRoot,
    StateRoot,
    GatesRoot,
    EvidenceParent,
    InstallRoot,
    TransactionsRoot,
    DeploymentChecker,
    HostChecker,
    EbpfObject,
    BundleManifest,
    BundleChecksums,
    ServiceUnit,
    AuthorizationExample,
    DeploymentAuthorization,
    PerformanceEvidence,
}

impl InstallRoleV1 {
    pub const fn fixed_destination(self) -> &'static str {
        match self {
            Self::UsrRoot => "/usr",
            Self::UsrBinRoot => "/usr/bin",
            Self::UsrLibRoot => "/usr/lib",
            Self::UsrLibexecRoot => "/usr/libexec",
            Self::ProductLibexecRoot => "/usr/libexec/l2-loop",
            Self::UsrLibSystemdRoot => "/usr/lib/systemd",
            Self::SystemdUnitRoot => "/usr/lib/systemd/system",
            Self::UsrShareRoot => "/usr/share",
            Self::UsrShareDocRoot => "/usr/share/doc",
            Self::ProductDocRoot => "/usr/share/doc/l2-loop",
            Self::EtcRoot => "/etc",
            Self::ConfigRoot => "/etc/l2-loop",
            Self::VarRoot => "/var",
            Self::VarLibRoot => "/var/lib",
            Self::StateRoot => "/var/lib/l2-loop",
            Self::GatesRoot => "/var/lib/l2-loop/gates",
            Self::EvidenceParent => "/var/lib/l2-loop/evidence",
            Self::EvidenceRoot => "/var/lib/l2-loop/evidence/v1",
            Self::InstallRoot => "/var/lib/l2-loop/install",
            Self::TransactionsRoot => "/var/lib/l2-loop/install/transactions",
            Self::Cli => "/usr/bin/l2-loopctl",
            Self::Daemon => "/usr/libexec/l2-loop/l2-loopd",
            Self::DeploymentChecker => "/usr/libexec/l2-loop/l2-loop-deploycheck",
            Self::HostChecker => "/usr/libexec/l2-loop/l2-loop-hostcheck",
            Self::EbpfObject => "/usr/libexec/l2-loop/l2-loop-ebpf.o",
            Self::BundleManifest => "/usr/libexec/l2-loop/manifest.json",
            Self::BundleChecksums => "/usr/libexec/l2-loop/SHA256SUMS",
            Self::ServiceUnit => "/usr/lib/systemd/system/l2-loop.service",
            Self::AuthorizationExample => "/usr/share/doc/l2-loop/deployment-v1.example.json",
            Self::DeploymentAuthorization => "/etc/l2-loop/deployment-v1.json",
            Self::PerformanceEvidence => "/var/lib/l2-loop/gates/performance-v1.json",
        }
    }

    pub const fn expected_mode(self) -> u32 {
        match self {
            Self::ConfigRoot
            | Self::StateRoot
            | Self::GatesRoot
            | Self::EvidenceParent
            | Self::EvidenceRoot
            | Self::InstallRoot
            | Self::TransactionsRoot => 0o700,
            Self::DeploymentAuthorization | Self::PerformanceEvidence => 0o600,
            Self::EbpfObject
            | Self::BundleManifest
            | Self::BundleChecksums
            | Self::ServiceUnit
            | Self::AuthorizationExample => 0o644,
            _ => 0o755,
        }
    }

    pub const fn install_order(self) -> u8 {
        match self {
            Self::UsrRoot => 0,
            Self::UsrBinRoot => 1,
            Self::UsrLibRoot => 2,
            Self::UsrLibexecRoot => 3,
            Self::ProductLibexecRoot => 4,
            Self::UsrLibSystemdRoot => 5,
            Self::SystemdUnitRoot => 6,
            Self::UsrShareRoot => 7,
            Self::UsrShareDocRoot => 8,
            Self::ProductDocRoot => 9,
            Self::EtcRoot => 10,
            Self::ConfigRoot => 11,
            Self::VarRoot => 12,
            Self::VarLibRoot => 13,
            Self::StateRoot => 14,
            Self::GatesRoot => 15,
            Self::EvidenceParent => 16,
            Self::EvidenceRoot => 17,
            Self::InstallRoot => 18,
            Self::TransactionsRoot => 19,
            Self::Cli => 20,
            Self::Daemon => 21,
            Self::DeploymentChecker => 22,
            Self::HostChecker => 23,
            Self::EbpfObject => 24,
            Self::BundleManifest => 25,
            Self::BundleChecksums => 26,
            Self::ServiceUnit => 27,
            Self::AuthorizationExample => 28,
            Self::DeploymentAuthorization => 29,
            Self::PerformanceEvidence => 30,
        }
    }

    const fn is_directory(self) -> bool {
        self.install_order() < 20
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallObjectKindV1 {
    Directory,
    RegularFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallIntendedIdentityV1 {
    kind: InstallObjectKindV1,
    sha256: Option<String>,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl InstallIntendedIdentityV1 {
    pub fn regular_file(
        sha256: impl Into<String>,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Self, InstallJournalError> {
        let identity = Self {
            kind: InstallObjectKindV1::RegularFile,
            sha256: Some(sha256.into()),
            mode,
            uid,
            gid,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn directory(mode: u32, uid: u32, gid: u32) -> Result<Self, InstallJournalError> {
        let identity = Self {
            kind: InstallObjectKindV1::Directory,
            sha256: None,
            mode,
            uid,
            gid,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), InstallJournalError> {
        let digest_valid = match (&self.kind, &self.sha256) {
            (InstallObjectKindV1::RegularFile, Some(digest)) => is_lower_hex(digest, 64),
            (InstallObjectKindV1::Directory, None) => true,
            _ => false,
        };
        if !digest_valid || self.mode > 0o7777 {
            return Err(InstallJournalError::InvalidJournal);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallObjectIdentityV1 {
    kind: InstallObjectKindV1,
    device: u64,
    inode: u64,
    hard_links: u64,
    sha256: Option<String>,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl InstallObjectIdentityV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn regular_file(
        device: u64,
        inode: u64,
        hard_links: u64,
        sha256: impl Into<String>,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Self, InstallJournalError> {
        let identity = Self {
            kind: InstallObjectKindV1::RegularFile,
            device,
            inode,
            hard_links,
            sha256: Some(sha256.into()),
            mode,
            uid,
            gid,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn directory(
        device: u64,
        inode: u64,
        hard_links: u64,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Self, InstallJournalError> {
        let identity = Self {
            kind: InstallObjectKindV1::Directory,
            device,
            inode,
            hard_links,
            sha256: None,
            mode,
            uid,
            gid,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), InstallJournalError> {
        let shape_valid = match (&self.kind, &self.sha256) {
            (InstallObjectKindV1::RegularFile, Some(digest)) => {
                self.hard_links == 1 && is_lower_hex(digest, 64)
            }
            (InstallObjectKindV1::Directory, None) => self.hard_links > 0,
            _ => false,
        };
        if self.device == 0 || self.inode == 0 || self.mode > 0o7777 || !shape_valid {
            return Err(InstallJournalError::InvalidJournal);
        }
        Ok(())
    }

    fn matches_intended(&self, intended: &InstallIntendedIdentityV1) -> bool {
        self.kind == intended.kind
            && self.sha256 == intended.sha256
            && self.mode == intended.mode
            && self.uid == intended.uid
            && self.gid == intended.gid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstallPriorStateV1 {
    Absent,
    PriorOwned {
        identity: InstallObjectIdentityV1,
        backup_basename: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallJournalEntryPhaseV1 {
    Pending,
    Applied,
    Verified,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallJournalEntryV1 {
    role: InstallRoleV1,
    fixed_path: String,
    intended: InstallIntendedIdentityV1,
    sibling_basename: Option<String>,
    prior_state: InstallPriorStateV1,
    current_identity: Option<InstallObjectIdentityV1>,
    created_parent_identity: Option<InstallObjectIdentityV1>,
    phase: InstallJournalEntryPhaseV1,
}

impl InstallJournalEntryV1 {
    pub fn absent_directory(
        role: InstallRoleV1,
        intended: InstallIntendedIdentityV1,
    ) -> Result<Self, InstallJournalError> {
        Self::new(role, intended, None, InstallPriorStateV1::Absent)
    }

    pub fn absent_file(
        role: InstallRoleV1,
        intended: InstallIntendedIdentityV1,
        sibling_basename: impl Into<String>,
    ) -> Result<Self, InstallJournalError> {
        Self::new(
            role,
            intended,
            Some(sibling_basename.into()),
            InstallPriorStateV1::Absent,
        )
    }

    pub fn prior_owned_file(
        role: InstallRoleV1,
        intended: InstallIntendedIdentityV1,
        sibling_basename: impl Into<String>,
        backup_basename: impl Into<String>,
        prior_identity: InstallObjectIdentityV1,
    ) -> Result<Self, InstallJournalError> {
        Self::new(
            role,
            intended,
            Some(sibling_basename.into()),
            InstallPriorStateV1::PriorOwned {
                identity: prior_identity,
                backup_basename: backup_basename.into(),
            },
        )
    }

    fn new(
        role: InstallRoleV1,
        intended: InstallIntendedIdentityV1,
        sibling_basename: Option<String>,
        prior_state: InstallPriorStateV1,
    ) -> Result<Self, InstallJournalError> {
        let entry = Self {
            role,
            fixed_path: role.fixed_destination().to_owned(),
            intended,
            sibling_basename,
            prior_state,
            current_identity: None,
            created_parent_identity: None,
            phase: InstallJournalEntryPhaseV1::Pending,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub const fn role(&self) -> InstallRoleV1 {
        self.role
    }

    pub fn fixed_path(&self) -> &str {
        &self.fixed_path
    }

    pub const fn prior_state(&self) -> &InstallPriorStateV1 {
        &self.prior_state
    }

    pub fn sibling_basename(&self) -> Option<&str> {
        self.sibling_basename.as_deref()
    }

    pub const fn current_identity(&self) -> Option<&InstallObjectIdentityV1> {
        self.current_identity.as_ref()
    }

    pub const fn created_parent_identity(&self) -> Option<&InstallObjectIdentityV1> {
        self.created_parent_identity.as_ref()
    }

    pub const fn phase(&self) -> InstallJournalEntryPhaseV1 {
        self.phase
    }

    fn validate(&self) -> Result<(), InstallJournalError> {
        self.intended.validate()?;
        if self.fixed_path != self.role.fixed_destination()
            || self.intended.mode != self.role.expected_mode()
            || self.intended.uid != 0
            || self.intended.gid != 0
            || self.role.is_directory() != (self.intended.kind == InstallObjectKindV1::Directory)
        {
            return Err(InstallJournalError::InvalidJournal);
        }

        if self.role.is_directory() {
            if self.sibling_basename.is_some() || self.prior_state != InstallPriorStateV1::Absent {
                return Err(InstallJournalError::InvalidJournal);
            }
        } else if !self.sibling_basename.as_deref().is_some_and(safe_basename) {
            return Err(InstallJournalError::InvalidJournal);
        }

        if let InstallPriorStateV1::PriorOwned {
            identity,
            backup_basename,
        } = &self.prior_state
        {
            identity.validate()?;
            if self.role.is_directory()
                || identity.kind != InstallObjectKindV1::RegularFile
                || identity.mode != self.role.expected_mode()
                || identity.uid != 0
                || identity.gid != 0
                || !safe_basename(backup_basename)
            {
                return Err(InstallJournalError::InvalidJournal);
            }
        }

        match self.phase {
            InstallJournalEntryPhaseV1::Pending => {
                if self.current_identity.is_some() || self.created_parent_identity.is_some() {
                    return Err(InstallJournalError::InvalidJournal);
                }
            }
            InstallJournalEntryPhaseV1::Applied
            | InstallJournalEntryPhaseV1::Verified
            | InstallJournalEntryPhaseV1::RolledBack => {
                let current = self
                    .current_identity
                    .as_ref()
                    .ok_or(InstallJournalError::InvalidJournal)?;
                current.validate()?;
                if !current.matches_intended(&self.intended) {
                    return Err(InstallJournalError::InvalidJournal);
                }
                if let Some(parent) = &self.created_parent_identity {
                    parent.validate()?;
                    if parent.kind != InstallObjectKindV1::Directory
                        || parent.uid != 0
                        || parent.gid != 0
                    {
                        return Err(InstallJournalError::InvalidJournal);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallJournalBindingsV1 {
    transaction_id: String,
    authorization_id: String,
    host_identity_sha256: String,
    artifact: DeploymentArtifactIdentityV1,
    bundle_manifest_sha256: String,
    deployment_authorization_sha256: String,
    performance_evidence_sha256: String,
}

impl InstallJournalBindingsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: impl Into<String>,
        authorization_id: impl Into<String>,
        host_identity_sha256: impl Into<String>,
        artifact: DeploymentArtifactIdentityV1,
        bundle_manifest_sha256: impl Into<String>,
        deployment_authorization_sha256: impl Into<String>,
        performance_evidence_sha256: impl Into<String>,
    ) -> Result<Self, InstallJournalError> {
        let bindings = Self {
            transaction_id: transaction_id.into(),
            authorization_id: authorization_id.into(),
            host_identity_sha256: host_identity_sha256.into(),
            artifact,
            bundle_manifest_sha256: bundle_manifest_sha256.into(),
            deployment_authorization_sha256: deployment_authorization_sha256.into(),
            performance_evidence_sha256: performance_evidence_sha256.into(),
        };
        bindings.validate()?;
        Ok(bindings)
    }

    fn validate(&self) -> Result<(), InstallJournalError> {
        if !is_lower_hex(&self.transaction_id, 32)
            || !is_lower_hex(&self.authorization_id, 32)
            || !is_lower_hex(&self.host_identity_sha256, 64)
            || !is_lower_hex(&self.bundle_manifest_sha256, 64)
            || !is_lower_hex(&self.deployment_authorization_sha256, 64)
            || !is_lower_hex(&self.performance_evidence_sha256, 64)
            || self.artifact.validate().is_err()
        {
            return Err(InstallJournalError::InvalidJournal);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallJournalStateV1 {
    Planned,
    Prepared,
    Applying,
    Installed,
    Failed,
    RollingBack,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallJournalForwardActionV1 {
    Apply {
        durable_step: u64,
        role: InstallRoleV1,
    },
    Verify {
        durable_step: u64,
        role: InstallRoleV1,
        expected_identity: InstallObjectIdentityV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallJournalRollbackActionV1 {
    RemoveExact {
        durable_step: u64,
        role: InstallRoleV1,
        expected_current: InstallObjectIdentityV1,
        created_parent_identity: Option<InstallObjectIdentityV1>,
    },
    RestoreExact {
        durable_step: u64,
        role: InstallRoleV1,
        expected_current: InstallObjectIdentityV1,
        backup_basename: String,
        expected_backup: InstallObjectIdentityV1,
        created_parent_identity: Option<InstallObjectIdentityV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallJournalV1 {
    schema_version: u16,
    transaction_id: String,
    authorization_id: String,
    host_identity_sha256: String,
    artifact: DeploymentArtifactIdentityV1,
    bundle_manifest_sha256: String,
    deployment_authorization_sha256: String,
    performance_evidence_sha256: String,
    state: InstallJournalStateV1,
    durable_step: u64,
    entries: Vec<InstallJournalEntryV1>,
    failure_code: Option<String>,
    rollback_possible: bool,
}

impl InstallJournalV1 {
    pub fn new(bindings: InstallJournalBindingsV1) -> Self {
        Self {
            schema_version: INSTALL_JOURNAL_SCHEMA_VERSION,
            transaction_id: bindings.transaction_id,
            authorization_id: bindings.authorization_id,
            host_identity_sha256: bindings.host_identity_sha256,
            artifact: bindings.artifact,
            bundle_manifest_sha256: bindings.bundle_manifest_sha256,
            deployment_authorization_sha256: bindings.deployment_authorization_sha256,
            performance_evidence_sha256: bindings.performance_evidence_sha256,
            state: InstallJournalStateV1::Planned,
            durable_step: 0,
            entries: Vec::new(),
            failure_code: None,
            rollback_possible: true,
        }
    }

    pub const fn state(&self) -> InstallJournalStateV1 {
        self.state
    }

    pub const fn durable_step(&self) -> u64 {
        self.durable_step
    }

    pub fn entries(&self) -> &[InstallJournalEntryV1] {
        &self.entries
    }

    pub fn failure_code(&self) -> Option<&str> {
        self.failure_code.as_deref()
    }

    pub const fn rollback_possible(&self) -> bool {
        self.rollback_possible
    }

    pub fn prepare(
        &mut self,
        mut entries: Vec<InstallJournalEntryV1>,
    ) -> Result<(), InstallJournalError> {
        entries.sort_by_key(|entry| entry.role.install_order());
        validate_entries(&entries)?;
        match self.state {
            InstallJournalStateV1::Planned => {
                self.entries = entries;
                self.state = InstallJournalStateV1::Prepared;
                self.advance_step()?;
                Ok(())
            }
            InstallJournalStateV1::Prepared if self.entries == entries => Ok(()),
            _ => Err(InstallJournalError::InvalidTransition),
        }
    }

    pub fn start_applying(&mut self) -> Result<(), InstallJournalError> {
        if self.state != InstallJournalStateV1::Prepared {
            return Err(InstallJournalError::InvalidTransition);
        }
        self.state = InstallJournalStateV1::Applying;
        self.advance_step()
    }

    pub fn next_forward_action(&self) -> Option<InstallJournalForwardActionV1> {
        if self.state != InstallJournalStateV1::Applying {
            return None;
        }
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.phase != InstallJournalEntryPhaseV1::Verified)?;
        let durable_step = self.durable_step.checked_add(1)?;
        match entry.phase {
            InstallJournalEntryPhaseV1::Pending => Some(InstallJournalForwardActionV1::Apply {
                durable_step,
                role: entry.role,
            }),
            InstallJournalEntryPhaseV1::Applied => Some(InstallJournalForwardActionV1::Verify {
                durable_step,
                role: entry.role,
                expected_identity: entry.current_identity.clone()?,
            }),
            InstallJournalEntryPhaseV1::Verified | InstallJournalEntryPhaseV1::RolledBack => None,
        }
    }

    pub fn record_applied(
        &mut self,
        role: InstallRoleV1,
        current_identity: InstallObjectIdentityV1,
        created_parent_identity: Option<InstallObjectIdentityV1>,
    ) -> Result<(), InstallJournalError> {
        if let Some(entry) = self.entries.iter().find(|entry| entry.role == role)
            && entry.phase == InstallJournalEntryPhaseV1::Applied
        {
            return if entry.current_identity.as_ref() == Some(&current_identity)
                && entry.created_parent_identity == created_parent_identity
            {
                Ok(())
            } else {
                Err(InstallJournalError::InvalidTransition)
            };
        }
        let Some(InstallJournalForwardActionV1::Apply {
            role: expected_role,
            ..
        }) = self.next_forward_action()
        else {
            return Err(InstallJournalError::InvalidTransition);
        };
        if role != expected_role {
            return Err(InstallJournalError::InvalidTransition);
        }
        let index = self.entry_index(role)?;
        current_identity.validate()?;
        if !current_identity.matches_intended(&self.entries[index].intended) {
            return Err(InstallJournalError::InvalidTransition);
        }
        if let Some(parent) = &created_parent_identity {
            parent.validate()?;
            if parent.kind != InstallObjectKindV1::Directory || parent.uid != 0 || parent.gid != 0 {
                return Err(InstallJournalError::InvalidTransition);
            }
        }
        self.entries[index].current_identity = Some(current_identity);
        self.entries[index].created_parent_identity = created_parent_identity;
        self.entries[index].phase = InstallJournalEntryPhaseV1::Applied;
        self.advance_step()
    }

    pub fn record_verified(
        &mut self,
        role: InstallRoleV1,
        observed_identity: InstallObjectIdentityV1,
    ) -> Result<(), InstallJournalError> {
        if let Some(entry) = self.entries.iter().find(|entry| entry.role == role)
            && entry.phase == InstallJournalEntryPhaseV1::Verified
        {
            return if entry.current_identity.as_ref() == Some(&observed_identity) {
                Ok(())
            } else {
                Err(InstallJournalError::InvalidTransition)
            };
        }
        let Some(InstallJournalForwardActionV1::Verify {
            role: expected_role,
            expected_identity,
            ..
        }) = self.next_forward_action()
        else {
            return Err(InstallJournalError::InvalidTransition);
        };
        if role != expected_role || observed_identity != expected_identity {
            return Err(InstallJournalError::InvalidTransition);
        }
        let index = self.entry_index(role)?;
        self.entries[index].phase = InstallJournalEntryPhaseV1::Verified;
        self.advance_step()
    }

    pub fn mark_installed(&mut self) -> Result<(), InstallJournalError> {
        if self.state != InstallJournalStateV1::Applying
            || self.next_forward_action().is_some()
            || self.entries.is_empty()
        {
            return Err(InstallJournalError::InvalidTransition);
        }
        self.state = InstallJournalStateV1::Installed;
        self.advance_step()
    }

    pub fn record_failure(
        &mut self,
        code: &str,
        rollback_possible: bool,
    ) -> Result<(), InstallJournalError> {
        InstallFindingV1::blocker(code).map_err(|_| InstallJournalError::InvalidJournal)?;
        if self.state == InstallJournalStateV1::Failed {
            return if self.failure_code.as_deref() == Some(code)
                && self.rollback_possible == rollback_possible
            {
                Ok(())
            } else {
                Err(InstallJournalError::InvalidTransition)
            };
        }
        if self.state != InstallJournalStateV1::Applying {
            return Err(InstallJournalError::InvalidTransition);
        }
        self.failure_code = Some(code.to_owned());
        self.rollback_possible = rollback_possible;
        self.state = InstallJournalStateV1::Failed;
        self.advance_step()
    }

    pub fn begin_rollback(&mut self) -> Result<(), InstallJournalError> {
        if !self.rollback_possible
            || !matches!(
                self.state,
                InstallJournalStateV1::Applying
                    | InstallJournalStateV1::Installed
                    | InstallJournalStateV1::Failed
            )
        {
            return Err(InstallJournalError::InvalidTransition);
        }
        self.state = InstallJournalStateV1::RollingBack;
        self.advance_step()
    }

    pub fn next_rollback_action(&self) -> Option<InstallJournalRollbackActionV1> {
        if self.state != InstallJournalStateV1::RollingBack || !self.rollback_possible {
            return None;
        }
        let entry = self.entries.iter().rev().find(|entry| {
            matches!(
                entry.phase,
                InstallJournalEntryPhaseV1::Applied | InstallJournalEntryPhaseV1::Verified
            )
        })?;
        let durable_step = self.durable_step.checked_add(1)?;
        let expected_current = entry.current_identity.clone()?;
        match &entry.prior_state {
            InstallPriorStateV1::Absent => Some(InstallJournalRollbackActionV1::RemoveExact {
                durable_step,
                role: entry.role,
                expected_current,
                created_parent_identity: entry.created_parent_identity.clone(),
            }),
            InstallPriorStateV1::PriorOwned {
                identity,
                backup_basename,
            } => Some(InstallJournalRollbackActionV1::RestoreExact {
                durable_step,
                role: entry.role,
                expected_current,
                backup_basename: backup_basename.clone(),
                expected_backup: identity.clone(),
                created_parent_identity: entry.created_parent_identity.clone(),
            }),
        }
    }

    pub fn record_rollback_completed(
        &mut self,
        action: &InstallJournalRollbackActionV1,
    ) -> Result<(), InstallJournalError> {
        if self.next_rollback_action().as_ref() != Some(action) {
            return Err(InstallJournalError::InvalidTransition);
        }
        let role = match action {
            InstallJournalRollbackActionV1::RemoveExact { role, .. }
            | InstallJournalRollbackActionV1::RestoreExact { role, .. } => *role,
        };
        let index = self.entry_index(role)?;
        self.entries[index].phase = InstallJournalEntryPhaseV1::RolledBack;
        self.advance_step()
    }

    pub fn mark_rolled_back(&mut self) -> Result<(), InstallJournalError> {
        if self.state != InstallJournalStateV1::RollingBack || self.next_rollback_action().is_some()
        {
            return Err(InstallJournalError::InvalidTransition);
        }
        self.state = InstallJournalStateV1::RolledBack;
        self.advance_step()
    }

    fn entry_index(&self, role: InstallRoleV1) -> Result<usize, InstallJournalError> {
        self.entries
            .iter()
            .position(|entry| entry.role == role)
            .ok_or(InstallJournalError::InvalidTransition)
    }

    fn advance_step(&mut self) -> Result<(), InstallJournalError> {
        self.durable_step = self
            .durable_step
            .checked_add(1)
            .ok_or(InstallJournalError::InvalidTransition)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), InstallJournalError> {
        InstallJournalBindingsV1 {
            transaction_id: self.transaction_id.clone(),
            authorization_id: self.authorization_id.clone(),
            host_identity_sha256: self.host_identity_sha256.clone(),
            artifact: self.artifact.clone(),
            bundle_manifest_sha256: self.bundle_manifest_sha256.clone(),
            deployment_authorization_sha256: self.deployment_authorization_sha256.clone(),
            performance_evidence_sha256: self.performance_evidence_sha256.clone(),
        }
        .validate()?;
        if self.schema_version != INSTALL_JOURNAL_SCHEMA_VERSION {
            return Err(InstallJournalError::InvalidJournal);
        }
        validate_entries_for_state(self)?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallJournalWireV1 {
    schema_version: u16,
    transaction_id: String,
    authorization_id: String,
    host_identity_sha256: String,
    artifact: DeploymentArtifactIdentityV1,
    bundle_manifest_sha256: String,
    deployment_authorization_sha256: String,
    performance_evidence_sha256: String,
    state: InstallJournalStateV1,
    durable_step: u64,
    entries: Vec<InstallJournalEntryV1>,
    failure_code: Option<String>,
    rollback_possible: bool,
}

impl<'de> Deserialize<'de> for InstallJournalV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = InstallJournalWireV1::deserialize(deserializer)?;
        let journal = Self {
            schema_version: wire.schema_version,
            transaction_id: wire.transaction_id,
            authorization_id: wire.authorization_id,
            host_identity_sha256: wire.host_identity_sha256,
            artifact: wire.artifact,
            bundle_manifest_sha256: wire.bundle_manifest_sha256,
            deployment_authorization_sha256: wire.deployment_authorization_sha256,
            performance_evidence_sha256: wire.performance_evidence_sha256,
            state: wire.state,
            durable_step: wire.durable_step,
            entries: wire.entries,
            failure_code: wire.failure_code,
            rollback_possible: wire.rollback_possible,
        };
        journal.validate().map_err(D::Error::custom)?;
        Ok(journal)
    }
}

fn validate_entries(entries: &[InstallJournalEntryV1]) -> Result<(), InstallJournalError> {
    if entries.is_empty() {
        return Err(InstallJournalError::InvalidJournal);
    }
    let mut prior_order = None;
    for entry in entries {
        entry.validate()?;
        let order = entry.role.install_order();
        if prior_order.is_some_and(|prior| prior >= order) {
            return Err(InstallJournalError::InvalidJournal);
        }
        prior_order = Some(order);
    }
    Ok(())
}

fn validate_entries_for_state(journal: &InstallJournalV1) -> Result<(), InstallJournalError> {
    let failure_valid = match journal.failure_code.as_deref() {
        Some(code) => InstallFindingV1::blocker(code).is_ok(),
        None => true,
    };
    if !failure_valid || (!journal.rollback_possible && journal.failure_code.is_none()) {
        return Err(InstallJournalError::InvalidJournal);
    }

    match journal.state {
        InstallJournalStateV1::Planned => {
            if journal.durable_step != 0
                || !journal.entries.is_empty()
                || journal.failure_code.is_some()
                || !journal.rollback_possible
            {
                return Err(InstallJournalError::InvalidJournal);
            }
            return Ok(());
        }
        _ => validate_entries(&journal.entries)?,
    }

    let phases = journal
        .entries
        .iter()
        .map(|entry| entry.phase)
        .collect::<Vec<_>>();
    match journal.state {
        InstallJournalStateV1::Prepared => {
            if journal.durable_step != 1
                || phases
                    .iter()
                    .any(|phase| *phase != InstallJournalEntryPhaseV1::Pending)
                || journal.failure_code.is_some()
            {
                return Err(InstallJournalError::InvalidJournal);
            }
        }
        InstallJournalStateV1::Applying => {
            let progress = validate_forward_prefix(&phases)?;
            if journal.durable_step != 2 + progress || journal.failure_code.is_some() {
                return Err(InstallJournalError::InvalidJournal);
            }
        }
        InstallJournalStateV1::Installed => {
            let expected = 3_u64
                .checked_add(2_u64.saturating_mul(journal.entries.len() as u64))
                .ok_or(InstallJournalError::InvalidJournal)?;
            if journal.durable_step != expected
                || phases
                    .iter()
                    .any(|phase| *phase != InstallJournalEntryPhaseV1::Verified)
                || journal.failure_code.is_some()
            {
                return Err(InstallJournalError::InvalidJournal);
            }
        }
        InstallJournalStateV1::Failed => {
            let progress = validate_forward_prefix(&phases)?;
            if journal.durable_step != 3 + progress || journal.failure_code.is_none() {
                return Err(InstallJournalError::InvalidJournal);
            }
        }
        InstallJournalStateV1::RollingBack => {
            validate_rollback_shape(&phases, false)?;
            if journal.durable_step < 3 {
                return Err(InstallJournalError::InvalidJournal);
            }
        }
        InstallJournalStateV1::RolledBack => {
            validate_rollback_shape(&phases, true)?;
            if journal.durable_step < 4 {
                return Err(InstallJournalError::InvalidJournal);
            }
        }
        InstallJournalStateV1::Planned => unreachable!(),
    }
    Ok(())
}

fn validate_forward_prefix(
    phases: &[InstallJournalEntryPhaseV1],
) -> Result<u64, InstallJournalError> {
    let mut progress = 0_u64;
    let mut saw_applied = false;
    let mut saw_pending = false;
    for phase in phases {
        match phase {
            InstallJournalEntryPhaseV1::Verified if !saw_applied && !saw_pending => progress += 2,
            InstallJournalEntryPhaseV1::Applied if !saw_applied && !saw_pending => {
                saw_applied = true;
                progress += 1;
            }
            InstallJournalEntryPhaseV1::Pending => saw_pending = true,
            _ => return Err(InstallJournalError::InvalidJournal),
        }
    }
    Ok(progress)
}

fn validate_rollback_shape(
    phases: &[InstallJournalEntryPhaseV1],
    terminal: bool,
) -> Result<(), InstallJournalError> {
    let mut saw_rolled_back = false;
    let mut saw_pending = false;
    for phase in phases {
        match phase {
            InstallJournalEntryPhaseV1::Verified | InstallJournalEntryPhaseV1::Applied
                if !saw_rolled_back && !saw_pending && !terminal => {}
            InstallJournalEntryPhaseV1::RolledBack if !saw_pending => saw_rolled_back = true,
            InstallJournalEntryPhaseV1::Pending => saw_pending = true,
            _ => return Err(InstallJournalError::InvalidJournal),
        }
    }
    Ok(())
}

fn safe_basename(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 255
        && !value.bytes().any(|byte| {
            byte == b'/'
                || byte == b'\\'
                || byte == b'*'
                || byte == b'?'
                || byte == b'['
                || byte == b']'
                || byte == 0
        })
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
