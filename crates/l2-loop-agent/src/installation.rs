use std::time::{SystemTimeError, UNIX_EPOCH};

pub use l2_loop_core::InstallRoleV1;
use l2_loop_core::{
    DeploymentArtifactIdentityV1, GI_AUTH_ARTIFACT, GI_AUTH_EXPIRED, GI_AUTH_HOST,
    GI_DESTINATION_FOREIGN, GI_ROLLBACK_IDENTITY, GI_TRANSACTION_CONFLICT, GI_WRITE_FAILED,
    InstallAuthorizationV1, InstallCommandV1, InstallContractError, InstallFindingV1,
    InstallOperationV1, InstallReportV1,
};
use thiserror::Error;

use crate::{
    Clock, HostIdentityReader, InstallSourceReader, InstallStateReader, InstallTransactionWriter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallDestinationStateV1 {
    AbsentDirectory,
    AbsentFile,
    PriorOwnedFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallDestinationSnapshotV1 {
    pub role: InstallRoleV1,
    pub state: InstallDestinationStateV1,
}

impl InstallDestinationSnapshotV1 {
    pub const fn new(role: InstallRoleV1, state: InstallDestinationStateV1) -> Self {
        Self { role, state }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSourceSnapshotV1 {
    pub authorization: InstallAuthorizationV1,
    pub artifact: DeploymentArtifactIdentityV1,
    pub bundle_manifest_sha256: String,
    pub deployment_authorization_sha256: String,
    pub performance_evidence_sha256: String,
}

impl InstallSourceSnapshotV1 {
    pub fn new(
        authorization: InstallAuthorizationV1,
        artifact: DeploymentArtifactIdentityV1,
        bundle_manifest_sha256: impl Into<String>,
        deployment_authorization_sha256: impl Into<String>,
        performance_evidence_sha256: impl Into<String>,
    ) -> Result<Self, InstallPlanningError> {
        let snapshot = Self {
            authorization,
            artifact,
            bundle_manifest_sha256: bundle_manifest_sha256.into(),
            deployment_authorization_sha256: deployment_authorization_sha256.into(),
            performance_evidence_sha256: performance_evidence_sha256.into(),
        };
        if snapshot.artifact.validate().is_err()
            || !is_lower_hex(&snapshot.bundle_manifest_sha256, 64)
            || !is_lower_hex(&snapshot.deployment_authorization_sha256, 64)
            || !is_lower_hex(&snapshot.performance_evidence_sha256, 64)
        {
            return Err(InstallPlanningError::InvalidSource);
        }
        Ok(snapshot)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallActionV1 {
    CreateDirectory { role: InstallRoleV1 },
    InstallAbsentFile { role: InstallRoleV1 },
    UpgradeOwnedFile { role: InstallRoleV1 },
    VerifyInstalledObject { role: InstallRoleV1 },
    RemoveOwnedEmptyDirectory { role: InstallRoleV1 },
}

impl InstallActionV1 {
    pub const fn role(&self) -> InstallRoleV1 {
        match self {
            Self::CreateDirectory { role }
            | Self::InstallAbsentFile { role }
            | Self::UpgradeOwnedFile { role }
            | Self::VerifyInstalledObject { role }
            | Self::RemoveOwnedEmptyDirectory { role } => *role,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallJournalSnapshotV1 {
    pub transaction_id: String,
    pub completed_actions: Vec<InstallActionV1>,
}

impl InstallJournalSnapshotV1 {
    pub fn new(
        transaction_id: impl Into<String>,
        completed_actions: Vec<InstallActionV1>,
    ) -> Result<Self, InstallPlanningError> {
        let snapshot = Self {
            transaction_id: transaction_id.into(),
            completed_actions,
        };
        if !is_lower_hex(&snapshot.transaction_id, 32) {
            return Err(InstallPlanningError::InvalidJournal);
        }
        Ok(snapshot)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlanV1 {
    pub authorization_id: String,
    pub transaction_id: String,
    pub operation: InstallOperationV1,
    pub artifact: DeploymentArtifactIdentityV1,
    pub actions: Vec<InstallActionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlanOutcomeV1 {
    pub report: InstallReportV1,
    pub plan: Option<InstallPlanV1>,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InstallPlanningError {
    #[error("installation source is invalid")]
    InvalidSource,
    #[error("installation destination state is invalid")]
    InvalidDestination,
    #[error("installation journal is invalid")]
    InvalidJournal,
    #[error("installation transaction conflicts with existing state")]
    TransactionConflict,
}

pub struct InstallPlanner;

impl InstallPlanner {
    pub fn plan(
        source: &InstallSourceSnapshotV1,
        destinations: &[InstallDestinationSnapshotV1],
        prior_journal: Option<&InstallJournalSnapshotV1>,
    ) -> Result<InstallPlanV1, InstallPlanningError> {
        if prior_journal.is_some() {
            return Err(InstallPlanningError::TransactionConflict);
        }
        if source.authorization.operation == InstallOperationV1::Rollback {
            return Err(InstallPlanningError::InvalidSource);
        }

        let mut destinations = destinations.to_vec();
        destinations.sort_by_key(|destination| destination.role);
        if destinations
            .windows(2)
            .any(|pair| pair[0].role == pair[1].role)
        {
            return Err(InstallPlanningError::InvalidDestination);
        }

        let mut actions = Vec::with_capacity(destinations.len().saturating_mul(2));
        for destination in &destinations {
            let action = match destination.state {
                InstallDestinationStateV1::AbsentDirectory => InstallActionV1::CreateDirectory {
                    role: destination.role,
                },
                InstallDestinationStateV1::AbsentFile => InstallActionV1::InstallAbsentFile {
                    role: destination.role,
                },
                InstallDestinationStateV1::PriorOwnedFile
                    if source.authorization.operation == InstallOperationV1::Upgrade =>
                {
                    InstallActionV1::UpgradeOwnedFile {
                        role: destination.role,
                    }
                }
                InstallDestinationStateV1::PriorOwnedFile => {
                    return Err(InstallPlanningError::InvalidDestination);
                }
            };
            actions.push(action);
        }
        actions.extend(destinations.iter().map(|destination| {
            InstallActionV1::VerifyInstalledObject {
                role: destination.role,
            }
        }));

        Ok(InstallPlanV1 {
            authorization_id: source.authorization.authorization_id.clone(),
            transaction_id: source.authorization.transaction_id.clone(),
            operation: source.authorization.operation,
            artifact: source.artifact.clone(),
            actions,
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InstallServiceError {
    #[error("installation input is unavailable")]
    InputUnavailable,
    #[error("installation clock is invalid")]
    InvalidClock,
    #[error("installation report could not be derived")]
    InvalidReport,
}

impl From<SystemTimeError> for InstallServiceError {
    fn from(_: SystemTimeError) -> Self {
        Self::InvalidClock
    }
}

impl From<InstallContractError> for InstallServiceError {
    fn from(_: InstallContractError) -> Self {
        Self::InvalidReport
    }
}

pub struct InstallService<S, R, W, H, C> {
    source: S,
    state: R,
    writer: W,
    host_identity: H,
    clock: C,
}

impl<S, R, W, H, C> InstallService<S, R, W, H, C>
where
    S: InstallSourceReader,
    R: InstallStateReader,
    W: InstallTransactionWriter,
    H: HostIdentityReader,
    C: Clock,
{
    pub fn new(source: S, state: R, writer: W, host_identity: H, clock: C) -> Self {
        Self {
            source,
            state,
            writer,
            host_identity,
            clock,
        }
    }

    pub fn plan(&mut self) -> Result<InstallPlanOutcomeV1, InstallServiceError> {
        let prepared = self.prepare(InstallCommandV1::Plan)?;
        if let Some(code) = prepared.blocker {
            return Ok(InstallPlanOutcomeV1 {
                report: prepared.blocked_report(InstallCommandV1::Plan, code, false)?,
                plan: None,
            });
        }
        let plan = match InstallPlanner::plan(
            &prepared.source,
            &prepared.destinations,
            prepared.journal.as_ref(),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                return Ok(InstallPlanOutcomeV1 {
                    report: prepared.blocked_report(
                        InstallCommandV1::Plan,
                        planning_error_code(error),
                        false,
                    )?,
                    plan: None,
                });
            }
        };
        let report = prepared.report(InstallCommandV1::Plan, Vec::new(), false)?;
        Ok(InstallPlanOutcomeV1 {
            report,
            plan: Some(plan),
        })
    }

    pub fn apply(&mut self) -> Result<InstallReportV1, InstallServiceError> {
        let prepared = self.prepare(InstallCommandV1::Apply)?;
        if let Some(code) = prepared.blocker {
            return prepared.blocked_report(InstallCommandV1::Apply, code, false);
        }
        let plan = match InstallPlanner::plan(
            &prepared.source,
            &prepared.destinations,
            prepared.journal.as_ref(),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                return prepared.blocked_report(
                    InstallCommandV1::Apply,
                    planning_error_code(error),
                    false,
                );
            }
        };

        if self.writer.begin_transaction(&plan).is_err() {
            return prepared.blocked_report(InstallCommandV1::Apply, GI_WRITE_FAILED, true);
        }
        for action in &plan.actions {
            if self.writer.apply_action(action).is_err() {
                return prepared.blocked_report(InstallCommandV1::Apply, GI_WRITE_FAILED, true);
            }
            if self.writer.record_completed(action).is_err() {
                return prepared.blocked_report(InstallCommandV1::Apply, GI_WRITE_FAILED, true);
            }
        }
        if self.writer.complete_transaction(&plan).is_err() {
            return prepared.blocked_report(InstallCommandV1::Apply, GI_WRITE_FAILED, true);
        }
        prepared.report(InstallCommandV1::Apply, Vec::new(), true)
    }

    pub fn status(&mut self) -> Result<InstallReportV1, InstallServiceError> {
        let prepared = self.prepare(InstallCommandV1::Status)?;
        if let Some(code) = prepared.blocker {
            return prepared.blocked_report(InstallCommandV1::Status, code, false);
        }
        prepared.report(InstallCommandV1::Status, Vec::new(), false)
    }

    pub fn rollback(&mut self) -> Result<InstallReportV1, InstallServiceError> {
        let prepared = self.prepare(InstallCommandV1::Rollback)?;
        if let Some(code) = prepared.blocker {
            return prepared.blocked_report(InstallCommandV1::Rollback, code, false);
        }
        let Some(journal) = prepared.journal.as_ref() else {
            return prepared.blocked_report(
                InstallCommandV1::Rollback,
                GI_TRANSACTION_CONFLICT,
                false,
            );
        };
        if self.writer.begin_rollback(journal).is_err() {
            return prepared.blocked_report(InstallCommandV1::Rollback, GI_ROLLBACK_IDENTITY, true);
        }
        for action in journal.completed_actions.iter().rev() {
            if self.writer.rollback_action(action).is_err() {
                return prepared.blocked_report(
                    InstallCommandV1::Rollback,
                    GI_ROLLBACK_IDENTITY,
                    true,
                );
            }
            if self.writer.record_rolled_back(action).is_err() {
                return prepared.blocked_report(
                    InstallCommandV1::Rollback,
                    GI_ROLLBACK_IDENTITY,
                    true,
                );
            }
        }
        if self.writer.complete_rollback(journal).is_err() {
            return prepared.blocked_report(InstallCommandV1::Rollback, GI_ROLLBACK_IDENTITY, true);
        }
        prepared.report(InstallCommandV1::Rollback, Vec::new(), true)
    }

    fn prepare(
        &mut self,
        command: InstallCommandV1,
    ) -> Result<PreparedInstall, InstallServiceError> {
        let captured_at_unix_ms = self.captured_at_unix_ms()?;
        let source = self
            .source
            .load_source()
            .map_err(|_| InstallServiceError::InputUnavailable)?;

        let mut blocker = source_binding_failure(&source, captured_at_unix_ms);
        let host_identity_sha256 = if blocker.is_none() {
            match self.host_identity.host_identity_sha256() {
                Ok(identity) => identity,
                Err(_) => {
                    blocker = Some(GI_AUTH_HOST);
                    String::new()
                }
            }
        } else {
            String::new()
        };

        if blocker.is_none()
            && source
                .authorization
                .validate_for(
                    captured_at_unix_ms,
                    source.authorization.operation,
                    &source.artifact,
                    &source.bundle_manifest_sha256,
                    &host_identity_sha256,
                    &source.deployment_authorization_sha256,
                    &source.performance_evidence_sha256,
                )
                .is_err()
        {
            blocker = Some(GI_AUTH_HOST);
        }

        let mut destinations = Vec::new();
        let mut journal = None;
        if blocker.is_none() {
            match self.state.inspect_destinations(&source) {
                Ok(snapshot) => destinations = snapshot,
                Err(_) => blocker = Some(GI_DESTINATION_FOREIGN),
            }
        }
        if blocker.is_none() {
            match self
                .state
                .inspect_prior_journal(&source.authorization.transaction_id)
            {
                Ok(snapshot) => journal = snapshot,
                Err(_) => blocker = Some(GI_TRANSACTION_CONFLICT),
            }
        }

        if command == InstallCommandV1::Rollback
            && source.authorization.operation != InstallOperationV1::Rollback
        {
            blocker = Some(GI_TRANSACTION_CONFLICT);
        }

        Ok(PreparedInstall {
            source,
            destinations,
            journal,
            captured_at_unix_ms,
            blocker,
        })
    }

    fn captured_at_unix_ms(&self) -> Result<u64, InstallServiceError> {
        let elapsed = self.clock.wall_time().duration_since(UNIX_EPOCH)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| InstallServiceError::InvalidClock)
    }
}

struct PreparedInstall {
    source: InstallSourceSnapshotV1,
    destinations: Vec<InstallDestinationSnapshotV1>,
    journal: Option<InstallJournalSnapshotV1>,
    captured_at_unix_ms: u64,
    blocker: Option<&'static str>,
}

impl PreparedInstall {
    fn report(
        &self,
        command: InstallCommandV1,
        findings: Vec<InstallFindingV1>,
        mutations_performed: bool,
    ) -> Result<InstallReportV1, InstallServiceError> {
        Ok(InstallReportV1::derive(
            command,
            self.source.authorization.operation,
            self.source.authorization.authorization_id.clone(),
            self.source.authorization.transaction_id.clone(),
            self.source.artifact.clone(),
            findings,
            self.captured_at_unix_ms,
            mutations_performed,
        )?)
    }

    fn blocked_report(
        &self,
        command: InstallCommandV1,
        code: &'static str,
        mutations_performed: bool,
    ) -> Result<InstallReportV1, InstallServiceError> {
        self.report(
            command,
            vec![InstallFindingV1::blocker(code)?],
            mutations_performed,
        )
    }
}

fn source_binding_failure(
    source: &InstallSourceSnapshotV1,
    captured_at_unix_ms: u64,
) -> Option<&'static str> {
    if source
        .authorization
        .validate_at(captured_at_unix_ms)
        .is_err()
    {
        return Some(GI_AUTH_EXPIRED);
    }
    if source.authorization.artifact_commit_sha != source.artifact.commit_sha
        || source.authorization.bundle_manifest_sha256 != source.bundle_manifest_sha256
        || source.authorization.deployment_authorization_sha256
            != source.deployment_authorization_sha256
        || source.authorization.performance_evidence_sha256 != source.performance_evidence_sha256
    {
        return Some(GI_AUTH_ARTIFACT);
    }
    None
}

const fn planning_error_code(error: InstallPlanningError) -> &'static str {
    match error {
        InstallPlanningError::TransactionConflict | InstallPlanningError::InvalidJournal => {
            GI_TRANSACTION_CONFLICT
        }
        InstallPlanningError::InvalidSource | InstallPlanningError::InvalidDestination => {
            GI_DESTINATION_FOREIGN
        }
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
