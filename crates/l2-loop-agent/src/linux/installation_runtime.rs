use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use l2_loop_core::{
    DeploymentArtifactIdentityV1, GI_DESTINATION_FOREIGN, GI_ROLLBACK_IDENTITY,
    GI_TRANSACTION_CONFLICT, GI_WRITE_FAILED, InstallCommandV1, InstallFindingV1,
    InstallIntendedIdentityV1, InstallJournalBindingsV1, InstallJournalEntryV1,
    InstallJournalForwardActionV1, InstallJournalRollbackActionV1, InstallJournalStateV1,
    InstallJournalV1, InstallObjectIdentityV1, InstallOperationV1, InstallPriorStateV1,
    InstallReportV1, InstallRoleV1,
};

use crate::{
    HostIdentityReader, InstallActionV1, InstallDestinationSnapshotV1, InstallDestinationStateV1,
    InstallIoError, InstallLayoutEntryKindV1, InstallLayoutV1, InstallPayloadSourceV1,
    InstallPlanner, InstallServiceError, InstallSourcePathsV1, InstallSourceReader,
    InstallSourceSnapshotV1, InstallationCliSourcePaths, InstallationCommandRunner,
    LinuxHostIdentityReaderV1, LinuxInstallSourceReaderV1, read_install_authorization_v1,
};

use super::{
    deployment_fs::LinuxDeploymentFilesystem,
    installation_fs::{FixedInstallRoot, LinuxInstallationFilesystem, NoInstallFaults},
};

pub struct SystemInstallationCommandRunner {
    artifact: DeploymentArtifactIdentityV1,
}

impl SystemInstallationCommandRunner {
    pub fn system() -> Result<Self, InstallServiceError> {
        let commit =
            option_env!("L2_LOOP_BUILD_COMMIT_SHA").ok_or(InstallServiceError::InputUnavailable)?;
        let artifact = DeploymentArtifactIdentityV1::new(commit, env!("CARGO_PKG_VERSION"))
            .map_err(|_| InstallServiceError::InputUnavailable)?;
        Ok(Self { artifact })
    }

    fn filesystem() -> LinuxInstallationFilesystem<FixedInstallRoot, NoInstallFaults> {
        LinuxInstallationFilesystem::production()
    }

    fn prepare(
        &self,
        paths: &InstallationCliSourcePaths,
    ) -> Result<PreparedSystemInstall, InstallServiceError> {
        let source_paths = InstallSourcePathsV1 {
            bundle: paths.bundle.clone(),
            authorization: paths.authorization.clone(),
            deployment_authorization: paths.deployment_authorization.clone(),
            performance_evidence: paths.performance_evidence.clone(),
        };
        let mut source_reader =
            LinuxInstallSourceReaderV1::new(source_paths, self.artifact.clone())
                .map_err(input_unavailable)?;
        let source = source_reader.load_source().map_err(input_unavailable)?;
        let mut host_reader = LinuxHostIdentityReaderV1;
        let host_identity_sha256 = host_reader
            .host_identity_sha256()
            .map_err(input_unavailable)?;
        let captured_at_unix_ms = unix_time_ms()?;
        source
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
            .map_err(|_| InstallServiceError::InputUnavailable)?;
        if !matches!(
            source.authorization.operation,
            InstallOperationV1::Install | InstallOperationV1::Upgrade
        ) {
            return Err(InstallServiceError::InputUnavailable);
        }
        let bundle = LinuxDeploymentFilesystem::new(self.artifact.clone())
            .map_err(|_| InstallServiceError::InputUnavailable)?
            .inspect_bundle(&paths.bundle)
            .map_err(|_| InstallServiceError::InputUnavailable)?;
        Ok(PreparedSystemInstall {
            source,
            paths: paths.clone(),
            host_identity_sha256,
            captured_at_unix_ms,
            bundle,
        })
    }
}

impl InstallationCommandRunner for SystemInstallationCommandRunner {
    fn plan(
        &mut self,
        paths: &InstallationCliSourcePaths,
    ) -> Result<InstallReportV1, InstallServiceError> {
        let prepared = self.prepare(paths)?;
        let mut filesystem = Self::filesystem();
        let layout = inspect_layout(&mut filesystem, &prepared)?;
        match layout {
            Ok((destinations, _)) => {
                if InstallPlanner::plan(&prepared.source, &destinations, None).is_err() {
                    return blocked_report(
                        &prepared,
                        InstallCommandV1::Plan,
                        GI_DESTINATION_FOREIGN,
                        false,
                    );
                }
                report(&prepared, InstallCommandV1::Plan, Vec::new(), false)
            }
            Err(code) => blocked_report(&prepared, InstallCommandV1::Plan, code, false),
        }
    }

    fn apply(
        &mut self,
        paths: &InstallationCliSourcePaths,
    ) -> Result<InstallReportV1, InstallServiceError> {
        let prepared = self.prepare(paths)?;
        let mut filesystem = Self::filesystem();
        let (destinations, prior) = match inspect_layout(&mut filesystem, &prepared)? {
            Ok(layout) => layout,
            Err(code) => {
                return blocked_report(&prepared, InstallCommandV1::Apply, code, false);
            }
        };
        let plan = match InstallPlanner::plan(&prepared.source, &destinations, None) {
            Ok(plan) => plan,
            Err(_) => {
                return blocked_report(
                    &prepared,
                    InstallCommandV1::Apply,
                    GI_DESTINATION_FOREIGN,
                    false,
                );
            }
        };
        let result = apply_plan(&mut filesystem, &prepared, &plan.actions, prior.as_ref());
        match result {
            Ok(()) => report(&prepared, InstallCommandV1::Apply, Vec::new(), true),
            Err(()) => blocked_report(&prepared, InstallCommandV1::Apply, GI_WRITE_FAILED, true),
        }
    }

    fn status(&mut self) -> Result<InstallReportV1, InstallServiceError> {
        let captured_at_unix_ms = unix_time_ms()?;
        let mut filesystem = Self::filesystem();
        let journal = current_installed_journal(&mut filesystem)?
            .ok_or(InstallServiceError::InputUnavailable)?;
        InstallReportV1::derive(
            InstallCommandV1::Status,
            journal_operation(&journal),
            journal.authorization_id(),
            journal.transaction_id(),
            journal.artifact().clone(),
            Vec::new(),
            captured_at_unix_ms,
            false,
        )
        .map_err(Into::into)
    }

    fn rollback(
        &mut self,
        transaction_id: &str,
        authorization_path: &Path,
    ) -> Result<InstallReportV1, InstallServiceError> {
        let captured_at_unix_ms = unix_time_ms()?;
        let authorization =
            read_install_authorization_v1(authorization_path).map_err(input_unavailable)?;
        if authorization.transaction_id != transaction_id
            || authorization.operation != InstallOperationV1::Rollback
        {
            return Err(InstallServiceError::InputUnavailable);
        }
        let mut filesystem = Self::filesystem();
        let mut journal = filesystem
            .load_journal_exact(transaction_id)
            .map_err(input_unavailable)?;
        let mut host_reader = LinuxHostIdentityReaderV1;
        let host_identity_sha256 = host_reader
            .host_identity_sha256()
            .map_err(input_unavailable)?;
        authorization
            .validate_for(
                captured_at_unix_ms,
                InstallOperationV1::Rollback,
                journal.artifact(),
                journal.bundle_manifest_sha256(),
                &host_identity_sha256,
                journal.deployment_authorization_sha256(),
                journal.performance_evidence_sha256(),
            )
            .map_err(|_| InstallServiceError::InputUnavailable)?;
        if authorization.authorization_id == journal.authorization_id()
            || authorization.host_identity_sha256 != journal.host_identity_sha256()
        {
            return Err(InstallServiceError::InputUnavailable);
        }

        let result = rollback_journal(&mut filesystem, &mut journal);
        let findings = if result.is_ok() {
            Vec::new()
        } else {
            vec![InstallFindingV1::blocker(GI_ROLLBACK_IDENTITY)?]
        };
        InstallReportV1::derive(
            InstallCommandV1::Rollback,
            InstallOperationV1::Rollback,
            authorization.authorization_id,
            transaction_id,
            journal.artifact().clone(),
            findings,
            captured_at_unix_ms,
            true,
        )
        .map_err(Into::into)
    }
}

struct PreparedSystemInstall {
    source: InstallSourceSnapshotV1,
    paths: InstallationCliSourcePaths,
    host_identity_sha256: String,
    captured_at_unix_ms: u64,
    bundle: crate::BundleSnapshotV1,
}

type LayoutInspection =
    Result<(Vec<InstallDestinationSnapshotV1>, Option<InstallJournalV1>), &'static str>;

fn inspect_layout(
    filesystem: &mut LinuxInstallationFilesystem<FixedInstallRoot, NoInstallFaults>,
    prepared: &PreparedSystemInstall,
) -> Result<LayoutInspection, InstallServiceError> {
    let current = current_installed_journal(filesystem)?;
    match prepared.source.authorization.operation {
        InstallOperationV1::Install if current.is_some() => {
            return Ok(Err(GI_TRANSACTION_CONFLICT));
        }
        InstallOperationV1::Upgrade if current.is_none() => {
            return Ok(Err(GI_TRANSACTION_CONFLICT));
        }
        InstallOperationV1::Install | InstallOperationV1::Upgrade => {}
        InstallOperationV1::Rollback => return Ok(Err(GI_TRANSACTION_CONFLICT)),
    }

    let mut destinations = Vec::with_capacity(InstallLayoutV1::entries().len());
    for entry in InstallLayoutV1::entries() {
        let observed = filesystem
            .inspect_optional_exact(entry.role)
            .map_err(input_unavailable)?;
        let state = match (entry.kind, observed) {
            (InstallLayoutEntryKindV1::Directory, None) => {
                InstallDestinationStateV1::AbsentDirectory
            }
            (InstallLayoutEntryKindV1::Regular, None) => InstallDestinationStateV1::AbsentFile,
            (InstallLayoutEntryKindV1::Directory, Some(identity))
                if is_standard_prerequisite(entry.role)
                    || journal_identity(current.as_ref(), entry.role)
                        .is_some_and(|expected| expected.matches_persistent_object(&identity)) =>
            {
                InstallDestinationStateV1::ExistingPrerequisiteDirectory
            }
            (InstallLayoutEntryKindV1::Regular, Some(identity))
                if prepared.source.authorization.operation == InstallOperationV1::Upgrade
                    && journal_identity(current.as_ref(), entry.role) == Some(&identity) =>
            {
                InstallDestinationStateV1::PriorOwnedFile
            }
            _ => return Ok(Err(GI_DESTINATION_FOREIGN)),
        };
        destinations.push(InstallDestinationSnapshotV1::new(entry.role, state));
    }
    Ok(Ok((destinations, current)))
}

fn current_installed_journal(
    filesystem: &mut LinuxInstallationFilesystem<FixedInstallRoot, NoInstallFaults>,
) -> Result<Option<InstallJournalV1>, InstallServiceError> {
    let mut current = None;
    for transaction_id in filesystem.transaction_ids().map_err(input_unavailable)? {
        let journal = filesystem
            .load_journal_exact(&transaction_id)
            .map_err(input_unavailable)?;
        match journal.state() {
            InstallJournalStateV1::RolledBack => continue,
            InstallJournalStateV1::Installed => {}
            _ => return Err(InstallServiceError::InputUnavailable),
        }
        let mut matches = true;
        for entry in journal.entries() {
            let Some(expected) = entry.current_identity() else {
                matches = false;
                break;
            };
            if !filesystem
                .inspect_optional_exact(entry.role())
                .ok()
                .flatten()
                .is_some_and(|observed| expected.matches_persistent_object(&observed))
            {
                matches = false;
                break;
            }
        }
        if matches {
            if current.is_some() {
                return Err(InstallServiceError::InputUnavailable);
            }
            current = Some(journal);
        }
    }
    Ok(current)
}

fn apply_plan(
    filesystem: &mut LinuxInstallationFilesystem<FixedInstallRoot, NoInstallFaults>,
    prepared: &PreparedSystemInstall,
    actions: &[InstallActionV1],
    prior: Option<&InstallJournalV1>,
) -> Result<(), ()> {
    let entries = actions
        .iter()
        .filter(|action| !matches!(action, InstallActionV1::VerifyInstalledObject { .. }))
        .map(|action| journal_entry(prepared, action, prior))
        .collect::<Result<Vec<_>, _>>()?;
    let bindings = InstallJournalBindingsV1::new(
        &prepared.source.authorization.transaction_id,
        &prepared.source.authorization.authorization_id,
        &prepared.host_identity_sha256,
        prepared.source.artifact.clone(),
        &prepared.source.bundle_manifest_sha256,
        &prepared.source.deployment_authorization_sha256,
        &prepared.source.performance_evidence_sha256,
    )
    .map_err(|_| ())?;
    let mut journal = InstallJournalV1::new(bindings);
    journal.prepare(entries).map_err(|_| ())?;
    filesystem.bootstrap_journal(&journal).map_err(|_| ())?;
    let final_parent_exists = filesystem
        .inspect_optional_exact(InstallRoleV1::TransactionsRoot)
        .map_err(|_| ())?
        .is_some();
    if final_parent_exists {
        filesystem.publish_journal(&journal).map_err(|_| ())?;
    }
    journal.start_applying().map_err(|_| ())?;
    filesystem.persist_journal(&journal).map_err(|_| ())?;

    while let Some(action) = journal.next_forward_action() {
        let step = match action {
            InstallJournalForwardActionV1::Apply { role, .. } => {
                let entry = journal
                    .entries()
                    .iter()
                    .find(|entry| entry.role() == role)
                    .ok_or(())?
                    .clone();
                let mut payload = payload_file(prepared, role).map_err(|_| ())?;
                let outcome = filesystem
                    .apply_entry(
                        &entry,
                        payload.as_mut().map(|file| file as &mut dyn std::io::Read),
                    )
                    .map_err(|_| ())?;
                journal
                    .record_applied(
                        role,
                        outcome.current_identity,
                        outcome.created_parent_identity,
                    )
                    .map_err(|_| ())?;
                filesystem.persist_journal(&journal).map_err(|_| ())?;
                false
            }
            InstallJournalForwardActionV1::Verify {
                role,
                expected_identity,
                ..
            } => {
                filesystem
                    .verify_exact(role, &expected_identity)
                    .map_err(|_| ())?;
                journal
                    .record_verified(role, expected_identity)
                    .map_err(|_| ())?;
                filesystem.persist_journal(&journal).map_err(|_| ())?;
                role == InstallRoleV1::TransactionsRoot && !final_parent_exists
            }
        };
        if step {
            filesystem.publish_journal(&journal).map_err(|_| ())?;
        }
    }
    journal.mark_installed().map_err(|_| ())?;
    filesystem.persist_journal(&journal).map_err(|_| ())
}

fn rollback_journal(
    filesystem: &mut LinuxInstallationFilesystem<FixedInstallRoot, NoInstallFaults>,
    journal: &mut InstallJournalV1,
) -> Result<(), ()> {
    if journal.state() != InstallJournalStateV1::RollingBack {
        journal.begin_rollback().map_err(|_| ())?;
        filesystem.persist_journal(journal).map_err(|_| ())?;
    }
    while let Some(action) = journal.next_rollback_action() {
        match &action {
            InstallJournalRollbackActionV1::RemoveExact {
                role,
                expected_current,
                ..
            } => filesystem
                .rollback_remove_exact(*role, expected_current)
                .map_err(|_| ())?,
            InstallJournalRollbackActionV1::RestoreExact {
                role,
                expected_current,
                backup_basename,
                expected_backup,
                ..
            } => filesystem
                .rollback_restore_exact(*role, expected_current, backup_basename, expected_backup)
                .map_err(|_| ())?,
            InstallJournalRollbackActionV1::RetainExact {
                role,
                expected_current,
                ..
            } => {
                let observed = filesystem.inspect_exact(*role).map_err(|_| ())?;
                if !expected_current.matches_persistent_object(&observed) {
                    return Err(());
                }
            }
        }
        journal.record_rollback_completed(&action).map_err(|_| ())?;
        filesystem.persist_journal(journal).map_err(|_| ())?;
    }
    journal.mark_rolled_back().map_err(|_| ())?;
    filesystem.persist_journal(journal).map_err(|_| ())
}

fn journal_entry(
    prepared: &PreparedSystemInstall,
    action: &InstallActionV1,
    prior: Option<&InstallJournalV1>,
) -> Result<InstallJournalEntryV1, ()> {
    let role = action.role();
    let layout = InstallLayoutV1::entry(role).ok_or(())?;
    let intended = match layout.kind {
        InstallLayoutEntryKindV1::Directory => {
            InstallIntendedIdentityV1::directory(layout.mode, 0, 0).map_err(|_| ())?
        }
        InstallLayoutEntryKindV1::Regular => InstallIntendedIdentityV1::regular_file(
            payload_sha256(prepared, role)?,
            layout.mode,
            0,
            0,
        )
        .map_err(|_| ())?,
    };
    let sibling = format!(
        ".l2-loop-{}-{}.new",
        prepared.source.authorization.transaction_id,
        role.install_order()
    );
    match action {
        InstallActionV1::CreateDirectory { .. } => {
            InstallJournalEntryV1::absent_directory(role, intended).map_err(|_| ())
        }
        InstallActionV1::InstallAbsentFile { .. } => {
            InstallJournalEntryV1::absent_file(role, intended, sibling).map_err(|_| ())
        }
        InstallActionV1::UpgradeOwnedFile { .. } => {
            let prior_identity = journal_identity(prior, role).ok_or(())?.clone();
            let backup = format!(
                ".l2-loop-{}-{}.bak",
                prepared.source.authorization.transaction_id,
                role.install_order()
            );
            InstallJournalEntryV1::prior_owned_file(role, intended, sibling, backup, prior_identity)
                .map_err(|_| ())
        }
        InstallActionV1::VerifyInstalledObject { .. }
        | InstallActionV1::RemoveOwnedEmptyDirectory { .. } => Err(()),
    }
}

fn payload_sha256(prepared: &PreparedSystemInstall, role: InstallRoleV1) -> Result<String, ()> {
    let layout = InstallLayoutV1::entry(role).ok_or(())?;
    match layout.source {
        InstallPayloadSourceV1::Bundle(filename) => prepared
            .bundle
            .files
            .get(filename)
            .map(|file| file.sha256.clone())
            .ok_or(()),
        InstallPayloadSourceV1::DeploymentAuthorization => {
            Ok(prepared.source.deployment_authorization_sha256.clone())
        }
        InstallPayloadSourceV1::PerformanceEvidence => {
            Ok(prepared.source.performance_evidence_sha256.clone())
        }
        InstallPayloadSourceV1::None => Err(()),
    }
}

fn payload_file(
    prepared: &PreparedSystemInstall,
    role: InstallRoleV1,
) -> Result<Option<File>, InstallIoError> {
    let layout = InstallLayoutV1::entry(role).ok_or(InstallIoError::Unavailable)?;
    let path = match layout.source {
        InstallPayloadSourceV1::None => return Ok(None),
        InstallPayloadSourceV1::Bundle(filename) => prepared.paths.bundle.join(filename),
        InstallPayloadSourceV1::DeploymentAuthorization => {
            prepared.paths.deployment_authorization.clone()
        }
        InstallPayloadSourceV1::PerformanceEvidence => prepared.paths.performance_evidence.clone(),
    };
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)
        .map(Some)
        .map_err(|_| InstallIoError::Unavailable)
}

fn journal_identity(
    journal: Option<&InstallJournalV1>,
    role: InstallRoleV1,
) -> Option<&InstallObjectIdentityV1> {
    journal?
        .entries()
        .iter()
        .find(|entry| entry.role() == role)
        .and_then(InstallJournalEntryV1::current_identity)
}

fn journal_operation(journal: &InstallJournalV1) -> InstallOperationV1 {
    if journal
        .entries()
        .iter()
        .any(|entry| matches!(entry.prior_state(), InstallPriorStateV1::PriorOwned { .. }))
    {
        InstallOperationV1::Upgrade
    } else {
        InstallOperationV1::Install
    }
}

const fn is_standard_prerequisite(role: InstallRoleV1) -> bool {
    matches!(
        role,
        InstallRoleV1::UsrRoot
            | InstallRoleV1::UsrBinRoot
            | InstallRoleV1::UsrLibRoot
            | InstallRoleV1::UsrLibexecRoot
            | InstallRoleV1::UsrLibSystemdRoot
            | InstallRoleV1::SystemdUnitRoot
            | InstallRoleV1::UsrShareRoot
            | InstallRoleV1::UsrShareDocRoot
            | InstallRoleV1::EtcRoot
            | InstallRoleV1::VarRoot
            | InstallRoleV1::VarLibRoot
    )
}

fn report(
    prepared: &PreparedSystemInstall,
    command: InstallCommandV1,
    findings: Vec<InstallFindingV1>,
    mutations_performed: bool,
) -> Result<InstallReportV1, InstallServiceError> {
    InstallReportV1::derive(
        command,
        prepared.source.authorization.operation,
        &prepared.source.authorization.authorization_id,
        &prepared.source.authorization.transaction_id,
        prepared.source.artifact.clone(),
        findings,
        prepared.captured_at_unix_ms,
        mutations_performed,
    )
    .map_err(Into::into)
}

fn blocked_report(
    prepared: &PreparedSystemInstall,
    command: InstallCommandV1,
    code: &'static str,
    mutations_performed: bool,
) -> Result<InstallReportV1, InstallServiceError> {
    report(
        prepared,
        command,
        vec![InstallFindingV1::blocker(code)?],
        mutations_performed,
    )
}

fn unix_time_ms() -> Result<u64, InstallServiceError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InstallServiceError::InvalidClock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| InstallServiceError::InvalidClock)
}

fn input_unavailable(_: InstallIoError) -> InstallServiceError {
    InstallServiceError::InputUnavailable
}
