use l2_loop_core::{
    DeploymentArtifactIdentityV1, GI_ROLLBACK_IDENTITY, GI_WRITE_FAILED,
    INSTALL_JOURNAL_SCHEMA_VERSION, InstallIntendedIdentityV1, InstallJournalBindingsV1,
    InstallJournalEntryPhaseV1, InstallJournalEntryV1, InstallJournalForwardActionV1,
    InstallJournalRollbackActionV1, InstallJournalStateV1, InstallJournalV1,
    InstallObjectIdentityV1, InstallPriorStateV1, InstallRoleV1,
};
use serde_json::{Value, json};

const TRANSACTION_ID: &str = "ffeeddccbbaa99887766554433221100";
const AUTHORIZATION_ID: &str = "00112233445566778899aabbccddeeff";
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const HOST_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const MANIFEST_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DEPLOYMENT_SHA256: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const PERFORMANCE_SHA256: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const CLI_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DAEMON_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PRIOR_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[test]
fn roles_own_the_fixed_destinations_and_install_order() {
    assert_eq!(INSTALL_JOURNAL_SCHEMA_VERSION, 1);
    assert_eq!(InstallRoleV1::UsrRoot.fixed_destination(), "/usr");
    assert_eq!(
        InstallRoleV1::Cli.fixed_destination(),
        "/usr/bin/l2-loopctl"
    );
    assert_eq!(
        InstallRoleV1::Daemon.fixed_destination(),
        "/usr/libexec/l2-loop/l2-loopd"
    );
    assert_eq!(
        InstallRoleV1::Installer.fixed_destination(),
        "/usr/libexec/l2-loop/l2-loop-install"
    );
    assert_eq!(
        InstallRoleV1::TransactionsRoot.fixed_destination(),
        "/var/lib/l2-loop/install/transactions"
    );
    assert_eq!(InstallRoleV1::UsrRoot.expected_mode(), 0o755);
    assert_eq!(InstallRoleV1::TransactionsRoot.expected_mode(), 0o700);
    assert_eq!(InstallRoleV1::Cli.expected_mode(), 0o755);
    assert!(InstallRoleV1::UsrRoot.install_order() < InstallRoleV1::Cli.install_order());
    assert!(InstallRoleV1::Cli.install_order() < InstallRoleV1::Daemon.install_order());
    assert!(
        InstallRoleV1::DeploymentChecker.install_order()
            < InstallRoleV1::Installer.install_order()
    );
    assert!(InstallRoleV1::Installer.install_order() < InstallRoleV1::HostChecker.install_order());
}

#[test]
fn journal_serialization_is_strict_and_revalidates_private_invariants() {
    let mut journal = journal();
    journal.prepare(entries()).unwrap();
    journal.start_applying().unwrap();
    apply_and_verify(&mut journal, InstallRoleV1::UsrRoot, usr_identity(), None);
    apply_and_verify(
        &mut journal,
        InstallRoleV1::Cli,
        cli_identity(),
        Some(parent_identity()),
    );
    apply_and_verify(&mut journal, InstallRoleV1::Daemon, daemon_identity(), None);
    journal.mark_installed().unwrap();

    let encoded = serde_json::to_string(&journal).unwrap();
    let decoded: InstallJournalV1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, journal);
    assert!(!encoded.contains("machine-id"));
    assert!(!encoded.contains("source_path"));

    let value: Value = serde_json::from_str(&encoded).unwrap();
    let mut unknown = value.clone();
    unknown["destination_root"] = json!("/tmp/override");
    assert!(serde_json::from_value::<InstallJournalV1>(unknown).is_err());

    let mut wrong_path = value.clone();
    wrong_path["entries"][1]["fixed_path"] = json!("/tmp/l2-loopctl");
    assert!(serde_json::from_value::<InstallJournalV1>(wrong_path).is_err());

    let mut decreasing_step = value.clone();
    decreasing_step["durable_step"] = json!(0);
    assert!(serde_json::from_value::<InstallJournalV1>(decreasing_step).is_err());

    let mut non_prefix_progress = value;
    non_prefix_progress["entries"][0]["phase"] = json!("pending");
    assert!(serde_json::from_value::<InstallJournalV1>(non_prefix_progress).is_err());
}

#[test]
fn preparation_is_deterministic_and_preserves_exact_prior_and_generated_identities() {
    let mut journal = journal();
    let unsorted = vec![daemon_entry(), usr_entry(), cli_entry()];
    journal.prepare(unsorted.clone()).unwrap();

    assert_eq!(journal.state(), InstallJournalStateV1::Prepared);
    assert_eq!(journal.durable_step(), 1);
    assert_eq!(
        journal
            .entries()
            .iter()
            .map(|entry| entry.role())
            .collect::<Vec<_>>(),
        [
            InstallRoleV1::UsrRoot,
            InstallRoleV1::Cli,
            InstallRoleV1::Daemon
        ]
    );
    assert_eq!(journal.entries()[0].fixed_path(), "/usr");
    assert_eq!(
        journal.entries()[0].prior_state(),
        &InstallPriorStateV1::Absent
    );
    assert_eq!(
        journal.entries()[1].sibling_basename(),
        Some(".l2-loop-cli-new")
    );
    assert_eq!(
        journal.entries()[2].prior_state(),
        &InstallPriorStateV1::PriorOwned {
            identity: prior_daemon_identity(),
            backup_basename: ".l2-loop-daemon-backup".to_owned(),
        }
    );

    let step = journal.durable_step();
    journal.prepare(unsorted).unwrap();
    assert_eq!(journal.durable_step(), step);
    assert!(journal.prepare(vec![cli_entry()]).is_err());
}

#[test]
fn applying_exposes_one_exact_forward_action_at_every_crash_point() {
    let mut journal = prepared_journal();
    assert!(journal.mark_installed().is_err());
    journal.start_applying().unwrap();
    assert_eq!(journal.state(), InstallJournalStateV1::Applying);
    assert_eq!(journal.durable_step(), 2);
    assert_eq!(
        journal.next_forward_action(),
        Some(InstallJournalForwardActionV1::Apply {
            durable_step: 3,
            role: InstallRoleV1::UsrRoot,
        })
    );

    assert!(
        journal
            .record_applied(InstallRoleV1::Cli, cli_identity(), None)
            .is_err()
    );
    journal
        .record_applied(InstallRoleV1::UsrRoot, usr_identity(), None)
        .unwrap();
    assert_eq!(journal.durable_step(), 3);
    assert_eq!(
        journal.next_forward_action(),
        Some(InstallJournalForwardActionV1::Verify {
            durable_step: 4,
            role: InstallRoleV1::UsrRoot,
            expected_identity: usr_identity(),
        })
    );

    let step = journal.durable_step();
    journal
        .record_applied(InstallRoleV1::UsrRoot, usr_identity(), None)
        .unwrap();
    assert_eq!(journal.durable_step(), step);
    assert!(
        journal
            .record_applied(
                InstallRoleV1::UsrRoot,
                InstallObjectIdentityV1::directory(9, 999, 2, 0o755, 0, 0).unwrap(),
                None,
            )
            .is_err()
    );
    assert!(
        journal
            .record_verified(InstallRoleV1::UsrRoot, cli_identity())
            .is_err()
    );
    journal
        .record_verified(InstallRoleV1::UsrRoot, usr_identity())
        .unwrap();
    assert_eq!(journal.durable_step(), 4);
    assert_eq!(
        journal.next_forward_action(),
        Some(InstallJournalForwardActionV1::Apply {
            durable_step: 5,
            role: InstallRoleV1::Cli,
        })
    );

    apply_and_verify(
        &mut journal,
        InstallRoleV1::Cli,
        cli_identity(),
        Some(parent_identity()),
    );
    assert_eq!(
        journal.entries()[1].created_parent_identity(),
        Some(&parent_identity())
    );
    apply_and_verify(&mut journal, InstallRoleV1::Daemon, daemon_identity(), None);
    assert_eq!(journal.next_forward_action(), None);
    journal.mark_installed().unwrap();
    assert_eq!(journal.state(), InstallJournalStateV1::Installed);
    assert_eq!(journal.durable_step(), 9);
    assert!(journal.start_applying().is_err());
}

#[test]
fn rollback_is_reverse_ordered_and_includes_only_durably_applied_entries() {
    let mut journal = prepared_journal();
    journal.start_applying().unwrap();
    apply_and_verify(&mut journal, InstallRoleV1::UsrRoot, usr_identity(), None);
    apply_and_verify(
        &mut journal,
        InstallRoleV1::Cli,
        cli_identity(),
        Some(parent_identity()),
    );
    assert_eq!(
        journal.entries()[2].phase(),
        InstallJournalEntryPhaseV1::Pending
    );

    journal.begin_rollback().unwrap();
    assert_eq!(journal.state(), InstallJournalStateV1::RollingBack);
    let cli_rollback = InstallJournalRollbackActionV1::RemoveExact {
        durable_step: 8,
        role: InstallRoleV1::Cli,
        expected_current: cli_identity(),
        created_parent_identity: Some(parent_identity()),
    };
    assert_eq!(journal.next_rollback_action(), Some(cli_rollback.clone()));
    assert!(
        journal
            .record_rollback_completed(&InstallJournalRollbackActionV1::RemoveExact {
                durable_step: 8,
                role: InstallRoleV1::Cli,
                expected_current: daemon_identity(),
                created_parent_identity: Some(parent_identity()),
            })
            .is_err()
    );
    journal.record_rollback_completed(&cli_rollback).unwrap();

    let root_rollback = InstallJournalRollbackActionV1::RemoveExact {
        durable_step: 9,
        role: InstallRoleV1::UsrRoot,
        expected_current: usr_identity(),
        created_parent_identity: None,
    };
    assert_eq!(journal.next_rollback_action(), Some(root_rollback.clone()));
    journal.record_rollback_completed(&root_rollback).unwrap();
    assert_eq!(journal.next_rollback_action(), None);
    assert_eq!(
        journal.entries()[2].phase(),
        InstallJournalEntryPhaseV1::Pending
    );
    journal.mark_rolled_back().unwrap();
    assert_eq!(journal.state(), InstallJournalStateV1::RolledBack);
    assert!(journal.begin_rollback().is_err());
}

#[test]
fn installed_upgrade_rollback_carries_both_exact_current_and_backup_identity() {
    let mut journal = prepared_journal();
    journal.start_applying().unwrap();
    apply_and_verify(&mut journal, InstallRoleV1::UsrRoot, usr_identity(), None);
    apply_and_verify(
        &mut journal,
        InstallRoleV1::Cli,
        cli_identity(),
        Some(parent_identity()),
    );
    apply_and_verify(&mut journal, InstallRoleV1::Daemon, daemon_identity(), None);
    journal.mark_installed().unwrap();
    journal.begin_rollback().unwrap();

    assert_eq!(
        journal.next_rollback_action(),
        Some(InstallJournalRollbackActionV1::RestoreExact {
            durable_step: 11,
            role: InstallRoleV1::Daemon,
            expected_current: daemon_identity(),
            backup_basename: ".l2-loop-daemon-backup".to_owned(),
            expected_backup: prior_daemon_identity(),
            created_parent_identity: None,
        })
    );
}

#[test]
fn first_failure_is_immutable_and_identity_uncertainty_blocks_rollback() {
    let mut journal = prepared_journal();
    journal.start_applying().unwrap();
    journal
        .record_applied(InstallRoleV1::UsrRoot, usr_identity(), None)
        .unwrap();
    journal.record_failure(GI_WRITE_FAILED, true).unwrap();
    assert_eq!(journal.state(), InstallJournalStateV1::Failed);
    assert_eq!(journal.failure_code(), Some(GI_WRITE_FAILED));
    assert!(journal.rollback_possible());
    let step = journal.durable_step();
    journal.record_failure(GI_WRITE_FAILED, true).unwrap();
    assert_eq!(journal.durable_step(), step);
    assert!(journal.record_failure(GI_ROLLBACK_IDENTITY, true).is_err());
    assert!(journal.record_failure(GI_WRITE_FAILED, false).is_err());
    journal.begin_rollback().unwrap();

    let mut blocked = prepared_journal();
    blocked.start_applying().unwrap();
    blocked
        .record_applied(InstallRoleV1::UsrRoot, usr_identity(), None)
        .unwrap();
    blocked.record_failure(GI_ROLLBACK_IDENTITY, false).unwrap();
    assert!(!blocked.rollback_possible());
    assert!(blocked.begin_rollback().is_err());
}

#[test]
fn generated_names_and_identity_shapes_fail_closed() {
    for basename in [
        "",
        ".",
        "..",
        "nested/name",
        "nested\\name",
        "*.tmp",
        "name?tmp",
        "[name]",
    ] {
        assert!(
            InstallJournalEntryV1::absent_file(
                InstallRoleV1::Cli,
                InstallIntendedIdentityV1::regular_file(CLI_SHA256, 0o755, 0, 0).unwrap(),
                basename,
            )
            .is_err(),
            "accepted unsafe basename: {basename}"
        );
    }

    assert!(InstallIntendedIdentityV1::regular_file(CLI_SHA256, 0o777, 0, 0).is_ok());
    assert!(
        InstallJournalEntryV1::absent_file(
            InstallRoleV1::Cli,
            InstallIntendedIdentityV1::regular_file(CLI_SHA256, 0o777, 0, 0).unwrap(),
            ".l2-loop-cli-new",
        )
        .is_err()
    );
    assert!(InstallObjectIdentityV1::regular_file(1, 2, 2, CLI_SHA256, 0o755, 0, 0).is_err());
    assert!(InstallObjectIdentityV1::regular_file(1, 2, 1, "A".repeat(64), 0o755, 0, 0).is_err());
}

fn journal() -> InstallJournalV1 {
    InstallJournalV1::new(
        InstallJournalBindingsV1::new(
            TRANSACTION_ID,
            AUTHORIZATION_ID,
            HOST_SHA256,
            artifact(),
            MANIFEST_SHA256,
            DEPLOYMENT_SHA256,
            PERFORMANCE_SHA256,
        )
        .unwrap(),
    )
}

fn prepared_journal() -> InstallJournalV1 {
    let mut journal = journal();
    journal.prepare(entries()).unwrap();
    journal
}

fn entries() -> Vec<InstallJournalEntryV1> {
    vec![daemon_entry(), usr_entry(), cli_entry()]
}

fn usr_entry() -> InstallJournalEntryV1 {
    InstallJournalEntryV1::absent_directory(
        InstallRoleV1::UsrRoot,
        InstallIntendedIdentityV1::directory(0o755, 0, 0).unwrap(),
    )
    .unwrap()
}

fn cli_entry() -> InstallJournalEntryV1 {
    InstallJournalEntryV1::absent_file(
        InstallRoleV1::Cli,
        InstallIntendedIdentityV1::regular_file(CLI_SHA256, 0o755, 0, 0).unwrap(),
        ".l2-loop-cli-new",
    )
    .unwrap()
}

fn daemon_entry() -> InstallJournalEntryV1 {
    InstallJournalEntryV1::prior_owned_file(
        InstallRoleV1::Daemon,
        InstallIntendedIdentityV1::regular_file(DAEMON_SHA256, 0o755, 0, 0).unwrap(),
        ".l2-loop-daemon-new",
        ".l2-loop-daemon-backup",
        prior_daemon_identity(),
    )
    .unwrap()
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn usr_identity() -> InstallObjectIdentityV1 {
    InstallObjectIdentityV1::directory(9, 100, 2, 0o755, 0, 0).unwrap()
}

fn parent_identity() -> InstallObjectIdentityV1 {
    InstallObjectIdentityV1::directory(9, 101, 2, 0o755, 0, 0).unwrap()
}

fn cli_identity() -> InstallObjectIdentityV1 {
    InstallObjectIdentityV1::regular_file(9, 200, 1, CLI_SHA256, 0o755, 0, 0).unwrap()
}

fn daemon_identity() -> InstallObjectIdentityV1 {
    InstallObjectIdentityV1::regular_file(9, 300, 1, DAEMON_SHA256, 0o755, 0, 0).unwrap()
}

fn prior_daemon_identity() -> InstallObjectIdentityV1 {
    InstallObjectIdentityV1::regular_file(9, 301, 1, PRIOR_SHA256, 0o755, 0, 0).unwrap()
}

fn apply_and_verify(
    journal: &mut InstallJournalV1,
    role: InstallRoleV1,
    identity: InstallObjectIdentityV1,
    created_parent_identity: Option<InstallObjectIdentityV1>,
) {
    journal
        .record_applied(role, identity.clone(), created_parent_identity)
        .unwrap();
    journal.record_verified(role, identity).unwrap();
}
