use std::{
    cell::RefCell,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use l2_loop_agent::{
    Clock, HostIdentityReader, InstallActionV1, InstallDestinationSnapshotV1,
    InstallDestinationStateV1, InstallIoError, InstallJournalSnapshotV1, InstallPlanV1,
    InstallPlanner, InstallRoleV1, InstallService, InstallSourceReader, InstallSourceSnapshotV1,
    InstallStateReader, InstallTransactionWriter,
};
use l2_loop_core::{
    DeploymentArtifactIdentityV1, GI_AUTH_ARTIFACT, GI_AUTH_HOST, GI_TRANSACTION_CONFLICT,
    GI_WRITE_FAILED, INSTALL_AUTHORIZATION_MAX_LIFETIME_MS, InstallAuthorizationV1,
    InstallDecisionV1, InstallOperationV1,
};
use serde_json::json;

const NOW_MS: u64 = 1_786_665_600_000;
const AUTHORIZATION_ID: &str = "00112233445566778899aabbccddeeff";
const TRANSACTION_ID: &str = "ffeeddccbbaa99887766554433221100";
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const MANIFEST_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HOST_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DEPLOYMENT_AUTHORIZATION_SHA256: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const PERFORMANCE_EVIDENCE_SHA256: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";

#[test]
fn planner_builds_deterministic_fixed_role_actions() {
    let source = source(InstallOperationV1::Upgrade);
    let destinations = vec![
        destination(InstallRoleV1::Cli, InstallDestinationStateV1::AbsentFile),
        destination(
            InstallRoleV1::Daemon,
            InstallDestinationStateV1::PriorOwnedFile,
        ),
        destination(
            InstallRoleV1::EvidenceRoot,
            InstallDestinationStateV1::AbsentDirectory,
        ),
    ];

    let plan = InstallPlanner::plan(&source, &destinations, None).unwrap();

    assert_eq!(plan.authorization_id, AUTHORIZATION_ID);
    assert_eq!(plan.transaction_id, TRANSACTION_ID);
    assert_eq!(plan.operation, InstallOperationV1::Upgrade);
    assert_eq!(
        plan.actions,
        vec![
            InstallActionV1::CreateDirectory {
                role: InstallRoleV1::EvidenceRoot,
            },
            InstallActionV1::UpgradeOwnedFile {
                role: InstallRoleV1::Daemon,
            },
            InstallActionV1::InstallAbsentFile {
                role: InstallRoleV1::Cli,
            },
            InstallActionV1::VerifyInstalledObject {
                role: InstallRoleV1::EvidenceRoot,
            },
            InstallActionV1::VerifyInstalledObject {
                role: InstallRoleV1::Daemon,
            },
            InstallActionV1::VerifyInstalledObject {
                role: InstallRoleV1::Cli,
            },
        ]
    );
}

#[test]
fn planner_rejects_prior_journal_and_install_over_owned_state() {
    let install = source(InstallOperationV1::Install);
    let owned = vec![destination(
        InstallRoleV1::Daemon,
        InstallDestinationStateV1::PriorOwnedFile,
    )];
    assert!(InstallPlanner::plan(&install, &owned, None).is_err());

    let journal = InstallJournalSnapshotV1::new(TRANSACTION_ID, Vec::new()).unwrap();
    let absent = vec![destination(
        InstallRoleV1::Daemon,
        InstallDestinationStateV1::AbsentFile,
    )];
    assert!(InstallPlanner::plan(&install, &absent, Some(&journal)).is_err());
}

#[test]
fn service_plan_reads_in_order_and_never_calls_writer() {
    let shared = Shared::default();
    let mut service = service(
        shared.clone(),
        source(InstallOperationV1::Install),
        default_destinations(),
        None,
    );

    let outcome = service.plan().unwrap();

    assert_eq!(outcome.report.decision, InstallDecisionV1::InstallPlanReady);
    assert!(outcome.plan.is_some());
    assert!(!outcome.report.mutations_performed);
    assert_eq!(
        shared.calls(),
        [
            "load_source",
            "host_identity_sha256",
            "inspect_destinations",
            "inspect_prior_journal",
        ]
    );
    assert!(shared.applied().is_empty());
    assert!(shared.recorded().is_empty());
    assert!(shared.rolled_back().is_empty());
}

#[test]
fn service_apply_durably_records_each_action_before_the_next() {
    let shared = Shared::default();
    let mut service = service(
        shared.clone(),
        source(InstallOperationV1::Install),
        default_destinations(),
        None,
    );

    let report = service.apply().unwrap();

    assert_eq!(report.decision, InstallDecisionV1::InstalledVerified);
    assert!(report.mutations_performed);
    assert_eq!(shared.applied(), shared.recorded());
    assert_eq!(shared.applied().len(), 4);
    assert_eq!(
        shared.calls(),
        [
            "load_source",
            "host_identity_sha256",
            "inspect_destinations",
            "inspect_prior_journal",
            "begin_transaction",
            "apply_action",
            "record_completed",
            "apply_action",
            "record_completed",
            "apply_action",
            "record_completed",
            "apply_action",
            "record_completed",
            "complete_transaction",
        ]
    );
}

#[test]
fn apply_stops_before_state_or_writer_on_artifact_identity_mismatch() {
    let shared = Shared::default();
    let mut mismatched = source(InstallOperationV1::Install);
    mismatched.artifact =
        DeploymentArtifactIdentityV1::new("1123456789abcdef0123456789abcdef01234567", "0.1.0")
            .unwrap();
    let mut service = service(shared.clone(), mismatched, default_destinations(), None);

    let report = service.apply().unwrap();

    assert_eq!(report.decision, InstallDecisionV1::Blocked);
    assert_eq!(report.findings[0].code, GI_AUTH_ARTIFACT);
    assert_eq!(shared.calls(), ["load_source"]);
    assert!(shared.applied().is_empty());
}

#[test]
fn apply_stops_before_state_or_writer_on_host_identity_mismatch() {
    let shared = Shared::default();
    shared.set_host_sha256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let mut service = service(
        shared.clone(),
        source(InstallOperationV1::Install),
        default_destinations(),
        None,
    );

    let report = service.apply().unwrap();

    assert_eq!(report.decision, InstallDecisionV1::Blocked);
    assert_eq!(report.findings[0].code, GI_AUTH_HOST);
    assert_eq!(shared.calls(), ["load_source", "host_identity_sha256"]);
    assert!(shared.applied().is_empty());
}

#[test]
fn prior_journal_blocks_apply_without_beginning_a_transaction() {
    let shared = Shared::default();
    let journal = InstallJournalSnapshotV1::new(TRANSACTION_ID, Vec::new()).unwrap();
    let mut service = service(
        shared.clone(),
        source(InstallOperationV1::Install),
        default_destinations(),
        Some(journal),
    );

    let report = service.apply().unwrap();

    assert_eq!(report.decision, InstallDecisionV1::Blocked);
    assert_eq!(report.findings[0].code, GI_TRANSACTION_CONFLICT);
    assert_eq!(
        shared.calls(),
        [
            "load_source",
            "host_identity_sha256",
            "inspect_destinations",
            "inspect_prior_journal",
        ]
    );
    assert!(shared.applied().is_empty());
}

#[test]
fn status_is_read_only_and_reports_verified_state() {
    let shared = Shared::default();
    let mut service = service(
        shared.clone(),
        source(InstallOperationV1::Install),
        default_destinations(),
        None,
    );

    let report = service.status().unwrap();

    assert_eq!(report.decision, InstallDecisionV1::InstalledVerified);
    assert!(!report.mutations_performed);
    assert_eq!(
        shared.calls(),
        [
            "load_source",
            "host_identity_sha256",
            "inspect_destinations",
            "inspect_prior_journal",
        ]
    );
    assert!(shared.applied().is_empty());
    assert!(shared.recorded().is_empty());
    assert!(shared.rolled_back().is_empty());
}

#[test]
fn rollback_processes_only_journaled_actions_in_exact_reverse_order() {
    let shared = Shared::default();
    let completed = vec![
        InstallActionV1::CreateDirectory {
            role: InstallRoleV1::EvidenceRoot,
        },
        InstallActionV1::InstallAbsentFile {
            role: InstallRoleV1::Daemon,
        },
        InstallActionV1::VerifyInstalledObject {
            role: InstallRoleV1::Daemon,
        },
    ];
    let journal = InstallJournalSnapshotV1::new(TRANSACTION_ID, completed.clone()).unwrap();
    let mut service = service(
        shared.clone(),
        source(InstallOperationV1::Rollback),
        default_destinations(),
        Some(journal),
    );

    let report = service.rollback().unwrap();

    assert_eq!(report.decision, InstallDecisionV1::RolledBack);
    assert!(report.mutations_performed);
    let expected = completed.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(shared.rolled_back(), expected);
    assert_eq!(shared.recorded(), expected);
    assert_eq!(
        shared.calls(),
        [
            "load_source",
            "host_identity_sha256",
            "inspect_destinations",
            "inspect_prior_journal",
            "begin_rollback",
            "rollback_action",
            "record_rolled_back",
            "rollback_action",
            "record_rolled_back",
            "rollback_action",
            "record_rolled_back",
            "complete_rollback",
        ]
    );
}

#[test]
fn writer_failure_blocks_without_automatic_rollback_or_later_action() {
    let shared = Shared::default();
    shared.fail_writer_at_action(2);
    let mut service = service(
        shared.clone(),
        source(InstallOperationV1::Install),
        default_destinations(),
        None,
    );

    let report = service.apply().unwrap();

    assert_eq!(report.decision, InstallDecisionV1::Blocked);
    assert_eq!(report.findings[0].code, GI_WRITE_FAILED);
    assert!(report.mutations_performed);
    assert_eq!(shared.applied().len(), 2);
    assert_eq!(shared.recorded().len(), 1);
    assert!(shared.rolled_back().is_empty());
    assert!(!shared.calls().contains(&"complete_transaction"));
}

#[test]
fn service_source_contains_no_real_io_or_attachment_path() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(manifest_dir.join("src/installation.rs")).unwrap();
    for prohibited in [
        "std::fs",
        "tokio::fs",
        "systemctl",
        "journalctl",
        "rtnetlink",
        "aya::",
        "SafeXdpPort",
        "SafeTcPort",
        "remove_dir_all",
        "Command::new",
    ] {
        assert!(!source.contains(prohibited));
    }
}

fn destination(
    role: InstallRoleV1,
    state: InstallDestinationStateV1,
) -> InstallDestinationSnapshotV1 {
    InstallDestinationSnapshotV1::new(role, state)
}

fn default_destinations() -> Vec<InstallDestinationSnapshotV1> {
    vec![
        destination(
            InstallRoleV1::EvidenceRoot,
            InstallDestinationStateV1::AbsentDirectory,
        ),
        destination(InstallRoleV1::Daemon, InstallDestinationStateV1::AbsentFile),
    ]
}

fn service(
    shared: Shared,
    source: InstallSourceSnapshotV1,
    destinations: Vec<InstallDestinationSnapshotV1>,
    journal: Option<InstallJournalSnapshotV1>,
) -> InstallService<FakeSource, FakeState, FakeWriter, FakeHostIdentity, FixedClock> {
    InstallService::new(
        FakeSource {
            shared: shared.clone(),
            source,
        },
        FakeState {
            shared: shared.clone(),
            destinations,
            journal,
        },
        FakeWriter {
            shared: shared.clone(),
        },
        FakeHostIdentity { shared },
        FixedClock,
    )
}

fn source(operation: InstallOperationV1) -> InstallSourceSnapshotV1 {
    InstallSourceSnapshotV1::new(
        authorization(operation),
        artifact(),
        MANIFEST_SHA256,
        DEPLOYMENT_AUTHORIZATION_SHA256,
        PERFORMANCE_EVIDENCE_SHA256,
    )
    .unwrap()
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn authorization(operation: InstallOperationV1) -> InstallAuthorizationV1 {
    serde_json::from_value(json!({
        "schema_version": 1,
        "authorization_id": AUTHORIZATION_ID,
        "transaction_id": TRANSACTION_ID,
        "operation": operation,
        "artifact_commit_sha": COMMIT_SHA,
        "bundle_manifest_sha256": MANIFEST_SHA256,
        "host_identity_sha256": HOST_SHA256,
        "deployment_authorization_sha256": DEPLOYMENT_AUTHORIZATION_SHA256,
        "performance_evidence_sha256": PERFORMANCE_EVIDENCE_SHA256,
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": NOW_MS + INSTALL_AUTHORIZATION_MAX_LIFETIME_MS,
        "service_enable": false,
        "service_start": false,
        "physical_attach": false
    }))
    .unwrap()
}

#[derive(Clone, Default)]
struct Shared(Rc<RefCell<SharedState>>);

#[derive(Default)]
struct SharedState {
    calls: Vec<&'static str>,
    applied: Vec<InstallActionV1>,
    recorded: Vec<InstallActionV1>,
    rolled_back: Vec<InstallActionV1>,
    host_sha256: Option<String>,
    fail_writer_at_action: Option<usize>,
}

impl Shared {
    fn call(&self, name: &'static str) {
        self.0.borrow_mut().calls.push(name);
    }

    fn calls(&self) -> Vec<&'static str> {
        self.0.borrow().calls.clone()
    }

    fn applied(&self) -> Vec<InstallActionV1> {
        self.0.borrow().applied.clone()
    }

    fn recorded(&self) -> Vec<InstallActionV1> {
        self.0.borrow().recorded.clone()
    }

    fn rolled_back(&self) -> Vec<InstallActionV1> {
        self.0.borrow().rolled_back.clone()
    }

    fn set_host_sha256(&self, sha256: &str) {
        self.0.borrow_mut().host_sha256 = Some(sha256.to_owned());
    }

    fn host_sha256(&self) -> String {
        self.0
            .borrow()
            .host_sha256
            .clone()
            .unwrap_or_else(|| HOST_SHA256.to_owned())
    }

    fn fail_writer_at_action(&self, action_number: usize) {
        self.0.borrow_mut().fail_writer_at_action = Some(action_number);
    }
}

struct FakeSource {
    shared: Shared,
    source: InstallSourceSnapshotV1,
}

impl InstallSourceReader for FakeSource {
    fn load_source(&mut self) -> Result<InstallSourceSnapshotV1, InstallIoError> {
        self.shared.call("load_source");
        Ok(self.source.clone())
    }
}

struct FakeHostIdentity {
    shared: Shared,
}

impl HostIdentityReader for FakeHostIdentity {
    fn host_identity_sha256(&mut self) -> Result<String, InstallIoError> {
        self.shared.call("host_identity_sha256");
        Ok(self.shared.host_sha256())
    }
}

struct FakeState {
    shared: Shared,
    destinations: Vec<InstallDestinationSnapshotV1>,
    journal: Option<InstallJournalSnapshotV1>,
}

impl InstallStateReader for FakeState {
    fn inspect_destinations(
        &mut self,
        _source: &InstallSourceSnapshotV1,
    ) -> Result<Vec<InstallDestinationSnapshotV1>, InstallIoError> {
        self.shared.call("inspect_destinations");
        Ok(self.destinations.clone())
    }

    fn inspect_prior_journal(
        &mut self,
        _transaction_id: &str,
    ) -> Result<Option<InstallJournalSnapshotV1>, InstallIoError> {
        self.shared.call("inspect_prior_journal");
        Ok(self.journal.clone())
    }
}

struct FakeWriter {
    shared: Shared,
}

impl InstallTransactionWriter for FakeWriter {
    fn begin_transaction(&mut self, _plan: &InstallPlanV1) -> Result<(), InstallIoError> {
        self.shared.call("begin_transaction");
        Ok(())
    }

    fn apply_action(&mut self, action: &InstallActionV1) -> Result<(), InstallIoError> {
        self.shared.call("apply_action");
        let mut state = self.shared.0.borrow_mut();
        state.applied.push(action.clone());
        if state.fail_writer_at_action == Some(state.applied.len()) {
            Err(InstallIoError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn record_completed(&mut self, action: &InstallActionV1) -> Result<(), InstallIoError> {
        self.shared.call("record_completed");
        self.shared.0.borrow_mut().recorded.push(action.clone());
        Ok(())
    }

    fn complete_transaction(&mut self, _plan: &InstallPlanV1) -> Result<(), InstallIoError> {
        self.shared.call("complete_transaction");
        Ok(())
    }

    fn begin_rollback(
        &mut self,
        _journal: &InstallJournalSnapshotV1,
    ) -> Result<(), InstallIoError> {
        self.shared.call("begin_rollback");
        Ok(())
    }

    fn rollback_action(&mut self, action: &InstallActionV1) -> Result<(), InstallIoError> {
        self.shared.call("rollback_action");
        self.shared.0.borrow_mut().rolled_back.push(action.clone());
        Ok(())
    }

    fn record_rolled_back(&mut self, action: &InstallActionV1) -> Result<(), InstallIoError> {
        self.shared.call("record_rolled_back");
        self.shared.0.borrow_mut().recorded.push(action.clone());
        Ok(())
    }

    fn complete_rollback(
        &mut self,
        _journal: &InstallJournalSnapshotV1,
    ) -> Result<(), InstallIoError> {
        self.shared.call("complete_rollback");
        Ok(())
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn monotonic_ns(&self) -> u64 {
        123
    }

    fn wall_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(NOW_MS)
    }
}
