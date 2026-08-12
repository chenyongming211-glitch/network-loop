#![cfg(target_os = "linux")]

use std::{
    fs,
    io,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use l2_loop_agent::{
    EvidenceIo, EvidenceIoStep, EvidenceMetadata, EvidenceStore, EvidenceStoreError,
    LinuxEvidenceStore, StdEvidenceIo,
};
use l2_loop_core::{
    AlertCode, BaselineSummary, DetectionState, DetectionTransitionReason,
    EVIDENCE_SCHEMA_VERSION, EventId, EvidenceIntegrity, EvidenceListQuery, EvidenceStatus,
    FingerprintWindowReport, HookRole, IncidentRevisionV1, InterfaceName, ObservationCounters,
    ObservationHealth, ObservationSnapshot, RateIdentity, SamplingStatus, TrafficClass,
    VlanVisibility, warming_detailed_rate_windows, warming_status_rate_windows,
};

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct PrivateRoot(PathBuf);

impl PrivateRoot {
    fn new() -> Self {
        let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "l2-loop-evidence-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let prefix = format!("l2-loop-evidence-{}-", std::process::id());
        if self
            .0
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(&prefix))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn counters(packets: u64, bytes: u64) -> ObservationCounters {
    ObservationCounters { packets, bytes }
}

fn snapshot() -> ObservationSnapshot {
    const CLASSES: [TrafficClass; 6] = [
        TrafficClass::L2Broadcast,
        TrafficClass::Ipv4Multicast,
        TrafficClass::Ipv6Multicast,
        TrafficClass::OtherL2Multicast,
        TrafficClass::LinkLocalControl,
        TrafficClass::UnicastOrUnclassified,
    ];
    let hook = |role| l2_loop_core::HookObservation {
        role,
        total: counters(21, 1_260),
        classes: CLASSES.map(|traffic_class| l2_loop_core::ClassObservation {
            traffic_class,
            counters: counters(1, 60),
        }),
        parse_errors: counters(0, 0),
    };
    ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        41,
        7,
        1_786_300_000_000,
        VlanVisibility::VerifiedVisible,
        [
            hook(HookRole::ExternalXdpIngress),
            hook(HookRole::PhysicalTcEgress),
        ],
        SamplingStatus::default(),
        warming_detailed_rate_windows(),
    )
    .unwrap()
}

fn revision(event_id: EventId, revision: u64) -> IncidentRevisionV1 {
    let snapshot = snapshot();
    IncidentRevisionV1 {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        event_id,
        revision,
        interface: snapshot.interface.clone(),
        ifindex: snapshot.ifindex,
        interface_generation: snapshot.generation,
        transition_sequence: revision,
        previous_state: DetectionState::Normal,
        current_state: DetectionState::IngressStormConfirmed,
        transition_reason: DetectionTransitionReason::StormAsserted,
        opened_at_unix_ms: 1_786_300_000_000,
        occurred_at_unix_ms: 1_786_300_000_000 + revision,
        closed_at_unix_ms: None,
        alert_code: AlertCode::StormConfirmed,
        severity: AlertCode::StormConfirmed.severity(),
        evidence_status: EvidenceStatus::Stored,
        xdp_ingress: snapshot.hooks[0].total,
        tc_egress: snapshot.hooks[1].total,
        rate_windows: warming_status_rate_windows(),
        baseline: BaselineSummary::learning(
            RateIdentity::new(snapshot.ifindex, snapshot.generation).unwrap(),
            snapshot.captured_at_unix_ms,
        ),
        fingerprint_window: FingerprintWindowReport::warming(),
        detection: snapshot.detection,
        observation_health: ObservationHealth::Healthy,
        vlan_visibility: snapshot.vlan_visibility,
        last_error_code: None,
    }
}

#[test]
fn immutable_commit_get_list_and_restart_recovery_are_exact() {
    let root = PrivateRoot::new();
    let event_id = EventId::from_bytes([1; 16]);
    let mut store =
        LinuxEvidenceStore::open(StdEvidenceIo, root.path(), env!("CARGO_PKG_VERSION")).unwrap();

    let first = store.put(&revision(event_id, 1)).unwrap();
    assert_eq!(first.event_id, event_id);
    assert_eq!(first.latest_revision, 1);
    assert_eq!(first.integrity, EvidenceIntegrity::Valid);
    assert_eq!(store.get(event_id).unwrap().latest.revision, 1);
    assert_eq!(
        store
            .list(&EvidenceListQuery::new(None, Some(1), None).unwrap())
            .unwrap()
            .items,
        vec![first.clone()]
    );

    let revision_dir = root
        .path()
        .join(event_id.to_string())
        .join("0000000000000001");
    assert_eq!(
        fs::symlink_metadata(&revision_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for file in ["evidence.json", "manifest.json"] {
        assert_eq!(
            fs::symlink_metadata(revision_dir.join(file))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    assert_eq!(
        store.put(&revision(event_id, 1)),
        Err(EvidenceStoreError::RevisionConflict)
    );
    drop(store);

    let recovered =
        LinuxEvidenceStore::open(StdEvidenceIo, root.path(), env!("CARGO_PKG_VERSION")).unwrap();
    assert_eq!(recovered.get(event_id).unwrap().latest.revision, 1);
    assert!(recovered.health().available);
}

#[test]
fn root_and_object_security_refuse_missing_modes_and_links() {
    let missing = std::env::temp_dir().join(format!(
        "l2-loop-evidence-missing-{}",
        ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    assert!(matches!(
        LinuxEvidenceStore::open(StdEvidenceIo, &missing, "0.1.0"),
        Err(EvidenceStoreError::UnsafeRoot)
    ));

    let root = PrivateRoot::new();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        LinuxEvidenceStore::open(StdEvidenceIo, root.path(), "0.1.0"),
        Err(EvidenceStoreError::UnsafeRoot)
    ));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let target = PrivateRoot::new();
    let link = root.path().join("linked-root");
    symlink(target.path(), &link).unwrap();
    assert!(matches!(
        LinuxEvidenceStore::open(StdEvidenceIo, &link, "0.1.0"),
        Err(EvidenceStoreError::UnsafeRoot)
    ));
}

#[derive(Debug, Clone, Copy)]
struct FailingIo {
    fail: EvidenceIoStep,
}

impl EvidenceIo for FailingIo {
    fn checkpoint(&self, step: EvidenceIoStep) -> io::Result<()> {
        if step == self.fail {
            Err(io::Error::other("injected evidence I/O failure"))
        } else {
            Ok(())
        }
    }

    fn metadata(&self, path: &Path) -> io::Result<EvidenceMetadata> {
        StdEvidenceIo.metadata(path)
    }

    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        StdEvidenceIo.read_directory(path)
    }

    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
        StdEvidenceIo.read_file(path)
    }

    fn create_directory(&self, path: &Path, mode: u32) -> io::Result<()> {
        StdEvidenceIo.create_directory(path, mode)
    }

    fn write_file(&self, path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
        StdEvidenceIo.write_file(path, bytes, mode)
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        StdEvidenceIo.sync_directory(path)
    }

    fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()> {
        StdEvidenceIo.rename_noreplace(from, to)
    }

    fn remove_private_directory(&self, path: &Path) -> io::Result<()> {
        StdEvidenceIo.remove_private_directory(path)
    }
}

#[test]
fn every_atomic_publish_failure_preserves_the_prior_revision() {
    let steps = [
        EvidenceIoStep::CreateTemporary,
        EvidenceIoStep::WriteEvidence,
        EvidenceIoStep::WriteManifest,
        EvidenceIoStep::SyncTemporary,
        EvidenceIoStep::Publish,
        EvidenceIoStep::SyncEvent,
    ];
    for step in steps {
        let root = PrivateRoot::new();
        let event_id = EventId::from_bytes([2; 16]);
        LinuxEvidenceStore::open(StdEvidenceIo, root.path(), "0.1.0")
            .unwrap()
            .put(&revision(event_id, 1))
            .unwrap();

        let mut failing = LinuxEvidenceStore::open(FailingIo { fail: step }, root.path(), "0.1.0")
            .unwrap();
        assert!(failing.put(&revision(event_id, 2)).is_err(), "step {step:?}");
        drop(failing);

        let recovered = LinuxEvidenceStore::open(StdEvidenceIo, root.path(), "0.1.0").unwrap();
        assert_eq!(
            recovered.get(event_id).unwrap().latest.revision,
            if step == EvidenceIoStep::SyncEvent { 2 } else { 1 },
            "step {step:?}"
        );
    }
}

#[test]
fn recovery_preserves_and_counts_corrupt_incomplete_and_unknown_objects() {
    let root = PrivateRoot::new();
    let event_id = EventId::from_bytes([3; 16]);
    LinuxEvidenceStore::open(StdEvidenceIo, root.path(), "0.1.0")
        .unwrap()
        .put(&revision(event_id, 1))
        .unwrap();
    let event_dir = root.path().join(event_id.to_string());
    fs::write(
        event_dir.join("0000000000000001/evidence.json"),
        b"corrupt",
    )
    .unwrap();
    fs::create_dir(event_dir.join(".tmp-owned-incomplete")).unwrap();
    fs::create_dir(root.path().join("unknown-object")).unwrap();

    let recovered = LinuxEvidenceStore::open(StdEvidenceIo, root.path(), "0.1.0").unwrap();
    assert!(matches!(
        recovered.get(event_id),
        Err(EvidenceStoreError::NotFound)
    ));
    assert_eq!(recovered.health().corrupt_object_count, 1);
    assert_eq!(recovered.health().incomplete_object_count, 1);
    assert_eq!(recovered.health().unknown_object_count, 1);
    assert!(event_dir.join("0000000000000001").exists());
    assert!(event_dir.join(".tmp-owned-incomplete").exists());
    assert!(root.path().join("unknown-object").exists());
}

#[test]
fn serialization_and_event_bounds_fail_before_publishing() {
    let root = PrivateRoot::new();
    let event_id = EventId::from_bytes([4; 16]);
    let mut oversized = revision(event_id, 1);
    oversized.last_error_code = Some("x".repeat(1_100_000));
    let mut store = LinuxEvidenceStore::open(StdEvidenceIo, root.path(), "0.1.0").unwrap();
    assert_eq!(
        store.put(&oversized),
        Err(EvidenceStoreError::RevisionTooLarge)
    );
    assert!(!root.path().join(event_id.to_string()).exists());
}
