#![cfg(target_os = "linux")]

use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use l2_loop_agent::{
    EvidenceStore, EvidenceStoreError, FilesystemCapacity, FilesystemSpace, LinuxEvidenceStore,
    StdEvidenceIo, minimum_free_reserve,
};
use l2_loop_core::{
    AlertCode, BaselineSummary, DetectionState, DetectionTransitionReason,
    EVIDENCE_MAX_CLOSED_AGE_MS, EVIDENCE_MIN_FREE_RESERVE_BYTES,
    EVIDENCE_MIN_FREE_RESERVE_PERCENT, EVIDENCE_SCHEMA_VERSION, EventId, EvidenceStatus,
    FingerprintWindowReport, IncidentRevisionV1, InterfaceName, ObservationCounters,
    ObservationHealth, RateIdentity, VlanVisibility, warming_status_rate_windows,
};

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct PrivateRoot(PathBuf);

impl PrivateRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "l2-loop-retention-{}-{}",
            std::process::id(),
            ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let prefix = format!("l2-loop-retention-{}-", std::process::id());
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

#[derive(Debug, Clone, Copy)]
struct FixedCapacity(FilesystemSpace);

impl FilesystemCapacity for FixedCapacity {
    fn capacity(&self, _: &Path) -> io::Result<FilesystemSpace> {
        Ok(self.0)
    }
}

fn revision(event_id: EventId, closed_at: Option<u64>) -> IncidentRevisionV1 {
    let current_state = if closed_at.is_some() {
        DetectionState::Normal
    } else {
        DetectionState::IngressStormConfirmed
    };
    let code = if closed_at.is_some() {
        AlertCode::IncidentClosed
    } else {
        AlertCode::StormConfirmed
    };
    let identity = RateIdentity::new(41, 7).unwrap();
    IncidentRevisionV1 {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        event_id,
        revision: 1,
        interface: InterfaceName::new("l2h0123456789").unwrap(),
        ifindex: 41,
        interface_generation: 7,
        transition_sequence: 1,
        previous_state: DetectionState::Cooldown,
        current_state,
        transition_reason: DetectionTransitionReason::CooldownCompleted,
        opened_at_unix_ms: 1_000,
        occurred_at_unix_ms: closed_at.unwrap_or(2_000),
        closed_at_unix_ms: closed_at,
        alert_code: code,
        severity: code.severity(),
        evidence_status: EvidenceStatus::Stored,
        xdp_ingress: ObservationCounters {
            packets: 10,
            bytes: 600,
        },
        tc_egress: ObservationCounters {
            packets: 10,
            bytes: 600,
        },
        rate_windows: warming_status_rate_windows(),
        baseline: BaselineSummary::learning(identity, 1_000),
        fingerprint_window: FingerprintWindowReport::warming(),
        detection: l2_loop_core::DetectionReport::warming(identity, 1_000),
        observation_health: ObservationHealth::Healthy,
        vlan_visibility: VlanVisibility::VerifiedVisible,
        last_error_code: None,
    }
}

#[test]
fn fixed_age_and_free_reserve_boundaries_are_exact() {
    assert_eq!(EVIDENCE_MAX_CLOSED_AGE_MS, 30 * 24 * 60 * 60 * 1_000);
    assert_eq!(EVIDENCE_MIN_FREE_RESERVE_BYTES, 536_870_912);
    assert_eq!(EVIDENCE_MIN_FREE_RESERVE_PERCENT, 5);
    assert_eq!(minimum_free_reserve(1_000_000_000), 536_870_912);
    assert_eq!(minimum_free_reserve(20_000_000_000), 1_000_000_000);
    assert_eq!(minimum_free_reserve(u64::MAX), u64::MAX / 20);
}

#[test]
fn retention_deletes_only_oldest_closed_whole_event_with_id_tie_break() {
    let root = PrivateRoot::new();
    let older_low_id = EventId::from_bytes([1; 16]);
    let older_high_id = EventId::from_bytes([2; 16]);
    let active = EventId::from_bytes([3; 16]);
    let mut store = LinuxEvidenceStore::open(StdEvidenceIo, &root.0, "0.1.0").unwrap();
    let low = store.put(&revision(older_low_id, Some(2_000))).unwrap();
    store
        .put(&revision(older_high_id, Some(2_000)))
        .unwrap();
    store.put(&revision(active, None)).unwrap();

    let reserve = minimum_free_reserve(1_000_000_000);
    let outcome = store
        .enforce_retention(
            2_000,
            1,
            &FixedCapacity(FilesystemSpace {
                total_bytes: 1_000_000_000,
                available_bytes: reserve - low.bundle_bytes,
            }),
        )
        .unwrap();
    assert_eq!(outcome.deleted_event_ids, vec![older_low_id]);
    assert!(!root.0.join(older_low_id.to_string()).exists());
    assert!(root.0.join(older_high_id.to_string()).exists());
    assert!(root.0.join(active.to_string()).exists());
    assert!(matches!(
        store.get(older_low_id),
        Err(EvidenceStoreError::NotFound)
    ));
    assert!(store.get(older_high_id).is_ok());
    assert!(store.get(active).is_ok());
}

#[test]
fn age_expiry_is_exact_and_unknown_objects_are_never_deleted() {
    let root = PrivateRoot::new();
    let expired = EventId::from_bytes([4; 16]);
    let exact_boundary = EventId::from_bytes([5; 16]);
    let active = EventId::from_bytes([6; 16]);
    let now = EVIDENCE_MAX_CLOSED_AGE_MS + 10_000;
    let mut store = LinuxEvidenceStore::open(StdEvidenceIo, &root.0, "0.1.0").unwrap();
    store.put(&revision(expired, Some(9_999))).unwrap();
    store
        .put(&revision(exact_boundary, Some(10_000)))
        .unwrap();
    store.put(&revision(active, None)).unwrap();
    fs::create_dir(root.0.join("unknown-object")).unwrap();

    let outcome = store
        .enforce_retention(
            now,
            0,
            &FixedCapacity(FilesystemSpace {
                total_bytes: 20_000_000_000,
                available_bytes: 20_000_000_000,
            }),
        )
        .unwrap();
    assert_eq!(outcome.deleted_event_ids, vec![expired]);
    assert!(root.0.join(exact_boundary.to_string()).exists());
    assert!(root.0.join(active.to_string()).exists());
    assert!(root.0.join("unknown-object").exists());
}

#[test]
fn retention_reports_unavailable_when_only_active_evidence_remains() {
    let root = PrivateRoot::new();
    let active = EventId::from_bytes([7; 16]);
    let mut store = LinuxEvidenceStore::open(StdEvidenceIo, &root.0, "0.1.0").unwrap();
    store.put(&revision(active, None)).unwrap();
    assert_eq!(
        store.enforce_retention(
            2_000,
            1,
            &FixedCapacity(FilesystemSpace {
                total_bytes: 1_000_000_000,
                available_bytes: 0,
            }),
        ),
        Err(EvidenceStoreError::RetentionUnavailable)
    );
    assert!(store.get(active).is_ok());
    assert!(root.0.join(active.to_string()).exists());
}
