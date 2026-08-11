#![cfg(target_os = "linux")]

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use l2_loop_agent::{
    Clock, ObservationReader, ObservationService, PortError, RawObservation,
    ownership::{OWNED_MAP_NAMES, OWNERSHIP_SCHEMA_VERSION, OwnedMapPin, OwnershipRecord},
};
use l2_loop_common::ABI_VERSION;
use l2_loop_core::{
    ClassObservation, HookObservation, HookRole, InterfaceName, ObservationCounters,
    ObservationHealth, TrafficClass, VlanVisibility,
};

const RUN_ROOT: &str = "/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef";
const CLASS_ORDER: [TrafficClass; 6] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

#[test]
fn observe_builds_a_generation_scoped_snapshot() {
    let reader = FakeReader::returning(raw_observation(41, 7));
    let clock = FixedClock::unix_ms(1_786_300_000_000);
    let mut service = ObservationService::new(reader, clock);
    let active = interface();
    let ownership = ownership(41, 7);

    let snapshot = service.observe(&active, &active, &ownership).unwrap();

    assert_eq!(snapshot.ifindex, 41);
    assert_eq!(snapshot.generation, 7);
    assert_eq!(snapshot.captured_at_unix_ms, 1_786_300_000_000);
    assert_eq!(snapshot.vlan_visibility, VlanVisibility::VerifiedVisible);
    assert_eq!(snapshot.health, ObservationHealth::Healthy);
    assert_eq!(snapshot.hooks[0].total, counters(5, 300));
    assert_eq!(snapshot.hooks[1].total, counters(4, 240));
}

#[test]
fn interface_mismatch_is_rejected_before_reader_io() {
    let reader = FakeReader::panic_on_read();
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
    let active = interface();
    let ownership = ownership(41, 7);

    let error = service
        .observe(
            &InterfaceName::new("foreign0").unwrap(),
            &active,
            &ownership,
        )
        .unwrap_err();

    assert_eq!(error.code(), "OBS_INTERFACE_MISMATCH");
}

#[test]
fn raw_identity_must_match_the_ownership_journal() {
    for raw in [raw_observation(99, 7), raw_observation(41, 99)] {
        let reader = FakeReader::returning(raw);
        let calls = reader.calls();
        let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
        let active = interface();

        let error = service
            .observe(&active, &active, &ownership(41, 7))
            .unwrap_err();

        assert_eq!(error.code(), "OBS_OWNERSHIP_MISMATCH");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn reader_stable_codes_are_preserved_without_internal_evidence() {
    let reader = FakeReader::failing(PortError::coded_adapter(
        "OBS_MAP_IDENTITY_MISMATCH",
        "internal adapter evidence",
    ));
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
    let active = interface();

    let error = service
        .observe(&active, &active, &ownership(41, 7))
        .unwrap_err();

    assert_eq!(error.code(), "OBS_MAP_IDENTITY_MISMATCH");
    assert_eq!(error.evidence(), "observation reader failed");
}

#[test]
fn uncoded_reader_errors_use_the_map_unavailable_code() {
    let reader = FakeReader::failing(PortError::Adapter("read failed".into()));
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
    let active = interface();

    let error = service
        .observe(&active, &active, &ownership(41, 7))
        .unwrap_err();

    assert_eq!(error.code(), "OBS_MAP_UNAVAILABLE");
}

#[test]
fn clock_before_the_unix_epoch_is_a_snapshot_failure() {
    let reader = FakeReader::returning(raw_observation(41, 7));
    let mut service = ObservationService::new(reader, FixedClock::before_epoch());
    let active = interface();

    let error = service
        .observe(&active, &active, &ownership(41, 7))
        .unwrap_err();

    assert_eq!(error.code(), "OBS_SNAPSHOT_FAILED");
}

#[test]
fn invalid_raw_hook_order_is_a_snapshot_failure() {
    let mut raw = raw_observation(41, 7);
    raw.hooks.swap(0, 1);
    let reader = FakeReader::returning(raw);
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
    let active = interface();

    let error = service
        .observe(&active, &active, &ownership(41, 7))
        .unwrap_err();

    assert_eq!(error.code(), "OBS_SNAPSHOT_FAILED");
}

#[test]
fn status_returns_zero_sessions_without_reader_io() {
    let reader = FakeReader::panic_on_read();
    let mut service = ObservationService::new(reader, FixedClock::before_epoch());

    assert!(service.status(None, None, None).unwrap().is_empty());
}

#[test]
fn filtered_status_without_an_active_session_is_rejected() {
    let reader = FakeReader::panic_on_read();
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
    let requested = interface();

    let error = service.status(Some(&requested), None, None).unwrap_err();

    assert_eq!(error.code(), "OBS_SESSION_NOT_FOUND");
}

#[test]
fn filtered_status_for_a_different_interface_is_rejected_before_reader_io() {
    let reader = FakeReader::panic_on_read();
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
    let active = interface();
    let requested = InterfaceName::new("foreign0").unwrap();

    let error = service
        .status(Some(&requested), Some(&active), Some(&ownership(41, 7)))
        .unwrap_err();

    assert_eq!(error.code(), "OBS_SESSION_NOT_FOUND");
}

#[test]
fn status_summarizes_the_single_active_session() {
    let reader = FakeReader::returning(raw_observation(41, 7));
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(42));
    let active = interface();
    let ownership = ownership(41, 7);

    let statuses = service
        .status(None, Some(&active), Some(&ownership))
        .unwrap();

    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].interface, active);
    assert_eq!(statuses[0].generation, 7);
    assert_eq!(statuses[0].captured_at_unix_ms, 42);
    assert_eq!(statuses[0].xdp_ingress, counters(5, 300));
    assert_eq!(statuses[0].tc_egress, counters(4, 240));
}

#[test]
fn inconsistent_active_status_identity_is_rejected_before_reader_io() {
    let reader = FakeReader::panic_on_read();
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
    let active = interface();

    let error = service.status(None, Some(&active), None).unwrap_err();

    assert_eq!(error.code(), "OBS_OWNERSHIP_MISMATCH");
}

#[derive(Clone)]
struct FakeReader {
    outcome: Option<Result<RawObservation, PortError>>,
    calls: Arc<AtomicUsize>,
}

impl FakeReader {
    fn returning(raw: RawObservation) -> Self {
        Self {
            outcome: Some(Ok(raw)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn failing(error: PortError) -> Self {
        Self {
            outcome: Some(Err(error)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn panic_on_read() -> Self {
        Self {
            outcome: None,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> Arc<AtomicUsize> {
        self.calls.clone()
    }
}

impl ObservationReader for FakeReader {
    fn read_exact(&mut self, _ownership: &OwnershipRecord) -> Result<RawObservation, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcome
            .clone()
            .expect("observation reader must not be called")
    }
}

#[derive(Clone, Copy)]
struct FixedClock {
    wall_time: SystemTime,
}

impl FixedClock {
    fn unix_ms(milliseconds: u64) -> Self {
        Self {
            wall_time: UNIX_EPOCH
                .checked_add(Duration::from_millis(milliseconds))
                .unwrap(),
        }
    }

    fn before_epoch() -> Self {
        Self {
            wall_time: UNIX_EPOCH.checked_sub(Duration::from_millis(1)).unwrap(),
        }
    }
}

impl Clock for FixedClock {
    fn monotonic_ns(&self) -> u64 {
        0
    }

    fn wall_time(&self) -> SystemTime {
        self.wall_time
    }
}

fn raw_observation(ifindex: u32, generation: u64) -> RawObservation {
    RawObservation {
        ifindex,
        generation,
        vlan_visibility: VlanVisibility::VerifiedVisible,
        hooks: [
            hook(HookRole::ExternalXdpIngress, counters(5, 300)),
            hook(HookRole::PhysicalTcEgress, counters(4, 240)),
        ],
    }
}

fn hook(role: HookRole, total: ObservationCounters) -> HookObservation {
    HookObservation {
        role,
        total,
        classes: CLASS_ORDER.map(|traffic_class| ClassObservation {
            traffic_class,
            counters: counters(1, 60),
        }),
        parse_errors: counters(0, 0),
    }
}

fn counters(packets: u64, bytes: u64) -> ObservationCounters {
    ObservationCounters { packets, bytes }
}

fn interface() -> InterfaceName {
    InterfaceName::new("l2h0123456789").unwrap()
}

fn ownership(ifindex: u32, generation: u64) -> OwnershipRecord {
    OwnershipRecord {
        schema_version: OWNERSHIP_SCHEMA_VERSION,
        abi_version: ABI_VERSION,
        generation,
        ifindex,
        xdp: None,
        tc: Vec::new(),
        map_pins: OWNED_MAP_NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| OwnedMapPin::new(*name, pin(name), 301 + index as u32).unwrap())
            .collect(),
        created_at_unix_seconds: 1_787_000_000,
    }
}

fn pin(name: &str) -> PathBuf {
    Path::new(RUN_ROOT).join(name)
}
