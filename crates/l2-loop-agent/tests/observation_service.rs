#![cfg(target_os = "linux")]

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use l2_loop_agent::{
    BASELINE_SOURCE_UNAVAILABLE, Clock, EventIdSource, IncidentRecorderError, OBS_MAP_UNAVAILABLE,
    OBS_RATE_COUNTER_REGRESSION, ObservationReadPurpose, ObservationReader, PortError,
    RawFingerprints, RawObservation, SamplingService, SamplingTickOutcome,
    ownership::{OWNED_MAP_NAMES, OWNERSHIP_SCHEMA_VERSION, OwnedMapPin, OwnershipRecord},
};
use l2_loop_common::{ABI_VERSION, FingerprintKey, FingerprintValue, direction};
use l2_loop_core::{
    BaselineState, ClassObservation, DetectionState, EventId, FingerprintEvidence,
    FingerprintState, HookObservation, HookRole, InterfaceName, ObservationCounters,
    ObservationHealth, RateWindowState, TrafficClass, VlanVisibility,
};

const SECOND_NS: u64 = 1_000_000_000;
const RUN_ROOT: &str = "/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef";
const IDENTITY_ERROR: &str = "OBS_MAP_IDENTITY_MISMATCH";
const CLASS_ORDER: [TrafficClass; 6] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

struct FixedIncidentId;

impl EventIdSource for FixedIncidentId {
    fn next_id(&mut self) -> Result<EventId, IncidentRecorderError> {
        Ok(EventId::from_bytes([7; 16]))
    }
}

#[test]
fn request_reads_never_enqueue_incident_output() {
    let (mut service, _, purposes) = service([Ok(raw_observation(0)), Ok(raw_observation(0))]);
    let active = interface();
    let ownership = ownership();
    service
        .start_incident_generation_with_source(&active, &ownership, FixedIncidentId)
        .unwrap();

    service.observe(&active, &active, &ownership).unwrap();
    service
        .status(None, Some(&active), Some(&ownership))
        .unwrap();

    assert!(service.take_incident_jobs().is_empty());
    assert_eq!(
        purposes.lock().unwrap().as_slice(),
        [
            ObservationReadPurpose::Request,
            ObservationReadPurpose::Request
        ]
    );
}

#[test]
fn background_tick_inserts_exactly_one_sample() {
    let (mut service, clock, purposes) = service([Ok(raw_observation(0)), Ok(raw_observation(0))]);
    let active = interface();
    let ownership = ownership();

    assert_eq!(
        service.sample_tick(&ownership),
        SamplingTickOutcome::Sampled
    );
    let snapshot = service.observe(&active, &active, &ownership).unwrap();

    assert_eq!(snapshot.sampling.latest_success_at_unix_ms, Some(1_000));
    assert!(
        snapshot
            .rate_windows
            .iter()
            .all(|window| window.state == RateWindowState::WarmingUp)
    );
    assert_eq!(clock.monotonic_ns(), 0);
    assert_eq!(
        purposes.lock().unwrap().as_slice(),
        [
            ObservationReadPurpose::BackgroundSample,
            ObservationReadPurpose::Request,
        ]
    );
}

#[test]
fn request_observe_reads_current_maps_but_does_not_insert_history() {
    let (mut service, clock, purposes) = service([
        Ok(raw_observation(0)),
        Ok(raw_observation(10)),
        Ok(raw_observation(2)),
        Ok(raw_observation(2)),
    ]);
    let active = interface();
    let ownership = ownership();

    service.sample_tick(&ownership);
    clock.set(SECOND_NS, 2_000);
    service.observe(&active, &active, &ownership).unwrap();
    clock.set(2 * SECOND_NS, 3_000);
    service.sample_tick(&ownership);
    let snapshot = service.observe(&active, &active, &ownership).unwrap();

    let window = &snapshot.rate_windows[0];
    assert_eq!(window.state, RateWindowState::Ready);
    assert_eq!(window.elapsed_ns, Some(2 * SECOND_NS));
    assert_eq!(window.start_unix_ms, Some(1_000));
    assert_eq!(window.end_unix_ms, Some(3_000));
    let xdp = window.hooks.as_ref().unwrap()[0].total;
    assert_eq!(xdp.packet_delta, 14);
    assert_eq!(xdp.packets_per_second, 7);
    assert_eq!(
        purposes.lock().unwrap().as_slice(),
        [
            ObservationReadPurpose::BackgroundSample,
            ObservationReadPurpose::Request,
            ObservationReadPurpose::BackgroundSample,
            ObservationReadPurpose::Request,
        ]
    );
}

#[test]
fn request_status_summarizes_the_same_rate_windows() {
    let (mut service, clock, _) = service([
        Ok(raw_observation(0)),
        Ok(raw_observation(1)),
        Ok(raw_observation(1)),
        Ok(raw_observation(1)),
    ]);
    let active = interface();
    let ownership = ownership();

    service.sample_tick(&ownership);
    clock.set(SECOND_NS, 2_000);
    service.sample_tick(&ownership);
    let snapshot = service.observe(&active, &active, &ownership).unwrap();
    let statuses = service
        .status(None, Some(&active), Some(&ownership))
        .unwrap();

    let detailed = &snapshot.rate_windows[0];
    let summary = &statuses[0].rate_windows[0];
    assert_eq!(summary.window_ms, detailed.window_ms);
    assert_eq!(summary.state, detailed.state);
    assert_eq!(summary.coverage_ms, detailed.coverage_ms);
    assert_eq!(summary.elapsed_ns, detailed.elapsed_ns);
    assert_eq!(summary.start_unix_ms, detailed.start_unix_ms);
    assert_eq!(summary.end_unix_ms, detailed.end_unix_ms);
    let hooks = detailed.hooks.as_ref().unwrap();
    assert_eq!(summary.xdp_ingress, Some(hooks[0].total));
    assert_eq!(summary.tc_egress, Some(hooks[1].total));
}

#[test]
fn request_builds_privacy_reduced_fingerprint_relationships_for_observe_and_status() {
    let ingress = fingerprint(direction::INGRESS, 100, 2, 128);
    let egress = fingerprint(direction::EGRESS, 200, 3, 192);
    let raw = raw_with_fingerprints(0, RawFingerprints::Available(vec![ingress, egress]));
    let (mut service, _, _) = service([Ok(raw.clone()), Ok(raw)]);
    let active = interface();
    let ownership = ownership();

    let observed = service.observe(&active, &active, &ownership).unwrap();
    let status = service
        .status(None, Some(&active), Some(&ownership))
        .unwrap()
        .remove(0);

    assert_eq!(observed.fingerprints.state, FingerprintState::Observed);
    assert_eq!(observed.fingerprints.captured_entry_count, 2);
    assert_eq!(observed.fingerprints.correlated_relation_count, 1);
    assert_eq!(status.fingerprints.correlated_relation_count, 1);
    assert_eq!(
        status.fingerprints.maximum_packet_ratio_milli,
        observed.fingerprints.maximum_packet_ratio_milli
    );
    let json = serde_json::to_string(&observed).unwrap();
    for forbidden in [
        "fingerprint\"",
        "source_mac",
        "destination_mac",
        "first_seen_ns",
    ] {
        assert!(!json.contains(forbidden));
    }
}

#[test]
fn recoverable_fingerprint_read_failure_degrades_health_without_losing_counters() {
    let raw = raw_with_fingerprints(
        0,
        RawFingerprints::Unavailable {
            code: "OBS_FINGERPRINT_UNAVAILABLE",
        },
    );
    let (mut service, _, _) = service([Ok(raw)]);
    let active = interface();
    let ownership = ownership();

    let observed = service.observe(&active, &active, &ownership).unwrap();

    assert_eq!(observed.health, ObservationHealth::Degraded);
    assert_eq!(observed.hooks[0].total, counters(100, 10_000));
    assert_eq!(observed.fingerprints.state, FingerprintState::Unavailable);
    assert_eq!(
        observed.fingerprints.last_error_code.as_deref(),
        Some("OBS_FINGERPRINT_UNAVAILABLE")
    );
}

#[test]
fn request_and_background_read_purposes_are_distinct() {
    let (mut service, _, purposes) = service([
        Ok(raw_observation(0)),
        Ok(raw_observation(0)),
        Ok(raw_observation(0)),
    ]);
    let active = interface();
    let ownership = ownership();

    service.sample_tick(&ownership);
    service.observe(&active, &active, &ownership).unwrap();
    service
        .status(None, Some(&active), Some(&ownership))
        .unwrap();

    assert_eq!(
        purposes.lock().unwrap().as_slice(),
        [
            ObservationReadPurpose::BackgroundSample,
            ObservationReadPurpose::Request,
            ObservationReadPurpose::Request,
        ]
    );
}

#[test]
fn background_analysis_runs_once_at_each_ten_second_deadline() {
    let outcomes = (0..22).map(|units| Ok(raw_observation(units)));
    let (mut service, clock, purposes) = service(outcomes);
    let ownership = ownership();

    for units in 0..=20 {
        clock.set(units * SECOND_NS, 1_000 + units * 1_000);
        assert_eq!(
            service.sample_tick(&ownership),
            SamplingTickOutcome::Sampled
        );
    }

    let purposes = purposes.lock().unwrap();
    assert_eq!(purposes.len(), 21);
    for (index, purpose) in purposes.iter().enumerate() {
        let expected = if index == 10 || index == 20 {
            ObservationReadPurpose::BackgroundAnalysis
        } else {
            ObservationReadPurpose::BackgroundSample
        };
        assert_eq!(*purpose, expected, "unexpected purpose at tick {index}");
    }
}

#[test]
fn missed_analysis_deadlines_do_not_replay_catch_up_reads() {
    let (mut service, clock, purposes) = service([
        Ok(raw_observation(0)),
        Ok(raw_observation(35)),
        Ok(raw_observation(36)),
        Ok(raw_observation(40)),
    ]);
    let ownership = ownership();

    service.sample_tick(&ownership);
    clock.set(35 * SECOND_NS, 36_000);
    service.sample_tick(&ownership);
    clock.set(36 * SECOND_NS, 37_000);
    service.sample_tick(&ownership);
    clock.set(40 * SECOND_NS, 41_000);
    service.sample_tick(&ownership);

    assert_eq!(
        purposes.lock().unwrap().as_slice(),
        [
            ObservationReadPurpose::BackgroundSample,
            ObservationReadPurpose::BackgroundAnalysis,
            ObservationReadPurpose::BackgroundSample,
            ObservationReadPurpose::BackgroundAnalysis,
        ]
    );
}

#[test]
fn transient_background_error_retains_history() {
    let (mut service, clock, _) = service([
        Ok(raw_observation(0)),
        Ok(raw_observation(1)),
        Err(PortError::Adapter("temporary map read failure".to_owned())),
        Ok(raw_observation(2)),
    ]);
    let active = interface();
    let ownership = ownership();

    service.sample_tick(&ownership);
    clock.set(SECOND_NS, 2_000);
    service.sample_tick(&ownership);
    clock.set(2 * SECOND_NS, 3_000);
    assert_eq!(
        service.sample_tick(&ownership),
        SamplingTickOutcome::Rejected
    );
    let snapshot = service.observe(&active, &active, &ownership).unwrap();

    assert_eq!(snapshot.rate_windows[0].state, RateWindowState::Ready);
    assert_eq!(
        snapshot.sampling.last_error_code.as_deref(),
        Some(OBS_MAP_UNAVAILABLE)
    );
    assert_eq!(snapshot.sampling.consecutive_failures, 1);
}

#[test]
fn identity_background_error_clears_history() {
    let (mut service, clock, _) = service([
        Ok(raw_observation(0)),
        Ok(raw_observation(1)),
        Err(PortError::coded_adapter(
            IDENTITY_ERROR,
            "map identity changed",
        )),
        Ok(raw_observation(2)),
    ]);
    let active = interface();
    let ownership = ownership();

    service.sample_tick(&ownership);
    clock.set(SECOND_NS, 2_000);
    service.sample_tick(&ownership);
    clock.set(2 * SECOND_NS, 3_000);
    assert_eq!(
        service.sample_tick(&ownership),
        SamplingTickOutcome::Rejected
    );
    let snapshot = service.observe(&active, &active, &ownership).unwrap();

    assert!(
        snapshot
            .rate_windows
            .iter()
            .all(|window| window.state == RateWindowState::WarmingUp && window.hooks.is_none())
    );
    assert_eq!(
        snapshot.sampling.last_error_code.as_deref(),
        Some(IDENTITY_ERROR)
    );
}

#[test]
fn current_counter_regression_clears_before_response_rates() {
    let (mut service, clock, _) = service([
        Ok(raw_observation(0)),
        Ok(raw_observation(1)),
        Ok(raw_observation(0)),
        Ok(raw_observation(0)),
    ]);
    let active = interface();
    let ownership = ownership();

    service.sample_tick(&ownership);
    clock.set(SECOND_NS, 2_000);
    service.sample_tick(&ownership);
    clock.set(2 * SECOND_NS, 3_000);

    let error = service.observe(&active, &active, &ownership).unwrap_err();
    assert_eq!(error.code(), OBS_RATE_COUNTER_REGRESSION);

    let snapshot = service.observe(&active, &active, &ownership).unwrap();
    assert!(
        snapshot
            .rate_windows
            .iter()
            .all(|window| window.state == RateWindowState::WarmingUp && window.hooks.is_none())
    );
    assert_eq!(
        snapshot.sampling.last_error_code.as_deref(),
        Some(OBS_RATE_COUNTER_REGRESSION)
    );
    assert_eq!(snapshot.baseline.state, BaselineState::Unavailable);
    assert_eq!(snapshot.detection.state, DetectionState::Unavailable);
}

#[test]
fn request_read_error_never_falls_back_to_cached_cumulative_data() {
    let (mut service, clock, purposes) = service([
        Ok(raw_observation(0)),
        Ok(raw_observation(1)),
        Err(PortError::Adapter("request map read failed".to_owned())),
    ]);
    let active = interface();
    let ownership = ownership();

    service.sample_tick(&ownership);
    clock.set(SECOND_NS, 2_000);
    service.sample_tick(&ownership);

    let error = service.observe(&active, &active, &ownership).unwrap_err();

    assert_eq!(error.code(), OBS_MAP_UNAVAILABLE);
    assert_eq!(
        purposes.lock().unwrap().as_slice(),
        [
            ObservationReadPurpose::BackgroundSample,
            ObservationReadPurpose::BackgroundSample,
            ObservationReadPurpose::Request,
        ]
    );
}

#[test]
fn baseline_advances_only_from_ready_background_endpoints() {
    let outcomes = (0..70)
        .map(|units| Ok(raw_observation(units)))
        .chain([Ok(raw_observation(70)), Ok(raw_observation(70))]);
    let (mut service, clock, purposes) = service(outcomes);
    let active = interface();
    let ownership = ownership();

    for units in 0..70 {
        clock.set(units * SECOND_NS, 1_000 + units * 1_000);
        assert_eq!(
            service.sample_tick(&ownership),
            SamplingTickOutcome::Sampled
        );
    }
    clock.set(70 * SECOND_NS, 71_000);
    let observed = service.observe(&active, &active, &ownership).unwrap();
    let status = service
        .status(None, Some(&active), Some(&ownership))
        .unwrap()
        .remove(0);

    assert_eq!(observed.baseline.state, BaselineState::WithinBaseline);
    assert_eq!(observed.baseline.source_end_unix_ms, Some(70_000));
    assert_eq!(
        observed.baseline.last_successful_evaluation_at_unix_ms,
        Some(70_000)
    );
    assert!(
        observed
            .baseline
            .subjects
            .iter()
            .all(|subject| subject.sample_count == 60)
    );
    assert_eq!(status.baseline.state, BaselineState::WithinBaseline);
    assert!(
        status
            .baseline
            .subject_sample_counts
            .iter()
            .all(|subject| subject.sample_count == 60)
    );
    assert_eq!(
        status.baseline.evaluated_at_unix_ms,
        observed.baseline.evaluated_at_unix_ms
    );
    let purposes = purposes.lock().unwrap();
    assert_eq!(
        purposes
            .iter()
            .filter(|purpose| **purpose == ObservationReadPurpose::BackgroundSample)
            .count(),
        64
    );
    assert_eq!(
        purposes
            .iter()
            .filter(|purpose| **purpose == ObservationReadPurpose::BackgroundAnalysis)
            .count(),
        6
    );
}

#[test]
fn transient_background_failure_retains_baseline_and_degrades_health() {
    let outcomes = (0..70).map(|units| Ok(raw_observation(units))).chain([
        Err(PortError::Adapter(
            "temporary baseline read failure".to_owned(),
        )),
        Ok(raw_observation(70)),
    ]);
    let (mut service, clock, _) = service(outcomes);
    let active = interface();
    let ownership = ownership();

    for units in 0..70 {
        clock.set(units * SECOND_NS, 1_000 + units * 1_000);
        service.sample_tick(&ownership);
    }
    clock.set(70 * SECOND_NS, 71_000);
    assert_eq!(
        service.sample_tick(&ownership),
        SamplingTickOutcome::Rejected
    );
    let observed = service.observe(&active, &active, &ownership).unwrap();

    assert_eq!(observed.health, ObservationHealth::Degraded);
    assert_eq!(observed.baseline.state, BaselineState::Unavailable);
    assert_eq!(
        observed.baseline.last_error_code.as_deref(),
        Some(BASELINE_SOURCE_UNAVAILABLE)
    );
    assert_eq!(observed.baseline.source_end_unix_ms, None);
    assert_eq!(
        observed.baseline.last_successful_evaluation_at_unix_ms,
        Some(70_000)
    );
    assert!(
        observed
            .baseline
            .subjects
            .iter()
            .all(|subject| subject.sample_count == 60
                && subject.packets.current.is_none()
                && subject.bytes.current.is_none())
    );
}

fn service(
    outcomes: impl IntoIterator<Item = Result<RawObservation, PortError>>,
) -> (
    SamplingService<SequencedReader, MutableClock>,
    MutableClock,
    Arc<Mutex<Vec<ObservationReadPurpose>>>,
) {
    let (reader, purposes) = SequencedReader::new(outcomes);
    let clock = MutableClock::at(0, 1_000);
    let clock_control = clock.clone();
    let mut service = SamplingService::new(reader, clock);
    service.start(&ownership()).unwrap();
    (service, clock_control, purposes)
}

struct SequencedReader {
    outcomes: VecDeque<Result<RawObservation, PortError>>,
    purposes: Arc<Mutex<Vec<ObservationReadPurpose>>>,
}

impl SequencedReader {
    fn new(
        outcomes: impl IntoIterator<Item = Result<RawObservation, PortError>>,
    ) -> (Self, Arc<Mutex<Vec<ObservationReadPurpose>>>) {
        let purposes = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                outcomes: outcomes.into_iter().collect(),
                purposes: purposes.clone(),
            },
            purposes,
        )
    }
}

impl ObservationReader for SequencedReader {
    fn read_exact(
        &mut self,
        _ownership: &OwnershipRecord,
        purpose: ObservationReadPurpose,
    ) -> Result<RawObservation, PortError> {
        self.purposes.lock().unwrap().push(purpose);
        self.outcomes
            .pop_front()
            .expect("one sequenced observation outcome per read")
    }
}

#[derive(Clone)]
struct MutableClock {
    state: Arc<Mutex<ClockState>>,
}

struct ClockState {
    monotonic_ns: u64,
    wall_time: SystemTime,
}

impl MutableClock {
    fn at(monotonic_ns: u64, unix_ms: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClockState {
                monotonic_ns,
                wall_time: UNIX_EPOCH
                    .checked_add(Duration::from_millis(unix_ms))
                    .unwrap(),
            })),
        }
    }

    fn set(&self, monotonic_ns: u64, unix_ms: u64) {
        let mut state = self.state.lock().unwrap();
        state.monotonic_ns = monotonic_ns;
        state.wall_time = UNIX_EPOCH
            .checked_add(Duration::from_millis(unix_ms))
            .unwrap();
    }
}

impl Clock for MutableClock {
    fn monotonic_ns(&self) -> u64 {
        self.state.lock().unwrap().monotonic_ns
    }

    fn wall_time(&self) -> SystemTime {
        self.state.lock().unwrap().wall_time
    }
}

fn raw_observation(units: u64) -> RawObservation {
    raw_with_fingerprints(units, RawFingerprints::Available(Vec::new()))
}

fn raw_with_fingerprints(units: u64, fingerprints: RawFingerprints) -> RawObservation {
    RawObservation {
        ifindex: 41,
        generation: 7,
        vlan_visibility: VlanVisibility::VerifiedVisible,
        hooks: [
            hook(HookRole::ExternalXdpIngress, units, 7, 700),
            hook(HookRole::PhysicalTcEgress, units, 11, 1_100),
        ],
        fingerprints,
    }
}

fn fingerprint(direction: u8, first_seen_ns: u64, packets: u64, bytes: u64) -> FingerprintEvidence {
    FingerprintEvidence {
        key: FingerprintKey {
            interface_generation: 7,
            fingerprint: 0x1234,
            ifindex: 41,
            outer_vlan_id: l2_loop_common::NO_VLAN,
            ether_type: 0x0800,
            frame_len: 64,
            direction,
            vlan_depth: 0,
            protocol: 17,
            subtype: 0,
            reserved: [0; 2],
        },
        value: FingerprintValue {
            first_seen_ns,
            last_seen_ns: first_seen_ns + 10,
            packets,
            bytes,
            source_mac: [1; 6],
            destination_mac: [2; 6],
            reserved: [0; 4],
        },
    }
}

fn hook(role: HookRole, units: u64, packet_step: u64, byte_step: u64) -> HookObservation {
    HookObservation {
        role,
        total: counters(100 + packet_step * units, 10_000 + byte_step * units),
        classes: std::array::from_fn(|index| ClassObservation {
            traffic_class: CLASS_ORDER[index],
            counters: counters(
                200 + u64::try_from(index).unwrap() + units,
                20_000 + u64::try_from(index).unwrap() * 100 + units * 100,
            ),
        }),
        parse_errors: counters(300 + units, 30_000 + units * 100),
    }
}

const fn counters(packets: u64, bytes: u64) -> ObservationCounters {
    ObservationCounters { packets, bytes }
}

fn interface() -> InterfaceName {
    InterfaceName::new("l2h0123456789").unwrap()
}

fn ownership() -> OwnershipRecord {
    OwnershipRecord {
        schema_version: OWNERSHIP_SCHEMA_VERSION,
        abi_version: ABI_VERSION,
        generation: 7,
        ifindex: 41,
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
