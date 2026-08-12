use l2_loop_core::{
    BASELINE_MINIMUM_SAMPLES, BASELINE_SUBJECT_COUNT, BaselineEngine, BaselineError, BaselineState,
    ClassRate, DetailedRateWindow, HookRate, HookRole, OBSERVED_CLASS_COUNT, RateCounters,
    RateIdentity, RateWindowState, TrafficClass,
};

const CLASSES: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

#[test]
fn engine_learns_exact_fixed_subjects_and_becomes_ready_at_sixty() {
    let mut engine = engine(11);
    for index in 0..BASELINE_MINIMUM_SAMPLES {
        let report = engine
            .evaluate_ready_window(&window(10_000 + index as u64 * 1_000, 100, 100_000), 20_000)
            .unwrap();
        assert_eq!(report.subjects.len(), BASELINE_SUBJECT_COUNT);
    }

    let report = engine.cached_report();
    assert_eq!(report.state, BaselineState::WithinBaseline);
    assert_eq!(report.learning_subject_count, 0);
    assert_eq!(report.elevated_metric_count, 0);
    assert!(
        report
            .subjects
            .iter()
            .all(|subject| subject.sample_count == 60)
    );
    assert!(report.validate().is_ok());
}

#[test]
fn elevated_pair_is_rejected_atomically_while_siblings_continue() {
    let mut engine = ready_engine();
    let elevated = engine
        .evaluate_ready_window(&window(70_000, 401, 100_000), 70_001)
        .unwrap();

    assert_eq!(elevated.state, BaselineState::Elevated);
    assert_eq!(elevated.subjects[0].state, BaselineState::Elevated);
    assert_eq!(elevated.subjects[0].packets.elevated, Some(true));
    assert_eq!(elevated.subjects[0].bytes.elevated, Some(false));
    assert_eq!(elevated.subjects[0].sample_count, 60);
    assert_eq!(elevated.subjects[1].sample_count, 61);
    assert_eq!(elevated.subjects[8].sample_count, 61);
    assert_eq!(elevated.elevated_metric_count, 1);

    let recovered = engine
        .evaluate_ready_window(&window(71_000, 100, 100_000), 71_001)
        .unwrap();
    assert_eq!(recovered.state, BaselineState::WithinBaseline);
    assert_eq!(recovered.subjects[0].sample_count, 61);
}

#[test]
fn byte_elevation_rejects_the_same_subject_packet_pair() {
    let mut engine = ready_engine();
    let report = engine
        .evaluate_ready_window(&window(70_000, 100, 400_001), 70_001)
        .unwrap();

    assert_eq!(report.subjects[0].packets.elevated, Some(false));
    assert_eq!(report.subjects[0].bytes.elevated, Some(true));
    assert_eq!(report.subjects[0].sample_count, 60);
    assert_eq!(report.subjects[1].sample_count, 61);
}

#[test]
fn duplicate_or_regressed_endpoint_is_an_integrity_failure() {
    let mut engine = ready_engine();
    assert_eq!(
        engine.evaluate_ready_window(&window(69_000, 100, 100_000), 70_001),
        Err(BaselineError::SourceEndpointNotAdvancing)
    );
    let cleared = engine.cached_report();
    assert_eq!(cleared.state, BaselineState::Unavailable);
    assert!(
        cleared
            .subjects
            .iter()
            .all(|subject| subject.sample_count == 0)
    );
    assert_eq!(cleared.source_end_unix_ms, None);
}

#[test]
fn transient_unavailable_retains_history_and_first_recovery_compares_before_accept() {
    let mut engine = ready_engine();
    let unavailable = engine.unavailable(70_001, "baseline_read_failed");
    assert_eq!(unavailable.state, BaselineState::Unavailable);
    assert_eq!(
        unavailable.last_error_code.as_deref(),
        Some("baseline_read_failed")
    );
    assert_eq!(
        unavailable.last_successful_evaluation_at_unix_ms,
        Some(69_001)
    );
    assert!(
        unavailable
            .subjects
            .iter()
            .all(|subject| subject.sample_count == 60)
    );
    assert!(
        unavailable
            .subjects
            .iter()
            .all(|subject| subject.packets.current.is_none() && subject.bytes.current.is_none())
    );

    let recovered = engine
        .evaluate_ready_window(&window(70_000, 401, 100_000), 70_002)
        .unwrap();
    assert_eq!(recovered.state, BaselineState::Elevated);
    assert_eq!(recovered.subjects[0].sample_count, 60);
}

#[test]
fn integrity_clear_restarts_learning_for_the_new_generation() {
    let mut engine = ready_engine();
    let new_identity = RateIdentity::new(7, 12).unwrap();
    let cleared = engine.clear_integrity(new_identity, 70_000, "baseline_identity_changed");
    assert_eq!(engine.identity(), new_identity);
    assert_eq!(cleared.state, BaselineState::Unavailable);
    assert!(
        cleared
            .subjects
            .iter()
            .all(|subject| subject.sample_count == 0)
    );

    let learning = engine
        .evaluate_ready_window(&window(71_000, 100, 100_000), 71_001)
        .unwrap();
    assert_eq!(learning.state, BaselineState::Learning);
    assert!(
        learning
            .subjects
            .iter()
            .all(|subject| subject.sample_count == 1)
    );
}

fn ready_engine() -> BaselineEngine {
    let mut engine = engine(11);
    for index in 0..BASELINE_MINIMUM_SAMPLES {
        engine
            .evaluate_ready_window(
                &window(10_000 + index as u64 * 1_000, 100, 100_000),
                10_001 + index as u64 * 1_000,
            )
            .unwrap();
    }
    engine
}

fn engine(generation: u64) -> BaselineEngine {
    BaselineEngine::new(RateIdentity::new(7, generation).unwrap(), 1_000)
}

fn window(end_unix_ms: u64, xdp_total_pps: u64, xdp_total_bps: u64) -> DetailedRateWindow {
    DetailedRateWindow {
        window_ms: 10_000,
        state: RateWindowState::Ready,
        coverage_ms: 10_000,
        elapsed_ns: Some(10_000_000_000),
        start_unix_ms: Some(end_unix_ms - 10_000),
        end_unix_ms: Some(end_unix_ms),
        hooks: Some([
            hook(HookRole::ExternalXdpIngress, xdp_total_pps, xdp_total_bps),
            hook(HookRole::PhysicalTcEgress, 100, 100_000),
        ]),
    }
}

fn hook(role: HookRole, total_pps: u64, total_bps: u64) -> HookRate {
    HookRate {
        role,
        total: counters(total_pps, total_bps),
        classes: CLASSES.map(|traffic_class| ClassRate {
            traffic_class,
            counters: counters(100, 100_000),
        }),
        parse_errors: counters(100, 100_000),
    }
}

const fn counters(packets_per_second: u64, bytes_per_second: u64) -> RateCounters {
    RateCounters {
        packet_delta: packets_per_second * 10,
        byte_delta: bytes_per_second * 10,
        packets_per_second,
        bytes_per_second,
    }
}
