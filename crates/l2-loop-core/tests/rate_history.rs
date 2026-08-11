use l2_loop_core::{
    ClassObservation, DetailedRateWindow, DomainError, HookObservation, HookRole,
    OBSERVED_CLASS_COUNT, ObservationCounters, RATE_HISTORY_CAPACITY, RATE_STALE_AFTER_NS,
    RATE_WINDOW_COUNT, RateHistory, RateHistoryError, RateIdentity, RateSample, RateWindowState,
    TrafficClass, VlanVisibility,
};

const SECOND_NS: u64 = 1_000_000_000;
const TRANSIENT_ERROR: &str = "OBS_MAP_UNAVAILABLE";
const IDENTITY_ERROR: &str = "OBS_MAP_ID_MISMATCH";
const CLOCK_ERROR: &str = "OBS_RATE_CLOCK_REGRESSION";
const COUNTER_ERROR: &str = "OBS_RATE_COUNTER_REGRESSION";
const CALCULATION_ERROR: &str = "OBS_RATE_CALCULATION_FAILED";
const PAUSED_ERROR: &str = "OBS_RATE_SAMPLER_PAUSED";
const CLASS_ORDER: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

fn identity() -> RateIdentity {
    RateIdentity::new(41, 7).unwrap()
}

fn history() -> RateHistory {
    RateHistory::new(identity(), 0).unwrap()
}

fn sample(monotonic_ns: u64, unix_ms: u64, units: u64) -> RateSample {
    sample_for(identity(), monotonic_ns, unix_ms, units)
}

fn sample_for(identity: RateIdentity, monotonic_ns: u64, unix_ms: u64, units: u64) -> RateSample {
    RateSample::new(
        identity,
        monotonic_ns,
        unix_ms,
        VlanVisibility::VerifiedVisible,
        [
            hook(HookRole::ExternalXdpIngress, units, false),
            hook(HookRole::PhysicalTcEgress, units, true),
        ],
    )
    .unwrap()
}

fn hook(role: HookRole, units: u64, tc: bool) -> HookObservation {
    let (packet_step, byte_step, class_offset, parse_step) = if tc {
        (11, 1_100, 11, 17)
    } else {
        (7, 700, 1, 13)
    };

    HookObservation {
        role,
        total: cumulative(100, 10_000, packet_step, byte_step, units),
        classes: std::array::from_fn(|index| {
            let traffic_class = CLASS_ORDER[index];
            let class_step = class_offset + u64::try_from(index).unwrap();
            ClassObservation {
                traffic_class,
                counters: cumulative(
                    200 + class_step,
                    20_000 + class_step * 100,
                    class_step,
                    class_step * 100,
                    units,
                ),
            }
        }),
        parse_errors: cumulative(300, 30_000, parse_step, parse_step * 100, units),
    }
}

fn cumulative(
    packet_base: u64,
    byte_base: u64,
    packet_step: u64,
    byte_step: u64,
    units: u64,
) -> ObservationCounters {
    ObservationCounters {
        packets: packet_base + packet_step * units,
        bytes: byte_base + byte_step * units,
    }
}

fn detailed(history: &RateHistory, now_monotonic_ns: u64) -> [DetailedRateWindow; 3] {
    history.detailed_windows(now_monotonic_ns).unwrap()
}

fn assert_all_warming(windows: &[DetailedRateWindow; RATE_WINDOW_COUNT]) {
    assert_all_unavailable(windows, RateWindowState::WarmingUp);
}

fn assert_all_unavailable(
    windows: &[DetailedRateWindow; RATE_WINDOW_COUNT],
    expected_state: RateWindowState,
) {
    assert!(windows.iter().all(|window| {
        window.state == expected_state
            && window.elapsed_ns.is_none()
            && window.start_unix_ms.is_none()
            && window.end_unix_ms.is_none()
            && window.hooks.is_none()
    }));
}

#[test]
fn first_sample_keeps_all_windows_warming() {
    let mut history = history();
    history.insert(sample(SECOND_NS, 101_000, 1)).unwrap();

    assert_eq!(history.sample_count(), 1);
    let windows = detailed(&history, SECOND_NS);
    assert_all_warming(&windows);
    assert!(windows.iter().all(|window| window.coverage_ms == 0));
    assert!(
        history
            .status_windows(SECOND_NS)
            .unwrap()
            .iter()
            .all(|window| window.state == RateWindowState::WarmingUp)
    );
}

#[test]
fn exact_endpoints_make_each_fixed_window_ready() {
    let mut history = history();
    for seconds in [0, 50, 59, 60] {
        history
            .insert(sample(
                seconds * SECOND_NS,
                100_000 + seconds * 1_000,
                seconds,
            ))
            .unwrap();
    }

    let detailed = detailed(&history, 60 * SECOND_NS);
    let status = history.status_windows(60 * SECOND_NS).unwrap();
    for index in 0..RATE_WINDOW_COUNT {
        assert_eq!(detailed[index].state, RateWindowState::Ready);
        assert_eq!(status[index].state, RateWindowState::Ready);
        let hooks = detailed[index].hooks.as_ref().unwrap();
        assert_eq!(status[index].xdp_ingress, Some(hooks[0].total));
        assert_eq!(status[index].tc_egress, Some(hooks[1].total));
        assert_eq!(hooks[0].total.packets_per_second, 7);
        assert_eq!(hooks[0].total.bytes_per_second, 700);
    }
    assert_eq!(detailed[0].elapsed_ns, Some(SECOND_NS));
    assert_eq!(detailed[1].elapsed_ns, Some(10 * SECOND_NS));
    assert_eq!(detailed[2].elapsed_ns, Some(60 * SECOND_NS));
}

#[test]
fn selection_uses_the_closest_sample_not_later_than_the_target() {
    let mut history = history();
    for (monotonic_ns, unix_ms, units) in [
        (0, 1_000, 0),
        (2_400_000_000, 3_400, 2),
        (2_600_000_000, 3_600, 3),
        (12_500_000_000, 13_500, 13),
    ] {
        history
            .insert(sample(monotonic_ns, unix_ms, units))
            .unwrap();
    }

    let window = &detailed(&history, 12_500_000_000)[1];
    assert_eq!(window.state, RateWindowState::Ready);
    assert_eq!(window.start_unix_ms, Some(3_400));
    assert_eq!(window.end_unix_ms, Some(13_500));
    assert_eq!(window.elapsed_ns, Some(10_100_000_000));
}

#[test]
fn rates_use_actual_elapsed_nanoseconds_and_round_down() {
    let mut history = history();
    history.insert(sample(0, 10_000, 0)).unwrap();
    history.insert(sample(1_500_000_000, 11_500, 1)).unwrap();

    let window = &detailed(&history, 1_500_000_000)[0];
    let rate = window.hooks.as_ref().unwrap()[0].total;
    assert_eq!(window.elapsed_ns, Some(1_500_000_000));
    assert_eq!(rate.packet_delta, 7);
    assert_eq!(rate.byte_delta, 700);
    assert_eq!(rate.packets_per_second, 4);
    assert_eq!(rate.bytes_per_second, 466);
}

#[test]
fn all_hook_class_and_parse_error_deltas_are_calculated() {
    let mut history = history();
    history.insert(sample(0, 100_000, 0)).unwrap();
    history.insert(sample(SECOND_NS, 101_000, 1)).unwrap();

    let windows = detailed(&history, SECOND_NS);
    let hooks = windows[0].hooks.as_ref().unwrap();
    assert_eq!(hooks[0].total.packet_delta, 7);
    assert_eq!(hooks[0].total.byte_delta, 700);
    assert_eq!(hooks[1].total.packet_delta, 11);
    assert_eq!(hooks[1].total.byte_delta, 1_100);

    for (index, class) in hooks[0].classes.iter().enumerate() {
        let expected = u64::try_from(index).unwrap() + 1;
        assert_eq!(class.traffic_class, CLASS_ORDER[index]);
        assert_eq!(class.counters.packet_delta, expected);
        assert_eq!(class.counters.byte_delta, expected * 100);
        assert_eq!(class.counters.packets_per_second, expected);
        assert_eq!(class.counters.bytes_per_second, expected * 100);
    }
    for (index, class) in hooks[1].classes.iter().enumerate() {
        let expected = u64::try_from(index).unwrap() + 11;
        assert_eq!(class.traffic_class, CLASS_ORDER[index]);
        assert_eq!(class.counters.packet_delta, expected);
        assert_eq!(class.counters.byte_delta, expected * 100);
    }
    assert_eq!(hooks[0].parse_errors.packet_delta, 13);
    assert_eq!(hooks[0].parse_errors.byte_delta, 1_300);
    assert_eq!(hooks[1].parse_errors.packet_delta, 17);
    assert_eq!(hooks[1].parse_errors.byte_delta, 1_700);
}

#[test]
fn missing_intermediate_samples_need_no_interpolation() {
    let mut history = history();
    history.insert(sample(0, 100_000, 0)).unwrap();
    history.insert(sample(60 * SECOND_NS, 160_000, 60)).unwrap();

    let windows = detailed(&history, 60 * SECOND_NS);
    assert!(
        windows
            .iter()
            .all(|window| window.state == RateWindowState::Ready)
    );
    for window in windows {
        let total = window.hooks.unwrap()[0].total;
        assert_eq!(total.packets_per_second, 7);
        assert_eq!(total.bytes_per_second, 700);
        assert_eq!(window.elapsed_ns, Some(60 * SECOND_NS));
    }
}

#[test]
fn sixty_fifth_sample_evicts_exactly_the_oldest() {
    let mut history = history();
    for seconds in 0..=64 {
        history
            .insert(sample(
                seconds * SECOND_NS,
                100_000 + seconds * 1_000,
                seconds,
            ))
            .unwrap();
    }

    assert_eq!(history.sample_count(), RATE_HISTORY_CAPACITY);
    let window = &detailed(&history, 64 * SECOND_NS)[2];
    assert_eq!(window.state, RateWindowState::Ready);
    assert_eq!(window.start_unix_ms, Some(104_000));
    assert_eq!(window.end_unix_ms, Some(164_000));
    assert_eq!(window.elapsed_ns, Some(60 * SECOND_NS));
}

#[test]
fn full_ring_without_sixty_seconds_stays_warming() {
    let mut history = history();
    for index in 0..64 {
        let monotonic_ns = index * 500_000_000;
        history
            .insert(sample(monotonic_ns, 100_000 + index * 500, index))
            .unwrap();
    }

    assert_eq!(history.sample_count(), RATE_HISTORY_CAPACITY);
    let windows = detailed(&history, 31_500_000_000);
    assert_eq!(windows[0].state, RateWindowState::Ready);
    assert_eq!(windows[1].state, RateWindowState::Ready);
    assert_eq!(windows[2].state, RateWindowState::WarmingUp);
    assert_eq!(windows[2].coverage_ms, 31_500);
    assert!(windows[2].hooks.is_none());
}

#[test]
fn wall_clock_changes_do_not_change_rates() {
    let mut history = history();
    history.insert(sample(0, 20_000, 0)).unwrap();
    history.insert(sample(SECOND_NS, 10_000, 1)).unwrap();

    let window = &detailed(&history, SECOND_NS)[0];
    let total = window.hooks.as_ref().unwrap()[0].total;
    assert_eq!(window.start_unix_ms, Some(20_000));
    assert_eq!(window.end_unix_ms, Some(10_000));
    assert_eq!(total.packets_per_second, 7);
    assert_eq!(total.bytes_per_second, 700);
}

#[test]
fn identity_or_counter_regression_clears_before_output() {
    assert!(matches!(
        RateIdentity::new(0, 7),
        Err(DomainError::InvalidObservation(_)),
    ));
    assert!(matches!(
        RateIdentity::new(41, 0),
        Err(DomainError::InvalidObservation(_)),
    ));

    let mut identity_history = history();
    identity_history.insert(sample(0, 100_000, 0)).unwrap();
    let foreign = RateIdentity::new(42, 8).unwrap();
    assert_eq!(
        identity_history
            .insert(sample_for(foreign, SECOND_NS, 101_000, 1))
            .unwrap_err(),
        RateHistoryError::IdentityMismatch,
    );
    assert_eq!(identity_history.sample_count(), 0);
    assert_all_warming(&detailed(&identity_history, SECOND_NS));

    let mut insert_history = history();
    insert_history
        .insert(sample(10 * SECOND_NS, 110_000, 10))
        .unwrap();
    assert_eq!(
        insert_history
            .insert(sample(11 * SECOND_NS, 111_000, 9))
            .unwrap_err(),
        RateHistoryError::CounterRegression,
    );
    assert_eq!(insert_history.sample_count(), 0);

    let mut request_history = history();
    request_history
        .insert(sample(10 * SECOND_NS, 110_000, 10))
        .unwrap();
    assert_eq!(
        request_history
            .validate_current(&sample(11 * SECOND_NS, 111_000, 9))
            .unwrap_err(),
        RateHistoryError::CounterRegression,
    );
    assert_eq!(request_history.sample_count(), 0);
    assert_all_warming(&detailed(&request_history, 11 * SECOND_NS));
}

#[test]
fn request_validation_never_inserts_a_sample() {
    let mut history = history();
    history.insert(sample(0, 100_000, 0)).unwrap();
    history.insert(sample(SECOND_NS, 101_000, 1)).unwrap();
    let before = history.sample_count();

    history
        .validate_current(&sample(2 * SECOND_NS, 102_000, 2))
        .unwrap();

    assert_eq!(history.sample_count(), before);
    let window = &detailed(&history, 2 * SECOND_NS)[0];
    assert_eq!(window.end_unix_ms, Some(101_000));
    assert_eq!(window.elapsed_ns, Some(SECOND_NS));
    assert_eq!(window.hooks.as_ref().unwrap()[0].total.packet_delta, 7);
}

#[test]
fn transient_failure_retains_samples_and_saturates_failure_count() {
    let mut history = history();
    history.record_success(sample(0, 100_000, 0)).unwrap();
    history
        .record_success(sample(SECOND_NS, 101_000, 1))
        .unwrap();
    let sample_count = history.sample_count();

    history.record_transient_failure(TRANSIENT_ERROR);
    history.record_transient_failure(TRANSIENT_ERROR);

    assert_eq!(history.sample_count(), sample_count);
    assert_eq!(
        detailed(&history, SECOND_NS)[0].state,
        RateWindowState::Ready
    );
    assert_eq!(
        history.sampling_status(),
        l2_loop_core::SamplingStatus {
            latest_success_at_unix_ms: Some(101_000),
            last_error_code: Some(TRANSIENT_ERROR.to_owned()),
            consecutive_failures: 2,
            sampling_paused: false,
        }
    );
}

#[test]
fn identity_failure_clears_history_immediately() {
    let mut history = history();
    history.record_success(sample(0, 100_000, 0)).unwrap();
    history
        .record_success(sample(SECOND_NS, 101_000, 1))
        .unwrap();

    history.record_identity_failure(2 * SECOND_NS, IDENTITY_ERROR);

    assert_eq!(history.sample_count(), 0);
    assert_eq!(
        history.sampling_status().last_error_code.as_deref(),
        Some(IDENTITY_ERROR)
    );
    assert_all_warming(&detailed(&history, 2 * SECOND_NS));
}

#[test]
fn clock_counter_and_calculation_failures_start_a_new_epoch() {
    for error_code in [CLOCK_ERROR, COUNTER_ERROR, CALCULATION_ERROR] {
        let mut history = history();
        history.record_success(sample(0, 100_000, 0)).unwrap();
        history
            .record_success(sample(SECOND_NS, 101_000, 1))
            .unwrap();
        let new_epoch = 10 * SECOND_NS;

        history.record_rate_failure(new_epoch, error_code);

        assert_eq!(history.sample_count(), 0);
        assert_eq!(
            history.sampling_status().last_error_code.as_deref(),
            Some(error_code)
        );
        assert_all_warming(&detailed(&history, new_epoch));
        assert_all_unavailable(
            &detailed(&history, new_epoch + RATE_STALE_AFTER_NS + 1),
            RateWindowState::Stale,
        );
    }
}

#[test]
fn successful_sample_clears_transient_diagnostics() {
    let mut history = history();
    history.record_success(sample(0, 100_000, 0)).unwrap();
    history.record_transient_failure(TRANSIENT_ERROR);

    history
        .record_success(sample(SECOND_NS, 101_000, 1))
        .unwrap();

    assert_eq!(
        history.sampling_status(),
        l2_loop_core::SamplingStatus {
            latest_success_at_unix_ms: Some(101_000),
            last_error_code: None,
            consecutive_failures: 0,
            sampling_paused: false,
        }
    );
}

#[test]
fn age_equal_to_three_seconds_is_fresh() {
    let mut history = history();
    history.record_success(sample(0, 100_000, 0)).unwrap();
    history
        .record_success(sample(SECOND_NS, 101_000, 1))
        .unwrap();

    let windows = detailed(&history, SECOND_NS + RATE_STALE_AFTER_NS);

    assert_eq!(windows[0].state, RateWindowState::Ready);
    assert!(windows[0].hooks.is_some());
}

#[test]
fn age_greater_than_three_seconds_is_stale_and_has_no_rates() {
    let mut history = history();
    history.record_success(sample(0, 100_000, 0)).unwrap();
    history
        .record_success(sample(SECOND_NS, 101_000, 1))
        .unwrap();
    let now = SECOND_NS + RATE_STALE_AFTER_NS + 1;

    assert_all_unavailable(&detailed(&history, now), RateWindowState::Stale);
    assert!(history.status_windows(now).unwrap().iter().all(|window| {
        window.state == RateWindowState::Stale
            && window.elapsed_ns.is_none()
            && window.start_unix_ms.is_none()
            && window.end_unix_ms.is_none()
            && window.xdp_ingress.is_none()
            && window.tc_egress.is_none()
    }));
}

#[test]
fn empty_epoch_warms_for_three_seconds_then_becomes_stale() {
    let epoch = 10 * SECOND_NS;
    let history = RateHistory::new(identity(), epoch).unwrap();

    assert_all_warming(&detailed(&history, epoch + RATE_STALE_AFTER_NS));
    assert_all_unavailable(
        &detailed(&history, epoch + RATE_STALE_AFTER_NS + 1),
        RateWindowState::Stale,
    );
}

#[test]
fn pause_clears_history_and_is_immediately_stale() {
    let mut history = history();
    history.record_success(sample(0, 100_000, 0)).unwrap();
    history
        .record_success(sample(SECOND_NS, 101_000, 1))
        .unwrap();

    history.pause(2 * SECOND_NS, PAUSED_ERROR);

    assert_eq!(history.sample_count(), 0);
    assert_eq!(
        history.sampling_status(),
        l2_loop_core::SamplingStatus {
            latest_success_at_unix_ms: Some(101_000),
            last_error_code: Some(PAUSED_ERROR.to_owned()),
            consecutive_failures: 0,
            sampling_paused: true,
        }
    );
    assert_all_unavailable(&detailed(&history, 2 * SECOND_NS), RateWindowState::Stale);

    history
        .record_success(sample(3 * SECOND_NS, 103_000, 3))
        .unwrap();
    assert!(history.sampling_status().sampling_paused);
    assert_all_unavailable(&detailed(&history, 3 * SECOND_NS), RateWindowState::Stale);
}
