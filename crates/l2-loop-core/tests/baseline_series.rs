use l2_loop_core::{
    BASELINE_BYTE_NOISE_FLOOR_BPS, BASELINE_CAPACITY, BASELINE_MINIMUM_SAMPLES,
    BASELINE_PACKET_NOISE_FLOOR_PPS, BaselineSeries, BaselineState, evaluate_metric,
    median_absolute_deviation, upper_median,
};

#[test]
fn upper_median_and_mad_are_deterministic_for_odd_and_even_sets() {
    assert_eq!(upper_median(&[9, 1, 5]), Some(5));
    assert_eq!(upper_median(&[9, 1, 5, 3]), Some(5));
    assert_eq!(upper_median(&[]), None);
    assert_eq!(median_absolute_deviation(&[1, 3, 5, 7]), Some(2));
}

#[test]
fn fixed_threshold_is_strict_and_uses_noise_floors() {
    let packet_at_floor = evaluate_metric(10, 0, 0, BASELINE_PACKET_NOISE_FLOOR_PPS);
    let packet_above_floor = evaluate_metric(11, 0, 0, BASELINE_PACKET_NOISE_FLOOR_PPS);
    let bytes_at_floor = evaluate_metric(16_384, 0, 0, BASELINE_BYTE_NOISE_FLOOR_BPS);
    let bytes_above_floor = evaluate_metric(16_385, 0, 0, BASELINE_BYTE_NOISE_FLOOR_BPS);

    assert_eq!(packet_at_floor.threshold, Some(10));
    assert_eq!(packet_at_floor.elevated, Some(false));
    assert_eq!(packet_above_floor.elevated, Some(true));
    assert_eq!(bytes_at_floor.elevated, Some(false));
    assert_eq!(bytes_above_floor.elevated, Some(true));
    assert_eq!(packet_at_floor.ratio_milli, None);

    assert_eq!(evaluate_metric(400, 100, 0, 10).elevated, Some(false));
    assert_eq!(evaluate_metric(401, 100, 0, 10).elevated, Some(true));
    assert_eq!(evaluate_metric(71, 10, 10, 10).elevated, Some(true));
}

#[test]
fn threshold_and_ratio_use_wide_intermediates_and_clamp() {
    let report = evaluate_metric(u64::MAX, u64::MAX, u64::MAX, 10);

    assert_eq!(report.threshold, Some(u64::MAX));
    assert_eq!(report.ratio_milli, Some(1_000));
    assert_eq!(report.elevated, Some(false));
    assert_eq!(evaluate_metric(450, 100, 0, 10).ratio_milli, Some(4_500));
}

#[test]
fn series_becomes_ready_at_sixty_atomic_sample_pairs() {
    let mut series = BaselineSeries::new();
    for accepted in 0..(BASELINE_MINIMUM_SAMPLES - 1) {
        series.accept(100, 1_000, accepted as u64);
    }

    let learning = series.evaluate(100, 1_000);
    assert_eq!(learning.state, BaselineState::Learning);
    assert_eq!(learning.packets.current, Some(100));
    assert_eq!(learning.packets.median, None);
    assert_eq!(series.sample_count(), BASELINE_MINIMUM_SAMPLES - 1);

    series.accept(100, 1_000, BASELINE_MINIMUM_SAMPLES as u64);
    let ready = series.evaluate(100, 1_000);
    assert_eq!(ready.state, BaselineState::WithinBaseline);
    assert_eq!(ready.packets.median, Some(100));
    assert_eq!(ready.bytes.median, Some(1_000));
}

#[test]
fn series_evicts_only_the_oldest_pair_at_fixed_capacity() {
    let mut series = BaselineSeries::new();
    for value in 0..BASELINE_CAPACITY {
        series.accept(value as u64, value as u64 * 10, value as u64);
    }
    assert_eq!(series.sample_count(), BASELINE_CAPACITY);
    assert_eq!(series.evaluate(150, 1_500).packets.median, Some(150));

    series.accept(300, 3_000, 300);
    assert_eq!(series.sample_count(), BASELINE_CAPACITY);
    assert_eq!(series.evaluate(151, 1_510).packets.median, Some(151));
    assert_eq!(series.latest_accepted_at_unix_ms(), Some(300));
}

#[test]
fn packet_and_byte_deviation_are_reported_independently() {
    let mut series = BaselineSeries::new();
    for accepted in 0..BASELINE_MINIMUM_SAMPLES {
        series.accept(100, 100_000, accepted as u64);
    }

    let packet_only = series.evaluate(401, 100_000);
    assert_eq!(packet_only.state, BaselineState::Elevated);
    assert_eq!(packet_only.packets.elevated, Some(true));
    assert_eq!(packet_only.bytes.elevated, Some(false));

    let byte_only = series.evaluate(100, 400_001);
    assert_eq!(byte_only.state, BaselineState::Elevated);
    assert_eq!(byte_only.packets.elevated, Some(false));
    assert_eq!(byte_only.bytes.elevated, Some(true));
}
