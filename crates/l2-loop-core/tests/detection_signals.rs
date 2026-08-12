use l2_loop_core::{
    BASELINE_BYTE_NOISE_FLOOR_BPS, BASELINE_CAPACITY, BASELINE_MINIMUM_SAMPLES,
    BASELINE_PACKET_NOISE_FLOOR_PPS, BASELINE_SOURCE_WINDOW_MS, BaselineMetricReport,
    BaselineReport, BaselineState, BaselineSubject, BaselineSubjectReport, ClassRate,
    DetailedRateWindow, DetectionSignals, FingerprintCounters, FingerprintWindowReport,
    FingerprintWindowState, HookRate, HookRole, OBSERVED_CLASS_COUNT, RateCounters, RateIdentity,
    RateWindowState, StormCandidate, TrafficClass,
};

const END_MS: u64 = 80_000;
const CLASSES: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

#[derive(Clone, Copy)]
struct HookFixture {
    bum_pps: u64,
    bum_bps: u64,
    excluded_pps: u64,
    excluded_bps: u64,
}

impl HookFixture {
    const fn new(bum_pps: u64, bum_bps: u64) -> Self {
        Self {
            bum_pps,
            bum_bps,
            excluded_pps: 0,
            excluded_bps: 0,
        }
    }
}

#[test]
fn bum_membership_excludes_link_local_and_unicast() {
    let ten_second = HookFixture {
        bum_pps: 1_000,
        bum_bps: 1_048_576,
        excluded_pps: 9_000_000,
        excluded_bps: 9_000_000_000,
    };
    let signals = derive(
        HookFixture::new(0, 0),
        HookFixture::new(0, 0),
        ten_second,
        HookFixture::new(0, 0),
        baseline(true, false),
        FingerprintWindowReport::warming(),
        END_MS,
    )
    .unwrap();

    assert_eq!(signals.ingress.bum_packets_per_second, Some(1_000));
    assert_eq!(signals.ingress.bum_bytes_per_second, Some(1_048_576));
    assert_eq!(signals.ingress.bum_ratio_milli, Some(0));
    assert_eq!(signals.ingress.adaptive_candidate, Some(true));
    assert_eq!(signals.candidate, StormCandidate::Ingress);
}

#[test]
fn adaptive_packet_and_byte_floors_are_inclusive() {
    for (pps, bps, expected) in [
        (999, 0, false),
        (1_000, 0, true),
        (1_001, 0, true),
        (0, 1_048_575, false),
        (0, 1_048_576, true),
        (0, 1_048_577, true),
    ] {
        let signals = derive(
            HookFixture::new(0, 0),
            HookFixture::new(0, 0),
            HookFixture::new(pps, bps),
            HookFixture::new(0, 0),
            baseline(true, false),
            FingerprintWindowReport::warming(),
            END_MS,
        )
        .unwrap();
        assert_eq!(signals.ingress.adaptive_candidate, Some(expected));
    }
}

#[test]
fn absolute_packet_and_byte_thresholds_are_inclusive_during_learning() {
    for (pps, bps, expected) in [
        (99_999, 0, false),
        (100_000, 0, true),
        (100_001, 0, true),
        (0, 104_857_599, false),
        (0, 104_857_600, true),
        (0, 104_857_601, true),
    ] {
        let signals = derive(
            HookFixture::new(pps, bps),
            HookFixture::new(0, 0),
            HookFixture::new(0, 0),
            HookFixture::new(0, 0),
            BaselineReport::learning(RateIdentity::new(7, 11).unwrap(), END_MS),
            FingerprintWindowReport::warming(),
            END_MS,
        )
        .unwrap();
        assert_eq!(signals.ingress.adaptive_candidate, None);
        assert_eq!(signals.ingress.absolute_candidate, Some(expected));
        assert_eq!(
            signals.candidate,
            if expected {
                StormCandidate::Ingress
            } else {
                StormCandidate::None
            }
        );
    }
}

#[test]
fn hook_candidates_map_to_the_fixed_directional_order() {
    for (ingress, egress, expected) in [
        (false, false, StormCandidate::None),
        (true, false, StormCandidate::Ingress),
        (false, true, StormCandidate::Egress),
        (true, true, StormCandidate::Bidirectional),
    ] {
        let signals = derive(
            HookFixture::new(if ingress { 100_000 } else { 0 }, 0),
            HookFixture::new(if egress { 100_000 } else { 0 }, 0),
            HookFixture::new(0, 0),
            HookFixture::new(0, 0),
            BaselineReport::learning(RateIdentity::new(7, 11).unwrap(), END_MS),
            FingerprintWindowReport::warming(),
            END_MS,
        )
        .unwrap();
        assert_eq!(signals.candidate, expected);
    }
}

#[test]
fn suspected_requires_every_relationship_condition_and_refuses_egress_only() {
    let base = ready_fingerprint();
    let mut cases = Vec::new();

    let mut insufficient_samples = base.clone();
    insufficient_samples.ingress.packets = 15;
    cases.push(insufficient_samples);

    let mut no_repeat = base.clone();
    no_repeat.repeated_relation_count = 0;
    cases.push(no_repeat);

    let mut no_dominance = base.clone();
    no_dominance.dominant_ingress_packet_ratio_milli = Some(799);
    cases.push(no_dominance);

    for fingerprint in cases {
        let signals = relationship_signals(
            HookFixture::new(100_000, 0),
            HookFixture::new(0, 0),
            HookFixture::new(800, 0),
            fingerprint,
            END_MS,
        );
        assert_eq!(signals.loop_suspected, Some(false));
    }

    let low_bum_share = relationship_signals(
        HookFixture::new(100_000, 0),
        HookFixture::new(0, 0),
        HookFixture::new(799, 0),
        base.clone(),
        END_MS,
    );
    assert_eq!(low_bum_share.loop_suspected, Some(false));

    let ingress = relationship_signals(
        HookFixture::new(100_000, 0),
        HookFixture::new(0, 0),
        HookFixture::new(800, 0),
        base.clone(),
        END_MS,
    );
    assert_eq!(ingress.loop_suspected, Some(true));

    let egress_only = relationship_signals(
        HookFixture::new(0, 0),
        HookFixture::new(100_000, 0),
        HookFixture::new(800, 0),
        base,
        END_MS,
    );
    assert_eq!(egress_only.candidate, StormCandidate::Egress);
    assert_eq!(egress_only.loop_suspected, Some(false));
}

#[test]
fn high_confidence_requires_egress_first_and_four_x_directional_amplification() {
    let mut fingerprint = ready_fingerprint();
    fingerprint.egress_first_correlated_relation_count = 1;

    fingerprint.maximum_ingress_to_egress_packet_ratio_milli = Some(3_999);
    let below = relationship_signals(
        HookFixture::new(100_000, 0),
        HookFixture::new(0, 0),
        HookFixture::new(800, 0),
        fingerprint.clone(),
        END_MS,
    );
    assert_eq!(below.loop_high_confidence, Some(false));

    fingerprint.maximum_ingress_to_egress_packet_ratio_milli = Some(4_000);
    let equal = relationship_signals(
        HookFixture::new(100_000, 0),
        HookFixture::new(0, 0),
        HookFixture::new(800, 0),
        fingerprint,
        END_MS,
    );
    assert_eq!(equal.loop_suspected, Some(true));
    assert_eq!(equal.loop_high_confidence, Some(true));
}

#[test]
fn stale_or_unavailable_fingerprint_evidence_cannot_upgrade_a_storm() {
    let stale = relationship_signals(
        HookFixture::new(100_000, 0),
        HookFixture::new(0, 0),
        HookFixture::new(800, 0),
        ready_fingerprint(),
        END_MS + 15_001,
    );
    assert_eq!(stale.loop_suspected, None);
    assert_eq!(stale.loop_high_confidence, None);

    let unavailable = relationship_signals(
        HookFixture::new(100_000, 0),
        HookFixture::new(0, 0),
        HookFixture::new(800, 0),
        FingerprintWindowReport::unavailable("FINGERPRINT_READ_FAILED").unwrap(),
        END_MS,
    );
    assert_eq!(unavailable.loop_suspected, None);
}

#[test]
fn mismatched_source_endpoints_and_impossible_totals_are_rejected() {
    let mut inconsistent_baseline = baseline(true, false);
    inconsistent_baseline.source_end_unix_ms = Some(END_MS - 1);
    assert!(
        DetectionSignals::derive(
            &windows(
                HookFixture::new(0, 0),
                HookFixture::new(0, 0),
                HookFixture::new(1_000, 0),
                HookFixture::new(0, 0),
            ),
            &inconsistent_baseline,
            &FingerprintWindowReport::warming(),
            END_MS,
        )
        .is_err()
    );

    let mut overflowing_windows = windows(
        HookFixture::new(0, 0),
        HookFixture::new(0, 0),
        HookFixture::new(u64::MAX, 0),
        HookFixture::new(0, 0),
    );
    overflowing_windows[1].hooks.as_mut().unwrap()[0].classes[1].counters = counters(1, 0);
    assert!(
        DetectionSignals::derive(
            &overflowing_windows,
            &baseline(true, false),
            &FingerprintWindowReport::warming(),
            END_MS,
        )
        .is_err()
    );
}

fn relationship_signals(
    ingress_one_second: HookFixture,
    egress_one_second: HookFixture,
    ingress_ten_second: HookFixture,
    fingerprint: FingerprintWindowReport,
    evaluated_at_unix_ms: u64,
) -> DetectionSignals {
    derive(
        ingress_one_second,
        egress_one_second,
        ingress_ten_second,
        HookFixture::new(0, 0),
        baseline(false, false),
        fingerprint,
        evaluated_at_unix_ms,
    )
    .unwrap()
}

fn derive(
    ingress_one_second: HookFixture,
    egress_one_second: HookFixture,
    ingress_ten_second: HookFixture,
    egress_ten_second: HookFixture,
    baseline: BaselineReport,
    fingerprint: FingerprintWindowReport,
    evaluated_at_unix_ms: u64,
) -> Result<DetectionSignals, l2_loop_core::DetectionError> {
    DetectionSignals::derive(
        &windows(
            ingress_one_second,
            egress_one_second,
            ingress_ten_second,
            egress_ten_second,
        ),
        &baseline,
        &fingerprint,
        evaluated_at_unix_ms,
    )
}

fn windows(
    ingress_one_second: HookFixture,
    egress_one_second: HookFixture,
    ingress_ten_second: HookFixture,
    egress_ten_second: HookFixture,
) -> [DetailedRateWindow; 3] {
    [
        ready_window(1_000, ingress_one_second, egress_one_second),
        ready_window(10_000, ingress_ten_second, egress_ten_second),
        DetailedRateWindow::warming(60_000).unwrap(),
    ]
}

fn ready_window(window_ms: u64, ingress: HookFixture, egress: HookFixture) -> DetailedRateWindow {
    DetailedRateWindow {
        window_ms,
        state: RateWindowState::Ready,
        coverage_ms: window_ms,
        elapsed_ns: Some(window_ms * 1_000_000),
        start_unix_ms: Some(END_MS - window_ms),
        end_unix_ms: Some(END_MS),
        hooks: Some([
            hook(HookRole::ExternalXdpIngress, ingress),
            hook(HookRole::PhysicalTcEgress, egress),
        ]),
    }
}

fn hook(role: HookRole, fixture: HookFixture) -> HookRate {
    let mut classes = CLASSES.map(|traffic_class| ClassRate {
        traffic_class,
        counters: counters(0, 0),
    });
    classes[0].counters = counters(fixture.bum_pps, fixture.bum_bps);
    classes[4].counters = counters(fixture.excluded_pps, fixture.excluded_bps);
    HookRate {
        role,
        total: counters(
            fixture.bum_pps.saturating_add(fixture.excluded_pps),
            fixture.bum_bps.saturating_add(fixture.excluded_bps),
        ),
        classes,
        parse_errors: counters(0, 0),
    }
}

const fn counters(packets_per_second: u64, bytes_per_second: u64) -> RateCounters {
    RateCounters {
        packet_delta: 0,
        byte_delta: 0,
        packets_per_second,
        bytes_per_second,
    }
}

fn baseline(ingress_elevated: bool, egress_elevated: bool) -> BaselineReport {
    let subjects = std::array::from_fn(|index| {
        let hook_index = index / 8;
        let subject_index = index % 8;
        let hook = if hook_index == 0 {
            HookRole::ExternalXdpIngress
        } else {
            HookRole::PhysicalTcEgress
        };
        let subject = match subject_index {
            0 => BaselineSubject::Total,
            1..=6 => BaselineSubject::TrafficClass {
                traffic_class: CLASSES[subject_index - 1],
            },
            _ => BaselineSubject::ParseErrors,
        };
        let elevated = subject_index == 1
            && ((hook_index == 0 && ingress_elevated) || (hook_index == 1 && egress_elevated));
        BaselineSubjectReport {
            hook,
            subject,
            state: if elevated {
                BaselineState::Elevated
            } else {
                BaselineState::WithinBaseline
            },
            sample_count: BASELINE_MINIMUM_SAMPLES as u16,
            latest_accepted_at_unix_ms: Some(END_MS),
            packets: evaluated_metric(elevated),
            bytes: evaluated_metric(false),
        }
    });
    let elevated_metric_count = ingress_elevated as u16 + egress_elevated as u16;
    BaselineReport {
        source_window_ms: BASELINE_SOURCE_WINDOW_MS,
        capacity: BASELINE_CAPACITY as u16,
        minimum_samples: BASELINE_MINIMUM_SAMPLES as u16,
        packet_noise_floor_pps: BASELINE_PACKET_NOISE_FLOOR_PPS,
        byte_noise_floor_bps: BASELINE_BYTE_NOISE_FLOOR_BPS,
        state: if elevated_metric_count == 0 {
            BaselineState::WithinBaseline
        } else {
            BaselineState::Elevated
        },
        evaluated_at_unix_ms: Some(END_MS),
        source_end_unix_ms: Some(END_MS),
        last_successful_evaluation_at_unix_ms: Some(END_MS),
        last_error_code: None,
        learning_subject_count: 0,
        elevated_metric_count,
        subjects,
    }
}

const fn evaluated_metric(elevated: bool) -> BaselineMetricReport {
    BaselineMetricReport {
        current: Some(1),
        median: Some(1),
        mad: Some(0),
        threshold: Some(1),
        ratio_milli: Some(1_000),
        elevated: Some(elevated),
    }
}

fn ready_fingerprint() -> FingerprintWindowReport {
    FingerprintWindowReport {
        state: FingerprintWindowState::Ready,
        window_ms: 10_000,
        coverage_ms: 10_000,
        start_unix_ms: Some(END_MS - 10_000),
        end_unix_ms: Some(END_MS),
        captured_entry_count: 2,
        delta_relation_count: 1,
        repeated_relation_count: 1,
        egress_first_correlated_relation_count: 0,
        ingress: FingerprintCounters {
            packets: 16,
            bytes: 1_024,
        },
        egress: FingerprintCounters {
            packets: 4,
            bytes: 256,
        },
        dominant_ingress_packet_ratio_milli: Some(800),
        maximum_ingress_to_egress_packet_ratio_milli: Some(4_000),
        last_error_code: None,
    }
}
