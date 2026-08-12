use l2_loop_core::{
    DetectionEngine, DetectionState, DetectionTransitionReason, FingerprintCounters,
    FingerprintWindowReport, FingerprintWindowState, HookDetectionSignals, RateIdentity,
    StormCandidate,
};

const IFINDEX: u32 = 7;
const GENERATION: u64 = 11;
const START_NS: u64 = 1_000_000_000;
const START_MS: u64 = 1_000;

#[test]
fn warming_requires_ready_baseline_but_absolute_evidence_can_assert_during_learning() {
    let mut warming = engine();
    let report = warming
        .evaluate(2_000_000_000, 2_000, signals(StormCandidate::None, false))
        .unwrap();
    assert_eq!(report.state, DetectionState::WarmingUp);

    let normal = warming
        .evaluate(3_000_000_000, 3_000, signals(StormCandidate::None, true))
        .unwrap();
    assert_eq!(normal.state, DetectionState::Normal);
    assert_eq!(normal.transition_sequence, 1);
    assert_eq!(normal.transitions[0].reason, DetectionTransitionReason::EvidenceReady);

    let mut absolute = engine();
    for tick in 1..=3 {
        let report = absolute
            .evaluate(
                START_NS + tick * 1_000_000_000,
                START_MS + tick * 1_000,
                absolute_signals(StormCandidate::Ingress),
            )
            .unwrap();
        assert_eq!(report.candidate_streak, tick as u8);
    }
    assert_eq!(
        absolute.cached_report().state,
        DetectionState::IngressStormConfirmed
    );
}

#[test]
fn three_equal_candidates_assert_and_candidate_kind_changes_reset_the_streak() {
    for (candidate, state) in [
        (StormCandidate::Ingress, DetectionState::IngressStormConfirmed),
        (StormCandidate::Egress, DetectionState::EgressStormConfirmed),
        (
            StormCandidate::Bidirectional,
            DetectionState::BidirectionalStormConfirmed,
        ),
    ] {
        let mut engine = engine();
        assert_eq!(
            engine
                .evaluate(2_000_000_000, 2_000, signals(candidate, true))
                .unwrap()
                .state,
            DetectionState::WarmingUp
        );
        assert_eq!(
            engine
                .evaluate(3_000_000_000, 3_000, signals(candidate, true))
                .unwrap()
                .state,
            DetectionState::WarmingUp
        );
        assert_eq!(
            engine
                .evaluate(4_000_000_000, 4_000, signals(candidate, true))
                .unwrap()
                .state,
            state
        );
    }

    let mut changed = engine();
    changed
        .evaluate(2_000_000_000, 2_000, signals(StormCandidate::Ingress, true))
        .unwrap();
    changed
        .evaluate(3_000_000_000, 3_000, signals(StormCandidate::Ingress, true))
        .unwrap();
    let reset = changed
        .evaluate(4_000_000_000, 4_000, signals(StormCandidate::Egress, true))
        .unwrap();
    assert_eq!(reset.candidate_streak, 1);
    assert_eq!(reset.state, DetectionState::WarmingUp);
}

#[test]
fn relationship_evidence_immediately_upgrades_an_ingress_storm_but_never_confirms_causality() {
    let mut engine = asserted_ingress();
    let suspected = engine
        .evaluate(5_000_000_000, 5_000, relationship_signals(false))
        .unwrap();
    assert_eq!(suspected.state, DetectionState::ExternalLoopSuspected);
    assert_eq!(
        suspected.transitions.last().unwrap().reason,
        DetectionTransitionReason::RelationshipSuspected
    );

    let high = engine
        .evaluate(6_000_000_000, 6_000, relationship_signals(true))
        .unwrap();
    assert_eq!(high.state, DetectionState::ExternalLoopHighConfidence);
    assert!(
        serde_json::to_string(&high)
            .unwrap()
            .find("confirmed_loop")
            .is_none()
    );

    let mut egress = engine();
    for tick in 1..=3 {
        egress
            .evaluate(
                START_NS + tick * 1_000_000_000,
                START_MS + tick * 1_000,
                signals(StormCandidate::Egress, true),
            )
            .unwrap();
    }
    let refused = egress
        .evaluate(5_000_000_000, 5_000, relationship_signals(true))
        .unwrap();
    assert_eq!(refused.state, DetectionState::EgressStormConfirmed);
}

#[test]
fn ten_clear_ticks_enter_cooldown_and_thirty_seconds_complete_recovery() {
    let mut engine = asserted_ingress();
    for tick in 1..10 {
        let report = engine
            .evaluate(
                4_000_000_000 + tick * 1_000_000_000,
                4_000 + tick * 1_000,
                signals(StormCandidate::None, true),
            )
            .unwrap();
        assert_eq!(report.state, DetectionState::IngressStormConfirmed);
        assert_eq!(report.clear_streak, tick as u8);
    }
    let cooldown_at_ns = 14_000_000_000;
    let cooldown = engine
        .evaluate(cooldown_at_ns, 14_000, signals(StormCandidate::None, true))
        .unwrap();
    assert_eq!(cooldown.state, DetectionState::Cooldown);
    assert_eq!(
        cooldown.retained_anomalous_state,
        Some(DetectionState::IngressStormConfirmed)
    );

    assert_eq!(
        engine
            .evaluate(
                cooldown_at_ns + 29_999_000_000,
                43_999,
                signals(StormCandidate::None, true),
            )
            .unwrap()
            .state,
        DetectionState::Cooldown
    );
    let normal = engine
        .evaluate(
            cooldown_at_ns + 30_000_000_000,
            44_000,
            signals(StormCandidate::None, true),
        )
        .unwrap();
    assert_eq!(normal.state, DetectionState::Normal);
    assert_eq!(normal.retained_anomalous_state, None);
}

#[test]
fn cooldown_reappearance_requires_three_ticks_and_keeps_sequence_continuity() {
    let mut engine = asserted_ingress();
    for tick in 1..=10 {
        engine
            .evaluate(
                4_000_000_000 + tick * 1_000_000_000,
                4_000 + tick * 1_000,
                signals(StormCandidate::None, true),
            )
            .unwrap();
    }
    let sequence = engine.cached_report().transition_sequence;
    for tick in 1..=2 {
        assert_eq!(
            engine
                .evaluate(
                    14_000_000_000 + tick * 1_000_000_000,
                    14_000 + tick * 1_000,
                    signals(StormCandidate::Ingress, true),
                )
                .unwrap()
                .state,
            DetectionState::Cooldown
        );
    }
    let asserted = engine
        .evaluate(
            17_000_000_000,
            17_000,
            signals(StormCandidate::Ingress, true),
        )
        .unwrap();
    assert_eq!(asserted.state, DetectionState::IngressStormConfirmed);
    assert_eq!(asserted.transition_sequence, sequence + 1);
}

#[test]
fn transient_unavailable_retains_anomaly_and_does_not_advance_streaks() {
    let mut engine = engine();
    engine
        .evaluate(2_000_000_000, 2_000, signals(StormCandidate::Ingress, true))
        .unwrap();
    let before = engine
        .evaluate(3_000_000_000, 3_000, signals(StormCandidate::Ingress, true))
        .unwrap();
    assert_eq!(before.candidate_streak, 2);

    let unavailable = engine.unavailable(3_500, "MAP_READ_FAILED").unwrap();
    assert_eq!(unavailable.state, DetectionState::Unavailable);
    assert_eq!(unavailable.candidate_streak, 2);
    assert_eq!(unavailable.retained_anomalous_state, None);

    let recovered = engine
        .evaluate(4_000_000_000, 4_000, signals(StormCandidate::Ingress, true))
        .unwrap();
    assert_eq!(recovered.state, DetectionState::IngressStormConfirmed);

    let retained = engine.unavailable(4_500, "MAP_READ_FAILED").unwrap();
    assert_eq!(
        retained.retained_anomalous_state,
        Some(DetectionState::IngressStormConfirmed)
    );
}

#[test]
fn integrity_clear_and_new_generation_reset_all_bounded_state() {
    let mut engine = asserted_ingress();
    let unavailable = engine
        .clear(
            RateIdentity::new(IFINDEX, GENERATION).unwrap(),
            5_000_000_000,
            5_000,
            "COUNTER_REGRESSION",
        )
        .unwrap();
    assert_eq!(unavailable.state, DetectionState::Unavailable);
    assert_eq!(unavailable.candidate_streak, 0);
    assert_eq!(unavailable.clear_streak, 0);
    assert_eq!(unavailable.signals.fingerprint_window.state, FingerprintWindowState::Unavailable);

    let reset = engine
        .clear(
            RateIdentity::new(IFINDEX, GENERATION + 1).unwrap(),
            6_000_000_000,
            6_000,
            "GENERATION_CHANGED",
        )
        .unwrap();
    assert_eq!(engine.identity().generation(), GENERATION + 1);
    assert_eq!(reset.transition_sequence, 0);
    assert!(reset.transitions.is_empty());
}

#[test]
fn transition_history_evicts_oldest_entries_but_keeps_the_global_sequence() {
    let mut engine = engine();
    for index in 0..9 {
        engine.unavailable(2_000 + index * 2, "MAP_READ_FAILED").unwrap();
        engine
            .evaluate(
                2_000_000_000 + index * 2_000_000_000,
                2_001 + index * 2,
                signals(StormCandidate::None, true),
            )
            .unwrap();
    }
    let report = engine.cached_report();
    assert_eq!(report.transition_sequence, 18);
    assert_eq!(report.transitions.len(), 16);
    assert_eq!(report.transitions[0].sequence, 3);
    assert_eq!(report.transitions[15].sequence, 18);
    assert!(report.validate().is_ok());
}

fn engine() -> DetectionEngine {
    DetectionEngine::new(
        RateIdentity::new(IFINDEX, GENERATION).unwrap(),
        START_NS,
        START_MS,
    )
}

fn asserted_ingress() -> DetectionEngine {
    let mut engine = engine();
    for tick in 1..=3 {
        engine
            .evaluate(
                START_NS + tick * 1_000_000_000,
                START_MS + tick * 1_000,
                signals(StormCandidate::Ingress, true),
            )
            .unwrap();
    }
    engine
}

fn absolute_signals(candidate: StormCandidate) -> l2_loop_core::DetectionSignals {
    let mut signals = signals(candidate, false);
    set_candidates(&mut signals, candidate, false, true);
    signals
}

fn relationship_signals(high_confidence: bool) -> l2_loop_core::DetectionSignals {
    let mut signals = signals(StormCandidate::Ingress, true);
    signals.loop_suspected = Some(true);
    signals.loop_high_confidence = Some(high_confidence);
    signals.fingerprint_window = ready_fingerprint(high_confidence);
    signals
}

fn signals(candidate: StormCandidate, evidence_ready: bool) -> l2_loop_core::DetectionSignals {
    let ready_value = evidence_ready.then_some(false);
    let mut signals = l2_loop_core::DetectionSignals {
        source_window_end_unix_ms: evidence_ready.then_some(1_000),
        ingress: HookDetectionSignals {
            bum_packets_per_second: evidence_ready.then_some(800),
            bum_bytes_per_second: evidence_ready.then_some(0),
            bum_ratio_milli: evidence_ready.then_some(800),
            baseline_elevated: ready_value,
            adaptive_candidate: ready_value,
            absolute_candidate: Some(false),
        },
        egress: HookDetectionSignals {
            bum_packets_per_second: evidence_ready.then_some(0),
            bum_bytes_per_second: evidence_ready.then_some(0),
            bum_ratio_milli: evidence_ready.then_some(0),
            baseline_elevated: ready_value,
            adaptive_candidate: ready_value,
            absolute_candidate: Some(false),
        },
        candidate,
        fingerprint_window: FingerprintWindowReport::warming(),
        loop_suspected: None,
        loop_high_confidence: None,
    };
    set_candidates(&mut signals, candidate, evidence_ready, false);
    signals
}

fn set_candidates(
    signals: &mut l2_loop_core::DetectionSignals,
    candidate: StormCandidate,
    adaptive_ready: bool,
    absolute: bool,
) {
    let ingress = matches!(candidate, StormCandidate::Ingress | StormCandidate::Bidirectional);
    let egress = matches!(candidate, StormCandidate::Egress | StormCandidate::Bidirectional);
    signals.ingress.adaptive_candidate = adaptive_ready.then_some(ingress);
    signals.egress.adaptive_candidate = adaptive_ready.then_some(egress);
    signals.ingress.absolute_candidate = Some(absolute && ingress);
    signals.egress.absolute_candidate = Some(absolute && egress);
}

fn ready_fingerprint(high_confidence: bool) -> FingerprintWindowReport {
    FingerprintWindowReport {
        state: FingerprintWindowState::Ready,
        window_ms: 10_000,
        coverage_ms: 10_000,
        start_unix_ms: Some(0),
        end_unix_ms: Some(1_000),
        captured_entry_count: 2,
        delta_relation_count: 1,
        repeated_relation_count: 1,
        egress_first_correlated_relation_count: u16::from(high_confidence),
        ingress: FingerprintCounters {
            packets: 16,
            bytes: 1_024,
        },
        egress: FingerprintCounters {
            packets: 4,
            bytes: 256,
        },
        dominant_ingress_packet_ratio_milli: Some(800),
        maximum_ingress_to_egress_packet_ratio_milli: high_confidence.then_some(4_000),
        last_error_code: None,
    }
}
