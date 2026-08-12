use l2_loop_core::{
    DETECTION_ABSOLUTE_BYTE_THRESHOLD_BPS, DETECTION_ABSOLUTE_PACKET_THRESHOLD_PPS,
    DETECTION_ADAPTIVE_BYTE_FLOOR_BPS, DETECTION_ADAPTIVE_PACKET_FLOOR_PPS,
    DETECTION_AMPLIFICATION_RATIO_MILLI, DETECTION_ASSERT_TICKS, DETECTION_BUM_RATIO_MILLI,
    DETECTION_CLEAR_TICKS, DETECTION_COOLDOWN_MS, DETECTION_DOMINANT_RATIO_MILLI,
    DETECTION_FINGERPRINT_FRESHNESS_MS, DETECTION_FINGERPRINT_WINDOW_MS,
    DETECTION_MINIMUM_INGRESS_SAMPLES, DETECTION_TRANSITION_CAPACITY, DetectionConfig,
    DetectionReport, DetectionState, DetectionSummary, DetectionTransitionReason,
    FingerprintWindowReport, FingerprintWindowState, OBSERVATION_SCHEMA_VERSION, RateIdentity,
};

#[test]
fn schema_five_detection_contract_is_fixed() {
    assert_eq!(OBSERVATION_SCHEMA_VERSION, 5);
    assert_eq!(DETECTION_FINGERPRINT_WINDOW_MS, 10_000);
    assert_eq!(DETECTION_FINGERPRINT_FRESHNESS_MS, 15_000);
    assert_eq!(DETECTION_ADAPTIVE_PACKET_FLOOR_PPS, 1_000);
    assert_eq!(DETECTION_ADAPTIVE_BYTE_FLOOR_BPS, 1_048_576);
    assert_eq!(DETECTION_ABSOLUTE_PACKET_THRESHOLD_PPS, 100_000);
    assert_eq!(DETECTION_ABSOLUTE_BYTE_THRESHOLD_BPS, 104_857_600);
    assert_eq!(DETECTION_BUM_RATIO_MILLI, 800);
    assert_eq!(DETECTION_DOMINANT_RATIO_MILLI, 800);
    assert_eq!(DETECTION_MINIMUM_INGRESS_SAMPLES, 16);
    assert_eq!(DETECTION_AMPLIFICATION_RATIO_MILLI, 4_000);
    assert_eq!(DETECTION_ASSERT_TICKS, 3);
    assert_eq!(DETECTION_CLEAR_TICKS, 10);
    assert_eq!(DETECTION_COOLDOWN_MS, 30_000);
    assert_eq!(DETECTION_TRANSITION_CAPACITY, 16);
    assert_eq!(DetectionConfig::fixed().transition_capacity, 16);
}

#[test]
fn public_detection_states_and_transition_reasons_have_stable_names() {
    let states = [
        (DetectionState::WarmingUp, "warming_up"),
        (DetectionState::Normal, "normal"),
        (
            DetectionState::IngressStormConfirmed,
            "ingress_storm_confirmed",
        ),
        (
            DetectionState::EgressStormConfirmed,
            "egress_storm_confirmed",
        ),
        (
            DetectionState::BidirectionalStormConfirmed,
            "bidirectional_storm_confirmed",
        ),
        (
            DetectionState::ExternalLoopSuspected,
            "external_loop_suspected",
        ),
        (
            DetectionState::ExternalLoopHighConfidence,
            "external_loop_high_confidence",
        ),
        (DetectionState::Cooldown, "cooldown"),
        (DetectionState::Unavailable, "unavailable"),
    ];
    for (state, expected) in states {
        assert_eq!(serde_json::to_value(state).unwrap(), expected);
    }

    let reasons = [
        (DetectionTransitionReason::EvidenceReady, "evidence_ready"),
        (DetectionTransitionReason::StormAsserted, "storm_asserted"),
        (
            DetectionTransitionReason::RelationshipSuspected,
            "relationship_suspected",
        ),
        (
            DetectionTransitionReason::RelationshipHighConfidence,
            "relationship_high_confidence",
        ),
        (
            DetectionTransitionReason::EvidenceCleared,
            "evidence_cleared",
        ),
        (
            DetectionTransitionReason::CooldownCompleted,
            "cooldown_completed",
        ),
        (
            DetectionTransitionReason::EvidenceUnavailable,
            "evidence_unavailable",
        ),
        (
            DetectionTransitionReason::EvidenceRecovered,
            "evidence_recovered",
        ),
        (DetectionTransitionReason::SamplerPaused, "sampler_paused"),
        (
            DetectionTransitionReason::IntegrityFailure,
            "integrity_failure",
        ),
    ];
    for (reason, expected) in reasons {
        assert_eq!(serde_json::to_value(reason).unwrap(), expected);
    }
}

#[test]
fn warming_report_and_status_summary_are_valid_and_bounded() {
    let identity = RateIdentity::new(41, 7).unwrap();
    let report = DetectionReport::warming(identity, 1_786_300_000_000);

    assert_eq!(report.state, DetectionState::WarmingUp);
    assert_eq!(report.retained_anomalous_state, None);
    assert_eq!(report.evaluated_at_unix_ms, 1_786_300_000_000);
    assert_eq!(report.state_since_unix_ms, 1_786_300_000_000);
    assert_eq!(report.last_trustworthy_at_unix_ms, None);
    assert_eq!(report.candidate_streak, 0);
    assert_eq!(report.clear_streak, 0);
    assert_eq!(report.transition_sequence, 0);
    assert!(report.transitions.is_empty());
    assert_eq!(
        report.signals.fingerprint_window.state,
        FingerprintWindowState::WarmingUp,
    );
    assert!(report.validate().is_ok());

    let summary = DetectionSummary::from(&report);
    assert_eq!(summary.state, DetectionState::WarmingUp);
    assert_eq!(summary.transition_sequence, 0);
    assert_eq!(
        summary.fingerprint_window_state,
        FingerprintWindowState::WarmingUp,
    );
    assert!(summary.validate().is_ok());
}

#[test]
fn unavailable_models_require_stable_codes_and_retain_only_anomalies() {
    let window = FingerprintWindowReport::unavailable("DETECTION_FINGERPRINT_UNAVAILABLE").unwrap();
    assert_eq!(window.state, FingerprintWindowState::Unavailable);
    assert_eq!(
        window.last_error_code.as_deref(),
        Some("DETECTION_FINGERPRINT_UNAVAILABLE"),
    );
    assert!(FingerprintWindowReport::unavailable("bad-code").is_err());

    let identity = RateIdentity::new(41, 7).unwrap();
    let retained = DetectionReport::unavailable(
        identity,
        1_786_300_010_000,
        Some(DetectionState::ExternalLoopHighConfidence),
        "DETECTION_SOURCE_UNAVAILABLE",
    )
    .unwrap();
    assert_eq!(retained.state, DetectionState::Unavailable);
    assert_eq!(
        retained.retained_anomalous_state,
        Some(DetectionState::ExternalLoopHighConfidence),
    );
    assert!(retained.validate().is_ok());

    assert!(
        DetectionReport::unavailable(
            identity,
            1_786_300_010_000,
            Some(DetectionState::Normal),
            "DETECTION_SOURCE_UNAVAILABLE",
        )
        .is_err(),
    );
}

#[test]
fn serialized_detection_output_contains_no_raw_or_mutating_contract() {
    let report = DetectionReport::warming(RateIdentity::new(41, 7).unwrap(), 1_000);
    let text = serde_json::to_string(&report).unwrap();
    for prohibited in [
        "fingerprint\"",
        "source_mac",
        "destination_mac",
        "packet_bytes",
        "raw_key",
        "first_seen_ns",
        "last_seen_ns",
        "monotonic_ns",
        "loop_confirmed",
        "probe",
        "drop",
        "policy",
    ] {
        assert!(!text.contains(prohibited), "leaked field: {prohibited}");
    }

    let source = include_str!("../src/detection.rs");
    for prohibited in ["LoopConfirmed", "ConfirmedLoop", "XDP_DROP", "TC_ACT_SHOT"] {
        assert!(!source.contains(prohibited), "forbidden API: {prohibited}");
    }
}
