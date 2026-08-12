use l2_loop_common::{FingerprintKey, FingerprintValue, NO_VLAN, direction};
use l2_loop_core::{
    FINGERPRINT_CAPACITY, FingerprintEvidence, FingerprintWindowHistory, FingerprintWindowState,
    RateIdentity,
};

const IFINDEX: u32 = 41;
const GENERATION: u64 = 7;

fn evidence(
    id: u64,
    raw_direction: u8,
    first_seen_ns: u64,
    last_seen_ns: u64,
    packets: u64,
    bytes: u64,
) -> FingerprintEvidence {
    FingerprintEvidence {
        key: FingerprintKey {
            interface_generation: GENERATION,
            fingerprint: id,
            ifindex: IFINDEX,
            outer_vlan_id: NO_VLAN,
            ether_type: 0x86dd,
            frame_len: 64,
            direction: raw_direction,
            vlan_depth: 0,
            protocol: 58,
            subtype: 135,
            reserved: [0; 2],
        },
        value: FingerprintValue {
            first_seen_ns,
            last_seen_ns,
            packets,
            bytes,
            source_mac: [0x02, 0, 0, 0, 0, id as u8],
            destination_mac: [0x33, 0x33, 0, 0, 0, 1],
            reserved: [0; 4],
        },
    }
}

fn history() -> FingerprintWindowHistory {
    FingerprintWindowHistory::new(RateIdentity::new(IFINDEX, GENERATION).unwrap())
}

fn first_scan() -> Vec<FingerprintEvidence> {
    vec![
        evidence(11, direction::EGRESS, 50, 90, 2, 128),
        evidence(11, direction::INGRESS, 100, 190, 10, 640),
        evidence(12, direction::INGRESS, 200, 290, 4, 256),
    ]
}

fn second_scan() -> Vec<FingerprintEvidence> {
    vec![
        evidence(11, direction::EGRESS, 50, 9_090, 10, 640),
        evidence(11, direction::INGRESS, 100, 9_190, 50, 3_200),
        evidence(12, direction::INGRESS, 200, 9_290, 8, 512),
    ]
}

#[test]
fn first_endpoint_warms_and_exact_window_builds_privacy_reduced_deltas() {
    let mut history = history();
    let first = history
        .record_scan(1_000_000_000, 1_000, first_scan())
        .unwrap();
    assert_eq!(first.state, FingerprintWindowState::WarmingUp);

    let report = history
        .record_scan(11_000_000_000, 11_000, second_scan())
        .unwrap();
    assert_eq!(report.state, FingerprintWindowState::Ready);
    assert_eq!(report.coverage_ms, 10_000);
    assert_eq!(report.start_unix_ms, Some(1_000));
    assert_eq!(report.end_unix_ms, Some(11_000));
    assert_eq!(report.captured_entry_count, 3);
    assert_eq!(report.delta_relation_count, 2);
    assert_eq!(report.repeated_relation_count, 2);
    assert_eq!(report.egress_first_correlated_relation_count, 1);
    assert_eq!(report.ingress.packets, 44);
    assert_eq!(report.ingress.bytes, 2_816);
    assert_eq!(report.egress.packets, 8);
    assert_eq!(report.egress.bytes, 512);
    assert_eq!(report.dominant_ingress_packet_ratio_milli, Some(909));
    assert_eq!(
        report.maximum_ingress_to_egress_packet_ratio_milli,
        Some(5_000),
    );
    assert!(report.validate().is_ok());
    assert_eq!(history.cached_report(), &report);
}

#[test]
fn early_scan_keeps_first_endpoint_and_long_gap_restarts_warming() {
    let mut early_history = history();
    early_history
        .record_scan(1_000_000_000, 1_000, first_scan())
        .unwrap();

    let early = early_history
        .record_scan(10_999_000_000, 10_999, second_scan())
        .unwrap();
    assert_eq!(early.state, FingerprintWindowState::WarmingUp);

    let exact = early_history
        .record_scan(11_000_000_000, 11_000, second_scan())
        .unwrap();
    assert_eq!(exact.state, FingerprintWindowState::Ready);

    let mut late = history();
    late.record_scan(1_000_000_000, 1_000, first_scan())
        .unwrap();
    let fresh_edge = late
        .record_scan(16_000_000_000, 16_000, second_scan())
        .unwrap();
    assert_eq!(fresh_edge.state, FingerprintWindowState::Ready);

    let mut stale = history();
    stale
        .record_scan(1_000_000_000, 1_000, first_scan())
        .unwrap();
    let reset = stale
        .record_scan(16_001_000_000, 16_001, second_scan())
        .unwrap();
    assert_eq!(reset.state, FingerprintWindowState::WarmingUp);
    let recovered = stale
        .record_scan(26_001_000_000, 26_001, second_scan())
        .unwrap();
    assert_eq!(recovered.state, FingerprintWindowState::Ready);
    assert_eq!(recovered.ingress.packets, 0);
}

#[test]
fn new_keys_contribute_current_counts_and_evicted_keys_contribute_nothing() {
    let mut history = history();
    history
        .record_scan(
            1_000_000_000,
            1_000,
            vec![evidence(1, direction::INGRESS, 10, 20, 100, 6_400)],
        )
        .unwrap();
    let report = history
        .record_scan(
            11_000_000_000,
            11_000,
            vec![evidence(2, direction::INGRESS, 30, 40, 7, 448)],
        )
        .unwrap();

    assert_eq!(report.captured_entry_count, 1);
    assert_eq!(report.delta_relation_count, 1);
    assert_eq!(report.ingress.packets, 7);
    assert_eq!(report.ingress.bytes, 448);
    assert_eq!(report.dominant_ingress_packet_ratio_milli, Some(1_000));
}

#[test]
fn unchanged_entries_produce_a_ready_empty_delta_window() {
    let mut history = history();
    history
        .record_scan(1_000_000_000, 1_000, first_scan())
        .unwrap();
    let report = history
        .record_scan(11_000_000_000, 11_000, first_scan())
        .unwrap();
    assert_eq!(report.state, FingerprintWindowState::Ready);
    assert_eq!(report.delta_relation_count, 0);
    assert_eq!(report.ingress.packets, 0);
    assert_eq!(report.egress.packets, 0);
    assert_eq!(report.dominant_ingress_packet_ratio_milli, None);
}

#[test]
fn invalid_second_scan_clears_endpoints_and_requires_a_new_pair() {
    let mut cases = Vec::new();
    let base = second_scan();

    let mut counter_regression = base.clone();
    counter_regression[1].value.packets = 9;
    cases.push(counter_regression);

    let mut last_seen_regression = base.clone();
    last_seen_regression[1].value.last_seen_ns = 180;
    cases.push(last_seen_regression);

    let mut changed_first_seen = base.clone();
    changed_first_seen[1].value.first_seen_ns = 101;
    cases.push(changed_first_seen);

    let mut wrong_identity = base.clone();
    wrong_identity[0].key.interface_generation = GENERATION + 1;
    cases.push(wrong_identity);

    let mut duplicate = base.clone();
    duplicate.push(base[0]);
    cases.push(duplicate);

    for invalid in cases {
        let mut history = history();
        history
            .record_scan(1_000_000_000, 1_000, first_scan())
            .unwrap();
        assert!(
            history
                .record_scan(11_000_000_000, 11_000, invalid)
                .is_err(),
        );
        assert_eq!(
            history.cached_report().state,
            FingerprintWindowState::Unavailable,
        );
        assert_eq!(
            history
                .record_scan(21_000_000_000, 21_000, second_scan())
                .unwrap()
                .state,
            FingerprintWindowState::WarmingUp,
        );
    }
}

#[test]
fn rejects_clock_regression_capacity_overflow_and_aggregate_overflow() {
    let mut clock = history();
    clock
        .record_scan(10_000_000_000, 10_000, first_scan())
        .unwrap();
    assert!(
        clock
            .record_scan(10_000_000_000, 10_001, second_scan())
            .is_err(),
    );

    let too_many = (0..=FINGERPRINT_CAPACITY)
        .map(|index| evidence(index as u64 + 1, direction::INGRESS, 1, 2, 1, 64))
        .collect();
    assert!(history().record_scan(1, 1, too_many).is_err());

    let mut overflow = history();
    overflow.record_scan(1, 1, Vec::new()).unwrap();
    let entries = vec![
        evidence(1, direction::INGRESS, 1, 2, u64::MAX, u64::MAX),
        evidence(2, direction::INGRESS, 1, 2, 1, 1),
    ];
    assert!(
        overflow
            .record_scan(10_000_000_001, 10_001, entries)
            .is_err(),
    );
}

#[test]
fn explicit_unavailable_and_clear_destroy_endpoint_history() {
    let mut history = history();
    history
        .record_scan(1_000_000_000, 1_000, first_scan())
        .unwrap();
    history
        .unavailable("DETECTION_FINGERPRINT_READ_FAILED")
        .unwrap();
    assert_eq!(
        history.cached_report().state,
        FingerprintWindowState::Unavailable,
    );
    assert_eq!(
        history
            .record_scan(11_000_000_000, 11_000, second_scan())
            .unwrap()
            .state,
        FingerprintWindowState::WarmingUp,
    );

    history.clear();
    assert_eq!(
        history.cached_report().state,
        FingerprintWindowState::WarmingUp,
    );
}

#[test]
fn serialized_window_contains_no_raw_fingerprint_material() {
    let mut history = history();
    history
        .record_scan(1_000_000_000, 1_000, first_scan())
        .unwrap();
    let report = history
        .record_scan(11_000_000_000, 11_000, second_scan())
        .unwrap();
    let text = serde_json::to_string(&report).unwrap();
    for prohibited in [
        "fingerprint\"",
        "source_mac",
        "destination_mac",
        "outer_vlan_id",
        "ether_type",
        "first_seen_ns",
        "last_seen_ns",
        "raw_key",
    ] {
        assert!(!text.contains(prohibited), "leaked field: {prohibited}");
    }
}
