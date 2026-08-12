use l2_loop_common::{FingerprintKey, FingerprintValue, NO_VLAN, direction};
use l2_loop_core::{
    DomainError, FINGERPRINT_CAPACITY, FINGERPRINT_SAMPLE_SHIFT, FingerprintEvidence,
    FingerprintReport, FingerprintState, FingerprintSummary,
};

fn evidence(
    id: u64,
    raw_direction: u8,
    first_seen_ns: u64,
    packets: u64,
    bytes: u64,
) -> FingerprintEvidence {
    FingerprintEvidence {
        key: FingerprintKey {
            interface_generation: 7,
            fingerprint: id,
            ifindex: 41,
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
            last_seen_ns: first_seen_ns + 10,
            packets,
            bytes,
            source_mac: [0x02, 0, 0, 0, 0, id as u8],
            destination_mac: [0x33, 0x33, 0, 0, 0, 1],
            reserved: [0; 4],
        },
    }
}

#[test]
fn fixed_contract_and_empty_report_are_stable() {
    assert_eq!(FINGERPRINT_CAPACITY, 8_192);
    assert_eq!(FINGERPRINT_SAMPLE_SHIFT, 4);

    let report = FingerprintReport::build(41, 7, Vec::new()).unwrap();
    assert_eq!(report.state, FingerprintState::Empty);
    assert_eq!(report.capacity, 8_192);
    assert_eq!(report.sample_shift, 4);
    assert_eq!(report.captured_entry_count, 0);
    assert_eq!(report.relation_count, 0);
    assert_eq!(report.last_error_code, None);
}

#[test]
fn groups_directions_and_summarizes_order_repetition_and_ratios() {
    let entries = vec![
        evidence(11, direction::INGRESS, 100, 3, 300),
        evidence(11, direction::EGRESS, 150, 2, 200),
        evidence(12, direction::INGRESS, 200, 1, 80),
        evidence(13, direction::EGRESS, 200, 4, 400),
        evidence(14, direction::INGRESS, 300, 1, 50),
        evidence(14, direction::EGRESS, 300, 1, 100),
        evidence(15, direction::EGRESS, 10, 1, 100),
        evidence(15, direction::INGRESS, 20, 2, 200),
    ];

    let report = FingerprintReport::build(41, 7, entries).unwrap();
    assert_eq!(report.state, FingerprintState::Observed);
    assert_eq!(report.captured_entry_count, 8);
    assert_eq!(report.relation_count, 5);
    assert_eq!(report.ingress_only_relation_count, 1);
    assert_eq!(report.egress_only_relation_count, 1);
    assert_eq!(report.correlated_relation_count, 3);
    assert_eq!(report.ingress_first_relation_count, 1);
    assert_eq!(report.egress_first_relation_count, 1);
    assert_eq!(report.simultaneous_relation_count, 1);
    assert_eq!(report.repeated_relation_count, 3);
    assert_eq!(report.ingress.packets, 7);
    assert_eq!(report.ingress.bytes, 630);
    assert_eq!(report.egress.packets, 8);
    assert_eq!(report.egress.bytes, 800);
    assert_eq!(report.maximum_packet_ratio_milli, Some(2_000));
    assert_eq!(report.maximum_byte_ratio_milli, Some(2_000));

    let summary = FingerprintSummary::from(&report);
    assert_eq!(summary.state, FingerprintState::Observed);
    assert_eq!(summary.relation_count, 5);
    assert_eq!(summary.correlated_relation_count, 3);
}

#[test]
fn input_order_does_not_change_the_privacy_reduced_report() {
    let mut entries = vec![
        evidence(11, direction::INGRESS, 100, 1, 64),
        evidence(11, direction::EGRESS, 200, 1, 64),
        evidence(12, direction::EGRESS, 100, 1, 64),
    ];
    let expected = FingerprintReport::build(41, 7, entries.clone()).unwrap();
    entries.reverse();
    assert_eq!(FingerprintReport::build(41, 7, entries).unwrap(), expected);
}

#[test]
fn rejects_wrong_identity_invalid_shape_and_duplicate_keys() {
    let base = evidence(11, direction::INGRESS, 100, 1, 64);
    let mut cases = Vec::new();

    let mut wrong_generation = base;
    wrong_generation.key.interface_generation = 8;
    cases.push(wrong_generation);

    let mut wrong_ifindex = base;
    wrong_ifindex.key.ifindex = 42;
    cases.push(wrong_ifindex);

    let mut bad_direction = base;
    bad_direction.key.direction = 9;
    cases.push(bad_direction);

    let mut bad_vlan = base;
    bad_vlan.key.outer_vlan_id = 4_095;
    cases.push(bad_vlan);

    let mut bad_depth = base;
    bad_depth.key.vlan_depth = 3;
    cases.push(bad_depth);

    let mut bad_reserved = base;
    bad_reserved.value.reserved[0] = 1;
    cases.push(bad_reserved);

    let mut bad_counts = base;
    bad_counts.value.packets = 0;
    cases.push(bad_counts);

    let mut bad_time = base;
    bad_time.value.last_seen_ns = 99;
    cases.push(bad_time);

    for invalid in cases {
        assert!(matches!(
            FingerprintReport::build(41, 7, vec![invalid]),
            Err(DomainError::InvalidObservation(_)),
        ));
    }

    assert!(matches!(
        FingerprintReport::build(41, 7, vec![base, base]),
        Err(DomainError::InvalidObservation(_)),
    ));
}

#[test]
fn enforces_capacity_checked_aggregation_and_clamped_ratios() {
    let too_many = (0..=FINGERPRINT_CAPACITY)
        .map(|index| evidence(index as u64 + 1, direction::INGRESS, 1, 1, 64))
        .collect();
    assert!(matches!(
        FingerprintReport::build(41, 7, too_many),
        Err(DomainError::InvalidObservation(_)),
    ));

    let mut maximum = evidence(1, direction::INGRESS, 1, u64::MAX, u64::MAX);
    maximum.key.frame_len = 1;
    let mut overflow = evidence(2, direction::INGRESS, 1, 1, 64);
    overflow.key.frame_len = 1;
    assert!(matches!(
        FingerprintReport::build(41, 7, vec![maximum, overflow]),
        Err(DomainError::InvalidObservation(_)),
    ));

    let mut large = evidence(3, direction::INGRESS, 1, u64::MAX, u64::MAX);
    large.key.frame_len = 1;
    let mut small = evidence(3, direction::EGRESS, 2, 1, 1);
    small.key.frame_len = 1;
    let clamped = FingerprintReport::build(41, 7, vec![large, small]).unwrap();
    assert_eq!(clamped.maximum_packet_ratio_milli, Some(u64::MAX));
    assert_eq!(clamped.maximum_byte_ratio_milli, Some(u64::MAX));
}

#[test]
fn unavailable_and_serialized_outputs_contain_no_raw_identifiers() {
    let report = FingerprintReport::unavailable("FINGERPRINT_MAP_UNAVAILABLE").unwrap();
    assert_eq!(report.state, FingerprintState::Unavailable);
    assert_eq!(
        report.last_error_code.as_deref(),
        Some("FINGERPRINT_MAP_UNAVAILABLE")
    );
    assert_eq!(report.captured_entry_count, 0);

    let observed = FingerprintReport::build(
        41,
        7,
        vec![
            evidence(0xfeed_beef, direction::INGRESS, 100, 1, 64),
            evidence(0xfeed_beef, direction::EGRESS, 200, 1, 64),
        ],
    )
    .unwrap();
    let text = serde_json::to_string(&observed).unwrap();
    for prohibited in [
        "source_mac",
        "destination_mac",
        "first_seen_ns",
        "last_seen_ns",
        "outer_vlan_id",
        "ether_type",
        "frame_len",
        "protocol",
        "subtype",
        "feedbeef",
    ] {
        assert!(!text.contains(prohibited), "leaked raw field: {prohibited}");
    }
}
