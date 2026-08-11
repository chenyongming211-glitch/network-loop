use l2_loop_common::{NO_VLAN, ParseError, parse_l2, parse_l2_word, traffic_class};

fn ethernet(destination: [u8; 6], ether_type: u16) -> Vec<u8> {
    let mut frame = vec![0_u8; 14];
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
    frame
}

fn tagged(destination: [u8; 6], tpid: u16, tci: u16, inner: u16) -> Vec<u8> {
    let mut frame = ethernet(destination, tpid);
    frame.extend_from_slice(&tci.to_be_bytes());
    frame.extend_from_slice(&inner.to_be_bytes());
    frame
}

#[test]
fn classifies_the_complete_untagged_matrix() {
    let cases = [
        ([0xff; 6], 0x0806, traffic_class::L2_BROADCAST),
        (
            [0x01, 0x80, 0xc2, 0, 0, 0x0e],
            0x88cc,
            traffic_class::LINK_LOCAL_CONTROL,
        ),
        (
            [0x01, 0, 0x5e, 0, 0, 1],
            0x0800,
            traffic_class::IPV4_MULTICAST,
        ),
        (
            [0x33, 0x33, 0, 0, 0, 1],
            0x86dd,
            traffic_class::IPV6_MULTICAST,
        ),
        (
            [0x01, 0, 0x5f, 0, 0, 1],
            0x88b5,
            traffic_class::OTHER_L2_MULTICAST,
        ),
        (
            [0x02, 0, 0, 0, 0, 2],
            0x0800,
            traffic_class::UNICAST_OR_UNCLASSIFIED,
        ),
    ];

    for (destination, ether_type, expected) in cases {
        let parsed = parse_l2(&ethernet(destination, ether_type)).unwrap();
        assert_eq!(parsed.traffic_class, expected);
        assert_eq!(parsed.outer_vlan_id, None);
        assert!(!parsed.nested_vlan);
    }
}

#[test]
fn classification_priority_and_link_local_boundaries_are_exact() {
    let cases = [
        ([0xff; 6], 0x0800, traffic_class::L2_BROADCAST),
        (
            [0x01, 0x80, 0xc2, 0, 0, 0],
            0x0800,
            traffic_class::LINK_LOCAL_CONTROL,
        ),
        (
            [0x01, 0x80, 0xc2, 0, 0, 0x0f],
            0x86dd,
            traffic_class::LINK_LOCAL_CONTROL,
        ),
        (
            [0x01, 0x80, 0xc2, 0, 0, 0x10],
            0x0800,
            traffic_class::OTHER_L2_MULTICAST,
        ),
        (
            [0x01, 0, 0x5e, 0, 0, 1],
            0x86dd,
            traffic_class::OTHER_L2_MULTICAST,
        ),
        (
            [0x33, 0x33, 0, 0, 0, 1],
            0x0800,
            traffic_class::OTHER_L2_MULTICAST,
        ),
    ];

    for (destination, ether_type, expected) in cases {
        assert_eq!(
            parse_l2(&ethernet(destination, ether_type))
                .unwrap()
                .traffic_class,
            expected,
        );
    }
}

#[test]
fn parses_one_supported_vlan_header_and_extracts_only_the_vlan_id() {
    let dot1q = parse_l2(&tagged([0x33, 0x33, 0, 0, 0, 1], 0x8100, 0xa07b, 0x86dd)).unwrap();
    assert_eq!(dot1q.outer_vlan_id, Some(123));
    assert_eq!(dot1q.traffic_class, traffic_class::IPV6_MULTICAST);
    assert!(!dot1q.nested_vlan);

    let dot1ad = parse_l2(&tagged([0x01, 0, 0x5e, 0, 0, 1], 0x88a8, 0xf007, 0x0800)).unwrap();
    assert_eq!(dot1ad.outer_vlan_id, Some(7));
    assert_eq!(dot1ad.traffic_class, traffic_class::IPV4_MULTICAST);
    assert!(!dot1ad.nested_vlan);
}

#[test]
fn bounds_nested_vlan_and_degrades_by_destination_only() {
    let cases = [
        ([0xff; 6], traffic_class::L2_BROADCAST),
        (
            [0x01, 0x80, 0xc2, 0, 0, 0x0f],
            traffic_class::LINK_LOCAL_CONTROL,
        ),
        ([0x33, 0x33, 0, 0, 0, 1], traffic_class::OTHER_L2_MULTICAST),
        (
            [0x02, 0, 0, 0, 0, 2],
            traffic_class::UNICAST_OR_UNCLASSIFIED,
        ),
    ];

    for (destination, expected) in cases {
        let parsed = parse_l2(&tagged(destination, 0x88a8, 7, 0x8100)).unwrap();
        assert_eq!(parsed.outer_vlan_id, Some(7));
        assert!(parsed.nested_vlan);
        assert_eq!(parsed.traffic_class, expected);
    }
}

#[test]
fn truncated_ethernet_and_first_vlan_headers_are_errors() {
    for length in 0..14 {
        assert_eq!(
            parse_l2(&vec![0_u8; length]),
            Err(ParseError::TruncatedEthernet),
        );
    }

    let tagged_header = ethernet([0xff; 6], 0x8100);
    for length in 14..18 {
        let mut truncated = tagged_header.clone();
        truncated.resize(length, 0);
        assert_eq!(parse_l2(&truncated), Err(ParseError::TruncatedVlan));
    }
}

#[test]
fn packed_parser_result_initializes_every_verifier_visible_bit() {
    let untagged = parse_l2_word(&ethernet([0x02, 0, 0, 0, 0, 2], 0x0800));
    assert!(!untagged.is_error());
    assert_eq!(untagged.traffic_class(), traffic_class::UNICAST_OR_UNCLASSIFIED);
    assert_eq!(untagged.outer_vlan_id(), NO_VLAN);
    assert!(!untagged.has_outer_vlan());
    assert!(!untagged.nested_vlan());
    assert_ne!(untagged.into_raw(), 0);

    let tagged = parse_l2_word(&tagged([0x33, 0x33, 0, 0, 0, 1], 0x8100, 123, 0x86dd));
    assert!(!tagged.is_error());
    assert_eq!(tagged.traffic_class(), traffic_class::IPV6_MULTICAST);
    assert_eq!(tagged.outer_vlan_id(), 123);
    assert!(tagged.has_outer_vlan());
    assert!(!tagged.nested_vlan());

    assert!(parse_l2_word(&[]).is_error());
    assert!(parse_l2_word(&ethernet([0xff; 6], 0x8100)).is_error());
}
