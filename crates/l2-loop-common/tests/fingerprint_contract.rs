use l2_loop_common::{
    FINGERPRINT_PREFIX_LEN, FINGERPRINT_SAMPLE_SHIFT, NO_VLAN, fingerprint_hash,
    fingerprint_hash_with_length, fingerprint_selected, parse_fingerprint_metadata,
};

#[test]
fn fixed_fnv_vectors_include_exact_length_and_bound_the_prefix() {
    let short = (0_u8..14).collect::<Vec<_>>();
    assert_eq!(fingerprint_hash(&short), Some(0xd0d7_0fe3_0876_5f64));

    let long = (0_u8..80)
        .map(|index| index.wrapping_mul(3).wrapping_add(7))
        .collect::<Vec<_>>();
    assert_eq!(FINGERPRINT_PREFIX_LEN, 60);
    assert_eq!(fingerprint_hash(&long), Some(0x8480_dad8_815a_62f9));
    assert_eq!(
        fingerprint_hash_with_length(80, &long[..FINGERPRINT_PREFIX_LEN]),
        fingerprint_hash(&long)
    );
    assert_eq!(fingerprint_hash_with_length(80, &long[..59]), None);

    let mut same_prefix_different_tail = long.clone();
    same_prefix_different_tail[79] ^= 0xff;
    assert_eq!(
        fingerprint_hash(&same_prefix_different_tail),
        fingerprint_hash(&long)
    );

    same_prefix_different_tail.push(0);
    assert_eq!(
        fingerprint_hash(&same_prefix_different_tail),
        Some(0xfa47_a937_8f95_8332),
    );
}

#[test]
fn fingerprint_rejects_unrepresentable_frames_and_uses_fixed_shift_four() {
    let mut selected = (0_u8..64)
        .map(|index| index.wrapping_mul(5).wrapping_add(11))
        .collect::<Vec<_>>();
    selected[59] = 1;
    let selected_hash = fingerprint_hash(&selected).expect("representable frame");

    assert_eq!(selected_hash, 0xf7b5_05e5_552f_7ab0);
    assert_eq!(FINGERPRINT_SAMPLE_SHIFT, 4);
    assert!(fingerprint_selected(selected_hash));

    selected[59] = 2;
    assert!(!fingerprint_selected(
        fingerprint_hash(&selected).expect("representable frame")
    ));
    assert_eq!(fingerprint_hash(&vec![0; usize::from(u16::MAX) + 1]), None);
}

#[test]
fn normalizes_untagged_ipv4_icmp_metadata() {
    let mut frame = [0_u8; 64];
    frame[..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0, 0, 1]);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[23] = 1;
    frame[34] = 8;

    let metadata = parse_fingerprint_metadata(&frame).expect("valid IPv4 frame");
    assert_eq!(metadata.outer_vlan_id, NO_VLAN);
    assert_eq!(metadata.ether_type, 0x0800);
    assert_eq!(metadata.vlan_depth, 0);
    assert_eq!(metadata.protocol, 1);
    assert_eq!(metadata.subtype, 8);
    assert_eq!(metadata.source_mac, [0x02, 0, 0, 0, 0, 1]);
    assert_eq!(metadata.destination_mac, [0x01, 0x00, 0x5e, 0, 0, 1]);
}

#[test]
fn normalizes_one_visible_vlan_and_bounds_a_nested_tag() {
    let mut ipv6 = [0_u8; 64];
    ipv6[..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 1]);
    ipv6[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    ipv6[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
    ipv6[14..16].copy_from_slice(&0x0123_u16.to_be_bytes());
    ipv6[16..18].copy_from_slice(&0x86dd_u16.to_be_bytes());
    ipv6[18] = 0x60;
    ipv6[24] = 58;
    ipv6[58] = 135;

    let metadata = parse_fingerprint_metadata(&ipv6).expect("valid VLAN IPv6 frame");
    assert_eq!(metadata.outer_vlan_id, 0x0123);
    assert_eq!(metadata.ether_type, 0x86dd);
    assert_eq!(metadata.vlan_depth, 1);
    assert_eq!(metadata.protocol, 58);
    assert_eq!(metadata.subtype, 135);

    ipv6[16..18].copy_from_slice(&0x88a8_u16.to_be_bytes());
    let nested = parse_fingerprint_metadata(&ipv6).expect("bounded nested VLAN frame");
    assert_eq!(nested.outer_vlan_id, 0x0123);
    assert_eq!(nested.ether_type, 0x88a8);
    assert_eq!(nested.vlan_depth, 2);
    assert_eq!(nested.protocol, 0);
    assert_eq!(nested.subtype, 0);
}

#[test]
fn normalizes_visible_arp_opcode_without_payload_capture() {
    let mut frame = [0_u8; 64];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 3]);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());

    let metadata = parse_fingerprint_metadata(&frame).expect("valid ARP frame");
    assert_eq!(metadata.protocol, 0);
    assert_eq!(metadata.subtype, 1);
}
