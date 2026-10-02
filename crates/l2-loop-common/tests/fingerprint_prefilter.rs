use l2_loop_common::selected_fingerprint_hash;

// Independent straightforward FNV oracle, not a production hash/helper call.
fn reference(length: u16, frame: &[u8; 60]) -> Option<u64> {
    if length < 60 {
        return None;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in length.to_be_bytes().iter().chain(frame) {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash & 15 == 0).then_some(hash)
}

#[test]
fn selected_hash_retains_literal_identity_and_rejects_unselected_or_short_frames() {
    let mut frame = core::array::from_fn(|index| (index as u8).wrapping_mul(5).wrapping_add(11));
    frame[59] = 1;
    assert_eq!(
        selected_fingerprint_hash(64, &frame),
        Some(0xf7b5_05e5_552f_7ab0)
    );
    frame[59] = 2;
    assert_eq!(selected_fingerprint_hash(64, &frame), None);
    for length in 0..60 {
        assert_eq!(selected_fingerprint_hash(length, &frame), None);
    }
}

#[test]
fn every_length_preserves_selection_and_exact_selected_hash() {
    let frame = core::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(19));
    for length in 60..=u16::MAX {
        assert_eq!(
            selected_fingerprint_hash(length, &frame),
            reference(length, &frame),
            "length {length}"
        );
    }
}

#[test]
fn every_prefix_position_and_byte_preserves_the_contract() {
    let mut frame = core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(3));
    for offset in 0..60 {
        for byte in 0..=u8::MAX {
            frame[offset] = byte;
            for length in [60, 64, 512, 1514, u16::MAX] {
                assert_eq!(
                    selected_fingerprint_hash(length, &frame),
                    reference(length, &frame),
                    "offset {offset}, byte {byte}, length {length}"
                );
            }
        }
    }
}

#[test]
fn deterministic_varied_frames_preserve_all_bits_not_just_selection() {
    let mut state = 0x74e9_2537_481d_a26f_u64;
    for _ in 0..20_000 {
        let mut frame = [0; 60];
        for byte in &mut frame {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state >> 32) as u8;
        }
        let length = 60 + (state % (u64::from(u16::MAX) - 59)) as u16;
        assert_eq!(
            selected_fingerprint_hash(length, &frame),
            reference(length, &frame)
        );
    }
}
