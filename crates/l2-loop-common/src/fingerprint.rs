use crate::NO_VLAN;

pub const FINGERPRINT_PREFIX_LEN: usize = 60;
pub const FINGERPRINT_SAMPLE_SHIFT: u8 = 4;

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintMetadata {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub outer_vlan_id: u16,
    pub ether_type: u16,
    pub vlan_depth: u8,
    pub protocol: u8,
    pub subtype: u8,
}

pub fn fingerprint_hash(frame: &[u8]) -> Option<u64> {
    let frame_len = u16::try_from(frame.len()).ok()?;
    let prefix_len = frame.len().min(FINGERPRINT_PREFIX_LEN);
    fingerprint_hash_with_length(frame_len, &frame[..prefix_len])
}

pub fn fingerprint_hash_with_length(frame_len: u16, prefix: &[u8]) -> Option<u64> {
    let expected_prefix_len = usize::from(frame_len).min(FINGERPRINT_PREFIX_LEN);
    if prefix.len() != expected_prefix_len {
        return None;
    }
    let mut hash = fingerprint_hash_init(frame_len);
    for byte in prefix {
        hash = fingerprint_hash_step(hash, *byte);
    }
    Some(hash)
}

pub const fn fingerprint_hash_init(frame_len: u16) -> u64 {
    let bytes = frame_len.to_be_bytes();
    fingerprint_hash_step(fingerprint_hash_step(FNV_OFFSET_BASIS, bytes[0]), bytes[1])
}

pub const fn fingerprint_hash_step(hash: u64, byte: u8) -> u64 {
    (hash ^ byte as u64).wrapping_mul(FNV_PRIME)
}

pub const fn fingerprint_selected(fingerprint: u64) -> bool {
    fingerprint & ((1_u64 << FINGERPRINT_SAMPLE_SHIFT) - 1) == 0
}

// Keep packet offsets static for the BPF verifier; use the same offsets for the
// low-bit screen and the unchanged complete hash.
macro_rules! each_prefix_byte {
    ($step:ident) => {
        $step!(0);
        $step!(1);
        $step!(2);
        $step!(3);
        $step!(4);
        $step!(5);
        $step!(6);
        $step!(7);
        $step!(8);
        $step!(9);
        $step!(10);
        $step!(11);
        $step!(12);
        $step!(13);
        $step!(14);
        $step!(15);
        $step!(16);
        $step!(17);
        $step!(18);
        $step!(19);
        $step!(20);
        $step!(21);
        $step!(22);
        $step!(23);
        $step!(24);
        $step!(25);
        $step!(26);
        $step!(27);
        $step!(28);
        $step!(29);
        $step!(30);
        $step!(31);
        $step!(32);
        $step!(33);
        $step!(34);
        $step!(35);
        $step!(36);
        $step!(37);
        $step!(38);
        $step!(39);
        $step!(40);
        $step!(41);
        $step!(42);
        $step!(43);
        $step!(44);
        $step!(45);
        $step!(46);
        $step!(47);
        $step!(48);
        $step!(49);
        $step!(50);
        $step!(51);
        $step!(52);
        $step!(53);
        $step!(54);
        $step!(55);
        $step!(56);
        $step!(57);
        $step!(58);
        $step!(59);
    };
}

/// Return exactly the existing 64-bit fingerprint for selected fixed prefixes.
///
/// FNV's low four bits depend only on the low four bits at each preceding step.
/// Modulo 16 its basis is 5 and prime is 3. Wrapping u32 arithmetic therefore
/// screens with the identical predicate, avoiding full-width FNV multiplication
/// for unselected packets. Selected packets still use the unchanged full hash.
#[inline(always)]
pub fn selected_fingerprint_hash(
    frame_len: u16,
    frame: &[u8; FINGERPRINT_PREFIX_LEN],
) -> Option<u64> {
    if usize::from(frame_len) < FINGERPRINT_PREFIX_LEN {
        return None;
    }
    let length = frame_len.to_be_bytes();
    let mut screen =
        ((5_u32 ^ u32::from(length[0])).wrapping_mul(3) ^ u32::from(length[1])).wrapping_mul(3);
    macro_rules! screen_step {
        ($offset:literal) => {
            // SAFETY: the reference covers every static offset. Volatile reads
            // prevent LLVM retaining all 60 bytes across the second pass and
            // spilling them beyond the BPF stack bound. No helpers or packet
            // mutation occur between the two passes.
            let byte = unsafe { core::ptr::read_volatile(&frame[$offset]) };
            screen = (screen ^ u32::from(byte)).wrapping_mul(3);
        };
    }
    each_prefix_byte!(screen_step);
    if screen & 15 != 0 {
        return None;
    }
    let mut hash = fingerprint_hash_init(frame_len);
    macro_rules! hash_step {
        ($offset:literal) => {
            // SAFETY: same bounded immutable prefix as the screen above.
            hash =
                fingerprint_hash_step(hash, unsafe { core::ptr::read_volatile(&frame[$offset]) });
        };
    }
    each_prefix_byte!(hash_step);
    Some(hash)
}

pub fn parse_fingerprint_metadata(frame: &[u8]) -> Option<FingerprintMetadata> {
    if frame.len() < 14 {
        return None;
    }
    let destination_mac = copy_mac(frame, 0)?;
    let source_mac = copy_mac(frame, 6)?;
    let outer_ether_type = read_u16(frame, 12)?;
    let (ether_type, outer_vlan_id, vlan_depth, network_offset) = if is_vlan_tpid(outer_ether_type)
    {
        if frame.len() < 18 {
            return None;
        }
        let inner_ether_type = read_u16(frame, 16)?;
        (
            inner_ether_type,
            read_u16(frame, 14)? & 0x0fff,
            if is_vlan_tpid(inner_ether_type) { 2 } else { 1 },
            18,
        )
    } else {
        (outer_ether_type, NO_VLAN, 0, 14)
    };
    let (protocol, subtype) = if vlan_depth == 2 {
        (0, 0)
    } else {
        protocol_and_subtype(frame, network_offset, ether_type)
    };

    Some(FingerprintMetadata {
        source_mac,
        destination_mac,
        outer_vlan_id,
        ether_type,
        vlan_depth,
        protocol,
        subtype,
    })
}

fn protocol_and_subtype(frame: &[u8], offset: usize, ether_type: u16) -> (u8, u8) {
    match ether_type {
        ETH_P_IPV4 => ipv4_protocol_and_subtype(frame, offset),
        ETH_P_IPV6 => ipv6_protocol_and_subtype(frame, offset),
        ETH_P_ARP => (
            0,
            read_u16(frame, offset + 6)
                .filter(|opcode| *opcode <= u16::from(u8::MAX))
                .unwrap_or_default() as u8,
        ),
        _ => (0, 0),
    }
}

fn ipv4_protocol_and_subtype(frame: &[u8], offset: usize) -> (u8, u8) {
    let Some(first) = frame.get(offset).copied() else {
        return (0, 0);
    };
    let header_len = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || header_len < 20 || offset + header_len > frame.len() {
        return (0, 0);
    }
    let Some(protocol) = frame.get(offset + 9).copied() else {
        return (0, 0);
    };
    let subtype = if protocol == IPPROTO_ICMP {
        frame.get(offset + header_len).copied().unwrap_or_default()
    } else {
        0
    };
    (protocol, subtype)
}

fn ipv6_protocol_and_subtype(frame: &[u8], offset: usize) -> (u8, u8) {
    if frame.get(offset).copied().unwrap_or_default() >> 4 != 6 || offset + 40 > frame.len() {
        return (0, 0);
    }
    let protocol = frame[offset + 6];
    let subtype = if protocol == IPPROTO_ICMPV6 {
        frame.get(offset + 40).copied().unwrap_or_default()
    } else {
        0
    };
    (protocol, subtype)
}

fn copy_mac(frame: &[u8], offset: usize) -> Option<[u8; 6]> {
    Some([
        *frame.get(offset)?,
        *frame.get(offset + 1)?,
        *frame.get(offset + 2)?,
        *frame.get(offset + 3)?,
        *frame.get(offset + 4)?,
        *frame.get(offset + 5)?,
    ])
}

fn read_u16(frame: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *frame.get(offset)?,
        *frame.get(offset + 1)?,
    ]))
}

const fn is_vlan_tpid(ether_type: u16) -> bool {
    matches!(ether_type, ETH_P_8021Q | ETH_P_8021AD)
}
