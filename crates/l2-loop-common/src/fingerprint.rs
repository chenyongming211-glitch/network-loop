use crate::NO_VLAN;

pub const FINGERPRINT_PREFIX_LEN: usize = 64;
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
    let mut hash = FNV_OFFSET_BASIS;
    for byte in frame_len.to_be_bytes() {
        hash = fnv_step(hash, byte);
    }
    for byte in frame.iter().take(FINGERPRINT_PREFIX_LEN) {
        hash = fnv_step(hash, *byte);
    }
    Some(hash)
}

pub const fn fingerprint_selected(fingerprint: u64) -> bool {
    fingerprint & ((1_u64 << FINGERPRINT_SAMPLE_SHIFT) - 1) == 0
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

const fn fnv_step(hash: u64, byte: u8) -> u64 {
    (hash ^ byte as u64).wrapping_mul(FNV_PRIME)
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
