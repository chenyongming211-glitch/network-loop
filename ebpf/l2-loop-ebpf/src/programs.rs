use aya_ebpf::{
    bindings::{TC_ACT_OK, xdp_action},
    helpers::bpf_ktime_get_ns,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use l2_loop_common::{
    CounterValue, FINGERPRINT_PREFIX_LEN, FINGERPRINT_SAMPLE_SHIFT, FingerprintKey,
    FingerprintMetadata, FingerprintValue, NO_VLAN, ParsedL2Word, StatsKey, direction,
    fingerprint_hash_init, fingerprint_hash_step, fingerprint_selected, hook_role, parse_l2_word,
    vlan_visibility,
};

use crate::maps::{FINGERPRINTS, HOOK_STATS, IFACE_CONFIG};

const BPF_NOEXIST: u64 = 1;

#[inline(always)]
fn increment_counter(counter: *mut CounterValue, bytes: u64) {
    unsafe {
        (*counter).packets = (*counter).packets.wrapping_add(1);
        (*counter).bytes = (*counter).bytes.wrapping_add(bytes);
    }
}

#[inline(always)]
fn increment_existing(key: StatsKey, bytes: u64) {
    if let Some(counter) = HOOK_STATS.get_ptr_mut(&key) {
        increment_counter(counter, bytes);
    }
}

#[inline(always)]
fn packet_prefix<const N: usize>(data: usize, data_end: usize) -> Option<*const [u8; N]> {
    if data + N > data_end {
        None
    } else {
        Some(data as *const [u8; N])
    }
}

#[inline(always)]
fn parse_packet(data: usize, data_end: usize) -> ParsedL2Word {
    let Some(ethernet) = packet_prefix::<14>(data, data_end) else {
        return ParsedL2Word::truncated_ethernet();
    };
    let ethernet = unsafe { &*ethernet };
    let outer_ether_type = u16::from_be_bytes([ethernet[12], ethernet[13]]);

    if matches!(outer_ether_type, 0x8100 | 0x88a8) {
        let Some(tagged) = packet_prefix::<18>(data, data_end) else {
            return ParsedL2Word::truncated_vlan();
        };
        parse_l2_word(unsafe { &*tagged })
    } else {
        parse_l2_word(ethernet)
    }
}

#[inline(always)]
fn packet_byte(data: usize, data_end: usize, prefix_len: usize, offset: usize) -> Option<u8> {
    if offset >= prefix_len || offset >= FINGERPRINT_PREFIX_LEN || data + offset + 1 > data_end {
        None
    } else {
        Some(unsafe { *((data + offset) as *const u8) })
    }
}

#[inline(always)]
fn packet_u16(data: usize, data_end: usize, prefix_len: usize, offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        packet_byte(data, data_end, prefix_len, offset)?,
        packet_byte(data, data_end, prefix_len, offset + 1)?,
    ]))
}

#[inline(always)]
fn packet_mac(data: usize, data_end: usize, prefix_len: usize, offset: usize) -> Option<[u8; 6]> {
    Some([
        packet_byte(data, data_end, prefix_len, offset)?,
        packet_byte(data, data_end, prefix_len, offset + 1)?,
        packet_byte(data, data_end, prefix_len, offset + 2)?,
        packet_byte(data, data_end, prefix_len, offset + 3)?,
        packet_byte(data, data_end, prefix_len, offset + 4)?,
        packet_byte(data, data_end, prefix_len, offset + 5)?,
    ])
}

#[inline(always)]
fn packet_fingerprint_hash(
    frame_len: u16,
    data: usize,
    data_end: usize,
    prefix_len: usize,
) -> Option<u64> {
    let mut hash = fingerprint_hash_init(frame_len);
    let mut index = 0;
    while index < FINGERPRINT_PREFIX_LEN {
        if index >= prefix_len {
            break;
        }
        hash = fingerprint_hash_step(hash, packet_byte(data, data_end, prefix_len, index)?);
        index += 1;
    }
    if index == prefix_len {
        Some(hash)
    } else {
        None
    }
}

#[inline(always)]
fn packet_protocol_subtype(
    data: usize,
    data_end: usize,
    prefix_len: usize,
    network_offset: usize,
    ether_type: u16,
) -> (u8, u8) {
    match ether_type {
        0x0800 => {
            let Some(first) = packet_byte(data, data_end, prefix_len, network_offset) else {
                return (0, 0);
            };
            let header_len = usize::from(first & 0x0f) * 4;
            if first >> 4 != 4
                || header_len < 20
                || network_offset + header_len > prefix_len
                || network_offset + header_len > FINGERPRINT_PREFIX_LEN
            {
                return (0, 0);
            }
            let Some(protocol) = packet_byte(data, data_end, prefix_len, network_offset + 9) else {
                return (0, 0);
            };
            let subtype = if protocol == 1 {
                packet_byte(data, data_end, prefix_len, network_offset + header_len)
                    .unwrap_or_default()
            } else {
                0
            };
            (protocol, subtype)
        }
        0x86dd => {
            if packet_byte(data, data_end, prefix_len, network_offset).unwrap_or_default() >> 4 != 6
                || network_offset + 40 > prefix_len
            {
                return (0, 0);
            }
            let protocol =
                packet_byte(data, data_end, prefix_len, network_offset + 6).unwrap_or_default();
            let subtype = if protocol == 58 {
                packet_byte(data, data_end, prefix_len, network_offset + 40).unwrap_or_default()
            } else {
                0
            };
            (protocol, subtype)
        }
        0x0806 => (
            0,
            packet_u16(data, data_end, prefix_len, network_offset + 6)
                .filter(|opcode| *opcode <= u16::from(u8::MAX))
                .unwrap_or_default() as u8,
        ),
        _ => (0, 0),
    }
}

#[inline(always)]
fn packet_fingerprint_metadata(
    data: usize,
    data_end: usize,
    prefix_len: usize,
) -> Option<FingerprintMetadata> {
    if prefix_len < 14 {
        return None;
    }
    let destination_mac = packet_mac(data, data_end, prefix_len, 0)?;
    let source_mac = packet_mac(data, data_end, prefix_len, 6)?;
    let outer_ether_type = packet_u16(data, data_end, prefix_len, 12)?;
    let (ether_type, outer_vlan_id, vlan_depth, network_offset) =
        if matches!(outer_ether_type, 0x8100 | 0x88a8) {
            if prefix_len < 18 {
                return None;
            }
            let inner_ether_type = packet_u16(data, data_end, prefix_len, 16)?;
            (
                inner_ether_type,
                packet_u16(data, data_end, prefix_len, 14)? & 0x0fff,
                if matches!(inner_ether_type, 0x8100 | 0x88a8) {
                    2
                } else {
                    1
                },
                18,
            )
        } else {
            (outer_ether_type, NO_VLAN, 0, 14)
        };
    let (protocol, subtype) = if vlan_depth == 2 {
        (0, 0)
    } else {
        packet_protocol_subtype(data, data_end, prefix_len, network_offset, ether_type)
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

#[inline(always)]
fn account_fingerprint(
    interface_generation: u64,
    ifindex: u32,
    direction: u8,
    bytes: u64,
    data: usize,
    data_end: usize,
) {
    let Ok(frame_len) = u16::try_from(bytes) else {
        return;
    };
    let prefix_len = if bytes < FINGERPRINT_PREFIX_LEN as u64 {
        bytes as usize
    } else {
        FINGERPRINT_PREFIX_LEN
    };
    let Some(fingerprint) = packet_fingerprint_hash(frame_len, data, data_end, prefix_len) else {
        return;
    };
    if !fingerprint_selected(fingerprint) {
        return;
    }
    let Some(metadata) = packet_fingerprint_metadata(data, data_end, prefix_len) else {
        return;
    };
    let key = FingerprintKey {
        interface_generation,
        fingerprint,
        ifindex,
        outer_vlan_id: metadata.outer_vlan_id,
        ether_type: metadata.ether_type,
        frame_len,
        direction,
        vlan_depth: metadata.vlan_depth,
        protocol: metadata.protocol,
        subtype: metadata.subtype,
        reserved: [0; 2],
    };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if let Some(value) = FINGERPRINTS.get_ptr_mut(&key) {
        unsafe {
            (*value).last_seen_ns = now_ns;
            (*value).packets = (*value).packets.saturating_add(1);
            (*value).bytes = (*value).bytes.saturating_add(bytes);
        }
        return;
    }
    let value = FingerprintValue {
        first_seen_ns: now_ns,
        last_seen_ns: now_ns,
        packets: 1,
        bytes,
        source_mac: metadata.source_mac,
        destination_mac: metadata.destination_mac,
        reserved: [0; 4],
    };
    let _ = FINGERPRINTS.insert(&key, &value, BPF_NOEXIST);
}

#[inline(always)]
fn account(ifindex: u32, hook_role: u8, bytes: u64, data: usize, data_end: usize) {
    let (interface_generation, current_vlan_visibility, sample_shift) = {
        let Some(config) = IFACE_CONFIG.get_ptr(&ifindex) else {
            return;
        };
        unsafe {
            (
                (*config).interface_generation,
                (*config).vlan_visibility,
                (*config).sample_shift,
            )
        }
    };
    increment_existing(
        StatsKey::total(interface_generation, ifindex, hook_role),
        bytes,
    );

    let parsed = parse_packet(data, data_end);
    if parsed.is_error() {
        increment_existing(
            StatsKey::parse_error(interface_generation, ifindex, hook_role),
            bytes,
        );
    } else {
        increment_existing(
            StatsKey::classified(
                interface_generation,
                ifindex,
                hook_role,
                parsed.traffic_class(),
            ),
            bytes,
        );
        if parsed.has_outer_vlan() && current_vlan_visibility == vlan_visibility::UNKNOWN {
            if let Some(config) = IFACE_CONFIG.get_ptr_mut(&ifindex) {
                unsafe {
                    if (*config).interface_generation == interface_generation
                        && (*config).vlan_visibility == vlan_visibility::UNKNOWN
                    {
                        (*config).vlan_visibility = vlan_visibility::VERIFIED_VISIBLE;
                    }
                }
            }
        }
        if sample_shift == FINGERPRINT_SAMPLE_SHIFT {
            let fingerprint_direction = match hook_role {
                hook_role::EXTERNAL_XDP_INGRESS => direction::INGRESS,
                hook_role::PHYSICAL_TC_EGRESS => direction::EGRESS,
                _ => return,
            };
            account_fingerprint(
                interface_generation,
                ifindex,
                fingerprint_direction,
                bytes,
                data,
                data_end,
            );
        }
    }
}

#[inline(always)]
fn account_xdp(ctx: &XdpContext, hook_role: u8) {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let Some(bytes) = data_end.checked_sub(data) else {
        return;
    };
    account(
        ctx.ingress_ifindex() as u32,
        hook_role,
        bytes as u64,
        data,
        data_end,
    );
}

#[inline(always)]
fn account_tc(ctx: &TcContext, hook_role: u8) {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    account(
        ifindex,
        hook_role,
        u64::from(ctx.len()),
        ctx.data(),
        ctx.data_end(),
    );
}

#[xdp]
pub fn l2_loop_xdp_ingress(ctx: XdpContext) -> u32 {
    account_xdp(&ctx, hook_role::EXTERNAL_XDP_INGRESS);
    xdp_action::XDP_PASS
}

#[classifier]
pub fn l2_loop_tc_egress(ctx: TcContext) -> i32 {
    account_tc(&ctx, hook_role::PHYSICAL_TC_EGRESS);
    TC_ACT_OK
}

#[classifier]
pub fn l2_loop_tc_path_ingress(ctx: TcContext) -> i32 {
    account_tc(&ctx, hook_role::TEMPORARY_PATH_INGRESS);
    TC_ACT_OK
}

#[classifier]
pub fn l2_loop_tc_path_egress(ctx: TcContext) -> i32 {
    account_tc(&ctx, hook_role::TEMPORARY_PATH_EGRESS);
    TC_ACT_OK
}
