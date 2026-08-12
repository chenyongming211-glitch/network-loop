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
fn packet_byte_at<const OFFSET: usize>(
    data: usize,
    data_end: usize,
    prefix_len: usize,
) -> Option<u8> {
    if prefix_len <= OFFSET || data + OFFSET + 1 > data_end {
        None
    } else {
        Some(unsafe { *((data + OFFSET) as *const u8) })
    }
}

#[inline(always)]
fn packet_u16_at<const OFFSET: usize>(
    data: usize,
    data_end: usize,
    prefix_len: usize,
) -> Option<u16> {
    if prefix_len < OFFSET + 2 || data + OFFSET + 2 > data_end {
        None
    } else {
        Some(unsafe {
            u16::from_be_bytes([
                *((data + OFFSET) as *const u8),
                *((data + OFFSET + 1) as *const u8),
            ])
        })
    }
}

#[inline(always)]
fn packet_mac_at<const OFFSET: usize>(
    data: usize,
    data_end: usize,
    prefix_len: usize,
) -> Option<[u8; 6]> {
    if prefix_len < OFFSET + 6 || data + OFFSET + 6 > data_end {
        None
    } else {
        Some(unsafe {
            [
                *((data + OFFSET) as *const u8),
                *((data + OFFSET + 1) as *const u8),
                *((data + OFFSET + 2) as *const u8),
                *((data + OFFSET + 3) as *const u8),
                *((data + OFFSET + 4) as *const u8),
                *((data + OFFSET + 5) as *const u8),
            ]
        })
    }
}

#[inline(always)]
fn packet_fingerprint_hash(
    frame_len: u16,
    data: usize,
    data_end: usize,
    prefix_len: usize,
) -> Option<u64> {
    let mut hash = fingerprint_hash_init(frame_len);
    macro_rules! hash_byte_at {
        ($offset:literal) => {
            if prefix_len > $offset {
                hash = fingerprint_hash_step(
                    hash,
                    packet_byte_at::<$offset>(data, data_end, prefix_len)?,
                );
            }
        };
    }
    hash_byte_at!(0);
    hash_byte_at!(1);
    hash_byte_at!(2);
    hash_byte_at!(3);
    hash_byte_at!(4);
    hash_byte_at!(5);
    hash_byte_at!(6);
    hash_byte_at!(7);
    hash_byte_at!(8);
    hash_byte_at!(9);
    hash_byte_at!(10);
    hash_byte_at!(11);
    hash_byte_at!(12);
    hash_byte_at!(13);
    hash_byte_at!(14);
    hash_byte_at!(15);
    hash_byte_at!(16);
    hash_byte_at!(17);
    hash_byte_at!(18);
    hash_byte_at!(19);
    hash_byte_at!(20);
    hash_byte_at!(21);
    hash_byte_at!(22);
    hash_byte_at!(23);
    hash_byte_at!(24);
    hash_byte_at!(25);
    hash_byte_at!(26);
    hash_byte_at!(27);
    hash_byte_at!(28);
    hash_byte_at!(29);
    hash_byte_at!(30);
    hash_byte_at!(31);
    hash_byte_at!(32);
    hash_byte_at!(33);
    hash_byte_at!(34);
    hash_byte_at!(35);
    hash_byte_at!(36);
    hash_byte_at!(37);
    hash_byte_at!(38);
    hash_byte_at!(39);
    hash_byte_at!(40);
    hash_byte_at!(41);
    hash_byte_at!(42);
    hash_byte_at!(43);
    hash_byte_at!(44);
    hash_byte_at!(45);
    hash_byte_at!(46);
    hash_byte_at!(47);
    hash_byte_at!(48);
    hash_byte_at!(49);
    hash_byte_at!(50);
    hash_byte_at!(51);
    hash_byte_at!(52);
    hash_byte_at!(53);
    hash_byte_at!(54);
    hash_byte_at!(55);
    hash_byte_at!(56);
    hash_byte_at!(57);
    hash_byte_at!(58);
    hash_byte_at!(59);
    hash_byte_at!(60);
    hash_byte_at!(61);
    hash_byte_at!(62);
    hash_byte_at!(63);
    Some(hash)
}

#[inline(always)]
fn ipv4_subtype_untagged(
    data: usize,
    data_end: usize,
    prefix_len: usize,
) -> u8 {
    let ihl = packet_byte_at::<14>(data, data_end, prefix_len).unwrap_or_default() & 0x0f;
    match ihl {
        5 => packet_byte_at::<34>(data, data_end, prefix_len),
        6 => packet_byte_at::<38>(data, data_end, prefix_len),
        7 => packet_byte_at::<42>(data, data_end, prefix_len),
        8 => packet_byte_at::<46>(data, data_end, prefix_len),
        9 => packet_byte_at::<50>(data, data_end, prefix_len),
        10 => packet_byte_at::<54>(data, data_end, prefix_len),
        11 => packet_byte_at::<58>(data, data_end, prefix_len),
        12 => packet_byte_at::<62>(data, data_end, prefix_len),
        _ => None,
    }
    .unwrap_or_default()
}

#[inline(always)]
fn ipv4_subtype_tagged(data: usize, data_end: usize, prefix_len: usize) -> u8 {
    let ihl = packet_byte_at::<18>(data, data_end, prefix_len).unwrap_or_default() & 0x0f;
    match ihl {
        5 => packet_byte_at::<38>(data, data_end, prefix_len),
        6 => packet_byte_at::<42>(data, data_end, prefix_len),
        7 => packet_byte_at::<46>(data, data_end, prefix_len),
        8 => packet_byte_at::<50>(data, data_end, prefix_len),
        9 => packet_byte_at::<54>(data, data_end, prefix_len),
        10 => packet_byte_at::<58>(data, data_end, prefix_len),
        11 => packet_byte_at::<62>(data, data_end, prefix_len),
        _ => None,
    }
    .unwrap_or_default()
}

#[inline(always)]
fn packet_protocol_subtype_untagged(
    data: usize,
    data_end: usize,
    prefix_len: usize,
    ether_type: u16,
) -> (u8, u8) {
    match ether_type {
        0x0800 => {
            let first = packet_byte_at::<14>(data, data_end, prefix_len).unwrap_or_default();
            let protocol = packet_byte_at::<23>(data, data_end, prefix_len).unwrap_or_default();
            if first >> 4 != 4 || first & 0x0f < 5 {
                (0, 0)
            } else {
                (
                    protocol,
                    if protocol == 1 {
                        ipv4_subtype_untagged(data, data_end, prefix_len)
                    } else {
                        0
                    },
                )
            }
        }
        0x86dd => {
            let first = packet_byte_at::<14>(data, data_end, prefix_len).unwrap_or_default();
            let protocol = packet_byte_at::<20>(data, data_end, prefix_len).unwrap_or_default();
            if first >> 4 != 6 {
                (0, 0)
            } else {
                (
                    protocol,
                    if protocol == 58 {
                        packet_byte_at::<54>(data, data_end, prefix_len).unwrap_or_default()
                    } else {
                        0
                    },
                )
            }
        }
        0x0806 => (
            0,
            packet_u16_at::<20>(data, data_end, prefix_len)
                .filter(|opcode| *opcode <= u16::from(u8::MAX))
                .unwrap_or_default() as u8,
        ),
        _ => (0, 0),
    }
}

#[inline(always)]
fn packet_protocol_subtype_tagged(
    data: usize,
    data_end: usize,
    prefix_len: usize,
    ether_type: u16,
) -> (u8, u8) {
    match ether_type {
        0x0800 => {
            let first = packet_byte_at::<18>(data, data_end, prefix_len).unwrap_or_default();
            let protocol = packet_byte_at::<27>(data, data_end, prefix_len).unwrap_or_default();
            if first >> 4 != 4 || first & 0x0f < 5 {
                (0, 0)
            } else {
                (
                    protocol,
                    if protocol == 1 {
                        ipv4_subtype_tagged(data, data_end, prefix_len)
                    } else {
                        0
                    },
                )
            }
        }
        0x86dd => {
            let first = packet_byte_at::<18>(data, data_end, prefix_len).unwrap_or_default();
            let protocol = packet_byte_at::<24>(data, data_end, prefix_len).unwrap_or_default();
            if first >> 4 != 6 {
                (0, 0)
            } else {
                (
                    protocol,
                    if protocol == 58 {
                        packet_byte_at::<58>(data, data_end, prefix_len).unwrap_or_default()
                    } else {
                        0
                    },
                )
            }
        }
        0x0806 => (
            0,
            packet_u16_at::<24>(data, data_end, prefix_len)
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
    let destination_mac = packet_mac_at::<0>(data, data_end, prefix_len)?;
    let source_mac = packet_mac_at::<6>(data, data_end, prefix_len)?;
    let outer_ether_type = packet_u16_at::<12>(data, data_end, prefix_len)?;
    let (ether_type, outer_vlan_id, vlan_depth) =
        if matches!(outer_ether_type, 0x8100 | 0x88a8) {
            if prefix_len < 18 {
                return None;
            }
            let inner_ether_type = packet_u16_at::<16>(data, data_end, prefix_len)?;
            (
                inner_ether_type,
                packet_u16_at::<14>(data, data_end, prefix_len)? & 0x0fff,
                if matches!(inner_ether_type, 0x8100 | 0x88a8) {
                    2
                } else {
                    1
                },
            )
        } else {
            (outer_ether_type, NO_VLAN, 0)
        };
    let (protocol, subtype) = if vlan_depth == 2 {
        (0, 0)
    } else if vlan_depth == 1 {
        packet_protocol_subtype_tagged(data, data_end, prefix_len, ether_type)
    } else {
        packet_protocol_subtype_untagged(data, data_end, prefix_len, ether_type)
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
