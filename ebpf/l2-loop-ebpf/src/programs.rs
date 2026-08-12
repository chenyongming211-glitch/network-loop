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
fn fixed_fingerprint_hash(frame_len: u16, frame: &[u8; FINGERPRINT_PREFIX_LEN]) -> u64 {
    let mut hash = fingerprint_hash_init(frame_len);
    macro_rules! step {
        ($offset:literal) => {
            hash = fingerprint_hash_step(hash, frame[$offset]);
        };
    }
    step!(0);
    step!(1);
    step!(2);
    step!(3);
    step!(4);
    step!(5);
    step!(6);
    step!(7);
    step!(8);
    step!(9);
    step!(10);
    step!(11);
    step!(12);
    step!(13);
    step!(14);
    step!(15);
    step!(16);
    step!(17);
    step!(18);
    step!(19);
    step!(20);
    step!(21);
    step!(22);
    step!(23);
    step!(24);
    step!(25);
    step!(26);
    step!(27);
    step!(28);
    step!(29);
    step!(30);
    step!(31);
    step!(32);
    step!(33);
    step!(34);
    step!(35);
    step!(36);
    step!(37);
    step!(38);
    step!(39);
    step!(40);
    step!(41);
    step!(42);
    step!(43);
    step!(44);
    step!(45);
    step!(46);
    step!(47);
    step!(48);
    step!(49);
    step!(50);
    step!(51);
    step!(52);
    step!(53);
    step!(54);
    step!(55);
    step!(56);
    step!(57);
    step!(58);
    step!(59);
    hash
}

#[inline(always)]
fn fixed_ipv4_subtype_untagged(frame: &[u8; FINGERPRINT_PREFIX_LEN]) -> u8 {
    match frame[14] & 0x0f {
        5 => frame[34],
        6 => frame[38],
        7 => frame[42],
        8 => frame[46],
        9 => frame[50],
        10 => frame[54],
        11 => frame[58],
        _ => 0,
    }
}

#[inline(always)]
fn fixed_ipv4_subtype_tagged(frame: &[u8; FINGERPRINT_PREFIX_LEN]) -> u8 {
    match frame[18] & 0x0f {
        5 => frame[38],
        6 => frame[42],
        7 => frame[46],
        8 => frame[50],
        9 => frame[54],
        10 => frame[58],
        _ => 0,
    }
}

#[inline(always)]
fn fixed_protocol_subtype_untagged(
    frame: &[u8; FINGERPRINT_PREFIX_LEN],
    ether_type: u16,
) -> (u8, u8) {
    match ether_type {
        0x0800 => {
            let first = frame[14];
            let protocol = frame[23];
            if first >> 4 != 4 || first & 0x0f < 5 {
                (0, 0)
            } else {
                (
                    protocol,
                    if protocol == 1 {
                        fixed_ipv4_subtype_untagged(frame)
                    } else {
                        0
                    },
                )
            }
        }
        0x86dd => {
            let protocol = frame[20];
            if frame[14] >> 4 != 6 {
                (0, 0)
            } else {
                (protocol, if protocol == 58 { frame[54] } else { 0 })
            }
        }
        0x0806 => {
            let opcode = u16::from_be_bytes([frame[20], frame[21]]);
            (
                0,
                if opcode <= u8::MAX.into() {
                    opcode as u8
                } else {
                    0
                },
            )
        }
        _ => (0, 0),
    }
}

#[inline(always)]
fn fixed_protocol_subtype_tagged(
    frame: &[u8; FINGERPRINT_PREFIX_LEN],
    ether_type: u16,
) -> (u8, u8) {
    match ether_type {
        0x0800 => {
            let first = frame[18];
            let protocol = frame[27];
            if first >> 4 != 4 || first & 0x0f < 5 {
                (0, 0)
            } else {
                (
                    protocol,
                    if protocol == 1 {
                        fixed_ipv4_subtype_tagged(frame)
                    } else {
                        0
                    },
                )
            }
        }
        0x86dd => {
            let protocol = frame[24];
            if frame[18] >> 4 != 6 {
                (0, 0)
            } else {
                (protocol, if protocol == 58 { frame[58] } else { 0 })
            }
        }
        0x0806 => {
            let opcode = u16::from_be_bytes([frame[24], frame[25]]);
            (
                0,
                if opcode <= u8::MAX.into() {
                    opcode as u8
                } else {
                    0
                },
            )
        }
        _ => (0, 0),
    }
}

#[inline(always)]
fn fixed_fingerprint_metadata(frame: &[u8; FINGERPRINT_PREFIX_LEN]) -> FingerprintMetadata {
    let destination_mac = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];
    let source_mac = [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
    let outer_ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let (ether_type, outer_vlan_id, vlan_depth) = if matches!(outer_ether_type, 0x8100 | 0x88a8) {
        let inner = u16::from_be_bytes([frame[16], frame[17]]);
        (
            inner,
            u16::from_be_bytes([frame[14], frame[15]]) & 0x0fff,
            if matches!(inner, 0x8100 | 0x88a8) {
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
        fixed_protocol_subtype_tagged(frame, ether_type)
    } else {
        fixed_protocol_subtype_untagged(frame, ether_type)
    };
    FingerprintMetadata {
        source_mac,
        destination_mac,
        outer_vlan_id,
        ether_type,
        vlan_depth,
        protocol,
        subtype,
    }
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
    let Some(frame) = packet_prefix::<FINGERPRINT_PREFIX_LEN>(data, data_end) else {
        return;
    };
    let frame = unsafe { &*frame };
    let fingerprint = fixed_fingerprint_hash(frame_len, frame);
    if !fingerprint_selected(fingerprint) {
        return;
    }
    let metadata = fixed_fingerprint_metadata(frame);
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
