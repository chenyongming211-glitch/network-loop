use aya_ebpf::{
    bindings::{TC_ACT_OK, xdp_action},
    helpers::bpf_ktime_get_ns,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use l2_loop_common::{
    CounterValue, FINGERPRINT_PREFIX_LEN, FINGERPRINT_SAMPLE_SHIFT, FingerprintKey,
    FingerprintValue, ParsedL2Word, StatsKey, direction, fingerprint_hash_with_length,
    fingerprint_selected, hook_role, parse_fingerprint_metadata, parse_l2_word, vlan_visibility,
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
    let Some(fingerprint) = fingerprint_hash_with_length(frame_len, frame) else {
        return;
    };
    if !fingerprint_selected(fingerprint) {
        return;
    }
    let Some(metadata) = parse_fingerprint_metadata(frame) else {
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
