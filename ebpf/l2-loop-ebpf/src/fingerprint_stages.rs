//! Acceptance-only cumulative stages with a common observable per-CPU sink.
//! Never compiled into the ordinary product or the original four profiles.
use super::*;
use aya_ebpf::{macros::map, maps::PerCpuHashMap};

#[map]
pub static DIAG_RESULTS: PerCpuHashMap<u32, [u64; 8]> = PerCpuHashMap::with_max_entries(2, 0);

#[inline(always)]
fn mac_word(mac: [u8; 6]) -> u64 {
    u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0])
}

#[inline(always)]
fn selected<const STAGE: u8>(ifindex: u32, direction: u8, bytes: u64, data: usize, end: usize) {
    let Some(config) = IFACE_CONFIG.get_ptr(&ifindex) else { return; };
    let (generation, shift) = unsafe { ((*config).interface_generation, (*config).sample_shift) };
    if shift != FINGERPRINT_SAMPLE_SHIFT || parse_packet(data, end).is_error() { return; }
    let Ok(frame_len) = u16::try_from(bytes) else { return; };
    let Some(prefix) = packet_prefix::<FINGERPRINT_PREFIX_LEN>(data, end) else { return; };
    // SAFETY: the same bounded immutable prefix proof as the ordinary path.
    let frame = unsafe { &*prefix };
    let fingerprint = fixed_fingerprint_hash(frame_len, frame);
    if !fingerprint_selected(fingerprint) { return; }
    let mut packed_l2 = 0;
    let mut source = 0;
    let mut destination = 0;
    let mut now_ns = 0;
    if STAGE >= 2 {
        let metadata = fixed_fingerprint_metadata(frame);
        packed_l2 = u64::from(metadata.outer_vlan_id) | (u64::from(metadata.ether_type) << 16)
            | (u64::from(frame_len) << 32) | (u64::from(direction) << 48)
            | (u64::from(metadata.vlan_depth) << 56);
        source = mac_word(metadata.source_mac) | (u64::from(metadata.protocol) << 48)
            | (u64::from(metadata.subtype) << 56);
        destination = mac_word(metadata.destination_mac);
        if STAGE >= 3 { now_ns = unsafe { bpf_ktime_get_ns() }; }
        if STAGE == 4 {
            let key = FingerprintKey {
                interface_generation: generation, fingerprint, ifindex,
                outer_vlan_id: metadata.outer_vlan_id, ether_type: metadata.ether_type,
                frame_len, direction, vlan_depth: metadata.vlan_depth,
                protocol: metadata.protocol, subtype: metadata.subtype, reserved: [0; 2],
            };
            if let Some(value) = FINGERPRINTS.get_ptr_mut(&key) {
                unsafe {
                    (*value).last_seen_ns = now_ns;
                    (*value).packets = (*value).packets.saturating_add(1);
                    (*value).bytes = (*value).bytes.saturating_add(bytes);
                }
            } else {
                let value = FingerprintValue {
                    first_seen_ns: now_ns, last_seen_ns: now_ns, packets: 1, bytes,
                    source_mac: metadata.source_mac, destination_mac: metadata.destination_mac,
                    reserved: [0; 4],
                };
                let _ = FINGERPRINTS.insert(&key, &value, BPF_NOEXIST);
            }
        }
    }
    // Every stage records the same fixed 64-byte shape. No packet is modified.
    if let Some(result) = DIAG_RESULTS.get_ptr_mut(&u32::from(direction - 1)) {
        unsafe {
            let count = (*result)[5].saturating_add(1);
            *result = [fingerprint, packed_l2, source, destination, now_ns, count, 0, 0];
        }
    }
}

#[inline(always)]
pub(crate) fn xdp<const STAGE: u8>(ctx: &XdpContext) {
    account_xdp_layer::<false>(ctx, hook_role::EXTERNAL_XDP_INGRESS);
    if let Some(bytes) = ctx.data_end().checked_sub(ctx.data()) {
        selected::<STAGE>(ctx.ingress_ifindex() as u32, direction::INGRESS, bytes as u64, ctx.data(), ctx.data_end());
    }
}

#[inline(always)]
pub(crate) fn tc<const STAGE: u8>(ctx: &TcContext) {
    account_tc_layer::<false>(ctx, hook_role::PHYSICAL_TC_EGRESS);
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    selected::<STAGE>(ifindex, direction::EGRESS, u64::from(ctx.len()), ctx.data(), ctx.data_end());
}
