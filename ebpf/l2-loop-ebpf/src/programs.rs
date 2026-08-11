use aya_ebpf::{
    bindings::{TC_ACT_OK, xdp_action},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use l2_loop_common::{
    CounterValue, ParseError, ParsedL2, StatsKey, hook_role, parse_l2, vlan_visibility,
};

use crate::maps::{HOOK_STATS, IFACE_CONFIG};

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
fn parse_packet(data: usize, data_end: usize) -> Result<ParsedL2, ParseError> {
    let ethernet = packet_prefix::<14>(data, data_end).ok_or(ParseError::TruncatedEthernet)?;
    let ethernet = unsafe { &*ethernet };
    let outer_ether_type = u16::from_be_bytes([ethernet[12], ethernet[13]]);

    if matches!(outer_ether_type, 0x8100 | 0x88a8) {
        let tagged = packet_prefix::<18>(data, data_end).ok_or(ParseError::TruncatedVlan)?;
        parse_l2(unsafe { &*tagged })
    } else {
        parse_l2(ethernet)
    }
}

#[inline(always)]
fn account(ifindex: u32, hook_role: u8, bytes: u64, data: usize, data_end: usize) {
    let (interface_generation, current_vlan_visibility) = {
        let Some(config) = IFACE_CONFIG.get_ptr(&ifindex) else {
            return;
        };
        unsafe { ((*config).interface_generation, (*config).vlan_visibility) }
    };
    increment_existing(
        StatsKey::total(interface_generation, ifindex, hook_role),
        bytes,
    );

    match parse_packet(data, data_end) {
        Ok(parsed) => {
            increment_existing(
                StatsKey::classified(
                    interface_generation,
                    ifindex,
                    hook_role,
                    parsed.traffic_class,
                ),
                bytes,
            );
            if parsed.outer_vlan_id.is_some() && current_vlan_visibility == vlan_visibility::UNKNOWN
            {
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
        }
        Err(_) => increment_existing(
            StatsKey::parse_error(interface_generation, ifindex, hook_role),
            bytes,
        ),
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
