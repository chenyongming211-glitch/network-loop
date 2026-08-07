use aya_ebpf::{
    bindings::{BPF_NOEXIST, TC_ACT_OK, xdp_action},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use l2_loop_common::{CounterValue, StatsKey, hook_role};

use crate::maps::{HOOK_STATS, IFACE_CONFIG};

#[inline(always)]
fn increment_counter(counter: *mut CounterValue, bytes: u64) {
    unsafe {
        (*counter).packets = (*counter).packets.wrapping_add(1);
        (*counter).bytes = (*counter).bytes.wrapping_add(bytes);
    }
}

#[inline(always)]
fn account(ifindex: u32, hook_role: u8, bytes: u64) {
    let Some(config) = IFACE_CONFIG.get_ptr(&ifindex) else {
        return;
    };
    let interface_generation = unsafe { (*config).interface_generation };
    let key = StatsKey::total(interface_generation, ifindex, hook_role);

    if let Some(counter) = HOOK_STATS.get_ptr_mut(&key) {
        increment_counter(counter, bytes);
        return;
    }

    let initial = CounterValue { packets: 1, bytes };
    if HOOK_STATS
        .insert(&key, &initial, BPF_NOEXIST as u64)
        .is_ok()
    {
        return;
    }

    if let Some(counter) = HOOK_STATS.get_ptr_mut(&key) {
        increment_counter(counter, bytes);
    }
}

#[inline(always)]
fn account_xdp(ctx: &XdpContext, hook_role: u8) {
    let Some(bytes) = ctx.data_end().checked_sub(ctx.data()) else {
        return;
    };
    account(ctx.ingress_ifindex() as u32, hook_role, bytes as u64);
}

#[inline(always)]
fn account_tc(ctx: &TcContext, hook_role: u8) {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    account(ifindex, hook_role, u64::from(ctx.len()));
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
