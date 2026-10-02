#![no_std]
#![no_main]

#[path = "../maps.rs"]
mod maps;
#[allow(dead_code)]
#[path = "../programs.rs"]
mod programs;

use aya_ebpf::{
    bindings::{TC_ACT_OK, xdp_action},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

#[xdp]
pub fn l2d_hooks_xdp(ctx: XdpContext) -> u32 {
    programs::diagnostic_xdp::<0>(&ctx);
    xdp_action::XDP_PASS
}

#[classifier]
pub fn l2d_hooks_tc(ctx: TcContext) -> i32 {
    programs::diagnostic_tc::<0>(&ctx);
    TC_ACT_OK
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
