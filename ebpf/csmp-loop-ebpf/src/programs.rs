use aya_ebpf::{
    bindings::{TC_ACT_OK, xdp_action},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

#[xdp]
pub fn csmp_xdp_ingress(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[classifier]
pub fn csmp_tc_egress(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

#[classifier]
pub fn csmp_tc_path_ingress(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

#[classifier]
pub fn csmp_tc_path_egress(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}
