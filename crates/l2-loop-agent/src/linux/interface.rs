use l2_loop_core::{InterfaceKind, InterfaceName};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelLinkKind {
    Bond,
    Veth,
    Bridge,
    Tun,
    OpenVSwitch,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunMode {
    Tap,
    Tun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRecord {
    pub name: InterfaceName,
    pub ifindex: u32,
    pub kind: Option<KernelLinkKind>,
    pub tun_mode: Option<TunMode>,
    pub driver_present: bool,
    pub master_ifindex: Option<u32>,
    pub admin_up: bool,
    pub oper_up: bool,
}

pub fn classify_interface(link: &LinkRecord) -> InterfaceKind {
    match (&link.kind, link.tun_mode) {
        (Some(KernelLinkKind::Bond), _) => InterfaceKind::Bond,
        (Some(KernelLinkKind::Veth), _) => InterfaceKind::Veth,
        (Some(KernelLinkKind::Bridge), _) => InterfaceKind::Bridge,
        (Some(KernelLinkKind::OpenVSwitch), _) => InterfaceKind::OvsInternal,
        (Some(KernelLinkKind::Tun), Some(TunMode::Tap)) => InterfaceKind::Tap,
        (None, _) if link.driver_present => InterfaceKind::Physical,
        _ => InterfaceKind::Unsupported,
    }
}
