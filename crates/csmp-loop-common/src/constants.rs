pub const ABI_VERSION: u16 = 1;
pub const NO_VLAN: u16 = 0xffff;

pub mod agent_mode {
    pub const DISABLED: u8 = 0;
    pub const OBSERVE: u8 = 1;
    pub const POLICE: u8 = 2;
}

pub mod direction {
    pub const INGRESS: u8 = 1;
    pub const EGRESS: u8 = 2;
}

pub mod hook_role {
    pub const EXTERNAL_XDP_INGRESS: u8 = 1;
    pub const PHYSICAL_TC_EGRESS: u8 = 2;
    pub const TEMPORARY_PATH_INGRESS: u8 = 3;
    pub const TEMPORARY_PATH_EGRESS: u8 = 4;
}

pub mod traffic_class {
    pub const ALL: u8 = 1;
    pub const L2_BROADCAST: u8 = 2;
    pub const IPV4_MULTICAST: u8 = 3;
    pub const IPV6_MULTICAST: u8 = 4;
    pub const OTHER_L2_MULTICAST: u8 = 5;
    pub const LINK_LOCAL_CONTROL: u8 = 6;
    pub const UNICAST_OR_UNCLASSIFIED: u8 = 7;
}

pub mod verdict {
    pub const PASS: u8 = 1;
    pub const WOULD_DROP: u8 = 2;
    pub const DROP: u8 = 3;
    pub const ERROR_PASS: u8 = 4;
}

pub mod observation_reason {
    pub const NONE: u8 = 0;
    pub const MISSING_CONFIGURATION: u8 = 1;
    pub const PARSE_ERROR: u8 = 2;
    pub const FINGERPRINT_SAMPLE_SELECTED: u8 = 3;
    pub const PROBE_MATCHED: u8 = 4;
    pub const PACKET_RATE_EXCEEDED: u8 = 5;
    pub const BYTE_RATE_EXCEEDED: u8 = 6;
    pub const BOTH_RATES_EXCEEDED: u8 = 7;
}

pub mod vlan_visibility {
    pub const UNKNOWN: u8 = 0;
    pub const VERIFIED_VISIBLE: u8 = 1;
    pub const UNAVAILABLE: u8 = 2;
}

pub mod probe_scope {
    pub const EXTERNAL: u8 = 1;
    pub const INTERNAL: u8 = 2;
}
