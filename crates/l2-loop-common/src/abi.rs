#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub logical_ifindex: u32,
    pub flags: u32,
    pub mode: u8,
    pub role: u8,
    pub vlan_visibility: u8,
    pub sample_shift: u8,
    pub reserved: [u8; 4],
}

impl InterfaceConfig {
    pub const fn new(
        interface_generation: u64,
        policy_generation: u64,
        logical_ifindex: u32,
        mode: u8,
        role: u8,
        vlan_visibility: u8,
        sample_shift: u8,
    ) -> Self {
        Self {
            interface_generation,
            policy_generation,
            logical_ifindex,
            flags: 0,
            mode,
            role,
            vlan_visibility,
            sample_shift,
            reserved: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsKey {
    pub interface_generation: u64,
    pub ifindex: u32,
    pub hook_role: u8,
    pub traffic_class: u8,
    pub verdict: u8,
    pub reason: u8,
}

impl StatsKey {
    pub const fn total(interface_generation: u64, ifindex: u32, hook_role: u8) -> Self {
        Self {
            interface_generation,
            ifindex,
            hook_role,
            traffic_class: crate::traffic_class::ALL,
            verdict: crate::verdict::PASS,
            reason: crate::observation_reason::NONE,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterValue {
    pub packets: u64,
    pub bytes: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintKey {
    pub interface_generation: u64,
    pub fingerprint: u64,
    pub ifindex: u32,
    pub outer_vlan_id: u16,
    pub ether_type: u16,
    pub frame_len: u16,
    pub direction: u8,
    pub vlan_depth: u8,
    pub protocol: u8,
    pub subtype: u8,
    pub reserved: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintValue {
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub reserved: [u8; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeKey {
    pub nonce: [u8; 16],
    pub interface_generation: u64,
    pub ifindex: u32,
    pub outer_vlan_id: u16,
    pub scope: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRegistration {
    pub registered_at_ns: u64,
    pub expires_at_ns: u64,
    pub flags: u32,
    pub reserved: [u8; 12],
}

impl ProbeRegistration {
    pub const fn new(registered_at_ns: u64, expires_at_ns: u64) -> Self {
        Self {
            registered_at_ns,
            expires_at_ns,
            flags: 0,
            reserved: [0; 12],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyKey {
    pub policy_generation: u64,
    pub ifindex: u32,
    pub outer_vlan_id: u16,
    pub direction: u8,
    pub traffic_class: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatePolicy {
    pub pps_limit: u64,
    pub bps_limit: u64,
    pub packet_burst: u64,
    pub byte_burst: u64,
    pub expires_at_ns: u64,
}

#[cfg(feature = "user")]
macro_rules! unsafe_impl_pod {
    ($($type:ty),+ $(,)?) => {
        $(unsafe impl aya::Pod for $type {})+
    };
}

#[cfg(feature = "user")]
unsafe_impl_pod!(
    InterfaceConfig,
    StatsKey,
    CounterValue,
    FingerprintKey,
    FingerprintValue,
    ProbeKey,
    ProbeRegistration,
    PolicyKey,
    RatePolicy,
);
