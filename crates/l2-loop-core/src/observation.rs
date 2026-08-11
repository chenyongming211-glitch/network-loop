use serde::{Deserialize, Serialize};

use crate::{
    DetailedRateWindow, DomainError, HookRole, InterfaceName, RATE_WINDOW_COUNT, SamplingStatus,
    TrafficClass, VlanVisibility, rate::validate_detailed_rate_windows,
};

pub const OBSERVATION_SCHEMA_VERSION: u16 = 2;
pub const OBSERVED_HOOK_COUNT: usize = 2;
pub const OBSERVED_CLASS_COUNT: usize = 6;

const CLASS_ORDER: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationCounters {
    pub packets: u64,
    pub bytes: u64,
}

impl ObservationCounters {
    pub fn checked_add(self, other: Self) -> Result<Self, DomainError> {
        let packets = self
            .packets
            .checked_add(other.packets)
            .ok_or(DomainError::InvalidObservation("packet counter overflow"))?;
        let bytes = self
            .bytes
            .checked_add(other.bytes)
            .ok_or(DomainError::InvalidObservation("byte counter overflow"))?;
        Ok(Self { packets, bytes })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassObservation {
    pub traffic_class: TrafficClass,
    pub counters: ObservationCounters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookObservation {
    pub role: HookRole,
    pub total: ObservationCounters,
    pub classes: [ClassObservation; OBSERVED_CLASS_COUNT],
    pub parse_errors: ObservationCounters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationHealth {
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationSnapshot {
    pub schema_version: u16,
    pub interface: InterfaceName,
    pub ifindex: u32,
    pub generation: u64,
    pub captured_at_unix_ms: u64,
    pub vlan_visibility: VlanVisibility,
    pub health: ObservationHealth,
    pub hooks: [HookObservation; OBSERVED_HOOK_COUNT],
    pub sampling: SamplingStatus,
    pub rate_windows: [DetailedRateWindow; RATE_WINDOW_COUNT],
}

impl ObservationSnapshot {
    pub fn new(
        interface: InterfaceName,
        ifindex: u32,
        generation: u64,
        captured_at_unix_ms: u64,
        vlan_visibility: VlanVisibility,
        hooks: [HookObservation; OBSERVED_HOOK_COUNT],
        sampling: SamplingStatus,
        rate_windows: [DetailedRateWindow; RATE_WINDOW_COUNT],
    ) -> Result<Self, DomainError> {
        if ifindex == 0 {
            return Err(DomainError::InvalidObservation("ifindex must be non-zero"));
        }
        if generation == 0 {
            return Err(DomainError::InvalidObservation(
                "interface generation must be non-zero",
            ));
        }
        if hooks[0].role != HookRole::ExternalXdpIngress
            || hooks[1].role != HookRole::PhysicalTcEgress
        {
            return Err(DomainError::InvalidObservation(
                "hook observations must be ordered XDP ingress then TC egress",
            ));
        }
        if hooks.iter().any(|hook| {
            hook.classes
                .iter()
                .zip(CLASS_ORDER)
                .any(|(actual, expected)| actual.traffic_class != expected)
        }) {
            return Err(DomainError::InvalidObservation(
                "class observations do not match the fixed class order",
            ));
        }
        validate_detailed_rate_windows(&rate_windows)?;

        Ok(Self {
            schema_version: OBSERVATION_SCHEMA_VERSION,
            interface,
            ifindex,
            generation,
            captured_at_unix_ms,
            vlan_visibility,
            health: ObservationHealth::Healthy,
            hooks,
            sampling,
            rate_windows,
        })
    }
}
