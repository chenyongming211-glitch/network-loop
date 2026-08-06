use serde::{Deserialize, Serialize};

use crate::DomainError;

macro_rules! numeric_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident = $value:path),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant = $value),+
        }

        impl TryFrom<u8> for $name {
            type Error = DomainError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    value => Err(DomainError::InvalidNumericValue {
                        kind: stringify!($name),
                        value,
                    }),
                }
            }
        }

        impl From<$name> for u8 {
            fn from(value: $name) -> Self {
                value as Self
            }
        }
    };
}

numeric_enum! {
    pub enum AgentMode {
        Disabled = l2_loop_common::agent_mode::DISABLED,
        Observe = l2_loop_common::agent_mode::OBSERVE,
        Police = l2_loop_common::agent_mode::POLICE,
    }
}

numeric_enum! {
    pub enum Direction {
        Ingress = l2_loop_common::direction::INGRESS,
        Egress = l2_loop_common::direction::EGRESS,
    }
}

numeric_enum! {
    pub enum HookRole {
        ExternalXdpIngress = l2_loop_common::hook_role::EXTERNAL_XDP_INGRESS,
        PhysicalTcEgress = l2_loop_common::hook_role::PHYSICAL_TC_EGRESS,
        TemporaryPathIngress = l2_loop_common::hook_role::TEMPORARY_PATH_INGRESS,
        TemporaryPathEgress = l2_loop_common::hook_role::TEMPORARY_PATH_EGRESS,
    }
}

numeric_enum! {
    pub enum TrafficClass {
        All = l2_loop_common::traffic_class::ALL,
        L2Broadcast = l2_loop_common::traffic_class::L2_BROADCAST,
        Ipv4Multicast = l2_loop_common::traffic_class::IPV4_MULTICAST,
        Ipv6Multicast = l2_loop_common::traffic_class::IPV6_MULTICAST,
        OtherL2Multicast = l2_loop_common::traffic_class::OTHER_L2_MULTICAST,
        LinkLocalControl = l2_loop_common::traffic_class::LINK_LOCAL_CONTROL,
        UnicastOrUnclassified = l2_loop_common::traffic_class::UNICAST_OR_UNCLASSIFIED,
    }
}

impl TrafficClass {
    pub const fn supports_policing(self) -> bool {
        !matches!(self, Self::All | Self::UnicastOrUnclassified)
    }
}

numeric_enum! {
    pub enum Verdict {
        Pass = l2_loop_common::verdict::PASS,
        WouldDrop = l2_loop_common::verdict::WOULD_DROP,
        Drop = l2_loop_common::verdict::DROP,
        ErrorPass = l2_loop_common::verdict::ERROR_PASS,
    }
}

numeric_enum! {
    pub enum ObservationReason {
        None = l2_loop_common::observation_reason::NONE,
        MissingConfiguration = l2_loop_common::observation_reason::MISSING_CONFIGURATION,
        ParseError = l2_loop_common::observation_reason::PARSE_ERROR,
        FingerprintSampleSelected =
            l2_loop_common::observation_reason::FINGERPRINT_SAMPLE_SELECTED,
        ProbeMatched = l2_loop_common::observation_reason::PROBE_MATCHED,
        PacketRateExceeded = l2_loop_common::observation_reason::PACKET_RATE_EXCEEDED,
        ByteRateExceeded = l2_loop_common::observation_reason::BYTE_RATE_EXCEEDED,
        BothRatesExceeded = l2_loop_common::observation_reason::BOTH_RATES_EXCEEDED,
    }
}

numeric_enum! {
    pub enum VlanVisibility {
        Unknown = l2_loop_common::vlan_visibility::UNKNOWN,
        VerifiedVisible = l2_loop_common::vlan_visibility::VERIFIED_VISIBLE,
        Unavailable = l2_loop_common::vlan_visibility::UNAVAILABLE,
    }
}

numeric_enum! {
    pub enum ProbeScope {
        External = l2_loop_common::probe_scope::EXTERNAL,
        Internal = l2_loop_common::probe_scope::INTERNAL,
    }
}
