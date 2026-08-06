use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{DomainError, InterfaceName, TrafficClass, interface::validate_vlan};

const MIN_POLICY_TTL: Duration = Duration::from_secs(1);
const MAX_POLICY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRequest {
    interface: InterfaceName,
    vlan: Option<u16>,
    class: TrafficClass,
    pps: Option<u64>,
    bps: Option<u64>,
    ttl: Duration,
}

impl PolicyRequest {
    pub fn new(
        interface: impl Into<String>,
        vlan: Option<u16>,
        class: TrafficClass,
        pps: Option<u64>,
        bps: Option<u64>,
        ttl: Duration,
    ) -> Result<Self, DomainError> {
        let interface = InterfaceName::new(interface)?;
        validate_vlan(vlan)?;

        if !class.supports_policing() {
            return Err(DomainError::UnsupportedPolicyClass(class.into()));
        }
        if pps.is_none() && bps.is_none() {
            return Err(DomainError::MissingRateLimit);
        }
        if pps == Some(0) {
            return Err(DomainError::ZeroRateLimit("packet"));
        }
        if bps == Some(0) {
            return Err(DomainError::ZeroRateLimit("byte"));
        }
        if !(MIN_POLICY_TTL..=MAX_POLICY_TTL).contains(&ttl) {
            return Err(DomainError::InvalidPolicyTtl(ttl.as_millis()));
        }

        Ok(Self {
            interface,
            vlan,
            class,
            pps,
            bps,
            ttl,
        })
    }

    pub const fn interface(&self) -> &InterfaceName {
        &self.interface
    }

    pub const fn vlan(&self) -> Option<u16> {
        self.vlan
    }

    pub const fn class(&self) -> TrafficClass {
        self.class
    }

    pub const fn pps(&self) -> Option<u64> {
        self.pps
    }

    pub const fn bps(&self) -> Option<u64> {
        self.bps
    }

    pub const fn ttl(&self) -> Duration {
        self.ttl
    }
}
