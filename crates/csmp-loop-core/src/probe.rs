use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{DomainError, InterfaceName, ProbeScope, interface::validate_vlan};

const MIN_PROBE_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    interface: InterfaceName,
    scope: ProbeScope,
    vlan: Option<u16>,
    timeout: Duration,
}

impl ProbeRequest {
    pub fn new(
        interface: impl Into<String>,
        scope: ProbeScope,
        vlan: Option<u16>,
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        let interface = InterfaceName::new(interface)?;
        validate_vlan(vlan)?;
        if !(MIN_PROBE_TIMEOUT..=MAX_PROBE_TIMEOUT).contains(&timeout) {
            return Err(DomainError::InvalidProbeTimeout(timeout.as_millis()));
        }

        Ok(Self {
            interface,
            scope,
            vlan,
            timeout,
        })
    }

    pub const fn interface(&self) -> &InterfaceName {
        &self.interface
    }

    pub const fn scope(&self) -> ProbeScope {
        self.scope
    }

    pub const fn vlan(&self) -> Option<u16> {
        self.vlan
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}
