use serde::{Deserialize, Serialize};

use crate::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 15
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            });

        if valid {
            Ok(Self(value))
        } else {
            Err(DomainError::InvalidInterfaceName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Generation(u64);

impl Generation {
    pub const fn new(value: u64) -> Result<Self, DomainError> {
        if value == 0 {
            Err(DomainError::InvalidGeneration)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceState {
    Detached,
    Attaching,
    Observing,
    Policing,
    Error,
}

impl InterfaceState {
    pub fn transition(self, target: Self) -> Result<Self, DomainError> {
        let valid = self == target
            || matches!(
                (self, target),
                (Self::Detached, Self::Attaching)
                    | (Self::Attaching, Self::Observing)
                    | (Self::Observing, Self::Policing)
                    | (Self::Policing, Self::Observing)
                    | (
                        Self::Attaching | Self::Observing | Self::Policing,
                        Self::Error
                    )
                    | (Self::Error, Self::Detached)
            );

        if valid {
            Ok(target)
        } else {
            Err(DomainError::InvalidTransition {
                from: self.name(),
                to: target.name(),
            })
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Detached => "detached",
            Self::Attaching => "attaching",
            Self::Observing => "observing",
            Self::Policing => "policing",
            Self::Error => "error",
        }
    }
}

pub(crate) const fn validate_vlan(vlan: Option<u16>) -> Result<(), DomainError> {
    match vlan {
        None | Some(1..=4094) => Ok(()),
        Some(value) => Err(DomainError::InvalidVlan(value)),
    }
}
