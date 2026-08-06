use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("unknown {kind} ABI value {value}")]
    InvalidNumericValue { kind: &'static str, value: u8 },
    #[error("interface name must be 1-15 safe ASCII characters")]
    InvalidInterfaceName,
    #[error("generation must be non-zero")]
    InvalidGeneration,
    #[error("VLAN must be in the range 1-4094, got {0}")]
    InvalidVlan(u16),
    #[error("invalid interface lifecycle transition from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("at least one rate limit is required")]
    MissingRateLimit,
    #[error("{0} rate limit must be non-zero when supplied")]
    ZeroRateLimit(&'static str),
    #[error("traffic class {0} cannot be policed")]
    UnsupportedPolicyClass(u8),
    #[error("policy TTL must be between 1 second and 24 hours, got {0} ms")]
    InvalidPolicyTtl(u128),
    #[error("probe timeout must be between 100 ms and 30 seconds, got {0} ms")]
    InvalidProbeTimeout(u128),
}
