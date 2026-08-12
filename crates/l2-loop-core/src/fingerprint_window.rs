use serde::{Deserialize, Serialize};

use crate::{DomainError, FINGERPRINT_CAPACITY, FingerprintCounters};

pub const DETECTION_FINGERPRINT_WINDOW_MS: u64 = 10_000;
pub const DETECTION_FINGERPRINT_FRESHNESS_MS: u64 = 15_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintWindowState {
    WarmingUp,
    Ready,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintWindowReport {
    pub state: FingerprintWindowState,
    pub window_ms: u64,
    pub coverage_ms: u64,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
    pub captured_entry_count: u16,
    pub delta_relation_count: u16,
    pub repeated_relation_count: u16,
    pub egress_first_correlated_relation_count: u16,
    pub ingress: FingerprintCounters,
    pub egress: FingerprintCounters,
    pub dominant_ingress_packet_ratio_milli: Option<u64>,
    pub maximum_ingress_to_egress_packet_ratio_milli: Option<u64>,
    pub last_error_code: Option<String>,
}

impl FingerprintWindowReport {
    pub const fn warming() -> Self {
        Self {
            state: FingerprintWindowState::WarmingUp,
            window_ms: DETECTION_FINGERPRINT_WINDOW_MS,
            coverage_ms: 0,
            start_unix_ms: None,
            end_unix_ms: None,
            captured_entry_count: 0,
            delta_relation_count: 0,
            repeated_relation_count: 0,
            egress_first_correlated_relation_count: 0,
            ingress: FingerprintCounters {
                packets: 0,
                bytes: 0,
            },
            egress: FingerprintCounters {
                packets: 0,
                bytes: 0,
            },
            dominant_ingress_packet_ratio_milli: None,
            maximum_ingress_to_egress_packet_ratio_milli: None,
            last_error_code: None,
        }
    }

    pub fn unavailable(code: &str) -> Result<Self, DomainError> {
        validate_error_code(code)?;
        Ok(Self {
            state: FingerprintWindowState::Unavailable,
            last_error_code: Some(code.to_owned()),
            ..Self::warming()
        })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.window_ms != DETECTION_FINGERPRINT_WINDOW_MS
            || usize::from(self.captured_entry_count) > FINGERPRINT_CAPACITY
            || self.repeated_relation_count > self.delta_relation_count
            || self.egress_first_correlated_relation_count > self.delta_relation_count
            || self
                .dominant_ingress_packet_ratio_milli
                .is_some_and(|ratio| ratio > 1_000)
        {
            return Err(DomainError::InvalidObservation(
                "fingerprint window fixed contract is invalid",
            ));
        }

        let counters_are_empty = self.delta_relation_count == 0
            && self.repeated_relation_count == 0
            && self.egress_first_correlated_relation_count == 0
            && self.ingress == FingerprintCounters::default()
            && self.egress == FingerprintCounters::default()
            && self.dominant_ingress_packet_ratio_milli.is_none()
            && self
                .maximum_ingress_to_egress_packet_ratio_milli
                .is_none();
        match self.state {
            FingerprintWindowState::WarmingUp => {
                if self.coverage_ms != 0
                    || self.start_unix_ms.is_some()
                    || self.end_unix_ms.is_some()
                    || self.captured_entry_count != 0
                    || !counters_are_empty
                    || self.last_error_code.is_some()
                {
                    return Err(DomainError::InvalidObservation(
                        "warming fingerprint window contains evidence",
                    ));
                }
            }
            FingerprintWindowState::Ready => {
                if !(DETECTION_FINGERPRINT_WINDOW_MS..=DETECTION_FINGERPRINT_FRESHNESS_MS)
                    .contains(&self.coverage_ms)
                    || self.start_unix_ms.is_none()
                    || self.end_unix_ms.is_none()
                    || self.start_unix_ms > self.end_unix_ms
                    || self.last_error_code.is_some()
                    || (self.ingress.packets == 0
                        && self.dominant_ingress_packet_ratio_milli.is_some())
                    || (self.egress.packets == 0
                        && self
                            .maximum_ingress_to_egress_packet_ratio_milli
                            .is_some())
                {
                    return Err(DomainError::InvalidObservation(
                        "ready fingerprint window evidence is invalid",
                    ));
                }
            }
            FingerprintWindowState::Unavailable => {
                if self.coverage_ms != 0
                    || self.start_unix_ms.is_some()
                    || self.end_unix_ms.is_some()
                    || self.captured_entry_count != 0
                    || !counters_are_empty
                    || self.last_error_code.as_deref().is_none()
                {
                    return Err(DomainError::InvalidObservation(
                        "unavailable fingerprint window shape is invalid",
                    ));
                }
                validate_error_code(self.last_error_code.as_deref().unwrap_or_default())?;
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_error_code(code: &str) -> Result<(), DomainError> {
    if code.is_empty()
        || code.len() > 64
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(DomainError::InvalidObservation(
            "detection error code is invalid",
        ));
    }
    Ok(())
}
