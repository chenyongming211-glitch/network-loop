use serde::{Deserialize, Serialize};

use crate::{DomainError, HookRole, TrafficClass, OBSERVED_CLASS_COUNT, OBSERVED_HOOK_COUNT};

pub const RATE_WINDOW_COUNT: usize = 3;
pub const RATE_WINDOW_MS: [u64; RATE_WINDOW_COUNT] = [1_000, 10_000, 60_000];
pub const RATE_HISTORY_CAPACITY: usize = 64;
pub const RATE_SAMPLE_PERIOD_NS: u64 = 1_000_000_000;
pub const RATE_STALE_AFTER_NS: u64 = 3_000_000_000;

const CLASS_ORDER: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateWindowState {
    WarmingUp,
    Ready,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateCounters {
    pub packet_delta: u64,
    pub byte_delta: u64,
    pub packets_per_second: u64,
    pub bytes_per_second: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SamplingStatus {
    pub latest_success_at_unix_ms: Option<u64>,
    pub last_error_code: Option<String>,
    pub consecutive_failures: u32,
    pub sampling_paused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassRate {
    pub traffic_class: TrafficClass,
    pub counters: RateCounters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookRate {
    pub role: HookRole,
    pub total: RateCounters,
    pub classes: [ClassRate; OBSERVED_CLASS_COUNT],
    pub parse_errors: RateCounters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailedRateWindow {
    pub window_ms: u64,
    pub state: RateWindowState,
    pub coverage_ms: u64,
    pub elapsed_ns: Option<u64>,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
    pub hooks: Option<[HookRate; OBSERVED_HOOK_COUNT]>,
}

impl DetailedRateWindow {
    pub fn warming(window_ms: u64) -> Result<Self, DomainError> {
        if !RATE_WINDOW_MS.contains(&window_ms) {
            return Err(DomainError::InvalidObservation(
                "rate window is not one of the fixed durations",
            ));
        }

        Ok(Self {
            window_ms,
            state: RateWindowState::WarmingUp,
            coverage_ms: 0,
            elapsed_ns: None,
            start_unix_ms: None,
            end_unix_ms: None,
            hooks: None,
        })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        validate_evidence_shape(
            self.window_ms,
            self.state,
            self.coverage_ms,
            self.elapsed_ns,
            self.start_unix_ms,
            self.end_unix_ms,
            self.hooks.is_some(),
        )?;

        if let Some(hooks) = &self.hooks {
            validate_hook_rates(hooks)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRateWindow {
    pub window_ms: u64,
    pub state: RateWindowState,
    pub coverage_ms: u64,
    pub elapsed_ns: Option<u64>,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
    pub xdp_ingress: Option<RateCounters>,
    pub tc_egress: Option<RateCounters>,
}

impl StatusRateWindow {
    pub fn warming(window_ms: u64) -> Result<Self, DomainError> {
        if !RATE_WINDOW_MS.contains(&window_ms) {
            return Err(DomainError::InvalidObservation(
                "rate window is not one of the fixed durations",
            ));
        }

        Ok(Self {
            window_ms,
            state: RateWindowState::WarmingUp,
            coverage_ms: 0,
            elapsed_ns: None,
            start_unix_ms: None,
            end_unix_ms: None,
            xdp_ingress: None,
            tc_egress: None,
        })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        let has_both_rates = self.xdp_ingress.is_some() && self.tc_egress.is_some();
        let has_any_rate = self.xdp_ingress.is_some() || self.tc_egress.is_some();
        if has_any_rate && !has_both_rates {
            return Err(DomainError::InvalidObservation(
                "status rate window must contain both hook rates or neither",
            ));
        }

        validate_evidence_shape(
            self.window_ms,
            self.state,
            self.coverage_ms,
            self.elapsed_ns,
            self.start_unix_ms,
            self.end_unix_ms,
            has_both_rates,
        )
    }
}

pub fn warming_detailed_rate_windows() -> [DetailedRateWindow; RATE_WINDOW_COUNT] {
    RATE_WINDOW_MS.map(|window_ms| DetailedRateWindow {
        window_ms,
        state: RateWindowState::WarmingUp,
        coverage_ms: 0,
        elapsed_ns: None,
        start_unix_ms: None,
        end_unix_ms: None,
        hooks: None,
    })
}

pub fn warming_status_rate_windows() -> [StatusRateWindow; RATE_WINDOW_COUNT] {
    RATE_WINDOW_MS.map(|window_ms| StatusRateWindow {
        window_ms,
        state: RateWindowState::WarmingUp,
        coverage_ms: 0,
        elapsed_ns: None,
        start_unix_ms: None,
        end_unix_ms: None,
        xdp_ingress: None,
        tc_egress: None,
    })
}

pub(crate) fn validate_detailed_rate_windows(
    windows: &[DetailedRateWindow; RATE_WINDOW_COUNT],
) -> Result<(), DomainError> {
    for (window, expected_ms) in windows.iter().zip(RATE_WINDOW_MS) {
        if window.window_ms != expected_ms {
            return Err(DomainError::InvalidObservation(
                "rate windows do not match the fixed duration order",
            ));
        }
        window.validate()?;
    }
    Ok(())
}

pub fn validate_status_rate_windows(
    windows: &[StatusRateWindow; RATE_WINDOW_COUNT],
) -> Result<(), DomainError> {
    for (window, expected_ms) in windows.iter().zip(RATE_WINDOW_MS) {
        if window.window_ms != expected_ms {
            return Err(DomainError::InvalidObservation(
                "status rate windows do not match the fixed duration order",
            ));
        }
        window.validate()?;
    }
    Ok(())
}

fn validate_evidence_shape(
    window_ms: u64,
    state: RateWindowState,
    coverage_ms: u64,
    elapsed_ns: Option<u64>,
    start_unix_ms: Option<u64>,
    end_unix_ms: Option<u64>,
    has_rates: bool,
) -> Result<(), DomainError> {
    if !RATE_WINDOW_MS.contains(&window_ms) {
        return Err(DomainError::InvalidObservation(
            "rate window is not one of the fixed durations",
        ));
    }

    let evidence_is_complete = elapsed_ns.is_some()
        && start_unix_ms.is_some()
        && end_unix_ms.is_some()
        && has_rates;
    let evidence_is_absent = elapsed_ns.is_none()
        && start_unix_ms.is_none()
        && end_unix_ms.is_none()
        && !has_rates;

    match state {
        RateWindowState::Ready => {
            if !evidence_is_complete {
                Err(DomainError::InvalidObservation(
                    "ready rate window requires complete rate evidence",
                ))
            } else if elapsed_ns == Some(0)
                || elapsed_ns.unwrap_or_default() < window_ms.saturating_mul(1_000_000)
                || coverage_ms < window_ms
            {
                Err(DomainError::InvalidObservation(
                    "ready rate window does not cover its fixed duration",
                ))
            } else {
                Ok(())
            }
        }
        RateWindowState::WarmingUp | RateWindowState::Stale => {
            if !evidence_is_absent {
                Err(DomainError::InvalidObservation(
                    "non-ready rate window must not contain rate evidence",
                ))
            } else {
                Ok(())
            }
        }
    }
}

fn validate_hook_rates(hooks: &[HookRate; OBSERVED_HOOK_COUNT]) -> Result<(), DomainError> {
    if hooks[0].role != HookRole::ExternalXdpIngress
        || hooks[1].role != HookRole::PhysicalTcEgress
    {
        return Err(DomainError::InvalidObservation(
            "rate hooks must be ordered XDP ingress then TC egress",
        ));
    }
    if hooks.iter().any(|hook| {
        hook.classes
            .iter()
            .zip(CLASS_ORDER)
            .any(|(actual, expected)| actual.traffic_class != expected)
    }) {
        return Err(DomainError::InvalidObservation(
            "rate classes do not match the fixed class order",
        ));
    }
    Ok(())
}
