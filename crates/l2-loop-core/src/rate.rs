use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ClassObservation, DomainError, HookObservation, HookRole, OBSERVED_CLASS_COUNT,
    OBSERVED_HOOK_COUNT, ObservationCounters, TrafficClass, VlanVisibility,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateIdentity {
    ifindex: u32,
    generation: u64,
}

impl RateIdentity {
    pub const fn new(ifindex: u32, generation: u64) -> Result<Self, DomainError> {
        if ifindex == 0 {
            return Err(DomainError::InvalidObservation("ifindex must be non-zero"));
        }
        if generation == 0 {
            return Err(DomainError::InvalidObservation(
                "interface generation must be non-zero",
            ));
        }
        Ok(Self {
            ifindex,
            generation,
        })
    }

    pub const fn ifindex(self) -> u32 {
        self.ifindex
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    fn validate(self) -> Result<(), DomainError> {
        Self::new(self.ifindex, self.generation).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateSample {
    identity: RateIdentity,
    captured_at_monotonic_ns: u64,
    captured_at_unix_ms: u64,
    vlan_visibility: VlanVisibility,
    hooks: [HookObservation; OBSERVED_HOOK_COUNT],
}

impl RateSample {
    pub fn new(
        identity: RateIdentity,
        captured_at_monotonic_ns: u64,
        captured_at_unix_ms: u64,
        vlan_visibility: VlanVisibility,
        hooks: [HookObservation; OBSERVED_HOOK_COUNT],
    ) -> Result<Self, DomainError> {
        identity.validate()?;
        validate_observation_hooks(&hooks)?;
        Ok(Self {
            identity,
            captured_at_monotonic_ns,
            captured_at_unix_ms,
            vlan_visibility,
            hooks,
        })
    }

    pub const fn identity(&self) -> RateIdentity {
        self.identity
    }

    pub const fn captured_at_monotonic_ns(&self) -> u64 {
        self.captured_at_monotonic_ns
    }

    pub const fn captured_at_unix_ms(&self) -> u64 {
        self.captured_at_unix_ms
    }

    pub const fn vlan_visibility(&self) -> VlanVisibility {
        self.vlan_visibility
    }

    pub const fn hooks(&self) -> &[HookObservation; OBSERVED_HOOK_COUNT] {
        &self.hooks
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RateHistoryError {
    #[error("rate sample identity does not match the active history")]
    IdentityMismatch,
    #[error("rate sample monotonic clock did not advance")]
    ClockRegression,
    #[error("cumulative observation counter regressed")]
    CounterRegression,
    #[error("rate calculation failed checked arithmetic")]
    CalculationFailed,
}

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

    let evidence_is_complete =
        elapsed_ns.is_some() && start_unix_ms.is_some() && end_unix_ms.is_some() && has_rates;
    let evidence_is_absent =
        elapsed_ns.is_none() && start_unix_ms.is_none() && end_unix_ms.is_none() && !has_rates;

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
    if hooks[0].role != HookRole::ExternalXdpIngress || hooks[1].role != HookRole::PhysicalTcEgress
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

#[derive(Debug, Clone)]
pub struct RateHistory {
    identity: RateIdentity,
    history_epoch_started_at_monotonic_ns: u64,
    samples: VecDeque<RateSample>,
}

impl RateHistory {
    pub fn new(
        identity: RateIdentity,
        history_epoch_started_at_monotonic_ns: u64,
    ) -> Result<Self, DomainError> {
        identity.validate()?;
        Ok(Self {
            identity,
            history_epoch_started_at_monotonic_ns,
            samples: VecDeque::with_capacity(RATE_HISTORY_CAPACITY),
        })
    }

    pub fn insert(&mut self, sample: RateSample) -> Result<(), RateHistoryError> {
        let sample_time = sample.captured_at_monotonic_ns;
        if sample.identity != self.identity {
            self.clear_at(sample_time);
            return Err(RateHistoryError::IdentityMismatch);
        }
        if sample_time < self.history_epoch_started_at_monotonic_ns
            || self
                .samples
                .back()
                .is_some_and(|latest| sample_time <= latest.captured_at_monotonic_ns)
        {
            self.clear_at(sample_time);
            return Err(RateHistoryError::ClockRegression);
        }
        if self
            .samples
            .back()
            .is_some_and(|latest| !hooks_are_monotonic(&latest.hooks, &sample.hooks))
        {
            self.clear_at(sample_time);
            return Err(RateHistoryError::CounterRegression);
        }

        self.samples.push_back(sample);
        if self.samples.len() > RATE_HISTORY_CAPACITY {
            self.samples.pop_front();
        }
        Ok(())
    }

    pub fn validate_current(&mut self, current: &RateSample) -> Result<(), RateHistoryError> {
        let current_time = current.captured_at_monotonic_ns;
        if current.identity != self.identity {
            self.clear_at(current_time);
            return Err(RateHistoryError::IdentityMismatch);
        }
        if current_time < self.history_epoch_started_at_monotonic_ns
            || self
                .samples
                .back()
                .is_some_and(|latest| current_time < latest.captured_at_monotonic_ns)
        {
            self.clear_at(current_time);
            return Err(RateHistoryError::ClockRegression);
        }
        if self
            .samples
            .back()
            .is_some_and(|latest| !hooks_are_monotonic(&latest.hooks, &current.hooks))
        {
            self.clear_at(current_time);
            return Err(RateHistoryError::CounterRegression);
        }
        Ok(())
    }

    pub fn detailed_windows(
        &self,
        now_monotonic_ns: u64,
    ) -> Result<[DetailedRateWindow; RATE_WINDOW_COUNT], RateHistoryError> {
        Ok(self
            .calculate_windows(now_monotonic_ns)?
            .map(CalculatedRateWindow::into_detailed))
    }

    pub fn status_windows(
        &self,
        now_monotonic_ns: u64,
    ) -> Result<[StatusRateWindow; RATE_WINDOW_COUNT], RateHistoryError> {
        Ok(self
            .calculate_windows(now_monotonic_ns)?
            .map(CalculatedRateWindow::into_status))
    }

    pub fn clear_at(&mut self, history_epoch_started_at_monotonic_ns: u64) {
        self.samples.clear();
        self.history_epoch_started_at_monotonic_ns = history_epoch_started_at_monotonic_ns;
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    fn calculate_windows(
        &self,
        now_monotonic_ns: u64,
    ) -> Result<[CalculatedRateWindow; RATE_WINDOW_COUNT], RateHistoryError> {
        if self
            .samples
            .back()
            .is_some_and(|latest| now_monotonic_ns < latest.captured_at_monotonic_ns)
        {
            return Err(RateHistoryError::ClockRegression);
        }

        let coverage_ms = self.coverage_ms()?;
        let first = self.calculate_window(RATE_WINDOW_MS[0], coverage_ms)?;
        let second = self.calculate_window(RATE_WINDOW_MS[1], coverage_ms)?;
        let third = self.calculate_window(RATE_WINDOW_MS[2], coverage_ms)?;
        Ok([first, second, third])
    }

    fn calculate_window(
        &self,
        window_ms: u64,
        coverage_ms: u64,
    ) -> Result<CalculatedRateWindow, RateHistoryError> {
        let Some(latest) = self.samples.back() else {
            return Ok(CalculatedRateWindow::Warming {
                window_ms,
                coverage_ms,
            });
        };
        let window_ns = window_ms
            .checked_mul(1_000_000)
            .ok_or(RateHistoryError::CalculationFailed)?;
        let Some(target_ns) = latest.captured_at_monotonic_ns.checked_sub(window_ns) else {
            return Ok(CalculatedRateWindow::Warming {
                window_ms,
                coverage_ms,
            });
        };
        let Some(start) = self
            .samples
            .iter()
            .rev()
            .find(|sample| sample.captured_at_monotonic_ns <= target_ns)
        else {
            return Ok(CalculatedRateWindow::Warming {
                window_ms,
                coverage_ms,
            });
        };
        let elapsed_ns = latest
            .captured_at_monotonic_ns
            .checked_sub(start.captured_at_monotonic_ns)
            .ok_or(RateHistoryError::CalculationFailed)?;
        if elapsed_ns < window_ns || elapsed_ns == 0 {
            return Ok(CalculatedRateWindow::Warming {
                window_ms,
                coverage_ms,
            });
        }
        let hooks = calculate_hook_rates(&start.hooks, &latest.hooks, elapsed_ns)?;

        Ok(CalculatedRateWindow::Ready {
            window_ms,
            coverage_ms,
            elapsed_ns,
            start_unix_ms: start.captured_at_unix_ms,
            end_unix_ms: latest.captured_at_unix_ms,
            hooks,
        })
    }

    fn coverage_ms(&self) -> Result<u64, RateHistoryError> {
        let (Some(first), Some(latest)) = (self.samples.front(), self.samples.back()) else {
            return Ok(0);
        };
        latest
            .captured_at_monotonic_ns
            .checked_sub(first.captured_at_monotonic_ns)
            .map(|coverage_ns| coverage_ns / 1_000_000)
            .ok_or(RateHistoryError::CalculationFailed)
    }
}

// The fixed two-hook/six-class payload is bounded and avoids per-window heap indirection.
#[allow(clippy::large_enum_variant)]
enum CalculatedRateWindow {
    Warming {
        window_ms: u64,
        coverage_ms: u64,
    },
    Ready {
        window_ms: u64,
        coverage_ms: u64,
        elapsed_ns: u64,
        start_unix_ms: u64,
        end_unix_ms: u64,
        hooks: [HookRate; OBSERVED_HOOK_COUNT],
    },
}

impl CalculatedRateWindow {
    fn into_detailed(self) -> DetailedRateWindow {
        match self {
            Self::Warming {
                window_ms,
                coverage_ms,
            } => DetailedRateWindow {
                window_ms,
                state: RateWindowState::WarmingUp,
                coverage_ms,
                elapsed_ns: None,
                start_unix_ms: None,
                end_unix_ms: None,
                hooks: None,
            },
            Self::Ready {
                window_ms,
                coverage_ms,
                elapsed_ns,
                start_unix_ms,
                end_unix_ms,
                hooks,
            } => DetailedRateWindow {
                window_ms,
                state: RateWindowState::Ready,
                coverage_ms,
                elapsed_ns: Some(elapsed_ns),
                start_unix_ms: Some(start_unix_ms),
                end_unix_ms: Some(end_unix_ms),
                hooks: Some(hooks),
            },
        }
    }

    fn into_status(self) -> StatusRateWindow {
        match self {
            Self::Warming {
                window_ms,
                coverage_ms,
            } => StatusRateWindow {
                window_ms,
                state: RateWindowState::WarmingUp,
                coverage_ms,
                elapsed_ns: None,
                start_unix_ms: None,
                end_unix_ms: None,
                xdp_ingress: None,
                tc_egress: None,
            },
            Self::Ready {
                window_ms,
                coverage_ms,
                elapsed_ns,
                start_unix_ms,
                end_unix_ms,
                hooks: [xdp, tc],
            } => StatusRateWindow {
                window_ms,
                state: RateWindowState::Ready,
                coverage_ms,
                elapsed_ns: Some(elapsed_ns),
                start_unix_ms: Some(start_unix_ms),
                end_unix_ms: Some(end_unix_ms),
                xdp_ingress: Some(xdp.total),
                tc_egress: Some(tc.total),
            },
        }
    }
}

fn validate_observation_hooks(
    hooks: &[HookObservation; OBSERVED_HOOK_COUNT],
) -> Result<(), DomainError> {
    if hooks[0].role != HookRole::ExternalXdpIngress || hooks[1].role != HookRole::PhysicalTcEgress
    {
        return Err(DomainError::InvalidObservation(
            "rate samples must be ordered XDP ingress then TC egress",
        ));
    }
    if hooks.iter().any(|hook| {
        hook.classes
            .iter()
            .zip(CLASS_ORDER)
            .any(|(actual, expected)| actual.traffic_class != expected)
    }) {
        return Err(DomainError::InvalidObservation(
            "rate sample classes do not match the fixed class order",
        ));
    }
    Ok(())
}

fn hooks_are_monotonic(
    previous: &[HookObservation; OBSERVED_HOOK_COUNT],
    current: &[HookObservation; OBSERVED_HOOK_COUNT],
) -> bool {
    previous.iter().zip(current).all(|(before, after)| {
        counters_are_monotonic(before.total, after.total)
            && counters_are_monotonic(before.parse_errors, after.parse_errors)
            && before
                .classes
                .iter()
                .zip(after.classes)
                .all(|(before, after)| {
                    before.traffic_class == after.traffic_class
                        && counters_are_monotonic(before.counters, after.counters)
                })
    })
}

fn counters_are_monotonic(previous: ObservationCounters, current: ObservationCounters) -> bool {
    current.packets >= previous.packets && current.bytes >= previous.bytes
}

fn calculate_hook_rates(
    start: &[HookObservation; OBSERVED_HOOK_COUNT],
    end: &[HookObservation; OBSERVED_HOOK_COUNT],
    elapsed_ns: u64,
) -> Result<[HookRate; OBSERVED_HOOK_COUNT], RateHistoryError> {
    Ok([
        calculate_hook_rate(&start[0], &end[0], elapsed_ns)?,
        calculate_hook_rate(&start[1], &end[1], elapsed_ns)?,
    ])
}

fn calculate_hook_rate(
    start: &HookObservation,
    end: &HookObservation,
    elapsed_ns: u64,
) -> Result<HookRate, RateHistoryError> {
    if start.role != end.role {
        return Err(RateHistoryError::CalculationFailed);
    }
    Ok(HookRate {
        role: end.role,
        total: calculate_rate_counters(start.total, end.total, elapsed_ns)?,
        classes: calculate_class_rates(&start.classes, &end.classes, elapsed_ns)?,
        parse_errors: calculate_rate_counters(start.parse_errors, end.parse_errors, elapsed_ns)?,
    })
}

fn calculate_class_rates(
    start: &[ClassObservation; OBSERVED_CLASS_COUNT],
    end: &[ClassObservation; OBSERVED_CLASS_COUNT],
    elapsed_ns: u64,
) -> Result<[ClassRate; OBSERVED_CLASS_COUNT], RateHistoryError> {
    Ok([
        calculate_class_rate(&start[0], &end[0], elapsed_ns)?,
        calculate_class_rate(&start[1], &end[1], elapsed_ns)?,
        calculate_class_rate(&start[2], &end[2], elapsed_ns)?,
        calculate_class_rate(&start[3], &end[3], elapsed_ns)?,
        calculate_class_rate(&start[4], &end[4], elapsed_ns)?,
        calculate_class_rate(&start[5], &end[5], elapsed_ns)?,
    ])
}

fn calculate_class_rate(
    start: &ClassObservation,
    end: &ClassObservation,
    elapsed_ns: u64,
) -> Result<ClassRate, RateHistoryError> {
    if start.traffic_class != end.traffic_class {
        return Err(RateHistoryError::CalculationFailed);
    }
    Ok(ClassRate {
        traffic_class: end.traffic_class,
        counters: calculate_rate_counters(start.counters, end.counters, elapsed_ns)?,
    })
}

fn calculate_rate_counters(
    start: ObservationCounters,
    end: ObservationCounters,
    elapsed_ns: u64,
) -> Result<RateCounters, RateHistoryError> {
    if elapsed_ns == 0 {
        return Err(RateHistoryError::CalculationFailed);
    }
    let packet_delta = end
        .packets
        .checked_sub(start.packets)
        .ok_or(RateHistoryError::CounterRegression)?;
    let byte_delta = end
        .bytes
        .checked_sub(start.bytes)
        .ok_or(RateHistoryError::CounterRegression)?;
    Ok(RateCounters {
        packet_delta,
        byte_delta,
        packets_per_second: calculate_rate(packet_delta, elapsed_ns)?,
        bytes_per_second: calculate_rate(byte_delta, elapsed_ns)?,
    })
}

fn calculate_rate(delta: u64, elapsed_ns: u64) -> Result<u64, RateHistoryError> {
    let numerator = u128::from(delta)
        .checked_mul(u128::from(RATE_SAMPLE_PERIOD_NS))
        .ok_or(RateHistoryError::CalculationFailed)?;
    let rate = numerator
        .checked_div(u128::from(elapsed_ns))
        .ok_or(RateHistoryError::CalculationFailed)?;
    u64::try_from(rate).map_err(|_| RateHistoryError::CalculationFailed)
}
