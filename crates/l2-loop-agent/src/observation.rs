use std::time::UNIX_EPOCH;

use l2_loop_core::{
    BaselineEngine, BaselineState, BaselineSummary, FingerprintReport, FingerprintState,
    FingerprintSummary, InterfaceName, InterfaceState, InterfaceStatus, OBSERVED_HOOK_COUNT,
    ObservationHealth, ObservationSnapshot, RATE_WINDOW_COUNT, RateHistory, RateHistoryError,
    RateIdentity, RateSample, RateWindowState, SamplingStatus, StatusRateWindow,
    warming_detailed_rate_windows, warming_status_rate_windows,
};

use crate::{
    Clock, ObservationReadPurpose, ObservationReader, PortError, RawFingerprints, RawObservation,
    ownership::OwnershipRecord,
};

pub const OBS_SESSION_NOT_FOUND: &str = "OBS_SESSION_NOT_FOUND";
pub const OBS_INTERFACE_MISMATCH: &str = "OBS_INTERFACE_MISMATCH";
pub const OBS_OWNERSHIP_MISMATCH: &str = "OBS_OWNERSHIP_MISMATCH";
pub const OBS_MAP_UNAVAILABLE: &str = "OBS_MAP_UNAVAILABLE";
pub const OBS_SNAPSHOT_FAILED: &str = "OBS_SNAPSHOT_FAILED";
pub const OBS_RATE_CLOCK_REGRESSION: &str = "OBS_RATE_CLOCK_REGRESSION";
pub const OBS_RATE_COUNTER_REGRESSION: &str = "OBS_RATE_COUNTER_REGRESSION";
pub const OBS_RATE_CALCULATION_FAILED: &str = "OBS_RATE_CALCULATION_FAILED";
pub const OBS_RATE_SAMPLER_PAUSED: &str = "OBS_RATE_SAMPLER_PAUSED";
pub const BASELINE_SOURCE_UNAVAILABLE: &str = "BASELINE_SOURCE_UNAVAILABLE";
pub const BASELINE_IDENTITY_CHANGED: &str = "BASELINE_IDENTITY_CHANGED";
pub const BASELINE_CLOCK_REGRESSION: &str = "BASELINE_CLOCK_REGRESSION";
pub const BASELINE_COUNTER_REGRESSION: &str = "BASELINE_COUNTER_REGRESSION";
pub const BASELINE_CALCULATION_FAILED: &str = "BASELINE_CALCULATION_FAILED";
pub const BASELINE_SAMPLER_PAUSED: &str = "BASELINE_SAMPLER_PAUSED";

const OBS_MAP_IDENTITY_MISMATCH: &str = "OBS_MAP_IDENTITY_MISMATCH";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationError {
    code: &'static str,
    evidence: &'static str,
}

impl ObservationError {
    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub const fn evidence(&self) -> &'static str {
        self.evidence
    }

    const fn new(code: &'static str, evidence: &'static str) -> Self {
        Self { code, evidence }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingTickOutcome {
    Sampled,
    Rejected,
}

pub struct SamplingService<R, C> {
    reader: R,
    clock: C,
    history: Option<RateHistory>,
    baseline: Option<BaselineEngine>,
}

impl<R, C> SamplingService<R, C>
where
    R: ObservationReader,
    C: Clock,
{
    pub const fn new(reader: R, clock: C) -> Self {
        Self {
            reader,
            clock,
            history: None,
            baseline: None,
        }
    }

    pub fn start(&mut self, ownership: &OwnershipRecord) -> Result<(), ObservationError> {
        let identity = RateIdentity::new(ownership.ifindex, ownership.generation)
            .map_err(|_| ownership_error())?;
        let started_at_unix_ms = wall_time_ms(&self.clock).ok_or_else(snapshot_error)?;
        self.history = Some(
            RateHistory::new(identity, self.clock.monotonic_ns()).map_err(|_| snapshot_error())?,
        );
        self.baseline = Some(BaselineEngine::new(identity, started_at_unix_ms));
        Ok(())
    }

    pub fn sample_tick(&mut self, ownership: &OwnershipRecord) -> SamplingTickOutcome {
        if self.history.is_none() || self.baseline.is_none() {
            return SamplingTickOutcome::Rejected;
        }
        let read_result = self
            .reader
            .read_exact(ownership, ObservationReadPurpose::BackgroundSample);
        let now_monotonic_ns = self.clock.monotonic_ns();
        let evaluated_at_unix_ms = wall_time_ms(&self.clock).unwrap_or_default();
        let Some(history) = self.history.as_mut() else {
            return SamplingTickOutcome::Rejected;
        };
        let raw = match read_result {
            Ok(raw) => raw,
            Err(error) => {
                let code = error.stable_code().unwrap_or(OBS_MAP_UNAVAILABLE);
                if is_identity_code(code) {
                    history.record_identity_failure(now_monotonic_ns, code);
                    if let Some(baseline) = self.baseline.as_mut() {
                        baseline.clear_integrity(
                            baseline.identity(),
                            evaluated_at_unix_ms,
                            BASELINE_IDENTITY_CHANGED,
                        );
                    }
                } else {
                    history.record_transient_failure(code);
                    if let Some(baseline) = self.baseline.as_mut() {
                        baseline.unavailable(evaluated_at_unix_ms, BASELINE_SOURCE_UNAVAILABLE);
                    }
                }
                return SamplingTickOutcome::Rejected;
            }
        };
        if raw.ifindex != ownership.ifindex || raw.generation != ownership.generation {
            history.record_identity_failure(now_monotonic_ns, OBS_OWNERSHIP_MISMATCH);
            if let Some(baseline) = self.baseline.as_mut() {
                baseline.clear_integrity(
                    baseline.identity(),
                    evaluated_at_unix_ms,
                    BASELINE_IDENTITY_CHANGED,
                );
            }
            return SamplingTickOutcome::Rejected;
        }
        let Some(captured_at_unix_ms) = wall_time_ms(&self.clock) else {
            history.record_rate_failure(now_monotonic_ns, OBS_SNAPSHOT_FAILED);
            if let Some(baseline) = self.baseline.as_mut() {
                baseline.clear_integrity(
                    baseline.identity(),
                    evaluated_at_unix_ms,
                    BASELINE_CLOCK_REGRESSION,
                );
            }
            return SamplingTickOutcome::Rejected;
        };
        let sample = match rate_sample(raw, now_monotonic_ns, captured_at_unix_ms) {
            Ok(sample) => sample,
            Err(()) => {
                history.record_rate_failure(now_monotonic_ns, OBS_RATE_CALCULATION_FAILED);
                if let Some(baseline) = self.baseline.as_mut() {
                    baseline.clear_integrity(
                        baseline.identity(),
                        captured_at_unix_ms,
                        BASELINE_CALCULATION_FAILED,
                    );
                }
                return SamplingTickOutcome::Rejected;
            }
        };
        match history.record_success(sample) {
            Ok(()) => {
                let windows = match history.detailed_windows(now_monotonic_ns) {
                    Ok(windows) => windows,
                    Err(error) => {
                        record_history_failure(history, now_monotonic_ns, error);
                        if let Some(baseline) = self.baseline.as_mut() {
                            baseline.clear_integrity(
                                baseline.identity(),
                                captured_at_unix_ms,
                                baseline_code_for_rate_error(error),
                            );
                        }
                        return SamplingTickOutcome::Rejected;
                    }
                };
                if windows[1].state == RateWindowState::Ready
                    && self.baseline.as_mut().is_none_or(|baseline| {
                        baseline
                            .evaluate_ready_window(&windows[1], captured_at_unix_ms)
                            .is_err()
                    })
                {
                    return SamplingTickOutcome::Rejected;
                }
                SamplingTickOutcome::Sampled
            }
            Err(error) => {
                record_history_failure(history, now_monotonic_ns, error);
                if let Some(baseline) = self.baseline.as_mut() {
                    baseline.clear_integrity(
                        baseline.identity(),
                        captured_at_unix_ms,
                        baseline_code_for_rate_error(error),
                    );
                }
                SamplingTickOutcome::Rejected
            }
        }
    }

    pub fn observe(
        &mut self,
        requested: &InterfaceName,
        active_interface: &InterfaceName,
        ownership: &OwnershipRecord,
    ) -> Result<ObservationSnapshot, ObservationError> {
        self.current_snapshot(requested, active_interface, ownership)
            .map(|(snapshot, _)| snapshot)
    }

    pub fn status(
        &mut self,
        requested: Option<&InterfaceName>,
        active_interface: Option<&InterfaceName>,
        ownership: Option<&OwnershipRecord>,
    ) -> Result<Vec<InterfaceStatus>, ObservationError> {
        let (active_interface, ownership) = match (active_interface, ownership) {
            (None, None) if requested.is_none() => return Ok(Vec::new()),
            (None, None) => return Err(session_error()),
            (Some(active_interface), Some(ownership)) => (active_interface, ownership),
            _ => return Err(ownership_error()),
        };
        let requested = requested.unwrap_or(active_interface);
        if requested != active_interface {
            return Err(session_error());
        }
        let (snapshot, rate_windows) =
            self.current_snapshot(requested, active_interface, ownership)?;
        let xdp_ingress = snapshot.hooks[0].total;
        let tc_egress = snapshot.hooks[OBSERVED_HOOK_COUNT - 1].total;
        let baseline = BaselineSummary::from_report(&snapshot.baseline);

        Ok(vec![InterfaceStatus {
            interface: snapshot.interface,
            state: InterfaceState::Observing,
            generation: snapshot.generation,
            captured_at_unix_ms: snapshot.captured_at_unix_ms,
            health: snapshot.health,
            vlan_visibility: snapshot.vlan_visibility,
            xdp_ingress,
            tc_egress,
            sampling: snapshot.sampling,
            rate_windows,
            baseline,
            fingerprints: FingerprintSummary::from(&snapshot.fingerprints),
        }])
    }

    pub fn pause(&mut self) {
        if let Some(history) = self.history.as_mut() {
            history.pause(self.clock.monotonic_ns(), OBS_RATE_SAMPLER_PAUSED);
        }
        if let Some(baseline) = self.baseline.as_mut() {
            baseline.unavailable(
                wall_time_ms(&self.clock).unwrap_or_default(),
                BASELINE_SAMPLER_PAUSED,
            );
        }
    }

    pub fn clear(&mut self) {
        self.history = None;
        self.baseline = None;
    }

    fn current_snapshot(
        &mut self,
        requested: &InterfaceName,
        active_interface: &InterfaceName,
        ownership: &OwnershipRecord,
    ) -> Result<(ObservationSnapshot, [StatusRateWindow; RATE_WINDOW_COUNT]), ObservationError>
    {
        if requested != active_interface {
            return Err(ObservationError::new(
                OBS_INTERFACE_MISMATCH,
                "requested interface does not match the active session",
            ));
        }
        if self.history.is_none() {
            return Err(session_error());
        }
        let RawObservation {
            ifindex,
            generation,
            vlan_visibility,
            hooks,
            fingerprints,
        } = self
            .reader
            .read_exact(ownership, ObservationReadPurpose::Request)
            .map_err(reader_error)?;
        let now_monotonic_ns = self.clock.monotonic_ns();
        let Some(history) = self.history.as_mut() else {
            return Err(session_error());
        };
        if ifindex != ownership.ifindex || generation != ownership.generation {
            history.record_identity_failure(now_monotonic_ns, OBS_OWNERSHIP_MISMATCH);
            return Err(ownership_error());
        }
        let captured_at_unix_ms = wall_time_ms(&self.clock).ok_or_else(snapshot_error)?;
        let current = match RateSample::new(
            RateIdentity::new(ifindex, generation).map_err(|_| ownership_error())?,
            now_monotonic_ns,
            captured_at_unix_ms,
            vlan_visibility,
            hooks.clone(),
        ) {
            Ok(current) => current,
            Err(_) => {
                history.record_rate_failure(now_monotonic_ns, OBS_RATE_CALCULATION_FAILED);
                return Err(snapshot_error());
            }
        };
        if let Err(error) = history.validate_current(&current) {
            let observation_error = rate_history_error(error);
            record_history_failure(history, now_monotonic_ns, error);
            return Err(observation_error);
        }
        let rate_windows = match history.detailed_windows(now_monotonic_ns) {
            Ok(windows) => windows,
            Err(error) => {
                let observation_error = rate_history_error(error);
                record_history_failure(history, now_monotonic_ns, error);
                return Err(observation_error);
            }
        };
        let status_rate_windows = match history.status_windows(now_monotonic_ns) {
            Ok(windows) => windows,
            Err(error) => {
                let observation_error = rate_history_error(error);
                record_history_failure(history, now_monotonic_ns, error);
                return Err(observation_error);
            }
        };
        let sampling = history.sampling_status();
        let baseline = self
            .baseline
            .as_ref()
            .ok_or_else(session_error)?
            .cached_report()
            .clone();
        let fingerprints = fingerprint_report(ifindex, generation, fingerprints)?;
        let health = observation_health(
            &sampling,
            &rate_windows,
            baseline.state,
            fingerprints.state,
        );
        let mut snapshot = ObservationSnapshot::new(
            requested.clone(),
            ifindex,
            generation,
            captured_at_unix_ms,
            vlan_visibility,
            hooks,
            sampling,
            rate_windows,
        )
        .map_err(|_| snapshot_error())?;
        snapshot.health = health;
        snapshot.baseline = baseline;
        snapshot.fingerprints = fingerprints;
        Ok((snapshot, status_rate_windows))
    }
}

fn rate_sample(
    raw: RawObservation,
    captured_at_monotonic_ns: u64,
    captured_at_unix_ms: u64,
) -> Result<RateSample, ()> {
    RateSample::new(
        RateIdentity::new(raw.ifindex, raw.generation).map_err(|_| ())?,
        captured_at_monotonic_ns,
        captured_at_unix_ms,
        raw.vlan_visibility,
        raw.hooks,
    )
    .map_err(|_| ())
}

fn record_history_failure(
    history: &mut RateHistory,
    now_monotonic_ns: u64,
    error: RateHistoryError,
) {
    let code = rate_error_code(error);
    if error == RateHistoryError::IdentityMismatch {
        history.record_identity_failure(now_monotonic_ns, code);
    } else {
        history.record_rate_failure(now_monotonic_ns, code);
    }
}

const fn rate_error_code(error: RateHistoryError) -> &'static str {
    match error {
        RateHistoryError::IdentityMismatch => OBS_OWNERSHIP_MISMATCH,
        RateHistoryError::ClockRegression => OBS_RATE_CLOCK_REGRESSION,
        RateHistoryError::CounterRegression => OBS_RATE_COUNTER_REGRESSION,
        RateHistoryError::CalculationFailed => OBS_RATE_CALCULATION_FAILED,
    }
}

fn rate_history_error(error: RateHistoryError) -> ObservationError {
    ObservationError::new(rate_error_code(error), "rate history validation failed")
}

fn observation_health(
    sampling: &SamplingStatus,
    windows: &[l2_loop_core::DetailedRateWindow; RATE_WINDOW_COUNT],
    baseline_state: BaselineState,
    fingerprint_state: FingerprintState,
) -> ObservationHealth {
    if sampling.sampling_paused
        || sampling.last_error_code.is_some()
        || windows
            .iter()
            .any(|window| window.state == RateWindowState::Stale)
        || baseline_state == BaselineState::Unavailable
        || fingerprint_state == FingerprintState::Unavailable
    {
        ObservationHealth::Degraded
    } else {
        ObservationHealth::Healthy
    }
}

fn fingerprint_report(
    ifindex: u32,
    generation: u64,
    raw: RawFingerprints,
) -> Result<FingerprintReport, ObservationError> {
    match raw {
        RawFingerprints::NotRequested => Ok(FingerprintReport::empty()),
        RawFingerprints::Available(evidence) => {
            FingerprintReport::build(ifindex, generation, evidence).map_err(|_| snapshot_error())
        }
        RawFingerprints::Unavailable { code } => {
            FingerprintReport::unavailable(code).map_err(|_| snapshot_error())
        }
    }
}

const fn baseline_code_for_rate_error(error: RateHistoryError) -> &'static str {
    match error {
        RateHistoryError::IdentityMismatch => BASELINE_IDENTITY_CHANGED,
        RateHistoryError::ClockRegression => BASELINE_CLOCK_REGRESSION,
        RateHistoryError::CounterRegression => BASELINE_COUNTER_REGRESSION,
        RateHistoryError::CalculationFailed => BASELINE_CALCULATION_FAILED,
    }
}

fn wall_time_ms<C: Clock>(clock: &C) -> Option<u64> {
    clock
        .wall_time()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn is_identity_code(code: &str) -> bool {
    matches!(code, OBS_OWNERSHIP_MISMATCH | OBS_MAP_IDENTITY_MISMATCH)
}

const fn session_error() -> ObservationError {
    ObservationError::new(
        OBS_SESSION_NOT_FOUND,
        "no active isolated session matches the request",
    )
}

const fn ownership_error() -> ObservationError {
    ObservationError::new(
        OBS_OWNERSHIP_MISMATCH,
        "observation identity does not match the ownership journal",
    )
}

pub struct ObservationService<R, C> {
    reader: R,
    clock: C,
}

impl<R, C> ObservationService<R, C>
where
    R: ObservationReader,
    C: Clock,
{
    pub const fn new(reader: R, clock: C) -> Self {
        Self { reader, clock }
    }

    pub fn observe(
        &mut self,
        requested: &InterfaceName,
        active_interface: &InterfaceName,
        ownership: &OwnershipRecord,
    ) -> Result<ObservationSnapshot, ObservationError> {
        if requested != active_interface {
            return Err(ObservationError::new(
                OBS_INTERFACE_MISMATCH,
                "requested interface does not match the active session",
            ));
        }

        let RawObservation {
            ifindex,
            generation,
            vlan_visibility,
            hooks,
            fingerprints,
        } = self
            .reader
            .read_exact(ownership, ObservationReadPurpose::Request)
            .map_err(reader_error)?;
        if ifindex != ownership.ifindex || generation != ownership.generation {
            return Err(ownership_error());
        }

        let captured_at_unix_ms = wall_time_ms(&self.clock).ok_or_else(snapshot_error)?;

        let mut snapshot = ObservationSnapshot::new(
            requested.clone(),
            ifindex,
            generation,
            captured_at_unix_ms,
            vlan_visibility,
            hooks,
            SamplingStatus::default(),
            warming_detailed_rate_windows(),
        )
        .map_err(|_| snapshot_error())?;
        snapshot.fingerprints = fingerprint_report(ifindex, generation, fingerprints)?;
        if snapshot.fingerprints.state == FingerprintState::Unavailable {
            snapshot.health = ObservationHealth::Degraded;
        }
        Ok(snapshot)
    }

    pub fn status(
        &mut self,
        requested: Option<&InterfaceName>,
        active_interface: Option<&InterfaceName>,
        ownership: Option<&OwnershipRecord>,
    ) -> Result<Vec<InterfaceStatus>, ObservationError> {
        let (active_interface, ownership) = match (active_interface, ownership) {
            (None, None) if requested.is_none() => return Ok(Vec::new()),
            (None, None) => return Err(session_error()),
            (Some(active_interface), Some(ownership)) => (active_interface, ownership),
            _ => return Err(ownership_error()),
        };
        let requested = requested.unwrap_or(active_interface);
        if requested != active_interface {
            return Err(session_error());
        }
        let snapshot = self.observe(requested, active_interface, ownership)?;
        let xdp_ingress = snapshot.hooks[0].total;
        let tc_egress = snapshot.hooks[OBSERVED_HOOK_COUNT - 1].total;
        let baseline = BaselineSummary::from_report(&snapshot.baseline);

        Ok(vec![InterfaceStatus {
            interface: snapshot.interface,
            state: InterfaceState::Observing,
            generation: snapshot.generation,
            captured_at_unix_ms: snapshot.captured_at_unix_ms,
            health: snapshot.health,
            vlan_visibility: snapshot.vlan_visibility,
            xdp_ingress,
            tc_egress,
            sampling: snapshot.sampling,
            rate_windows: warming_status_rate_windows(),
            baseline,
            fingerprints: FingerprintSummary::from(&snapshot.fingerprints),
        }])
    }
}

fn reader_error(error: PortError) -> ObservationError {
    ObservationError::new(
        error.stable_code().unwrap_or(OBS_MAP_UNAVAILABLE),
        "observation reader failed",
    )
}

const fn snapshot_error() -> ObservationError {
    ObservationError::new(
        OBS_SNAPSHOT_FAILED,
        "observation snapshot construction failed",
    )
}
