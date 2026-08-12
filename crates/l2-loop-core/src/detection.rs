use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BaselineReport, BaselineState, BaselineSubject, DetailedRateWindow, DomainError,
    FingerprintWindowReport, FingerprintWindowState, HookRate, HookRole, RateIdentity,
    RateWindowState, TrafficClass,
    fingerprint_window::validate_error_code,
    rate::validate_detailed_rate_windows,
};

pub const DETECTION_ADAPTIVE_PACKET_FLOOR_PPS: u64 = 1_000;
pub const DETECTION_ADAPTIVE_BYTE_FLOOR_BPS: u64 = 1_048_576;
pub const DETECTION_ABSOLUTE_PACKET_THRESHOLD_PPS: u64 = 100_000;
pub const DETECTION_ABSOLUTE_BYTE_THRESHOLD_BPS: u64 = 104_857_600;
pub const DETECTION_BUM_RATIO_MILLI: u64 = 800;
pub const DETECTION_DOMINANT_RATIO_MILLI: u64 = 800;
pub const DETECTION_MINIMUM_INGRESS_SAMPLES: u64 = 16;
pub const DETECTION_AMPLIFICATION_RATIO_MILLI: u64 = 4_000;
pub const DETECTION_ASSERT_TICKS: u8 = 3;
pub const DETECTION_CLEAR_TICKS: u8 = 10;
pub const DETECTION_COOLDOWN_MS: u64 = 30_000;
pub const DETECTION_TRANSITION_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub fingerprint_window_ms: u64,
    pub fingerprint_freshness_ms: u64,
    pub adaptive_packet_floor_pps: u64,
    pub adaptive_byte_floor_bps: u64,
    pub absolute_packet_threshold_pps: u64,
    pub absolute_byte_threshold_bps: u64,
    pub bum_ratio_milli: u64,
    pub dominant_ratio_milli: u64,
    pub minimum_ingress_samples: u64,
    pub amplification_ratio_milli: u64,
    pub assert_ticks: u8,
    pub clear_ticks: u8,
    pub cooldown_ms: u64,
    pub transition_capacity: u8,
}

impl DetectionConfig {
    pub const fn fixed() -> Self {
        Self {
            fingerprint_window_ms: crate::DETECTION_FINGERPRINT_WINDOW_MS,
            fingerprint_freshness_ms: crate::DETECTION_FINGERPRINT_FRESHNESS_MS,
            adaptive_packet_floor_pps: DETECTION_ADAPTIVE_PACKET_FLOOR_PPS,
            adaptive_byte_floor_bps: DETECTION_ADAPTIVE_BYTE_FLOOR_BPS,
            absolute_packet_threshold_pps: DETECTION_ABSOLUTE_PACKET_THRESHOLD_PPS,
            absolute_byte_threshold_bps: DETECTION_ABSOLUTE_BYTE_THRESHOLD_BPS,
            bum_ratio_milli: DETECTION_BUM_RATIO_MILLI,
            dominant_ratio_milli: DETECTION_DOMINANT_RATIO_MILLI,
            minimum_ingress_samples: DETECTION_MINIMUM_INGRESS_SAMPLES,
            amplification_ratio_milli: DETECTION_AMPLIFICATION_RATIO_MILLI,
            assert_ticks: DETECTION_ASSERT_TICKS,
            clear_ticks: DETECTION_CLEAR_TICKS,
            cooldown_ms: DETECTION_COOLDOWN_MS,
            transition_capacity: DETECTION_TRANSITION_CAPACITY as u8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionState {
    WarmingUp,
    Normal,
    IngressStormConfirmed,
    EgressStormConfirmed,
    BidirectionalStormConfirmed,
    ExternalLoopSuspected,
    ExternalLoopHighConfidence,
    Cooldown,
    Unavailable,
}

impl DetectionState {
    pub const fn is_anomalous(self) -> bool {
        matches!(
            self,
            Self::IngressStormConfirmed
                | Self::EgressStormConfirmed
                | Self::BidirectionalStormConfirmed
                | Self::ExternalLoopSuspected
                | Self::ExternalLoopHighConfidence
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StormCandidate {
    None,
    Ingress,
    Egress,
    Bidirectional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookDetectionSignals {
    pub bum_packets_per_second: Option<u64>,
    pub bum_bytes_per_second: Option<u64>,
    pub bum_ratio_milli: Option<u64>,
    pub baseline_elevated: Option<bool>,
    pub adaptive_candidate: Option<bool>,
    pub absolute_candidate: Option<bool>,
}

impl HookDetectionSignals {
    const fn warming() -> Self {
        Self {
            bum_packets_per_second: None,
            bum_bytes_per_second: None,
            bum_ratio_milli: None,
            baseline_elevated: None,
            adaptive_candidate: None,
            absolute_candidate: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionSignals {
    pub source_window_end_unix_ms: Option<u64>,
    pub ingress: HookDetectionSignals,
    pub egress: HookDetectionSignals,
    pub candidate: StormCandidate,
    pub fingerprint_window: FingerprintWindowReport,
    pub loop_suspected: Option<bool>,
    pub loop_high_confidence: Option<bool>,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DetectionError {
    #[error("rate evidence is invalid for passive detection")]
    InvalidRateEvidence,
    #[error("baseline evidence is invalid for passive detection")]
    InvalidBaselineEvidence,
    #[error("fingerprint-window evidence is invalid for passive detection")]
    InvalidFingerprintEvidence,
    #[error("passive detection source windows do not share one endpoint")]
    SourceEndpointMismatch,
    #[error("passive detection wall clock precedes its evidence")]
    ClockRegression,
    #[error("passive detection checked arithmetic failed")]
    CalculationFailed,
}

impl DetectionSignals {
    pub const fn warming() -> Self {
        Self {
            source_window_end_unix_ms: None,
            ingress: HookDetectionSignals::warming(),
            egress: HookDetectionSignals::warming(),
            candidate: StormCandidate::None,
            fingerprint_window: FingerprintWindowReport::warming(),
            loop_suspected: None,
            loop_high_confidence: None,
        }
    }

    pub fn derive(
        rate_windows: &[DetailedRateWindow; crate::RATE_WINDOW_COUNT],
        baseline: &BaselineReport,
        fingerprint_window: &FingerprintWindowReport,
        evaluated_at_unix_ms: u64,
    ) -> Result<Self, DetectionError> {
        validate_detailed_rate_windows(rate_windows)
            .map_err(|_| DetectionError::InvalidRateEvidence)?;
        baseline
            .validate()
            .map_err(|_| DetectionError::InvalidBaselineEvidence)?;
        fingerprint_window
            .validate()
            .map_err(|_| DetectionError::InvalidFingerprintEvidence)?;

        let one_second = fixed_window(rate_windows, 1_000)?;
        let ten_second = fixed_window(rate_windows, 10_000)?;
        let source_window_end_unix_ms = validate_source_endpoints(
            rate_windows,
            baseline,
            fingerprint_window,
            evaluated_at_unix_ms,
        )?;

        let ingress = derive_hook(
            one_second,
            ten_second,
            baseline,
            HookRole::ExternalXdpIngress,
        )?;
        let egress = derive_hook(
            one_second,
            ten_second,
            baseline,
            HookRole::PhysicalTcEgress,
        )?;
        let ingress_candidate = hook_is_candidate(&ingress);
        let egress_candidate = hook_is_candidate(&egress);
        let candidate = match (ingress_candidate, egress_candidate) {
            (false, false) => StormCandidate::None,
            (true, false) => StormCandidate::Ingress,
            (false, true) => StormCandidate::Egress,
            (true, true) => StormCandidate::Bidirectional,
        };

        let (loop_suspected, loop_high_confidence) = derive_relationship_signals(
            candidate,
            &ingress,
            fingerprint_window,
            evaluated_at_unix_ms,
        )?;
        let signals = Self {
            source_window_end_unix_ms,
            ingress,
            egress,
            candidate,
            fingerprint_window: fingerprint_window.clone(),
            loop_suspected,
            loop_high_confidence,
        };
        signals
            .validate()
            .map_err(|_| DetectionError::CalculationFailed)?;
        Ok(signals)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        self.fingerprint_window.validate()?;
        for hook in [&self.ingress, &self.egress] {
            if hook.bum_ratio_milli.is_some_and(|ratio| ratio > 1_000) {
                return Err(DomainError::InvalidObservation(
                    "detection BUM ratio exceeds one thousand milli",
                ));
            }
        }
        if self.loop_high_confidence == Some(true) && self.loop_suspected != Some(true) {
            return Err(DomainError::InvalidObservation(
                "high-confidence detection requires suspected evidence",
            ));
        }
        Ok(())
    }
}

fn fixed_window(
    windows: &[DetailedRateWindow; crate::RATE_WINDOW_COUNT],
    window_ms: u64,
) -> Result<&DetailedRateWindow, DetectionError> {
    windows
        .iter()
        .find(|window| window.window_ms == window_ms)
        .ok_or(DetectionError::InvalidRateEvidence)
}

fn validate_source_endpoints(
    rate_windows: &[DetailedRateWindow; crate::RATE_WINDOW_COUNT],
    baseline: &BaselineReport,
    fingerprint_window: &FingerprintWindowReport,
    evaluated_at_unix_ms: u64,
) -> Result<Option<u64>, DetectionError> {
    let mut source_end = None;
    for window in rate_windows
        .iter()
        .filter(|window| window.state == RateWindowState::Ready)
    {
        let end = window
            .end_unix_ms
            .ok_or(DetectionError::InvalidRateEvidence)?;
        if source_end.is_some_and(|existing| existing != end) {
            return Err(DetectionError::SourceEndpointMismatch);
        }
        if end > evaluated_at_unix_ms {
            return Err(DetectionError::ClockRegression);
        }
        source_end = Some(end);
    }
    if let Some(baseline_end) = baseline.source_end_unix_ms {
        if source_end != Some(baseline_end) {
            return Err(DetectionError::SourceEndpointMismatch);
        }
        if baseline_end > evaluated_at_unix_ms {
            return Err(DetectionError::ClockRegression);
        }
    }
    if fingerprint_window
        .end_unix_ms
        .is_some_and(|end| end > evaluated_at_unix_ms)
    {
        return Err(DetectionError::ClockRegression);
    }
    Ok(source_end)
}

fn derive_hook(
    one_second: &DetailedRateWindow,
    ten_second: &DetailedRateWindow,
    baseline: &BaselineReport,
    role: HookRole,
) -> Result<HookDetectionSignals, DetectionError> {
    let ten_second_rates = hook_rates(ten_second, role)?;
    let one_second_rates = hook_rates(one_second, role)?;
    let baseline_elevated = baseline_bum_elevated(baseline, role)?;

    let (bum_packets_per_second, bum_bytes_per_second, bum_ratio_milli) =
        if let Some(rates) = ten_second_rates {
            let (packets, bytes) = bum_rates(rates)?;
            let ratio = ratio_milli(packets, rates.total.packets_per_second)?;
            (Some(packets), Some(bytes), Some(ratio))
        } else {
            (None, None, None)
        };
    let adaptive_candidate = match (
        bum_packets_per_second,
        bum_bytes_per_second,
        baseline_elevated,
    ) {
        (Some(packets), Some(bytes), Some(elevated)) => Some(
            elevated
                && (packets >= DETECTION_ADAPTIVE_PACKET_FLOOR_PPS
                    || bytes >= DETECTION_ADAPTIVE_BYTE_FLOOR_BPS),
        ),
        _ => None,
    };
    let absolute_candidate = one_second_rates
        .map(bum_rates)
        .transpose()?
        .map(|(packets, bytes)| {
            packets >= DETECTION_ABSOLUTE_PACKET_THRESHOLD_PPS
                || bytes >= DETECTION_ABSOLUTE_BYTE_THRESHOLD_BPS
        });

    Ok(HookDetectionSignals {
        bum_packets_per_second,
        bum_bytes_per_second,
        bum_ratio_milli,
        baseline_elevated,
        adaptive_candidate,
        absolute_candidate,
    })
}

fn hook_rates(
    window: &DetailedRateWindow,
    role: HookRole,
) -> Result<Option<&HookRate>, DetectionError> {
    if window.state != RateWindowState::Ready {
        return Ok(None);
    }
    window
        .hooks
        .as_ref()
        .and_then(|hooks| hooks.iter().find(|hook| hook.role == role))
        .map(Some)
        .ok_or(DetectionError::InvalidRateEvidence)
}

fn bum_rates(rates: &HookRate) -> Result<(u64, u64), DetectionError> {
    let mut packets = 0_u64;
    let mut bytes = 0_u64;
    for class in rates.classes.iter().take(4) {
        packets = packets
            .checked_add(class.counters.packets_per_second)
            .ok_or(DetectionError::CalculationFailed)?;
        bytes = bytes
            .checked_add(class.counters.bytes_per_second)
            .ok_or(DetectionError::CalculationFailed)?;
    }
    if packets > rates.total.packets_per_second || bytes > rates.total.bytes_per_second {
        return Err(DetectionError::InvalidRateEvidence);
    }
    Ok((packets, bytes))
}

fn ratio_milli(numerator: u64, denominator: u64) -> Result<u64, DetectionError> {
    if denominator == 0 {
        return if numerator == 0 {
            Ok(0)
        } else {
            Err(DetectionError::InvalidRateEvidence)
        };
    }
    let ratio = u128::from(numerator)
        .checked_mul(1_000)
        .ok_or(DetectionError::CalculationFailed)?
        / u128::from(denominator);
    u64::try_from(ratio).map_err(|_| DetectionError::CalculationFailed)
}

fn baseline_bum_elevated(
    baseline: &BaselineReport,
    role: HookRole,
) -> Result<Option<bool>, DetectionError> {
    const BUM_CLASSES: [TrafficClass; 4] = [
        TrafficClass::L2Broadcast,
        TrafficClass::Ipv4Multicast,
        TrafficClass::Ipv6Multicast,
        TrafficClass::OtherL2Multicast,
    ];
    let mut elevated = false;
    for traffic_class in BUM_CLASSES {
        let subject = baseline
            .subjects
            .iter()
            .find(|subject| {
                subject.hook == role
                    && subject.subject == (BaselineSubject::TrafficClass { traffic_class })
            })
            .ok_or(DetectionError::InvalidBaselineEvidence)?;
        match subject.state {
            BaselineState::Learning | BaselineState::Unavailable => return Ok(None),
            BaselineState::WithinBaseline | BaselineState::Elevated => {
                elevated |= subject.packets.elevated == Some(true)
                    || subject.bytes.elevated == Some(true);
            }
        }
    }
    Ok(Some(elevated))
}

fn hook_is_candidate(signals: &HookDetectionSignals) -> bool {
    signals.adaptive_candidate == Some(true) || signals.absolute_candidate == Some(true)
}

fn derive_relationship_signals(
    candidate: StormCandidate,
    ingress: &HookDetectionSignals,
    fingerprint: &FingerprintWindowReport,
    evaluated_at_unix_ms: u64,
) -> Result<(Option<bool>, Option<bool>), DetectionError> {
    if fingerprint.state != FingerprintWindowState::Ready {
        return Ok((None, None));
    }
    let end = fingerprint
        .end_unix_ms
        .ok_or(DetectionError::InvalidFingerprintEvidence)?;
    let age = evaluated_at_unix_ms
        .checked_sub(end)
        .ok_or(DetectionError::ClockRegression)?;
    if age > crate::DETECTION_FINGERPRINT_FRESHNESS_MS {
        return Ok((None, None));
    }
    let ingress_or_bidirectional = matches!(
        candidate,
        StormCandidate::Ingress | StormCandidate::Bidirectional
    );
    let suspected = ingress_or_bidirectional
        && ingress
            .bum_ratio_milli
            .is_some_and(|ratio| ratio >= DETECTION_BUM_RATIO_MILLI)
        && fingerprint.ingress.packets >= DETECTION_MINIMUM_INGRESS_SAMPLES
        && fingerprint.repeated_relation_count > 0
        && fingerprint
            .dominant_ingress_packet_ratio_milli
            .is_some_and(|ratio| ratio >= DETECTION_DOMINANT_RATIO_MILLI);
    let high_confidence = suspected
        && fingerprint.egress_first_correlated_relation_count > 0
        && fingerprint
            .maximum_ingress_to_egress_packet_ratio_milli
            .is_some_and(|ratio| ratio >= DETECTION_AMPLIFICATION_RATIO_MILLI);
    Ok((Some(suspected), Some(high_confidence)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionTransitionReason {
    EvidenceReady,
    StormAsserted,
    RelationshipSuspected,
    RelationshipHighConfidence,
    EvidenceCleared,
    CooldownCompleted,
    EvidenceUnavailable,
    EvidenceRecovered,
    SamplerPaused,
    IntegrityFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionTransition {
    pub sequence: u64,
    pub previous_state: DetectionState,
    pub current_state: DetectionState,
    pub reason: DetectionTransitionReason,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionReport {
    pub state: DetectionState,
    pub retained_anomalous_state: Option<DetectionState>,
    pub evaluated_at_unix_ms: u64,
    pub state_since_unix_ms: u64,
    pub last_trustworthy_at_unix_ms: Option<u64>,
    pub config: DetectionConfig,
    pub signals: DetectionSignals,
    pub candidate_streak: u8,
    pub clear_streak: u8,
    pub transition_sequence: u64,
    pub transitions: Vec<DetectionTransition>,
    pub last_error_code: Option<String>,
}

impl DetectionReport {
    pub fn warming(identity: RateIdentity, evaluated_at_unix_ms: u64) -> Self {
        let _ = (identity.ifindex(), identity.generation());
        Self {
            state: DetectionState::WarmingUp,
            retained_anomalous_state: None,
            evaluated_at_unix_ms,
            state_since_unix_ms: evaluated_at_unix_ms,
            last_trustworthy_at_unix_ms: None,
            config: DetectionConfig::fixed(),
            signals: DetectionSignals::warming(),
            candidate_streak: 0,
            clear_streak: 0,
            transition_sequence: 0,
            transitions: Vec::new(),
            last_error_code: None,
        }
    }

    pub fn unavailable(
        identity: RateIdentity,
        evaluated_at_unix_ms: u64,
        retained_anomalous_state: Option<DetectionState>,
        code: &str,
    ) -> Result<Self, DomainError> {
        validate_error_code(code)?;
        if retained_anomalous_state.is_some_and(|state| !state.is_anomalous()) {
            return Err(DomainError::InvalidObservation(
                "detection retained state is not anomalous",
            ));
        }
        let mut report = Self::warming(identity, evaluated_at_unix_ms);
        report.state = DetectionState::Unavailable;
        report.retained_anomalous_state = retained_anomalous_state;
        report.signals.fingerprint_window = FingerprintWindowReport::unavailable(code)?;
        report.last_error_code = Some(code.to_owned());
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.config != DetectionConfig::fixed()
            || self.candidate_streak > DETECTION_ASSERT_TICKS
            || self.clear_streak > DETECTION_CLEAR_TICKS
            || self.transitions.len() > DETECTION_TRANSITION_CAPACITY
        {
            return Err(DomainError::InvalidObservation(
                "detection report fixed bounds are invalid",
            ));
        }
        self.signals.validate()?;
        validate_retained_state(self.state, self.retained_anomalous_state)?;

        match (self.state, self.last_error_code.as_deref()) {
            (DetectionState::Unavailable, Some(code)) => validate_error_code(code)?,
            (DetectionState::Unavailable, None) => {
                return Err(DomainError::InvalidObservation(
                    "unavailable detection requires an error code",
                ));
            }
            (_, Some(code)) => {
                validate_error_code(code)?;
                if self.signals.fingerprint_window.state != FingerprintWindowState::Unavailable {
                    return Err(DomainError::InvalidObservation(
                        "available detection has an unrelated error code",
                    ));
                }
            }
            (_, None) => {}
        }

        if self.transitions.is_empty() {
            if self.transition_sequence != 0 {
                return Err(DomainError::InvalidObservation(
                    "empty detection history has a non-zero sequence",
                ));
            }
        } else {
            let mut previous: Option<u64> = None;
            for transition in &self.transitions {
                if transition.sequence == 0
                    || previous.is_some_and(|sequence| {
                        sequence.checked_add(1) != Some(transition.sequence)
                    })
                    || transition.previous_state == transition.current_state
                {
                    return Err(DomainError::InvalidObservation(
                        "detection transition history is invalid",
                    ));
                }
                previous = Some(transition.sequence);
            }
            if previous != Some(self.transition_sequence) {
                return Err(DomainError::InvalidObservation(
                    "detection transition sequence is inconsistent",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionSummary {
    pub state: DetectionState,
    pub retained_anomalous_state: Option<DetectionState>,
    pub transition_sequence: u64,
    pub state_since_unix_ms: u64,
    pub last_trustworthy_at_unix_ms: Option<u64>,
    pub candidate: StormCandidate,
    pub fingerprint_window_state: FingerprintWindowState,
    pub last_error_code: Option<String>,
}

impl DetectionSummary {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_retained_state(self.state, self.retained_anomalous_state)?;
        if let Some(code) = self.last_error_code.as_deref() {
            validate_error_code(code)?;
        }
        if self.state == DetectionState::Unavailable && self.last_error_code.is_none() {
            return Err(DomainError::InvalidObservation(
                "unavailable detection summary requires an error code",
            ));
        }
        Ok(())
    }
}

impl From<&DetectionReport> for DetectionSummary {
    fn from(report: &DetectionReport) -> Self {
        Self {
            state: report.state,
            retained_anomalous_state: report.retained_anomalous_state,
            transition_sequence: report.transition_sequence,
            state_since_unix_ms: report.state_since_unix_ms,
            last_trustworthy_at_unix_ms: report.last_trustworthy_at_unix_ms,
            candidate: report.signals.candidate,
            fingerprint_window_state: report.signals.fingerprint_window.state,
            last_error_code: report.last_error_code.clone(),
        }
    }
}

fn validate_retained_state(
    state: DetectionState,
    retained: Option<DetectionState>,
) -> Result<(), DomainError> {
    if retained.is_some_and(|value| !value.is_anomalous())
        || (retained.is_some()
            && !matches!(
                state,
                DetectionState::Cooldown | DetectionState::Unavailable
            ))
        || (state == DetectionState::Cooldown && retained.is_none())
    {
        return Err(DomainError::InvalidObservation(
            "detection retained state is invalid",
        ));
    }
    Ok(())
}
