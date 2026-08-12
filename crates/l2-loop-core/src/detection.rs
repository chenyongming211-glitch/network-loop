use serde::{Deserialize, Serialize};

use crate::{
    DomainError, FingerprintWindowReport, FingerprintWindowState, RateIdentity,
    fingerprint_window::validate_error_code,
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
            let mut previous = None;
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
