use std::{fs::File, io::Read};

use l2_loop_core::{
    AlertCode, BaselineSummary, DetectionState, DetectionTransition, DetectionTransitionReason,
    EVIDENCE_MAX_REVISIONS_PER_EVENT, EVIDENCE_SCHEMA_VERSION, EventId, EvidenceStatus,
    IncidentRevisionV1, InterfaceName, OBSERVED_HOOK_COUNT, ObservationSnapshot, StatusRateWindow,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentIdentity {
    pub interface: InterfaceName,
    pub ifindex: u32,
    pub generation: u64,
}

impl IncidentIdentity {
    pub fn new(
        interface: InterfaceName,
        ifindex: u32,
        generation: u64,
    ) -> Result<Self, IncidentRecorderError> {
        if ifindex == 0 || generation == 0 {
            return Err(IncidentRecorderError::InvalidIdentity);
        }
        Ok(Self {
            interface,
            ifindex,
            generation,
        })
    }
}

pub trait EventIdSource: Send {
    fn next_id(&mut self) -> Result<EventId, IncidentRecorderError>;
}

impl<T: EventIdSource + ?Sized> EventIdSource for Box<T> {
    fn next_id(&mut self) -> Result<EventId, IncidentRecorderError> {
        (**self).next_id()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxEventIdSource;

impl EventIdSource for LinuxEventIdSource {
    fn next_id(&mut self) -> Result<EventId, IncidentRecorderError> {
        let mut bytes = [0_u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut bytes))
            .map_err(|_| IncidentRecorderError::IdUnavailable)?;
        Ok(EventId::from_bytes(bytes))
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum IncidentRecorderError {
    #[error("incident identity requires non-zero ifindex and generation")]
    InvalidIdentity,
    #[error("incident event ID source is unavailable")]
    IdUnavailable,
    #[error("detection transition sequence is not contiguous")]
    TransitionGap,
    #[error("incident reached its fixed revision limit")]
    RevisionLimit,
    #[error("incident closure timestamp precedes its opening")]
    ClockRegression,
    #[error("incident snapshot does not match the active generation")]
    InvalidSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentWriteJob {
    pub revision: IncidentRevisionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveIncident {
    event_id: EventId,
    revision: u64,
    opened_at_unix_ms: u64,
    last_state: DetectionState,
}

pub struct IncidentRecorder<S> {
    identity: IncidentIdentity,
    id_source: S,
    active: Option<ActiveIncident>,
    last_transition_sequence: u64,
    suppressed_duplicate_count: u64,
}

impl<S: EventIdSource> IncidentRecorder<S> {
    pub fn new(identity: IncidentIdentity, id_source: S) -> Self {
        Self {
            identity,
            id_source,
            active: None,
            last_transition_sequence: 0,
            suppressed_duplicate_count: 0,
        }
    }

    pub const fn identity(&self) -> &IncidentIdentity {
        &self.identity
    }

    pub const fn active_event(&self) -> Option<EventId> {
        match self.active {
            Some(active) => Some(active.event_id),
            None => None,
        }
    }

    pub const fn last_transition_sequence(&self) -> u64 {
        self.last_transition_sequence
    }

    pub const fn suppressed_duplicate_count(&self) -> u64 {
        self.suppressed_duplicate_count
    }

    pub fn reset_identity(&mut self, identity: IncidentIdentity) {
        self.identity = identity;
        self.active = None;
        self.last_transition_sequence = 0;
        self.suppressed_duplicate_count = 0;
    }

    pub fn acknowledge_without_output(
        &mut self,
        transition: &DetectionTransition,
    ) -> Result<(), IncidentRecorderError> {
        if transition.sequence <= self.last_transition_sequence {
            self.suppressed_duplicate_count = self.suppressed_duplicate_count.saturating_add(1);
            return Ok(());
        }
        if transition.sequence != self.last_transition_sequence.saturating_add(1) {
            return Err(IncidentRecorderError::TransitionGap);
        }
        if let Some(active) = self.active.as_mut() {
            active.last_state = transition.current_state;
        }
        self.last_transition_sequence = transition.sequence;
        Ok(())
    }

    pub fn record(
        &mut self,
        transition: &DetectionTransition,
        snapshot: &ObservationSnapshot,
    ) -> Result<Option<IncidentWriteJob>, IncidentRecorderError> {
        self.validate_snapshot(snapshot)?;
        if transition.sequence <= self.last_transition_sequence {
            self.suppressed_duplicate_count = self.suppressed_duplicate_count.saturating_add(1);
            return Ok(None);
        }
        if transition.sequence != self.last_transition_sequence.saturating_add(1) {
            return Err(IncidentRecorderError::TransitionGap);
        }

        let job = match self.active {
            None if transition.current_state.is_anomalous() => {
                let event_id = self.id_source.next_id()?;
                let code = AlertCode::for_state(transition.current_state)
                    .expect("an anomalous state always has an alert code");
                let active = ActiveIncident {
                    event_id,
                    revision: 1,
                    opened_at_unix_ms: transition.occurred_at_unix_ms,
                    last_state: transition.current_state,
                };
                let job = self.job(active, *transition, code, None, snapshot)?;
                self.active = Some(active);
                Some(job)
            }
            None => None,
            Some(active) => {
                let code = match transition.current_state {
                    state if state.is_anomalous() => AlertCode::for_state(state),
                    DetectionState::Unavailable => Some(AlertCode::OutputDegraded),
                    DetectionState::Cooldown => Some(AlertCode::IncidentCooldown),
                    DetectionState::Normal => Some(AlertCode::IncidentClosed),
                    DetectionState::WarmingUp => None,
                    _ => None,
                };
                match code {
                    Some(code) => {
                        if active.revision >= EVIDENCE_MAX_REVISIONS_PER_EVENT {
                            return Err(IncidentRecorderError::RevisionLimit);
                        }
                        let next = ActiveIncident {
                            revision: active.revision + 1,
                            last_state: transition.current_state,
                            ..active
                        };
                        let closed_at = (code == AlertCode::IncidentClosed)
                            .then_some(transition.occurred_at_unix_ms);
                        let job = self.job(next, *transition, code, closed_at, snapshot)?;
                        self.active = if closed_at.is_some() {
                            None
                        } else {
                            Some(next)
                        };
                        Some(job)
                    }
                    None => {
                        self.active = Some(ActiveIncident {
                            last_state: transition.current_state,
                            ..active
                        });
                        None
                    }
                }
            }
        };
        self.last_transition_sequence = transition.sequence;
        Ok(job)
    }

    pub fn generation_ended(
        &mut self,
        occurred_at_unix_ms: u64,
        snapshot: &ObservationSnapshot,
    ) -> Result<Option<IncidentWriteJob>, IncidentRecorderError> {
        self.validate_snapshot(snapshot)?;
        let Some(active) = self.active else {
            return Ok(None);
        };
        if active.revision >= EVIDENCE_MAX_REVISIONS_PER_EVENT {
            return Err(IncidentRecorderError::RevisionLimit);
        }
        if occurred_at_unix_ms < active.opened_at_unix_ms {
            return Err(IncidentRecorderError::ClockRegression);
        }
        let next = ActiveIncident {
            revision: active.revision + 1,
            ..active
        };
        let transition = DetectionTransition {
            sequence: self.last_transition_sequence,
            previous_state: active.last_state,
            current_state: active.last_state,
            reason: DetectionTransitionReason::SamplerPaused,
            occurred_at_unix_ms,
        };
        let job = self.job(
            next,
            transition,
            AlertCode::GenerationEnded,
            Some(occurred_at_unix_ms),
            snapshot,
        )?;
        self.active = None;
        Ok(Some(job))
    }

    fn job(
        &self,
        active: ActiveIncident,
        transition: DetectionTransition,
        code: AlertCode,
        closed_at_unix_ms: Option<u64>,
        snapshot: &ObservationSnapshot,
    ) -> Result<IncidentWriteJob, IncidentRecorderError> {
        let rate_windows = snapshot.rate_windows.clone().map(|window| StatusRateWindow {
            window_ms: window.window_ms,
            state: window.state,
            coverage_ms: window.coverage_ms,
            elapsed_ns: window.elapsed_ns,
            start_unix_ms: window.start_unix_ms,
            end_unix_ms: window.end_unix_ms,
            xdp_ingress: window.hooks.as_ref().map(|hooks| hooks[0].total),
            tc_egress: window
                .hooks
                .as_ref()
                .map(|hooks| hooks[OBSERVED_HOOK_COUNT - 1].total),
        });
        let revision = IncidentRevisionV1 {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            event_id: active.event_id,
            revision: active.revision,
            interface: self.identity.interface.clone(),
            ifindex: self.identity.ifindex,
            interface_generation: self.identity.generation,
            transition_sequence: transition.sequence,
            previous_state: transition.previous_state,
            current_state: transition.current_state,
            transition_reason: transition.reason,
            opened_at_unix_ms: active.opened_at_unix_ms,
            occurred_at_unix_ms: transition.occurred_at_unix_ms,
            closed_at_unix_ms,
            alert_code: code,
            severity: code.severity(),
            evidence_status: EvidenceStatus::Stored,
            xdp_ingress: snapshot.hooks[0].total,
            tc_egress: snapshot.hooks[OBSERVED_HOOK_COUNT - 1].total,
            rate_windows,
            baseline: BaselineSummary::from_report(&snapshot.baseline),
            fingerprint_window: snapshot.detection.signals.fingerprint_window.clone(),
            detection: snapshot.detection.clone(),
            observation_health: snapshot.health,
            vlan_visibility: snapshot.vlan_visibility,
            last_error_code: snapshot
                .detection
                .last_error_code
                .clone()
                .or_else(|| snapshot.baseline.last_error_code.clone())
                .or_else(|| snapshot.sampling.last_error_code.clone()),
        };
        revision
            .validate()
            .map_err(|_| IncidentRecorderError::InvalidSnapshot)?;
        Ok(IncidentWriteJob { revision })
    }

    fn validate_snapshot(
        &self,
        snapshot: &ObservationSnapshot,
    ) -> Result<(), IncidentRecorderError> {
        if snapshot.interface != self.identity.interface
            || snapshot.ifindex != self.identity.ifindex
            || snapshot.generation != self.identity.generation
        {
            return Err(IncidentRecorderError::InvalidSnapshot);
        }
        Ok(())
    }
}
