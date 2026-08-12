use l2_loop_core::{
    AlertCode, AlertSeverity, DetectionState, DetectionTransition, DetectionTransitionReason,
    EVIDENCE_MAX_REVISIONS_PER_EVENT, EventId, InterfaceName,
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

pub trait EventIdSource {
    fn next_id(&mut self) -> Result<EventId, IncidentRecorderError>;
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentWriteJob {
    pub event_id: EventId,
    pub revision: u64,
    pub identity: IncidentIdentity,
    pub transition: DetectionTransition,
    pub opened_at_unix_ms: u64,
    pub closed_at_unix_ms: Option<u64>,
    pub code: AlertCode,
    pub severity: AlertSeverity,
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

    pub fn record(
        &mut self,
        transition: &DetectionTransition,
    ) -> Result<Option<IncidentWriteJob>, IncidentRecorderError> {
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
                self.active = Some(active);
                Some(self.job(active, *transition, code, None))
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
                        let job = self.job(next, *transition, code, closed_at);
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
    ) -> Result<Option<IncidentWriteJob>, IncidentRecorderError> {
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
        );
        self.active = None;
        Ok(Some(job))
    }

    fn job(
        &self,
        active: ActiveIncident,
        transition: DetectionTransition,
        code: AlertCode,
        closed_at_unix_ms: Option<u64>,
    ) -> IncidentWriteJob {
        IncidentWriteJob {
            event_id: active.event_id,
            revision: active.revision,
            identity: self.identity.clone(),
            transition,
            opened_at_unix_ms: active.opened_at_unix_ms,
            closed_at_unix_ms,
            code,
            severity: code.severity(),
        }
    }
}
