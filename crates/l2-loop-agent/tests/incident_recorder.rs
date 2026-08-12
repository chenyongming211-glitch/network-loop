use std::collections::VecDeque;

use l2_loop_agent::{EventIdSource, IncidentIdentity, IncidentRecorder, IncidentRecorderError};
use l2_loop_core::{
    AlertCode, AlertSeverity, DetectionState, DetectionTransition, DetectionTransitionReason,
    EventId, InterfaceName,
};

#[derive(Debug)]
struct FixedIds(VecDeque<EventId>);

impl EventIdSource for FixedIds {
    fn next_id(&mut self) -> Result<EventId, IncidentRecorderError> {
        self.0.pop_front().ok_or(IncidentRecorderError::IdUnavailable)
    }
}

fn id(byte: u8) -> EventId {
    EventId::from_bytes([byte; 16])
}

fn identity(generation: u64) -> IncidentIdentity {
    IncidentIdentity::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        42,
        generation,
    )
    .unwrap()
}

fn transition(
    sequence: u64,
    previous_state: DetectionState,
    current_state: DetectionState,
    reason: DetectionTransitionReason,
) -> DetectionTransition {
    DetectionTransition {
        sequence,
        previous_state,
        current_state,
        reason,
        occurred_at_unix_ms: 1_000 + sequence,
    }
}

#[test]
fn recorder_opens_revises_retains_and_closes_one_generation_incident() {
    let mut recorder = IncidentRecorder::new(identity(7), FixedIds(VecDeque::from([id(1), id(2)])));

    assert!(
        recorder
            .record(&transition(
                1,
                DetectionState::WarmingUp,
                DetectionState::Normal,
                DetectionTransitionReason::EvidenceReady,
            ))
            .unwrap()
            .is_none()
    );

    let opened = recorder
        .record(&transition(
            2,
            DetectionState::Normal,
            DetectionState::IngressStormConfirmed,
            DetectionTransitionReason::StormAsserted,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(opened.event_id, id(1));
    assert_eq!(opened.revision, 1);
    assert_eq!(opened.code, AlertCode::StormConfirmed);
    assert_eq!(opened.severity, AlertSeverity::Notice);
    assert_eq!(opened.opened_at_unix_ms, 1_002);
    assert_eq!(opened.closed_at_unix_ms, None);

    let upgraded = recorder
        .record(&transition(
            3,
            DetectionState::IngressStormConfirmed,
            DetectionState::ExternalLoopHighConfidence,
            DetectionTransitionReason::RelationshipHighConfidence,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(upgraded.event_id, opened.event_id);
    assert_eq!(upgraded.revision, 2);
    assert_eq!(upgraded.code, AlertCode::ExternalLoopHighConfidence);
    assert_eq!(upgraded.severity, AlertSeverity::Warning);

    let unavailable = recorder
        .record(&transition(
            4,
            DetectionState::ExternalLoopHighConfidence,
            DetectionState::Unavailable,
            DetectionTransitionReason::EvidenceUnavailable,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(unavailable.event_id, opened.event_id);
    assert_eq!(unavailable.revision, 3);
    assert_eq!(unavailable.code, AlertCode::OutputDegraded);

    let cooldown = recorder
        .record(&transition(
            5,
            DetectionState::Unavailable,
            DetectionState::Cooldown,
            DetectionTransitionReason::EvidenceCleared,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(cooldown.revision, 4);
    assert_eq!(cooldown.code, AlertCode::IncidentCooldown);

    let closed = recorder
        .record(&transition(
            6,
            DetectionState::Cooldown,
            DetectionState::Normal,
            DetectionTransitionReason::CooldownCompleted,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(closed.event_id, opened.event_id);
    assert_eq!(closed.revision, 5);
    assert_eq!(closed.closed_at_unix_ms, Some(1_006));
    assert_eq!(recorder.active_event(), None);

    let next = recorder
        .record(&transition(
            7,
            DetectionState::Normal,
            DetectionState::EgressStormConfirmed,
            DetectionTransitionReason::StormAsserted,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(next.event_id, id(2));
    assert_ne!(next.event_id, opened.event_id);
}

#[test]
fn duplicate_and_gap_handling_is_bounded_and_generation_scoped() {
    let mut recorder = IncidentRecorder::new(identity(7), FixedIds(VecDeque::from([id(1)])));
    let first = transition(
        1,
        DetectionState::Normal,
        DetectionState::IngressStormConfirmed,
        DetectionTransitionReason::StormAsserted,
    );
    assert!(recorder.record(&first).unwrap().is_some());
    assert!(recorder.record(&first).unwrap().is_none());
    assert_eq!(recorder.suppressed_duplicate_count(), 1);

    assert_eq!(
        recorder.record(&transition(
            3,
            DetectionState::IngressStormConfirmed,
            DetectionState::ExternalLoopSuspected,
            DetectionTransitionReason::RelationshipSuspected,
        )),
        Err(IncidentRecorderError::TransitionGap)
    );

    recorder.reset_identity(identity(8));
    assert_eq!(recorder.identity().generation, 8);
    assert_eq!(recorder.active_event(), None);
    assert_eq!(recorder.last_transition_sequence(), 0);
}

#[test]
fn generation_end_closes_active_incident_without_reusing_detection_sequence() {
    let mut recorder = IncidentRecorder::new(identity(7), FixedIds(VecDeque::from([id(1)])));
    recorder
        .record(&transition(
            1,
            DetectionState::Normal,
            DetectionState::IngressStormConfirmed,
            DetectionTransitionReason::StormAsserted,
        ))
        .unwrap();
    let ended = recorder.generation_ended(2_000).unwrap().unwrap();
    assert_eq!(ended.code, AlertCode::GenerationEnded);
    assert_eq!(ended.severity, AlertSeverity::Information);
    assert_eq!(ended.revision, 2);
    assert_eq!(ended.closed_at_unix_ms, Some(2_000));
    assert_eq!(ended.transition.sequence, 1);
    assert_eq!(recorder.active_event(), None);
}

#[test]
fn revision_bound_refuses_more_output_without_losing_active_identity() {
    let mut recorder = IncidentRecorder::new(identity(7), FixedIds(VecDeque::from([id(1)])));
    for sequence in 1..=16 {
        let current_state = if sequence % 2 == 0 {
            DetectionState::IngressStormConfirmed
        } else {
            DetectionState::ExternalLoopSuspected
        };
        let previous_state = if sequence == 1 {
            DetectionState::Normal
        } else if sequence % 2 == 0 {
            DetectionState::ExternalLoopSuspected
        } else {
            DetectionState::IngressStormConfirmed
        };
        assert!(
            recorder
                .record(&transition(
                    sequence,
                    previous_state,
                    current_state,
                    DetectionTransitionReason::StormAsserted,
                ))
                .unwrap()
                .is_some()
        );
    }
    let active = recorder.active_event();
    assert_eq!(
        recorder.record(&transition(
            17,
            DetectionState::IngressStormConfirmed,
            DetectionState::ExternalLoopSuspected,
            DetectionTransitionReason::RelationshipSuspected,
        )),
        Err(IncidentRecorderError::RevisionLimit)
    );
    assert_eq!(recorder.active_event(), active);
}
