use std::collections::VecDeque;

use l2_loop_agent::{EventIdSource, IncidentIdentity, IncidentRecorder, IncidentRecorderError};
use l2_loop_core::{
    AlertCode, AlertSeverity, ClassObservation, DetectionState, DetectionTransition,
    DetectionTransitionReason, EventId, HookObservation, HookRole, InterfaceName,
    ObservationCounters, ObservationSnapshot, SamplingStatus, TrafficClass, VlanVisibility,
    warming_detailed_rate_windows,
};

#[derive(Debug)]
struct FixedIds(VecDeque<EventId>);

impl EventIdSource for FixedIds {
    fn next_id(&mut self) -> Result<EventId, IncidentRecorderError> {
        self.0
            .pop_front()
            .ok_or(IncidentRecorderError::IdUnavailable)
    }
}

fn id(byte: u8) -> EventId {
    EventId::from_bytes([byte; 16])
}

fn identity(generation: u64) -> IncidentIdentity {
    IncidentIdentity::new(InterfaceName::new("l2h0123456789").unwrap(), 42, generation).unwrap()
}

fn snapshot(generation: u64) -> ObservationSnapshot {
    const CLASSES: [TrafficClass; 6] = [
        TrafficClass::L2Broadcast,
        TrafficClass::Ipv4Multicast,
        TrafficClass::Ipv6Multicast,
        TrafficClass::OtherL2Multicast,
        TrafficClass::LinkLocalControl,
        TrafficClass::UnicastOrUnclassified,
    ];
    let hook = |role| HookObservation {
        role,
        total: ObservationCounters {
            packets: 21,
            bytes: 1_260,
        },
        classes: CLASSES.map(|traffic_class| ClassObservation {
            traffic_class,
            counters: ObservationCounters {
                packets: 1,
                bytes: 60,
            },
        }),
        parse_errors: ObservationCounters {
            packets: 0,
            bytes: 0,
        },
    };
    ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        42,
        generation,
        1_000,
        VlanVisibility::VerifiedVisible,
        [
            hook(HookRole::ExternalXdpIngress),
            hook(HookRole::PhysicalTcEgress),
        ],
        SamplingStatus::default(),
        warming_detailed_rate_windows(),
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
            .record(
                &transition(
                    1,
                    DetectionState::WarmingUp,
                    DetectionState::Normal,
                    DetectionTransitionReason::EvidenceReady,
                ),
                &snapshot(7),
            )
            .unwrap()
            .is_none()
    );

    let opened = recorder
        .record(
            &transition(
                2,
                DetectionState::Normal,
                DetectionState::IngressStormConfirmed,
                DetectionTransitionReason::StormAsserted,
            ),
            &snapshot(7),
        )
        .unwrap()
        .unwrap();
    assert_eq!(opened.revision.event_id, id(1));
    assert_eq!(opened.revision.revision, 1);
    assert_eq!(opened.revision.alert_code, AlertCode::StormConfirmed);
    assert_eq!(opened.revision.severity, AlertSeverity::Notice);
    assert_eq!(opened.revision.opened_at_unix_ms, 1_002);
    assert_eq!(opened.revision.closed_at_unix_ms, None);

    let upgraded = recorder
        .record(
            &transition(
                3,
                DetectionState::IngressStormConfirmed,
                DetectionState::ExternalLoopHighConfidence,
                DetectionTransitionReason::RelationshipHighConfidence,
            ),
            &snapshot(7),
        )
        .unwrap()
        .unwrap();
    assert_eq!(upgraded.revision.event_id, opened.revision.event_id);
    assert_eq!(upgraded.revision.revision, 2);
    assert_eq!(
        upgraded.revision.alert_code,
        AlertCode::ExternalLoopHighConfidence
    );
    assert_eq!(upgraded.revision.severity, AlertSeverity::Warning);

    let unavailable = recorder
        .record(
            &transition(
                4,
                DetectionState::ExternalLoopHighConfidence,
                DetectionState::Unavailable,
                DetectionTransitionReason::EvidenceUnavailable,
            ),
            &snapshot(7),
        )
        .unwrap()
        .unwrap();
    assert_eq!(unavailable.revision.event_id, opened.revision.event_id);
    assert_eq!(unavailable.revision.revision, 3);
    assert_eq!(unavailable.revision.alert_code, AlertCode::OutputDegraded);

    let cooldown = recorder
        .record(
            &transition(
                5,
                DetectionState::Unavailable,
                DetectionState::Cooldown,
                DetectionTransitionReason::EvidenceCleared,
            ),
            &snapshot(7),
        )
        .unwrap()
        .unwrap();
    assert_eq!(cooldown.revision.revision, 4);
    assert_eq!(cooldown.revision.alert_code, AlertCode::IncidentCooldown);

    let closed = recorder
        .record(
            &transition(
                6,
                DetectionState::Cooldown,
                DetectionState::Normal,
                DetectionTransitionReason::CooldownCompleted,
            ),
            &snapshot(7),
        )
        .unwrap()
        .unwrap();
    assert_eq!(closed.revision.event_id, opened.revision.event_id);
    assert_eq!(closed.revision.revision, 5);
    assert_eq!(closed.revision.closed_at_unix_ms, Some(1_006));
    assert_eq!(recorder.active_event(), None);

    let next = recorder
        .record(
            &transition(
                7,
                DetectionState::Normal,
                DetectionState::EgressStormConfirmed,
                DetectionTransitionReason::StormAsserted,
            ),
            &snapshot(7),
        )
        .unwrap()
        .unwrap();
    assert_eq!(next.revision.event_id, id(2));
    assert_ne!(next.revision.event_id, opened.revision.event_id);
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
    assert!(recorder.record(&first, &snapshot(7)).unwrap().is_some());
    assert!(recorder.record(&first, &snapshot(7)).unwrap().is_none());
    assert_eq!(recorder.suppressed_duplicate_count(), 1);

    assert_eq!(
        recorder.record(
            &transition(
                3,
                DetectionState::IngressStormConfirmed,
                DetectionState::ExternalLoopSuspected,
                DetectionTransitionReason::RelationshipSuspected,
            ),
            &snapshot(7),
        ),
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
        .record(
            &transition(
                1,
                DetectionState::Normal,
                DetectionState::IngressStormConfirmed,
                DetectionTransitionReason::StormAsserted,
            ),
            &snapshot(7),
        )
        .unwrap();
    let ended = recorder
        .generation_ended(2_000, &snapshot(7))
        .unwrap()
        .unwrap();
    assert_eq!(ended.revision.alert_code, AlertCode::GenerationEnded);
    assert_eq!(ended.revision.severity, AlertSeverity::Information);
    assert_eq!(ended.revision.revision, 2);
    assert_eq!(ended.revision.closed_at_unix_ms, Some(2_000));
    assert_eq!(ended.revision.transition_sequence, 1);
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
                .record(
                    &transition(
                        sequence,
                        previous_state,
                        current_state,
                        DetectionTransitionReason::StormAsserted,
                    ),
                    &snapshot(7),
                )
                .unwrap()
                .is_some()
        );
    }
    let active = recorder.active_event();
    assert_eq!(
        recorder.record(
            &transition(
                17,
                DetectionState::IngressStormConfirmed,
                DetectionState::ExternalLoopSuspected,
                DetectionTransitionReason::RelationshipSuspected,
            ),
            &snapshot(7),
        ),
        Err(IncidentRecorderError::RevisionLimit)
    );
    assert_eq!(recorder.active_event(), active);
}
