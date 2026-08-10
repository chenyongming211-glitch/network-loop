use l2_loop_core::{
    AgentMode, AgentResult, Direction, Generation, InterfaceName, InterfaceState, InterfaceStatus,
    ObservationCounters, ObservationHealth, TrafficClass, VlanVisibility,
};

#[test]
fn accepts_every_documented_lifecycle_transition() {
    let observing = InterfaceState::Detached
        .transition(InterfaceState::Attaching)
        .unwrap()
        .transition(InterfaceState::Observing)
        .unwrap();
    let policing = observing.transition(InterfaceState::Policing).unwrap();
    assert_eq!(
        policing.transition(InterfaceState::Observing).unwrap(),
        observing
    );

    for active in [
        InterfaceState::Attaching,
        InterfaceState::Observing,
        InterfaceState::Policing,
    ] {
        assert_eq!(
            active.transition(InterfaceState::Error).unwrap(),
            InterfaceState::Error
        );
    }

    assert_eq!(
        InterfaceState::Error
            .transition(InterfaceState::Detached)
            .unwrap(),
        InterfaceState::Detached
    );
}

#[test]
fn rejects_undocumented_lifecycle_transitions() {
    let invalid = [
        (InterfaceState::Detached, InterfaceState::Observing),
        (InterfaceState::Detached, InterfaceState::Policing),
        (InterfaceState::Detached, InterfaceState::Error),
        (InterfaceState::Attaching, InterfaceState::Policing),
        (InterfaceState::Observing, InterfaceState::Detached),
        (InterfaceState::Policing, InterfaceState::Detached),
        (InterfaceState::Error, InterfaceState::Observing),
    ];

    for (from, to) in invalid {
        assert!(from.transition(to).is_err(), "accepted {from:?} -> {to:?}");
    }
}

#[test]
fn generation_must_be_non_zero() {
    assert!(Generation::new(0).is_err());
    assert_eq!(Generation::new(9).unwrap().get(), 9);
}

#[test]
fn numeric_domain_values_reject_unknown_inputs() {
    assert_eq!(AgentMode::try_from(1).unwrap(), AgentMode::Observe);
    assert_eq!(Direction::try_from(2).unwrap(), Direction::Egress);
    assert_eq!(
        TrafficClass::try_from(2).unwrap(),
        TrafficClass::L2Broadcast
    );

    assert!(AgentMode::try_from(3).is_err());
    assert!(Direction::try_from(0).is_err());
    assert!(TrafficClass::try_from(255).is_err());
}

#[test]
fn status_supports_zero_or_one_bounded_session_summary() {
    let empty = AgentResult::Status {
        interfaces: Vec::new(),
    };
    assert_eq!(
        serde_json::to_value(empty).unwrap()["interfaces"],
        serde_json::json!([]),
    );

    let status = InterfaceStatus {
        interface: InterfaceName::new("l2h0123456789").unwrap(),
        state: InterfaceState::Observing,
        generation: 7,
        captured_at_unix_ms: 1_786_300_000_000,
        health: ObservationHealth::Healthy,
        vlan_visibility: VlanVisibility::VerifiedVisible,
        xdp_ingress: ObservationCounters {
            packets: 11,
            bytes: 660,
        },
        tc_egress: ObservationCounters {
            packets: 9,
            bytes: 540,
        },
    };
    let value = serde_json::to_value(AgentResult::Status {
        interfaces: vec![status],
    })
    .unwrap();

    assert_eq!(value["interfaces"].as_array().unwrap().len(), 1);
    assert_eq!(value["interfaces"][0]["generation"], 7);
    assert_eq!(value["interfaces"][0]["xdp_ingress"]["packets"], 11);
    assert_eq!(value["interfaces"][0]["tc_egress"]["bytes"], 540);
}
