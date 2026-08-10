use std::collections::BTreeSet;

use l2_loop_core::{
    AgentResult, ClassObservation, DomainError, HookObservation, HookRole, InterfaceName,
    ObservationCounters, ObservationHealth, ObservationSnapshot, TrafficClass, VlanVisibility,
    OBSERVATION_SCHEMA_VERSION, OBSERVED_CLASS_COUNT, OBSERVED_HOOK_COUNT,
};

const CLASS_ORDER: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

fn counters(packets: u64, bytes: u64) -> ObservationCounters {
    ObservationCounters { packets, bytes }
}

fn classes() -> [ClassObservation; OBSERVED_CLASS_COUNT] {
    CLASS_ORDER.map(|traffic_class| ClassObservation {
        traffic_class,
        counters: counters(u64::from(traffic_class as u8), 60),
    })
}

fn hook(role: HookRole) -> HookObservation {
    HookObservation {
        role,
        total: counters(21, 1_260),
        classes: classes(),
        parse_errors: counters(1, 13),
    }
}

fn fixture_snapshot() -> ObservationSnapshot {
    ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        41,
        7,
        1_786_300_000_000,
        VlanVisibility::VerifiedVisible,
        [
            hook(HookRole::ExternalXdpIngress),
            hook(HookRole::PhysicalTcEgress),
        ],
    )
    .unwrap()
}

#[test]
fn snapshot_requires_exact_roles_classes_and_non_zero_identity() {
    let snapshot = fixture_snapshot();

    assert_eq!(snapshot.schema_version, OBSERVATION_SCHEMA_VERSION);
    assert_eq!(snapshot.schema_version, 1);
    assert_eq!(snapshot.ifindex, 41);
    assert_eq!(snapshot.generation, 7);
    assert_eq!(snapshot.health, ObservationHealth::Healthy);
    assert_eq!(snapshot.hooks.len(), OBSERVED_HOOK_COUNT);
    assert_eq!(snapshot.hooks[0].role, HookRole::ExternalXdpIngress);
    assert_eq!(snapshot.hooks[1].role, HookRole::PhysicalTcEgress);
    assert_eq!(
        snapshot.hooks[0]
            .classes
            .map(|observation| observation.traffic_class),
        CLASS_ORDER,
    );
}

#[test]
fn snapshot_rejects_zero_ifindex_or_generation() {
    for (ifindex, generation) in [(0, 7), (41, 0)] {
        let result = ObservationSnapshot::new(
            InterfaceName::new("l2h0123456789").unwrap(),
            ifindex,
            generation,
            1,
            VlanVisibility::Unknown,
            [
                hook(HookRole::ExternalXdpIngress),
                hook(HookRole::PhysicalTcEgress),
            ],
        );
        assert!(matches!(result, Err(DomainError::InvalidObservation(_))));
    }
}

#[test]
fn snapshot_rejects_reordered_or_duplicate_hook_roles() {
    for hooks in [
        [
            hook(HookRole::PhysicalTcEgress),
            hook(HookRole::ExternalXdpIngress),
        ],
        [
            hook(HookRole::ExternalXdpIngress),
            hook(HookRole::ExternalXdpIngress),
        ],
    ] {
        let result = ObservationSnapshot::new(
            InterfaceName::new("l2h0123456789").unwrap(),
            41,
            7,
            1,
            VlanVisibility::Unknown,
            hooks,
        );
        assert!(matches!(result, Err(DomainError::InvalidObservation(_))));
    }
}

#[test]
fn snapshot_rejects_reordered_or_duplicate_classes() {
    let mut reordered = hook(HookRole::ExternalXdpIngress);
    reordered.classes.swap(0, 1);
    let mut duplicate = hook(HookRole::ExternalXdpIngress);
    duplicate.classes[1] = duplicate.classes[0];

    for xdp in [reordered, duplicate] {
        let result = ObservationSnapshot::new(
            InterfaceName::new("l2h0123456789").unwrap(),
            41,
            7,
            1,
            VlanVisibility::Unknown,
            [xdp, hook(HookRole::PhysicalTcEgress)],
        );
        assert!(matches!(result, Err(DomainError::InvalidObservation(_))));
    }
}

#[test]
fn counter_addition_is_checked_for_packets_and_bytes() {
    assert_eq!(
        counters(2, 120).checked_add(counters(3, 180)).unwrap(),
        counters(5, 300),
    );
    assert!(matches!(
        counters(u64::MAX, 0).checked_add(counters(1, 0)),
        Err(DomainError::InvalidObservation(_)),
    ));
    assert!(matches!(
        counters(0, u64::MAX).checked_add(counters(0, 1)),
        Err(DomainError::InvalidObservation(_)),
    ));
}

#[test]
fn json_contains_only_the_approved_observation_fields() {
    let value = serde_json::to_value(fixture_snapshot()).unwrap();
    let object = value.as_object().unwrap();
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = [
        "schema_version",
        "interface",
        "ifindex",
        "generation",
        "captured_at_unix_ms",
        "vlan_visibility",
        "health",
        "hooks",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);

    let text = value.to_string();
    for prohibited in [
        "mac",
        "ip_address",
        "hostname",
        "machine_id",
        "pin_path",
        "map_id",
    ] {
        assert!(!text.contains(prohibited));
    }
}

#[test]
fn agent_result_serializes_a_bounded_observation_variant() {
    let value = serde_json::to_value(AgentResult::Observation {
        snapshot: fixture_snapshot(),
    })
    .unwrap();

    assert_eq!(value["kind"], "observation");
    assert_eq!(value["snapshot"]["hooks"].as_array().unwrap().len(), 2);
    assert_eq!(
        serde_json::to_value(ObservationHealth::Degraded).unwrap(),
        "degraded",
    );
}
