use std::collections::BTreeSet;

use l2_loop_core::{
    AgentResult, ClassObservation, ClassRate, DetailedRateWindow, DomainError, HookObservation,
    HookRate, HookRole, InterfaceName, OBSERVATION_SCHEMA_VERSION, OBSERVED_CLASS_COUNT,
    OBSERVED_HOOK_COUNT, ObservationCounters, ObservationHealth, ObservationSnapshot,
    RATE_HISTORY_CAPACITY, RATE_SAMPLE_PERIOD_NS, RATE_STALE_AFTER_NS, RATE_WINDOW_COUNT,
    RATE_WINDOW_MS, RateCounters, RateWindowState, SamplingStatus, TrafficClass, VlanVisibility,
    warming_detailed_rate_windows,
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
        SamplingStatus::default(),
        warming_detailed_rate_windows(),
    )
    .unwrap()
}

fn rate_counters(packets: u64, bytes: u64) -> RateCounters {
    RateCounters {
        packet_delta: packets,
        byte_delta: bytes,
        packets_per_second: packets,
        bytes_per_second: bytes,
    }
}

fn rate_classes() -> [ClassRate; OBSERVED_CLASS_COUNT] {
    CLASS_ORDER.map(|traffic_class| ClassRate {
        traffic_class,
        counters: rate_counters(u64::from(traffic_class as u8), 60),
    })
}

fn rate_hook(role: HookRole) -> HookRate {
    HookRate {
        role,
        total: rate_counters(7, 700),
        classes: rate_classes(),
        parse_errors: rate_counters(1, 13),
    }
}

fn fixed_rate_windows() -> [DetailedRateWindow; RATE_WINDOW_COUNT] {
    [
        DetailedRateWindow {
            window_ms: 1_000,
            state: RateWindowState::Ready,
            coverage_ms: 1_000,
            elapsed_ns: Some(1_000_000_000),
            start_unix_ms: Some(1_786_300_000_000),
            end_unix_ms: Some(1_786_300_001_000),
            hooks: Some([
                rate_hook(HookRole::ExternalXdpIngress),
                rate_hook(HookRole::PhysicalTcEgress),
            ]),
        },
        DetailedRateWindow {
            window_ms: 10_000,
            state: RateWindowState::WarmingUp,
            coverage_ms: 1_000,
            elapsed_ns: None,
            start_unix_ms: None,
            end_unix_ms: None,
            hooks: None,
        },
        DetailedRateWindow {
            window_ms: 60_000,
            state: RateWindowState::WarmingUp,
            coverage_ms: 1_000,
            elapsed_ns: None,
            start_unix_ms: None,
            end_unix_ms: None,
            hooks: None,
        },
    ]
}

fn schema_three_snapshot() -> ObservationSnapshot {
    ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        41,
        7,
        1_786_300_001_000,
        VlanVisibility::VerifiedVisible,
        [
            hook(HookRole::ExternalXdpIngress),
            hook(HookRole::PhysicalTcEgress),
        ],
        SamplingStatus {
            latest_success_at_unix_ms: Some(1_786_300_001_000),
            last_error_code: None,
            consecutive_failures: 0,
            sampling_paused: false,
        },
        fixed_rate_windows(),
    )
    .unwrap()
}

fn snapshot_with_rate_windows(
    rate_windows: [DetailedRateWindow; RATE_WINDOW_COUNT],
) -> Result<ObservationSnapshot, DomainError> {
    ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        41,
        7,
        1_786_300_001_000,
        VlanVisibility::VerifiedVisible,
        [
            hook(HookRole::ExternalXdpIngress),
            hook(HookRole::PhysicalTcEgress),
        ],
        SamplingStatus::default(),
        rate_windows,
    )
}

#[test]
fn fixed_rate_contract_uses_only_the_approved_bounds() {
    assert_eq!(RATE_WINDOW_COUNT, 3);
    assert_eq!(RATE_WINDOW_MS, [1_000, 10_000, 60_000]);
    assert_eq!(RATE_HISTORY_CAPACITY, 64);
    assert_eq!(RATE_SAMPLE_PERIOD_NS, 1_000_000_000);
    assert_eq!(RATE_STALE_AFTER_NS, 3_000_000_000);
    assert_eq!(OBSERVATION_SCHEMA_VERSION, 3);
}

#[test]
fn schema_three_has_fixed_unambiguous_observation_fields() {
    let value = serde_json::to_value(schema_three_snapshot()).unwrap();
    let object = value.as_object().unwrap();
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = [
        "captured_at_unix_ms",
        "baseline",
        "generation",
        "health",
        "hooks",
        "ifindex",
        "interface",
        "rate_windows",
        "sampling",
        "schema_version",
        "vlan_visibility",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    assert_eq!(actual, expected);
    assert_eq!(value["schema_version"], 3);
    assert_eq!(value["rate_windows"][0]["window_ms"], 1_000);
    assert_eq!(value["rate_windows"][0]["state"], "ready");
    assert_eq!(value["rate_windows"][0]["elapsed_ns"], 1_000_000_000_u64);
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["total"]["packet_delta"],
        7,
    );
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["total"]["byte_delta"],
        700,
    );
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["total"]["packets_per_second"],
        7,
    );
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["total"]["bytes_per_second"],
        700,
    );
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["role"],
        "external_xdp_ingress",
    );
    assert_eq!(
        value["rate_windows"][0]["hooks"][1]["role"],
        "physical_tc_egress",
    );
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["classes"][0]["traffic_class"],
        "l2_broadcast",
    );
    for index in [1, 2] {
        assert_eq!(value["rate_windows"][index]["state"], "warming_up");
        assert!(value["rate_windows"][index]["elapsed_ns"].is_null());
        assert!(value["rate_windows"][index]["start_unix_ms"].is_null());
        assert!(value["rate_windows"][index]["end_unix_ms"].is_null());
        assert!(value["rate_windows"][index]["hooks"].is_null());
    }
}

#[test]
fn snapshot_rejects_invalid_rate_window_shapes_and_ordering() {
    let mut reordered_windows = fixed_rate_windows();
    reordered_windows.swap(0, 1);
    assert!(matches!(
        snapshot_with_rate_windows(reordered_windows),
        Err(DomainError::InvalidObservation(_)),
    ));

    let mut ready_without_rates = fixed_rate_windows();
    ready_without_rates[0].hooks = None;
    assert!(matches!(
        snapshot_with_rate_windows(ready_without_rates),
        Err(DomainError::InvalidObservation(_)),
    ));

    let mut non_ready_with_rates = fixed_rate_windows();
    non_ready_with_rates[0].state = RateWindowState::Stale;
    assert!(matches!(
        snapshot_with_rate_windows(non_ready_with_rates),
        Err(DomainError::InvalidObservation(_)),
    ));

    let mut reordered_hooks = fixed_rate_windows();
    reordered_hooks[0].hooks.as_mut().unwrap().swap(0, 1);
    assert!(matches!(
        snapshot_with_rate_windows(reordered_hooks),
        Err(DomainError::InvalidObservation(_)),
    ));

    let mut reordered_classes = fixed_rate_windows();
    reordered_classes[0].hooks.as_mut().unwrap()[0]
        .classes
        .swap(0, 1);
    assert!(matches!(
        snapshot_with_rate_windows(reordered_classes),
        Err(DomainError::InvalidObservation(_)),
    ));
}

#[test]
fn snapshot_requires_exact_roles_classes_and_non_zero_identity() {
    let snapshot = fixture_snapshot();

    assert_eq!(snapshot.schema_version, OBSERVATION_SCHEMA_VERSION);
    assert_eq!(snapshot.schema_version, 3);
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
            SamplingStatus::default(),
            warming_detailed_rate_windows(),
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
            SamplingStatus::default(),
            warming_detailed_rate_windows(),
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
            SamplingStatus::default(),
            warming_detailed_rate_windows(),
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
        "baseline",
        "vlan_visibility",
        "health",
        "hooks",
        "sampling",
        "rate_windows",
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
