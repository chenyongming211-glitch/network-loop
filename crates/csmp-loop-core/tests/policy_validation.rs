use std::time::Duration;

use csmp_loop_core::{PolicyRequest, TrafficClass};

#[test]
fn accepts_packet_byte_or_dual_rate_policy() {
    for (pps, bps) in [
        (Some(100), None),
        (None, Some(1_000_000)),
        (Some(100), Some(1_000_000)),
    ] {
        let policy = PolicyRequest::new(
            "bond0",
            Some(100),
            TrafficClass::Ipv6Multicast,
            pps,
            bps,
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(policy.interface().as_str(), "bond0");
    }
}

#[test]
fn rejects_missing_or_zero_rate_limits() {
    assert!(policy(None, None, TrafficClass::L2Broadcast, 60).is_err());
    assert!(policy(Some(0), None, TrafficClass::L2Broadcast, 60).is_err());
    assert!(policy(None, Some(0), TrafficClass::L2Broadcast, 60).is_err());
}

#[test]
fn rejects_aggregate_and_unicast_classes() {
    assert!(policy(Some(10), None, TrafficClass::All, 60).is_err());
    assert!(policy(Some(10), None, TrafficClass::UnicastOrUnclassified, 60).is_err());
}

#[test]
fn policy_ttl_is_bounded() {
    assert!(policy(Some(10), None, TrafficClass::L2Broadcast, 0).is_err());
    assert!(policy(Some(10), None, TrafficClass::L2Broadcast, 1).is_ok());
    assert!(policy(Some(10), None, TrafficClass::L2Broadcast, 86_400).is_ok());
    assert!(policy(Some(10), None, TrafficClass::L2Broadcast, 86_401).is_err());
}

#[test]
fn explicit_interface_and_vlan_are_validated() {
    assert!(
        PolicyRequest::new(
            "",
            None,
            TrafficClass::L2Broadcast,
            Some(10),
            None,
            Duration::from_secs(60)
        )
        .is_err()
    );

    assert!(policy_with_vlan(0).is_err());
    assert!(policy_with_vlan(1).is_ok());
    assert!(policy_with_vlan(4094).is_ok());
    assert!(policy_with_vlan(4095).is_err());
}

fn policy(
    pps: Option<u64>,
    bps: Option<u64>,
    class: TrafficClass,
    ttl_seconds: u64,
) -> Result<PolicyRequest, csmp_loop_core::DomainError> {
    PolicyRequest::new(
        "bond0",
        None,
        class,
        pps,
        bps,
        Duration::from_secs(ttl_seconds),
    )
}

fn policy_with_vlan(vlan: u16) -> Result<PolicyRequest, csmp_loop_core::DomainError> {
    PolicyRequest::new(
        "bond0",
        Some(vlan),
        TrafficClass::L2Broadcast,
        Some(10),
        None,
        Duration::from_secs(60),
    )
}
