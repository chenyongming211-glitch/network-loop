use csmp_loop_common::{
    ABI_VERSION, NO_VLAN, agent_mode, direction, hook_role, observation_reason, probe_scope,
    traffic_class, verdict, vlan_visibility,
};

#[test]
fn abi_version_and_vlan_sentinel_are_stable() {
    assert_eq!(ABI_VERSION, 1);
    assert_eq!(NO_VLAN, 0xffff);
}

#[test]
fn agent_mode_values_are_stable() {
    assert_eq!(agent_mode::DISABLED, 0);
    assert_eq!(agent_mode::OBSERVE, 1);
    assert_eq!(agent_mode::POLICE, 2);
}

#[test]
fn direction_and_hook_values_are_stable() {
    assert_eq!(direction::INGRESS, 1);
    assert_eq!(direction::EGRESS, 2);

    assert_eq!(hook_role::EXTERNAL_XDP_INGRESS, 1);
    assert_eq!(hook_role::PHYSICAL_TC_EGRESS, 2);
    assert_eq!(hook_role::TEMPORARY_PATH_INGRESS, 3);
    assert_eq!(hook_role::TEMPORARY_PATH_EGRESS, 4);
}

#[test]
fn traffic_class_values_are_stable() {
    assert_eq!(traffic_class::ALL, 1);
    assert_eq!(traffic_class::L2_BROADCAST, 2);
    assert_eq!(traffic_class::IPV4_MULTICAST, 3);
    assert_eq!(traffic_class::IPV6_MULTICAST, 4);
    assert_eq!(traffic_class::OTHER_L2_MULTICAST, 5);
    assert_eq!(traffic_class::LINK_LOCAL_CONTROL, 6);
    assert_eq!(traffic_class::UNICAST_OR_UNCLASSIFIED, 7);
}

#[test]
fn verdict_and_reason_values_are_stable() {
    assert_eq!(verdict::PASS, 1);
    assert_eq!(verdict::WOULD_DROP, 2);
    assert_eq!(verdict::DROP, 3);
    assert_eq!(verdict::ERROR_PASS, 4);

    assert_eq!(observation_reason::NONE, 0);
    assert_eq!(observation_reason::MISSING_CONFIGURATION, 1);
    assert_eq!(observation_reason::PARSE_ERROR, 2);
    assert_eq!(observation_reason::FINGERPRINT_SAMPLE_SELECTED, 3);
    assert_eq!(observation_reason::PROBE_MATCHED, 4);
    assert_eq!(observation_reason::PACKET_RATE_EXCEEDED, 5);
    assert_eq!(observation_reason::BYTE_RATE_EXCEEDED, 6);
    assert_eq!(observation_reason::BOTH_RATES_EXCEEDED, 7);
}

#[test]
fn visibility_and_scope_values_are_stable() {
    assert_eq!(vlan_visibility::UNKNOWN, 0);
    assert_eq!(vlan_visibility::VERIFIED_VISIBLE, 1);
    assert_eq!(vlan_visibility::UNAVAILABLE, 2);

    assert_eq!(probe_scope::EXTERNAL, 1);
    assert_eq!(probe_scope::INTERNAL, 2);
}
