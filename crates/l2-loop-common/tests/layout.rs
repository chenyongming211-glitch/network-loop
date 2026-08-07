use core::mem::{align_of, size_of};

use l2_loop_common::{
    CounterValue, FingerprintKey, FingerprintValue, InterfaceConfig, PolicyKey, ProbeKey,
    ProbeRegistration, RatePolicy, StatsKey, hook_role, observation_reason, traffic_class, verdict,
};

#[test]
fn abi_structs_have_stable_layouts() {
    assert_eq!(size_of::<InterfaceConfig>(), 32);
    assert_eq!(align_of::<InterfaceConfig>(), 8);

    assert_eq!(size_of::<StatsKey>(), 16);
    assert_eq!(align_of::<StatsKey>(), 8);

    assert_eq!(size_of::<CounterValue>(), 16);
    assert_eq!(align_of::<CounterValue>(), 8);

    assert_eq!(size_of::<FingerprintKey>(), 32);
    assert_eq!(align_of::<FingerprintKey>(), 8);

    assert_eq!(size_of::<FingerprintValue>(), 48);
    assert_eq!(align_of::<FingerprintValue>(), 8);

    assert_eq!(size_of::<ProbeKey>(), 32);
    assert_eq!(align_of::<ProbeKey>(), 8);

    assert_eq!(size_of::<ProbeRegistration>(), 32);
    assert_eq!(align_of::<ProbeRegistration>(), 8);

    assert_eq!(size_of::<PolicyKey>(), 16);
    assert_eq!(align_of::<PolicyKey>(), 8);

    assert_eq!(size_of::<RatePolicy>(), 40);
    assert_eq!(align_of::<RatePolicy>(), 8);
}

#[test]
fn constructors_zero_reserved_fields() {
    let interface = InterfaceConfig::new(7, 11, 3, 1, 2, 1, 4);
    assert_eq!(interface.flags, 0);
    assert_eq!(interface.reserved, [0; 4]);

    let probe = ProbeRegistration::new(100, 200);
    assert_eq!(probe.flags, 0);
    assert_eq!(probe.reserved, [0; 12]);
}

#[test]
fn total_hook_counter_key_uses_only_bounded_aggregate_dimensions() {
    let key = StatsKey::total(7, 11, hook_role::TEMPORARY_PATH_INGRESS);

    assert_eq!(key.interface_generation, 7);
    assert_eq!(key.ifindex, 11);
    assert_eq!(key.hook_role, hook_role::TEMPORARY_PATH_INGRESS);
    assert_eq!(key.traffic_class, traffic_class::ALL);
    assert_eq!(key.verdict, verdict::PASS);
    assert_eq!(key.reason, observation_reason::NONE);
}
