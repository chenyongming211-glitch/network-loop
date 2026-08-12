const MAP_SOURCE: &str = include_str!("../../ebpf/l2-loop-ebpf/src/maps.rs");
const PROGRAM_SOURCE: &str = include_str!("../../ebpf/l2-loop-ebpf/src/programs.rs");
const MAP_PUBLISHER_SOURCE: &str = include_str!("../../crates/l2-loop-agent/src/linux/maps.rs");

#[test]
fn declares_every_public_map_name() {
    for name in [
        "IFACE_CONFIG",
        "HOOK_STATS",
        "FINGERPRINTS",
        "PROBE_REGISTRY",
        "PROBE_STATS",
        "RATE_POLICY",
    ] {
        assert!(
            MAP_SOURCE.contains(&format!("static {name}:")),
            "missing public eBPF map {name}"
        );
    }
}

#[test]
fn declares_every_public_program_name() {
    for name in [
        "l2_loop_xdp_ingress",
        "l2_loop_tc_egress",
        "l2_loop_tc_path_ingress",
        "l2_loop_tc_path_egress",
    ] {
        assert!(
            PROGRAM_SOURCE.contains(&format!("fn {name}(")),
            "missing public eBPF program {name}"
        );
    }
}

#[test]
fn phase_one_programs_only_return_pass_or_continue() {
    assert!(!PROGRAM_SOURCE.contains("XDP_DROP"));
    assert!(!PROGRAM_SOURCE.contains("TC_ACT_SHOT"));
    assert!(PROGRAM_SOURCE.contains("XDP_PASS"));
    assert!(PROGRAM_SOURCE.contains("TC_ACT_OK"));
}

#[test]
fn every_program_accounts_with_its_exact_hook_role() {
    for call in [
        "account_xdp(&ctx, hook_role::EXTERNAL_XDP_INGRESS)",
        "account_tc(&ctx, hook_role::PHYSICAL_TC_EGRESS)",
        "account_tc(&ctx, hook_role::TEMPORARY_PATH_INGRESS)",
        "account_tc(&ctx, hook_role::TEMPORARY_PATH_EGRESS)",
    ] {
        assert!(
            PROGRAM_SOURCE.contains(call),
            "missing fail-open accounting call: {call}"
        );
    }
}

#[test]
fn accounting_uses_one_bounded_total_counter_key() {
    assert!(PROGRAM_SOURCE.contains("StatsKey::total("));
    assert!(PROGRAM_SOURCE.contains("HOOK_STATS"));
    assert!(PROGRAM_SOURCE.contains("CounterValue"));
    assert!(!PROGRAM_SOURCE.contains("XDP_DROP"));
    assert!(!PROGRAM_SOURCE.contains("TC_ACT_SHOT"));
}

#[test]
fn accounting_classifies_a_bounded_frame_and_promotes_vlan_visibility() {
    for required in [
        "parse_l2",
        "StatsKey::classified(",
        "StatsKey::parse_error(",
        "vlan_visibility::VERIFIED_VISIBLE",
        "xdp_action::XDP_PASS",
        "TC_ACT_OK",
    ] {
        assert!(
            PROGRAM_SOURCE.contains(required),
            "missing passive accounting marker: {required}"
        );
    }
}

#[test]
fn passive_programs_exclude_policy_probe_and_drop_paths() {
    for prohibited in [
        "RATE_POLICY",
        "PROBE_REGISTRY",
        "PROBE_STATS",
        "XDP_DROP",
        "TC_ACT_SHOT",
    ] {
        assert!(
            !PROGRAM_SOURCE.contains(prohibited),
            "passive program contains prohibited marker: {prohibited}"
        );
    }
}

#[test]
fn passive_fingerprints_are_fixed_bounded_and_fail_open() {
    for required in [
        "FINGERPRINTS",
        "FINGERPRINT_PREFIX_LEN",
        "FINGERPRINT_SAMPLE_SHIFT",
        "fingerprint_hash",
        "fingerprint_selected",
        "packet_fingerprint_metadata",
        "direction::INGRESS",
        "direction::EGRESS",
        "bpf_ktime_get_ns",
        "saturating_add",
    ] {
        assert!(
            PROGRAM_SOURCE.contains(required),
            "missing bounded fingerprint marker: {required}"
        );
    }
    assert!(PROGRAM_SOURCE.contains("FINGERPRINTS.get_ptr_mut"));
    assert!(PROGRAM_SOURCE.contains("FINGERPRINTS.insert"));
    assert!(PROGRAM_SOURCE.contains("xdp_action::XDP_PASS"));
    assert!(PROGRAM_SOURCE.contains("TC_ACT_OK"));
    assert!(!PROGRAM_SOURCE.contains("PROBE_REGISTRY"));
    assert!(!PROGRAM_SOURCE.contains("RATE_POLICY"));
}

#[test]
fn fingerprint_path_does_not_round_trip_packet_bytes_through_a_dynamic_stack_slice() {
    assert!(PROGRAM_SOURCE.contains("packet_fingerprint_hash("));
    assert!(PROGRAM_SOURCE.contains("packet_fingerprint_metadata("));
    assert!(!PROGRAM_SOURCE.contains("let mut prefix = [0_u8; FINGERPRINT_PREFIX_LEN]"));
    assert!(!PROGRAM_SOURCE.contains("&prefix[..prefix_len]"));
}

#[test]
fn userspace_publishes_only_the_fixed_fingerprint_sample_shift() {
    assert!(MAP_PUBLISHER_SOURCE.contains("FINGERPRINT_SAMPLE_SHIFT"));
    assert!(MAP_PUBLISHER_SOURCE.contains("agent_mode::OBSERVE"));
    assert!(!MAP_PUBLISHER_SOURCE.contains("sample_shift:"));
}
