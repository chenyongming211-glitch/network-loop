const MAP_SOURCE: &str = include_str!("../../ebpf/l2-loop-ebpf/src/maps.rs");
const PROGRAM_SOURCE: &str = include_str!("../../ebpf/l2-loop-ebpf/src/programs.rs");

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
