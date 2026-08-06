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
