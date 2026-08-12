use l2_loop_agent::protocol::{ControlResponse, ERROR_INTERNAL};
use l2_loop_cli::{EXIT_BLOCKED, EXIT_FAILURE, EXIT_SUCCESS, OutputFormat, render_response};
use l2_loop_core::{
    AgentResult, AttachmentState, BpfInspection, ClassObservation, ClassRate, DetailedRateWindow,
    HookObservation, HookRate, HookRole, InterfaceInspection, InterfaceKind, InterfaceName,
    InterfaceRef, InterfaceState, InterfaceStatus, KernelInspection, MemlockInspection,
    OBSERVED_CLASS_COUNT, ObservationCounters, ObservationSnapshot, PF_LIVE_INTERFACE,
    PinRootState, PreflightFinding, PreflightReport, RateCounters, RateWindowState, SamplingStatus,
    StatusRateWindow, TrafficClass, VlanVisibility,
};

#[test]
fn renders_complete_stable_text_and_json_without_prohibited_identity_fields() {
    let report = report(vec![PreflightFinding::warning(
        "PF_OPTIONAL_LOOKUP",
        "optional lookup was unavailable",
    )]);

    let text = render_response(
        ControlResponse::success(AgentResult::Preflight {
            report: report.clone(),
        }),
        OutputFormat::Text,
    );
    let json = render_response(
        ControlResponse::success(AgentResult::Preflight { report }),
        OutputFormat::Json,
    );

    assert_eq!(text.exit_code, EXIT_SUCCESS);
    assert!(text.stderr.is_empty());
    assert!(text.stdout.contains("decision: ready_with_warnings"));
    assert!(text.stdout.contains("findings:"));
    assert!(text.stdout.contains("code: PF_OPTIONAL_LOOKUP"));
    assert!(text.stdout.contains("requested:"));
    assert!(text.stdout.contains("ifindex: 17"));

    assert_eq!(json.exit_code, EXIT_SUCCESS);
    assert!(json.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(value["decision"], "ready_with_warnings");
    assert_eq!(value["interface"]["kind"], "veth");
    assert!(json.stdout.contains("live_shared"));
    assert!(!json.stdout.contains("liveShared"));

    assert_no_prohibited_fields(&text.stdout);
    assert_no_prohibited_fields(&json.stdout);
}

#[test]
fn maps_ready_warning_blocked_and_internal_responses_to_stable_exit_codes() {
    for (findings, expected) in [
        (Vec::new(), EXIT_SUCCESS),
        (
            vec![PreflightFinding::warning("PF_WARNING", "warning")],
            EXIT_SUCCESS,
        ),
        (
            vec![PreflightFinding::blocker("PF_BLOCKED", "blocked")],
            EXIT_BLOCKED,
        ),
    ] {
        let rendered = render_response(
            ControlResponse::success(AgentResult::Preflight {
                report: report(findings),
            }),
            OutputFormat::Text,
        );
        assert_eq!(rendered.exit_code, expected);
        assert!(rendered.stderr.is_empty());
    }

    let daemon_error = render_response(
        ControlResponse::error(ERROR_INTERNAL, "inspection failed"),
        OutputFormat::Text,
    );
    assert_eq!(daemon_error.exit_code, EXIT_FAILURE);
    assert!(daemon_error.stdout.is_empty());
    assert_eq!(daemon_error.stderr, "INTERNAL_ERROR: inspection failed");

    let accepted = render_response(
        ControlResponse::success(AgentResult::Accepted),
        OutputFormat::Text,
    );
    assert_eq!(accepted.exit_code, EXIT_SUCCESS);
    assert_eq!(accepted.stdout, "accepted");
    assert!(accepted.stderr.is_empty());

    let isolated_blocked = render_response(
        ControlResponse::error(PF_LIVE_INTERFACE, "isolated attachment was blocked"),
        OutputFormat::Text,
    );
    assert_eq!(isolated_blocked.exit_code, EXIT_BLOCKED);
    assert_eq!(
        isolated_blocked.stderr,
        "PF_LIVE_INTERFACE: isolated attachment was blocked"
    );
}

#[test]
fn renders_observation_and_status_as_stable_text_and_json() {
    let snapshot = observation();
    let status = InterfaceStatus {
        interface: snapshot.interface.clone(),
        state: InterfaceState::Observing,
        generation: snapshot.generation,
        captured_at_unix_ms: snapshot.captured_at_unix_ms,
        health: snapshot.health,
        vlan_visibility: snapshot.vlan_visibility,
        xdp_ingress: snapshot.hooks[0].total,
        tc_egress: snapshot.hooks[1].total,
        sampling: snapshot.sampling.clone(),
        rate_windows: status_rate_windows(),
        baseline: l2_loop_core::BaselineSummary::from_report(&snapshot.baseline),
        fingerprints: l2_loop_core::FingerprintSummary::from(&snapshot.fingerprints),
        detection: l2_loop_core::DetectionSummary::from(&snapshot.detection),
    };

    let text = render_response(
        ControlResponse::success(AgentResult::Observation {
            snapshot: snapshot.clone(),
        }),
        OutputFormat::Text,
    );
    let json = render_response(
        ControlResponse::success(AgentResult::Observation {
            snapshot: snapshot.clone(),
        }),
        OutputFormat::Json,
    );
    let status_json = render_response(
        ControlResponse::success(AgentResult::Status {
            interfaces: vec![status.clone()],
        }),
        OutputFormat::Json,
    );
    let status_text = render_response(
        ControlResponse::success(AgentResult::Status {
            interfaces: vec![status],
        }),
        OutputFormat::Text,
    );

    assert_eq!(text.exit_code, EXIT_SUCCESS);
    assert!(text.stdout.contains("interface: l2h0123456789"));
    assert!(text.stdout.contains("role: external_xdp_ingress"));
    assert!(text.stdout.contains("traffic_class: l2_broadcast"));
    assert!(text.stdout.contains("packets: 21"));
    assert!(text.stdout.contains("baseline:"));
    assert!(text.stdout.contains("source_window_ms: 10000"));
    assert!(text.stdout.contains("minimum_samples: 60"));
    assert!(text.stdout.contains("packet_noise_floor_pps: 10"));
    assert!(text.stdout.contains("byte_noise_floor_bps: 16384"));
    assert!(text.stdout.contains("learning_subject_count: 16"));
    assert!(text.stdout.contains("subject:"));
    assert!(text.stdout.contains("sample_count: 0"));
    assert!(text.stdout.contains("fingerprints:"));
    assert!(text.stdout.contains("state: observed"));
    assert!(text.stdout.contains("correlated_relation_count: 1"));
    assert!(text.stdout.contains("detection:"));
    assert!(text.stdout.contains("retained_anomalous_state: null"));
    assert!(text.stdout.contains("candidate_streak: 0"));
    assert!(text.stdout.contains("transition_sequence: 0"));
    assert!(text.stdout.contains("transitions:"));
    assert!(status_text.stdout.contains("detection:"));
    assert!(status_text.stdout.contains("state: warming_up"));
    assert!(
        status_text
            .stdout
            .contains("fingerprint_window_state: warming_up")
    );
    assert!(!status_text.stdout.contains("transitions:"));
    assert_eq!(json.exit_code, EXIT_SUCCESS);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(value["schema_version"], 5);
    assert_eq!(value["fingerprints"]["state"], "observed");
    assert_eq!(value["fingerprints"]["correlated_relation_count"], 1);
    assert_eq!(value["hooks"][1]["role"], "physical_tc_egress");
    assert_eq!(value["rate_windows"][0]["elapsed_ns"], 1_000_000_000_u64);
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["total"]["packet_delta"],
        7
    );
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["total"]["packets_per_second"],
        7
    );
    assert_eq!(
        value["rate_windows"][0]["hooks"][0]["total"]["bytes_per_second"],
        700
    );
    assert!(value["rate_windows"][1]["elapsed_ns"].is_null());
    assert!(value["rate_windows"][1]["hooks"].is_null());
    assert!(value["rate_windows"][2]["hooks"].is_null());
    let status_value: serde_json::Value = serde_json::from_str(&status_json.stdout).unwrap();
    assert_eq!(status_value["interfaces"][0]["state"], "observing");
    assert_eq!(status_value["interfaces"][0]["xdp_ingress"]["packets"], 21);
    assert_eq!(
        status_value["interfaces"][0]["fingerprints"]["correlated_relation_count"],
        1
    );
    assert_eq!(
        status_value["interfaces"][0]["baseline"]["state"],
        "learning"
    );
    assert_eq!(
        status_value["interfaces"][0]["baseline"]["subject_sample_counts"]
            .as_array()
            .unwrap()
            .len(),
        16
    );

    for output in [
        &text.stdout,
        &json.stdout,
        &status_text.stdout,
        &status_json.stdout,
    ] {
        for prohibited in [
            "ip_address",
            "mac_address",
            "hostname",
            "machine_id",
            "routes",
            "customer",
            "pin_path",
            "map_id",
            "run_id",
            "ownership",
            "source_mac",
            "destination_mac",
            "first_seen_ns",
            "last_seen_ns",
            "fingerprint\"",
            "confirmed_loop",
            "detection_threshold_override",
        ] {
            assert!(!output.contains(prohibited));
        }
    }
}

#[test]
fn renders_fixed_rate_labels_without_inventing_non_ready_rates() {
    let snapshot = observation();
    let status = status_from(&snapshot);

    let observe_text = render_response(
        ControlResponse::success(AgentResult::Observation { snapshot }),
        OutputFormat::Text,
    );
    let status_text = render_response(
        ControlResponse::success(AgentResult::Status {
            interfaces: vec![status],
        }),
        OutputFormat::Text,
    );

    for rendered in [&observe_text, &status_text] {
        assert_eq!(rendered.exit_code, EXIT_SUCCESS);
        assert!(rendered.stderr.is_empty());
        for expected in [
            "window: 1s",
            "state: ready",
            "pps: 7",
            "B/s: 700",
            "window: 10s",
            "state: warming_up",
            "window: 60s",
            "state: stale",
        ] {
            assert!(
                rendered.stdout.contains(expected),
                "missing `{expected}` in:\n{}",
                rendered.stdout
            );
        }
        assert!(!rendered.stdout.contains("pps: 0"));
        assert!(!rendered.stdout.contains("B/s: 0"));
        let rate_windows = rendered
            .stdout
            .split_once("rate_windows:")
            .unwrap()
            .1
            .split_once("baseline:")
            .unwrap()
            .0;
        assert!(!rate_windows.contains("packets_per_second:"));
        assert!(!rate_windows.contains("bytes_per_second:"));
    }
    assert!(observe_text.stdout.contains("traffic_class: l2_broadcast"));
    assert!(!status_text.stdout.contains("traffic_class:"));
}

#[test]
fn observation_errors_use_exit_one_and_do_not_leak_evidence() {
    let rendered = render_response(
        ControlResponse::error("OBS_MAP_IDENTITY_MISMATCH", "observation failed"),
        OutputFormat::Text,
    );

    assert_eq!(rendered.exit_code, EXIT_FAILURE);
    assert_eq!(
        rendered.stderr,
        "OBS_MAP_IDENTITY_MISMATCH: observation failed"
    );
    assert!(rendered.stdout.is_empty());
}

fn report(findings: Vec<PreflightFinding>) -> PreflightReport {
    PreflightReport::new(
        InterfaceInspection {
            requested: InterfaceRef {
                name: InterfaceName::new("veth-test").unwrap(),
                ifindex: 17,
            },
            kind: InterfaceKind::Veth,
            admin_up: true,
            oper_up: true,
            master: None,
            bond: None,
            proposed_targets: Vec::new(),
            isolated: true,
            live_shared: false,
        },
        KernelInspection {
            architecture: "x86_64".into(),
            release: "linux-test".into(),
            bpf_syscall: true,
            bpf_jit: true,
            btf_readable: true,
            tc_clsact: true,
        },
        BpfInspection {
            bpffs_mounted: true,
            relevant_objects_enumerable: true,
            pin_root: PinRootState::Absent,
            xdp_native: AttachmentState::Empty,
            xdp_generic: AttachmentState::Empty,
            tc_ingress: Vec::new(),
            tc_egress: Vec::new(),
            memlock: MemlockInspection {
                soft_bytes: Some(8 * 1024 * 1024),
                hard_bytes: None,
                required_bytes: 1024 * 1024,
                can_raise: true,
            },
        },
        findings,
    )
}

fn assert_no_prohibited_fields(output: &str) {
    let lower = output.to_ascii_lowercase();
    for key in [
        "ip_address",
        "mac_address",
        "hostname",
        "machine_id",
        "routes",
        "packet",
        "customer",
    ] {
        assert!(
            !lower.contains(key),
            "output exposed prohibited field {key}"
        );
    }
}

const CLASS_ORDER: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

fn observation() -> ObservationSnapshot {
    let mut snapshot = ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        41,
        7,
        1_786_300_000_000,
        VlanVisibility::VerifiedVisible,
        [
            observation_hook(HookRole::ExternalXdpIngress, 21, 1_260),
            observation_hook(HookRole::PhysicalTcEgress, 18, 1_080),
        ],
        SamplingStatus {
            latest_success_at_unix_ms: Some(1_786_300_000_000),
            last_error_code: Some("OBS_RATE_SAMPLE_FAILED".into()),
            consecutive_failures: 2,
            sampling_paused: false,
        },
        detailed_rate_windows(),
    )
    .unwrap();
    snapshot.fingerprints.state = l2_loop_core::FingerprintState::Observed;
    snapshot.fingerprints.captured_entry_count = 2;
    snapshot.fingerprints.relation_count = 1;
    snapshot.fingerprints.correlated_relation_count = 1;
    snapshot.fingerprints.ingress_first_relation_count = 1;
    snapshot.fingerprints.repeated_relation_count = 1;
    snapshot.fingerprints.ingress.packets = 2;
    snapshot.fingerprints.ingress.bytes = 128;
    snapshot.fingerprints.egress.packets = 3;
    snapshot.fingerprints.egress.bytes = 192;
    snapshot.fingerprints.maximum_packet_ratio_milli = Some(1_500);
    snapshot.fingerprints.maximum_byte_ratio_milli = Some(1_500);
    snapshot
}

fn status_from(snapshot: &ObservationSnapshot) -> InterfaceStatus {
    InterfaceStatus {
        interface: snapshot.interface.clone(),
        state: InterfaceState::Observing,
        generation: snapshot.generation,
        captured_at_unix_ms: snapshot.captured_at_unix_ms,
        health: snapshot.health,
        vlan_visibility: snapshot.vlan_visibility,
        xdp_ingress: snapshot.hooks[0].total,
        tc_egress: snapshot.hooks[1].total,
        sampling: snapshot.sampling.clone(),
        rate_windows: status_rate_windows(),
        baseline: l2_loop_core::BaselineSummary::from_report(&snapshot.baseline),
        fingerprints: l2_loop_core::FingerprintSummary::from(&snapshot.fingerprints),
        detection: l2_loop_core::DetectionSummary::from(&snapshot.detection),
    }
}

fn detailed_rate_windows() -> [DetailedRateWindow; 3] {
    [
        DetailedRateWindow {
            window_ms: 1_000,
            state: RateWindowState::Ready,
            coverage_ms: 1_000,
            elapsed_ns: Some(1_000_000_000),
            start_unix_ms: Some(1_786_299_999_000),
            end_unix_ms: Some(1_786_300_000_000),
            hooks: Some([
                hook_rate(HookRole::ExternalXdpIngress, rate_counters(7, 700)),
                hook_rate(HookRole::PhysicalTcEgress, rate_counters(5, 500)),
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
            state: RateWindowState::Stale,
            coverage_ms: 12_000,
            elapsed_ns: None,
            start_unix_ms: None,
            end_unix_ms: None,
            hooks: None,
        },
    ]
}

fn status_rate_windows() -> [StatusRateWindow; 3] {
    [
        StatusRateWindow {
            window_ms: 1_000,
            state: RateWindowState::Ready,
            coverage_ms: 1_000,
            elapsed_ns: Some(1_000_000_000),
            start_unix_ms: Some(1_786_299_999_000),
            end_unix_ms: Some(1_786_300_000_000),
            xdp_ingress: Some(rate_counters(7, 700)),
            tc_egress: Some(rate_counters(5, 500)),
        },
        StatusRateWindow {
            window_ms: 10_000,
            state: RateWindowState::WarmingUp,
            coverage_ms: 1_000,
            elapsed_ns: None,
            start_unix_ms: None,
            end_unix_ms: None,
            xdp_ingress: None,
            tc_egress: None,
        },
        StatusRateWindow {
            window_ms: 60_000,
            state: RateWindowState::Stale,
            coverage_ms: 12_000,
            elapsed_ns: None,
            start_unix_ms: None,
            end_unix_ms: None,
            xdp_ingress: None,
            tc_egress: None,
        },
    ]
}

fn hook_rate(role: HookRole, total: RateCounters) -> HookRate {
    HookRate {
        role,
        total,
        classes: CLASS_ORDER.map(|traffic_class| ClassRate {
            traffic_class,
            counters: rate_counters(1, 100),
        }),
        parse_errors: rate_counters(1, 100),
    }
}

fn rate_counters(packets: u64, bytes: u64) -> RateCounters {
    RateCounters {
        packet_delta: packets,
        byte_delta: bytes,
        packets_per_second: packets,
        bytes_per_second: bytes,
    }
}

fn observation_hook(role: HookRole, packets: u64, bytes: u64) -> HookObservation {
    HookObservation {
        role,
        total: ObservationCounters { packets, bytes },
        classes: CLASS_ORDER.map(|traffic_class| ClassObservation {
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
    }
}
