use l2_loop_core::{
    AUTHORIZATION_MAX_LIFETIME_MS, CANARY_MAX_OBSERVATION_MS, DEPLOYMENT_SCHEMA_VERSION,
    DG_ARTIFACT_CHECKSUM, DG_ARTIFACT_INVENTORY, DG_ARTIFACT_MANIFEST, DG_AUTH_ARTIFACT,
    DG_AUTH_EXPIRED, DG_AUTH_IDENTITY, DG_AUTH_SCHEMA, DG_EVIDENCE_ROOT, DG_INTERFACE_UNSUPPORTED,
    DG_INTERNAL, DG_LAYOUT_MODE, DG_LAYOUT_SYMLINK, DG_LAYOUT_TYPE, DG_NATIVE_XDP_UNVERIFIED,
    DG_PERFORMANCE_REGRESSION, DG_PERFORMANCE_UNAVAILABLE, DG_PLATFORM_BLOCKED,
    DG_REAL_JOURNALD_UNVERIFIED, DG_STAGING_ROOT, DG_SYSTEMD_CONTRACT, DG_TC_NOT_EMPTY,
    DG_WORKLOAD_PERFORMANCE_UNVERIFIED, DG_XDP_NOT_EMPTY, DeploymentArtifactIdentityV1,
    DeploymentAuthorizationV1, DeploymentCommandV1, DeploymentDecisionV1, DeploymentFindingV1,
    DeploymentGateReportV1, DeploymentGateSummariesV1, DeploymentHostCompatibilityV1,
    DeploymentInterfaceSummaryV1, InterfaceKind, PERFORMANCE_EVIDENCE_MAX_LIFETIME_MS,
    PERFORMANCE_FIXED_FRAME_SIZES, PERFORMANCE_FRAMES_PER_SIZE,
    PERFORMANCE_MAX_DAEMON_CPU_PERMILLE, PERFORMANCE_MAX_DAEMON_RSS_BYTES,
    PERFORMANCE_MAX_RSS_GROWTH_BYTES, PERFORMANCE_OBSERVE_MIN_PERMILLE,
    PERFORMANCE_PASS_THROUGH_MIN_PERMILLE, PERFORMANCE_TOTAL_TRIALS, PERFORMANCE_TRIALS_PER_MODE,
    PerformanceEvidenceV1,
};
use serde_json::{Value, json};

const NOW_MS: u64 = 1_786_579_200_000;
const EXPIRES_MS: u64 = NOW_MS + 86_400_000;
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const AUTHORIZATION_ID: &str = "00112233445566778899aabbccddeeff";
const EVIDENCE_ID: &str = "ffeeddccbbaa99887766554433221100";

#[test]
fn deployment_constants_and_decisions_are_fixed() {
    assert_eq!(DEPLOYMENT_SCHEMA_VERSION, 1);
    assert_eq!(AUTHORIZATION_MAX_LIFETIME_MS, 86_400_000);
    assert_eq!(PERFORMANCE_EVIDENCE_MAX_LIFETIME_MS, 86_400_000);
    assert_eq!(CANARY_MAX_OBSERVATION_MS, 15 * 60 * 1_000);
    assert_eq!(PERFORMANCE_TRIALS_PER_MODE, 5);
    assert_eq!(PERFORMANCE_TOTAL_TRIALS, 15);
    assert_eq!(PERFORMANCE_FIXED_FRAME_SIZES, [64, 512, 1_514]);
    assert_eq!(PERFORMANCE_FRAMES_PER_SIZE, 65_536);
    assert_eq!(PERFORMANCE_PASS_THROUGH_MIN_PERMILLE, 950);
    assert_eq!(PERFORMANCE_OBSERVE_MIN_PERMILLE, 900);
    assert_eq!(PERFORMANCE_MAX_DAEMON_RSS_BYTES, 256 * 1024 * 1024);
    assert_eq!(PERFORMANCE_MAX_RSS_GROWTH_BYTES, 16 * 1024 * 1024);
    assert_eq!(PERFORMANCE_MAX_DAEMON_CPU_PERMILLE, 1_000);

    assert_eq!(DeploymentDecisionV1::Blocked.to_string(), "blocked");
    assert_eq!(
        DeploymentDecisionV1::StagingReady.to_string(),
        "staging_ready"
    );
    assert_eq!(
        DeploymentDecisionV1::CanaryCandidate.to_string(),
        "canary_candidate"
    );
    assert_eq!(
        DeploymentDecisionV1::InstalledVerified.to_string(),
        "installed_verified"
    );
    assert_eq!(
        DeploymentDecisionV1::PhysicalCanaryReady.to_string(),
        "physical_canary_ready"
    );
}

#[test]
fn stable_findings_are_complete_and_unique() {
    let blockers = [
        DG_ARTIFACT_INVENTORY,
        DG_ARTIFACT_MANIFEST,
        DG_ARTIFACT_CHECKSUM,
        DG_STAGING_ROOT,
        DG_LAYOUT_TYPE,
        DG_LAYOUT_MODE,
        DG_LAYOUT_SYMLINK,
        DG_SYSTEMD_CONTRACT,
        DG_AUTH_SCHEMA,
        DG_AUTH_EXPIRED,
        DG_AUTH_ARTIFACT,
        DG_AUTH_IDENTITY,
        DG_INTERFACE_UNSUPPORTED,
        DG_XDP_NOT_EMPTY,
        DG_TC_NOT_EMPTY,
        DG_PLATFORM_BLOCKED,
        DG_EVIDENCE_ROOT,
        DG_PERFORMANCE_UNAVAILABLE,
        DG_PERFORMANCE_REGRESSION,
        DG_INTERNAL,
    ];
    let warnings = [
        DG_REAL_JOURNALD_UNVERIFIED,
        DG_NATIVE_XDP_UNVERIFIED,
        DG_WORKLOAD_PERFORMANCE_UNVERIFIED,
    ];
    assert_eq!(blockers.len(), 20);
    assert_eq!(warnings.len(), 3);
    for (index, code) in blockers.iter().enumerate() {
        assert!(code.starts_with("DG_"));
        assert!(!blockers[..index].contains(code));
        assert!(DeploymentFindingV1::blocker(code).is_ok());
    }
    for (index, code) in warnings.iter().enumerate() {
        assert!(code.starts_with("DG_"));
        assert!(!warnings[..index].contains(code));
        assert!(DeploymentFindingV1::warning(code).is_ok());
    }
    assert!(DeploymentFindingV1::blocker("DG_CALLER_SELECTED").is_err());
    assert!(DeploymentFindingV1::warning(DG_INTERNAL).is_err());
}

#[test]
fn authorization_json_is_strict_and_canonical() {
    let valid = valid_authorization_value();
    let parsed: DeploymentAuthorizationV1 = serde_json::from_value(valid.clone()).unwrap();
    parsed.validate_at(NOW_MS).unwrap();

    let mut unknown = valid.clone();
    unknown["override_interface"] = json!("eth0");
    assert!(serde_json::from_value::<DeploymentAuthorizationV1>(unknown).is_err());

    let raw = serde_json::to_string(&valid).unwrap();
    let duplicate = raw.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(serde_json::from_str::<DeploymentAuthorizationV1>(&duplicate).is_err());

    for field in [
        "schema_version",
        "authorization_id",
        "artifact_commit_sha",
        "mode",
        "interface",
        "issued_at_unix_ms",
        "expires_at_unix_ms",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<DeploymentAuthorizationV1>(missing).is_err(),
            "accepted missing field {field}"
        );
    }

    let mut wrong_type = valid;
    wrong_type["interface"]["ifindex"] = json!("7");
    assert!(serde_json::from_value::<DeploymentAuthorizationV1>(wrong_type).is_err());
}

#[test]
fn authorization_rejects_noncanonical_ids_commits_and_mode() {
    for invalid in [
        "",
        "00112233445566778899aabbccddeef",
        "00112233445566778899aabbccddeeff00",
        "00112233445566778899AABBCCDDEEFF",
        "../112233445566778899aabbccddeeff",
    ] {
        let mut value = valid_authorization_value();
        value["authorization_id"] = json!(invalid);
        assert!(serde_json::from_value::<DeploymentAuthorizationV1>(value).is_err());
    }

    for invalid in [
        "",
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "../3456789abcdef0123456789abcdef01234567",
    ] {
        let mut value = valid_authorization_value();
        value["artifact_commit_sha"] = json!(invalid);
        assert!(serde_json::from_value::<DeploymentAuthorizationV1>(value).is_err());
    }

    let mut mode = valid_authorization_value();
    mode["mode"] = json!("attach_read_only");
    assert!(serde_json::from_value::<DeploymentAuthorizationV1>(mode).is_err());
}

#[test]
fn authorization_requires_one_empty_hook_physical_interface() {
    let cases = [
        ("ifindex", json!(0)),
        ("kind", json!("veth")),
        ("administrative_state", json!("down")),
        ("operational_state", json!("down")),
        ("master_ifindex", json!(9)),
        ("xdp_native", json!("occupied")),
        ("xdp_generic", json!("unknown")),
        ("tc_clsact", json!(true)),
        ("tc_ingress", json!(["filter"])),
        ("tc_egress", json!(["filter"])),
    ];
    for (field, replacement) in cases {
        let mut value = valid_authorization_value();
        value["interface"][field] = replacement;
        if let Ok(parsed) = serde_json::from_value::<DeploymentAuthorizationV1>(value) {
            assert!(parsed.validate_at(NOW_MS).is_err(), "accepted {field}");
        }
    }

    let mut unsafe_name = valid_authorization_value();
    unsafe_name["interface"]["name"] = json!("../../eth0");
    let parsed: DeploymentAuthorizationV1 = serde_json::from_value(unsafe_name).unwrap();
    assert!(parsed.validate_at(NOW_MS).is_err());
}

#[test]
fn authorization_lifetime_is_positive_bounded_and_inclusive() {
    let parsed = valid_authorization();
    parsed.validate_at(NOW_MS).unwrap();
    parsed.validate_at(EXPIRES_MS).unwrap();
    assert!(parsed.validate_at(NOW_MS - 1).is_err());
    assert!(parsed.validate_at(EXPIRES_MS + 1).is_err());

    for (issued, expires) in [
        (NOW_MS, NOW_MS),
        (NOW_MS + 1, NOW_MS),
        (NOW_MS, EXPIRES_MS + 1),
        (0, EXPIRES_MS),
    ] {
        let mut value = valid_authorization_value();
        value["issued_at_unix_ms"] = json!(issued);
        value["expires_at_unix_ms"] = json!(expires);
        let parsed: DeploymentAuthorizationV1 = serde_json::from_value(value).unwrap();
        assert!(parsed.validate_at(NOW_MS).is_err());
    }
}

#[test]
fn authorization_binds_the_exact_artifact() {
    let authorization = valid_authorization();
    let expected = artifact();
    authorization.validate_for(NOW_MS, &expected).unwrap();

    let other =
        DeploymentArtifactIdentityV1::new("1123456789abcdef0123456789abcdef01234567", "0.1.0")
            .unwrap();
    assert!(authorization.validate_for(NOW_MS, &other).is_err());
}

#[test]
fn performance_json_is_strict_and_has_fixed_trial_order() {
    let valid = valid_performance_value();
    let parsed: PerformanceEvidenceV1 = serde_json::from_value(valid.clone()).unwrap();
    parsed.validate_for(NOW_MS, &artifact(), &host()).unwrap();

    let mut unknown = valid.clone();
    unknown["threshold_override"] = json!(1);
    assert!(serde_json::from_value::<PerformanceEvidenceV1>(unknown).is_err());

    let raw = serde_json::to_string(&valid).unwrap();
    let duplicate = raw.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(serde_json::from_str::<PerformanceEvidenceV1>(&duplicate).is_err());

    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("trials");
    assert!(serde_json::from_value::<PerformanceEvidenceV1>(missing).is_err());

    let mut short = valid.clone();
    short["trials"].as_array_mut().unwrap().pop();
    let parsed: PerformanceEvidenceV1 = serde_json::from_value(short).unwrap();
    assert!(parsed.validate_for(NOW_MS, &artifact(), &host()).is_err());

    let mut wrong_order = valid;
    wrong_order["trials"][0]["mode"] = json!("observe");
    let parsed: PerformanceEvidenceV1 = serde_json::from_value(wrong_order).unwrap();
    assert!(parsed.validate_for(NOW_MS, &artifact(), &host()).is_err());
}

#[test]
fn performance_identity_and_lifetime_are_exact() {
    let evidence = valid_performance();
    evidence.validate_for(NOW_MS, &artifact(), &host()).unwrap();
    evidence
        .validate_for(EXPIRES_MS, &artifact(), &host())
        .unwrap();
    assert!(
        evidence
            .validate_for(NOW_MS - 1, &artifact(), &host())
            .is_err()
    );
    assert!(
        evidence
            .validate_for(EXPIRES_MS + 1, &artifact(), &host())
            .is_err()
    );

    let other_artifact = DeploymentArtifactIdentityV1::new(COMMIT_SHA, "9.9.9").unwrap();
    assert!(
        evidence
            .validate_for(NOW_MS, &other_artifact, &host())
            .is_err()
    );

    for other_host in [
        DeploymentHostCompatibilityV1::new("aarch64", "6.12.0-test", 8).unwrap(),
        DeploymentHostCompatibilityV1::new("x86_64", "6.13.0-test", 8).unwrap(),
        DeploymentHostCompatibilityV1::new("x86_64", "6.12.0-test", 16).unwrap(),
    ] {
        assert!(
            evidence
                .validate_for(NOW_MS, &artifact(), &other_host)
                .is_err()
        );
    }
}

#[test]
fn passed_performance_requires_every_fixed_invariant() {
    let mutations = [
        ("pass_through_baseline_ratio_permille", json!(949)),
        ("observe_baseline_ratio_permille", json!(899)),
        ("daemon_cpu_permille", json!(1_001)),
        ("peak_resident_memory_bytes", json!(268_435_457_u64)),
        ("rss_growth_bytes", json!(16_777_217_u64)),
        ("packet_drop_delta", json!(1)),
        ("packet_error_delta", json!(1)),
        ("forwarding_intact", json!(false)),
        ("owned_cleanup_complete", json!(false)),
        ("network_identity_restored", json!(false)),
        ("ebpf_identity_restored", json!(false)),
    ];
    for (field, replacement) in mutations {
        let mut value = valid_performance_value();
        value[field] = replacement;
        let parsed: PerformanceEvidenceV1 = serde_json::from_value(value).unwrap();
        assert!(
            parsed.validate_for(NOW_MS, &artifact(), &host()).is_err(),
            "accepted failed invariant {field}"
        );
    }
}

#[test]
fn performance_rejects_impossible_arithmetic_inputs() {
    for (field, replacement) in [
        ("duration_ns", json!(0)),
        ("packets_per_second", json!(u64::MAX)),
        ("bytes_per_second", json!(u64::MAX)),
    ] {
        let mut value = valid_performance_value();
        value["trials"][0][field] = replacement;
        let parsed: PerformanceEvidenceV1 = serde_json::from_value(value).unwrap();
        assert!(
            parsed.validate_for(NOW_MS, &artifact(), &host()).is_err(),
            "accepted impossible {field}"
        );
    }
}

#[test]
fn canary_plan_is_fixed_non_executable_and_sanitized() {
    let authorization = valid_authorization();
    authorization.validate_for(NOW_MS, &artifact()).unwrap();
    let interface =
        DeploymentInterfaceSummaryV1::new("spare0", 7, InterfaceKind::Physical, true, true)
            .unwrap();
    let plan = l2_loop_core::CanaryPlanV1::new(&authorization, &interface).unwrap();
    let value = serde_json::to_value(&plan).unwrap();

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["executable"], false);
    assert_eq!(value["maximum_observation_duration_ms"], 900_000);
    assert_eq!(value["no_replace"], true);
    assert_eq!(value["reject_foreign_or_unknown_state"], true);
    assert_eq!(value["authorization_id"], AUTHORIZATION_ID);
    assert_eq!(value["artifact_commit_sha"], COMMIT_SHA);
    assert_eq!(value["interface"]["name"], "spare0");
    assert_eq!(value["interface"]["ifindex"], 7);
    assert!(value["required_snapshots"].as_array().unwrap().len() >= 7);
    assert_eq!(value["stop_conditions"].as_array().unwrap().len(), 7);
    assert!(value["rollback_requirements"].as_array().unwrap().len() >= 5);
    assert_eq!(
        value["warning_codes"],
        json!([
            DG_NATIVE_XDP_UNVERIFIED,
            DG_REAL_JOURNALD_UNVERIFIED,
            DG_WORKLOAD_PERFORMANCE_UNVERIFIED,
        ])
    );

    let rendered = serde_json::to_string(&plan).unwrap();
    for prohibited in [
        "action_token",
        "attach_endpoint",
        "consumer_command",
        "execute_command",
        "production_ready",
    ] {
        assert!(!rendered.contains(prohibited), "plan exposed {prohibited}");
    }
}

#[test]
fn report_derives_staging_ready_only_from_staging_gates() {
    let report = DeploymentGateReportV1::derive(
        DeploymentCommandV1::Staging,
        artifact(),
        None,
        DeploymentGateSummariesV1::staging_passed(),
        Vec::new(),
        None,
        NOW_MS,
    )
    .unwrap();
    assert_eq!(report.decision, DeploymentDecisionV1::StagingReady);
    assert!(report.interface.is_none());
    assert!(report.canary_plan.is_none());
    assert!(!report.mutations_performed);
    report.validate(DeploymentCommandV1::Staging).unwrap();
}

#[test]
fn report_derives_installed_verified_without_interface_or_canary_plan() {
    let report = DeploymentGateReportV1::derive(
        DeploymentCommandV1::Installed,
        artifact(),
        None,
        DeploymentGateSummariesV1::installed_passed(),
        Vec::new(),
        None,
        NOW_MS,
    )
    .unwrap();
    assert_eq!(report.decision, DeploymentDecisionV1::InstalledVerified);
    assert!(report.interface.is_none());
    assert!(report.canary_plan.is_none());
    assert!(!report.mutations_performed);
    report.validate(DeploymentCommandV1::Installed).unwrap();
}

#[test]
fn report_derives_physical_readiness_only_with_a_non_executable_plan() {
    let authorization = valid_authorization();
    let interface =
        DeploymentInterfaceSummaryV1::new("spare0", 7, InterfaceKind::Physical, true, true)
            .unwrap();
    let plan = l2_loop_core::CanaryPlanV1::new(&authorization, &interface).unwrap();
    let report = DeploymentGateReportV1::derive(
        DeploymentCommandV1::Inspect,
        artifact(),
        Some(interface),
        DeploymentGateSummariesV1::inspect_passed(),
        vec![
            DeploymentFindingV1::warning(DG_REAL_JOURNALD_UNVERIFIED).unwrap(),
            DeploymentFindingV1::warning(DG_NATIVE_XDP_UNVERIFIED).unwrap(),
            DeploymentFindingV1::warning(DG_WORKLOAD_PERFORMANCE_UNVERIFIED).unwrap(),
        ],
        Some(plan),
        NOW_MS,
    )
    .unwrap();
    assert_eq!(report.decision, DeploymentDecisionV1::PhysicalCanaryReady);
    assert!(!report.canary_plan.as_ref().unwrap().executable);
    assert_eq!(
        report
            .canary_plan
            .as_ref()
            .unwrap()
            .maximum_observation_duration_ms,
        15 * 60 * 1_000
    );
    report.validate(DeploymentCommandV1::Inspect).unwrap();
}

#[test]
fn report_blocks_on_any_blocker_and_sorts_findings() {
    let report = DeploymentGateReportV1::derive(
        DeploymentCommandV1::Inspect,
        artifact(),
        None,
        DeploymentGateSummariesV1::inspect_blocked(DG_PLATFORM_BLOCKED).unwrap(),
        vec![
            DeploymentFindingV1::warning(DG_REAL_JOURNALD_UNVERIFIED).unwrap(),
            DeploymentFindingV1::blocker(DG_PLATFORM_BLOCKED).unwrap(),
        ],
        None,
        NOW_MS,
    )
    .unwrap();
    assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
    assert!(report.canary_plan.is_none());
    assert_eq!(report.findings[0].code, DG_PLATFORM_BLOCKED);
    assert_eq!(report.findings[1].code, DG_REAL_JOURNALD_UNVERIFIED);
    report.validate(DeploymentCommandV1::Inspect).unwrap();
}

#[test]
fn report_validation_rejects_inconsistent_positive_states() {
    let staging = DeploymentGateReportV1::derive(
        DeploymentCommandV1::Staging,
        artifact(),
        None,
        DeploymentGateSummariesV1::staging_passed(),
        Vec::new(),
        None,
        NOW_MS,
    )
    .unwrap();
    let mut with_mutation = serde_json::to_value(&staging).unwrap();
    with_mutation["mutations_performed"] = json!(true);
    let parsed: DeploymentGateReportV1 = serde_json::from_value(with_mutation).unwrap();
    assert!(parsed.validate(DeploymentCommandV1::Staging).is_err());

    let mut with_blocker = serde_json::to_value(&staging).unwrap();
    with_blocker["findings"] = json!([{"code": DG_INTERNAL, "severity": "blocker"}]);
    let parsed: DeploymentGateReportV1 = serde_json::from_value(with_blocker).unwrap();
    assert!(parsed.validate(DeploymentCommandV1::Staging).is_err());

    let mut wrong_decision = serde_json::to_value(&staging).unwrap();
    wrong_decision["decision"] = json!("canary_candidate");
    let parsed: DeploymentGateReportV1 = serde_json::from_value(wrong_decision).unwrap();
    assert!(parsed.validate(DeploymentCommandV1::Staging).is_err());
}

#[test]
fn public_deployment_contract_contains_no_execution_or_production_ready_state() {
    let test_source = include_str!("deployment_contract.rs");
    let decision_json = serde_json::to_string(&[
        DeploymentDecisionV1::Blocked,
        DeploymentDecisionV1::StagingReady,
        DeploymentDecisionV1::CanaryCandidate,
        DeploymentDecisionV1::InstalledVerified,
        DeploymentDecisionV1::PhysicalCanaryReady,
    ])
    .unwrap();
    assert_eq!(
        decision_json,
        "[\"blocked\",\"staging_ready\",\"canary_candidate\",\"installed_verified\",\"physical_canary_ready\"]"
    );
    let production_ready = "production".to_owned() + "_ready";
    for prohibited in [
        "force_attach",
        "replace_hook",
        "adopt_foreign",
        production_ready.as_str(),
    ] {
        assert!(!decision_json.contains(prohibited));
        assert!(!test_source.contains(&format!("enum {prohibited}")));
    }
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn host() -> DeploymentHostCompatibilityV1 {
    DeploymentHostCompatibilityV1::new("x86_64", "6.12.0-test", 8).unwrap()
}

fn valid_authorization() -> DeploymentAuthorizationV1 {
    serde_json::from_value(valid_authorization_value()).unwrap()
}

fn valid_authorization_value() -> Value {
    json!({
        "schema_version": 1,
        "authorization_id": AUTHORIZATION_ID,
        "artifact_commit_sha": COMMIT_SHA,
        "mode": "read_only_canary_candidate",
        "interface": {
            "name": "spare0",
            "ifindex": 7,
            "kind": "physical",
            "administrative_state": "up",
            "operational_state": "up",
            "master_ifindex": null,
            "mac_address_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "driver": "test_driver",
            "device_identity_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "network_namespace_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "xdp_native": "empty",
            "xdp_generic": "empty",
            "tc_clsact": false,
            "tc_ingress": [],
            "tc_egress": []
        },
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": EXPIRES_MS
    })
}

fn valid_performance() -> PerformanceEvidenceV1 {
    serde_json::from_value(valid_performance_value()).unwrap()
}

fn valid_performance_value() -> Value {
    let orders = [
        ["baseline", "pass_through", "observe"],
        ["pass_through", "observe", "baseline"],
        ["observe", "baseline", "pass_through"],
        ["baseline", "observe", "pass_through"],
        ["pass_through", "baseline", "observe"],
    ];
    let mut trials = Vec::new();
    for (trial_index, order) in orders.iter().enumerate() {
        for mode in order {
            let (duration_ns, pps, bps) = match *mode {
                "baseline" => (196_608_000_u64, 1_000_000_u64, 696_666_666_u64),
                "pass_through" => (204_800_000_u64, 960_000_u64, 668_800_000_u64),
                "observe" => (216_052_747_u64, 910_000_u64, 633_966_667_u64),
                _ => unreachable!(),
            };
            trials.push(json!({
                "trial_number": trial_index + 1,
                "mode": mode,
                "frame_sizes": [64, 512, 1514],
                "frames_per_size": 65536,
                "duration_ns": duration_ns,
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "daemon_cpu_time_ns": 10_000_000,
                "peak_resident_memory_bytes": 67_108_864,
                "packet_drop_delta": 0,
                "packet_error_delta": 0
            }));
        }
    }
    json!({
        "schema_version": 1,
        "evidence_id": EVIDENCE_ID,
        "artifact_commit_sha": COMMIT_SHA,
        "package_version": "0.1.0",
        "architecture": "x86_64",
        "kernel_release": "6.12.0-test",
        "logical_cpu_count": 8,
        "veth_xdp_mode": "generic",
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": EXPIRES_MS,
        "warm_up_complete": true,
        "measurement_complete": true,
        "measurement_noisy": false,
        "host_identity_stable": true,
        "trials": trials,
        "medians": {
            "baseline": {"packets_per_second": 1_000_000, "bytes_per_second": 696_666_666},
            "pass_through": {"packets_per_second": 960_000, "bytes_per_second": 668_800_000},
            "observe": {"packets_per_second": 910_000, "bytes_per_second": 633_966_667}
        },
        "pass_through_baseline_ratio_permille": 960,
        "observe_baseline_ratio_permille": 910,
        "daemon_cpu_time_ns": 150_000_000,
        "daemon_cpu_permille": 48,
        "peak_resident_memory_bytes": 67_108_864,
        "rss_growth_bytes": 0,
        "packet_drop_delta": 0,
        "packet_error_delta": 0,
        "process_count_before": 1,
        "process_count_after": 1,
        "map_count_before": 6,
        "map_count_after": 6,
        "program_count_before": 2,
        "program_count_after": 2,
        "pin_count_before": 6,
        "pin_count_after": 6,
        "namespace_count_before": 1,
        "namespace_count_after": 1,
        "forwarding_intact": true,
        "owned_cleanup_complete": true,
        "network_identity_restored": true,
        "ebpf_identity_restored": true,
        "result": "passed",
        "findings": []
    })
}
