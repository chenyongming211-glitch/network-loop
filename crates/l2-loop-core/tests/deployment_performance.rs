use l2_loop_core::{
    DG_NATIVE_XDP_UNVERIFIED, DG_REAL_JOURNALD_UNVERIFIED, DG_WORKLOAD_PERFORMANCE_UNVERIFIED,
    DeploymentArtifactIdentityV1, DeploymentHostCompatibilityV1, PERFORMANCE_FIXED_FRAME_SIZES,
    PERFORMANCE_FRAMES_PER_SIZE, PERFORMANCE_MAX_DAEMON_RSS_BYTES,
    PERFORMANCE_MAX_RSS_GROWTH_BYTES, PerformanceEvidenceV1, PerformanceModeV1, PerformanceRateV1,
};
use serde_json::{Value, json};

const NOW_MS: u64 = 1_786_579_200_000;
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const SENT_PACKETS: u128 = 196_608;
const SENT_BYTES: u128 = 136_970_240;

#[test]
fn derives_lower_medians_checked_rates_and_conservative_ratios() {
    let evidence = evidence(valid_evidence_value());

    let assessment = evidence.assess_for(NOW_MS, &artifact(), &host()).unwrap();

    assert_eq!(assessment.medians.baseline, rate_for_duration(196_608_000));
    assert_eq!(
        assessment.medians.pass_through,
        rate_for_duration(204_800_000)
    );
    assert_eq!(assessment.medians.observe, rate_for_duration(216_052_747));
    assert_eq!(assessment.pass_through_baseline_ratio_permille, 960);
    assert_eq!(assessment.observe_baseline_ratio_permille, 910);
    assert_eq!(assessment.rss_growth_bytes, 1_048_576);
}

#[test]
fn accepts_exact_throughput_and_resource_boundaries() {
    let mut value = valid_evidence_value();
    set_mode_duration(&mut value, "pass_through", 206_955_789);
    set_mode_duration(&mut value, "observe", 218_453_333);
    value["peak_resident_memory_bytes"] = json!(PERFORMANCE_MAX_DAEMON_RSS_BYTES);
    value["rss_growth_bytes"] = json!(PERFORMANCE_MAX_RSS_GROWTH_BYTES);
    set_observe_rss_growth(
        &mut value,
        PERFORMANCE_MAX_DAEMON_RSS_BYTES - PERFORMANCE_MAX_RSS_GROWTH_BYTES,
        PERFORMANCE_MAX_DAEMON_RSS_BYTES,
    );
    for trial in value["trials"].as_array_mut().unwrap() {
        let duration = trial["duration_ns"].clone();
        trial["daemon_cpu_time_ns"] = duration;
    }
    refresh_aggregates(&mut value);

    evidence(value)
        .assess_for(NOW_MS, &artifact(), &host())
        .unwrap();
}

#[test]
fn rejects_actual_values_just_beyond_each_fixed_boundary() {
    let mut pass_through = valid_evidence_value();
    set_mode_duration(&mut pass_through, "pass_through", 206_955_790);
    refresh_aggregates(&mut pass_through);
    assert_invalid(pass_through);

    let mut observe = valid_evidence_value();
    set_mode_duration(&mut observe, "observe", 218_453_334);
    refresh_aggregates(&mut observe);
    assert_invalid(observe);

    let mut cpu = valid_evidence_value();
    for trial in cpu["trials"].as_array_mut().unwrap() {
        let duration = trial["duration_ns"].as_u64().unwrap();
        trial["daemon_cpu_time_ns"] = json!(duration + duration / 1_000 + 1);
    }
    refresh_aggregates(&mut cpu);
    assert_invalid(cpu);

    let mut rss = valid_evidence_value();
    set_observe_rss_growth(
        &mut rss,
        64 * 1024 * 1024,
        64 * 1024 * 1024 + PERFORMANCE_MAX_RSS_GROWTH_BYTES + 1,
    );
    refresh_aggregates(&mut rss);
    assert_invalid(rss);

    let mut drop_delta = valid_evidence_value();
    drop_delta["trials"][0]["packet_drop_delta"] = json!(1);
    drop_delta["packet_drop_delta"] = json!(1);
    assert_invalid(drop_delta);

    let mut error_delta = valid_evidence_value();
    error_delta["trials"][0]["packet_error_delta"] = json!(1);
    error_delta["packet_error_delta"] = json!(1);
    assert_invalid(error_delta);
}

#[test]
fn rejects_best_run_selection_zero_baseline_and_inexact_rate_arithmetic() {
    let mut best_run = valid_evidence_value();
    let forged = best_run["trials"][0]
        .as_object()
        .map(|trial| {
            json!({
                "packets_per_second": trial["packets_per_second"].as_u64().unwrap() + 1,
                "bytes_per_second": trial["bytes_per_second"].as_u64().unwrap() + 1
            })
        })
        .unwrap();
    best_run["medians"]["baseline"] = forged;
    assert_invalid(best_run);

    let mut zero_baseline = valid_evidence_value();
    zero_baseline["trials"][0]["packets_per_second"] = json!(0);
    assert_invalid(zero_baseline);

    let mut inexact_pps = valid_evidence_value();
    let current = inexact_pps["trials"][0]["packets_per_second"]
        .as_u64()
        .unwrap();
    inexact_pps["trials"][0]["packets_per_second"] = json!(current - 1);
    assert_invalid(inexact_pps);

    let mut inexact_bps = valid_evidence_value();
    let current = inexact_bps["trials"][0]["bytes_per_second"]
        .as_u64()
        .unwrap();
    inexact_bps["trials"][0]["bytes_per_second"] = json!(current - 1);
    assert_invalid(inexact_bps);
}

#[test]
fn rejects_wrong_fixed_workload_and_rotating_order() {
    for (path, replacement) in [
        ("frame_sizes", json!([64, 1_514, 512])),
        ("frames_per_size", json!(65_535)),
        ("trial_number", json!(2)),
        ("mode", json!("observe")),
    ] {
        let mut value = valid_evidence_value();
        value["trials"][0][path] = replacement;
        assert_invalid(value);
    }

    let mut missing = valid_evidence_value();
    missing["trials"].as_array_mut().unwrap().pop();
    assert_invalid(missing);
}

#[test]
fn rejects_untrusted_or_unavailable_measurements_as_passing() {
    for (field, replacement) in [
        ("warm_up_complete", json!(false)),
        ("measurement_complete", json!(false)),
        ("measurement_noisy", json!(true)),
        ("host_identity_stable", json!(false)),
        ("forwarding_intact", json!(false)),
        ("owned_cleanup_complete", json!(false)),
        ("network_identity_restored", json!(false)),
        ("ebpf_identity_restored", json!(false)),
    ] {
        let mut value = valid_evidence_value();
        value[field] = replacement;
        assert_invalid(value);
    }
}

#[test]
fn rejects_drop_error_cpu_memory_and_owned_object_growth() {
    for (field, replacement) in [
        ("packet_drop_delta", json!(1)),
        ("packet_error_delta", json!(1)),
        ("daemon_cpu_permille", json!(1_001)),
        (
            "peak_resident_memory_bytes",
            json!(PERFORMANCE_MAX_DAEMON_RSS_BYTES + 1),
        ),
        (
            "rss_growth_bytes",
            json!(PERFORMANCE_MAX_RSS_GROWTH_BYTES + 1),
        ),
        ("process_count_after", json!(2)),
        ("map_count_after", json!(7)),
        ("program_count_after", json!(3)),
        ("pin_count_after", json!(7)),
        ("namespace_count_after", json!(2)),
    ] {
        let mut value = valid_evidence_value();
        value[field] = replacement;
        assert_invalid(value);
    }
}

#[test]
fn rejects_forged_aggregates_and_checked_sum_overflow() {
    for field in [
        "daemon_cpu_time_ns",
        "daemon_cpu_permille",
        "peak_resident_memory_bytes",
        "rss_growth_bytes",
        "packet_drop_delta",
        "packet_error_delta",
    ] {
        let mut value = valid_evidence_value();
        let current = value[field].as_u64().unwrap();
        value[field] = json!(current + 1);
        assert_invalid(value);
    }

    let mut overflow = valid_evidence_value();
    for index in 0..overflow["trials"].as_array().unwrap().len() {
        overflow["trials"][index]["daemon_cpu_time_ns"] = json!(u64::MAX);
    }
    assert_invalid(overflow);
}

#[test]
fn binds_fresh_evidence_to_the_exact_artifact_and_host() {
    let evidence = evidence(valid_evidence_value());
    let other_artifact =
        DeploymentArtifactIdentityV1::new("1123456789abcdef0123456789abcdef01234567", "0.1.0")
            .unwrap();
    assert!(
        evidence
            .assess_for(NOW_MS, &other_artifact, &host())
            .is_err()
    );
    let other_package = DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.1").unwrap();
    assert!(
        evidence
            .assess_for(NOW_MS, &other_package, &host())
            .is_err()
    );
    for host in [
        DeploymentHostCompatibilityV1::new("aarch64", "6.12.0-test", 8).unwrap(),
        DeploymentHostCompatibilityV1::new("x86_64", "6.13.0-test", 8).unwrap(),
        DeploymentHostCompatibilityV1::new("x86_64", "6.12.0-test", 16).unwrap(),
    ] {
        assert!(evidence.assess_for(NOW_MS, &artifact(), &host).is_err());
    }
    assert!(
        evidence
            .assess_for(NOW_MS + 86_400_001, &artifact(), &host())
            .is_err()
    );
}

#[test]
fn passing_isolated_evidence_keeps_non_executable_canary_warnings() {
    let evidence = evidence(valid_evidence_value());
    let assessment = evidence.assess_for(NOW_MS, &artifact(), &host()).unwrap();

    assert_eq!(
        assessment.outstanding_warning_codes,
        [
            DG_NATIVE_XDP_UNVERIFIED.to_owned(),
            DG_REAL_JOURNALD_UNVERIFIED.to_owned(),
            DG_WORKLOAD_PERFORMANCE_UNVERIFIED.to_owned(),
        ]
    );
    let rendered = serde_json::to_string(&assessment).unwrap();
    assert!(!rendered.contains("production_ready"));
    assert!(!rendered.contains("action_token"));
    assert!(!rendered.contains("command"));
    assert!(!rendered.contains("endpoint"));
}

fn assert_invalid(value: Value) {
    let evidence = evidence(value);
    assert!(evidence.assess_for(NOW_MS, &artifact(), &host()).is_err());
}

fn evidence(value: Value) -> PerformanceEvidenceV1 {
    serde_json::from_value(value).unwrap()
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn host() -> DeploymentHostCompatibilityV1 {
    DeploymentHostCompatibilityV1::new("x86_64", "6.12.0-test", 8).unwrap()
}

fn valid_evidence_value() -> Value {
    let orders = [
        ["baseline", "pass_through", "observe"],
        ["pass_through", "observe", "baseline"],
        ["observe", "baseline", "pass_through"],
        ["baseline", "observe", "pass_through"],
        ["pass_through", "baseline", "observe"],
    ];
    let offsets = [2_i64, -2, 0, 1, -1];
    let mut trials = Vec::new();
    for (trial_index, order) in orders.iter().enumerate() {
        for mode in order {
            let base_duration = match *mode {
                "baseline" => 196_608_000_i64,
                "pass_through" => 204_800_000_i64,
                "observe" => 216_052_747_i64,
                _ => unreachable!(),
            };
            let duration_ns = u64::try_from(base_duration + offsets[trial_index]).unwrap();
            let rate = rate_for_duration(duration_ns);
            let peak_rss = if *mode == "observe" {
                67_108_864 + u64::try_from(trial_index).unwrap() * 262_144
            } else {
                67_108_864
            };
            trials.push(json!({
                "trial_number": trial_index + 1,
                "mode": mode,
                "frame_sizes": PERFORMANCE_FIXED_FRAME_SIZES,
                "frames_per_size": PERFORMANCE_FRAMES_PER_SIZE,
                "duration_ns": duration_ns,
                "packets_per_second": rate.packets_per_second,
                "bytes_per_second": rate.bytes_per_second,
                "daemon_cpu_time_ns": if *mode == "baseline" { 0 } else { 10_000_000 },
                "peak_resident_memory_bytes": peak_rss,
                "packet_drop_delta": 0,
                "packet_error_delta": 0
            }));
        }
    }
    let mut value = json!({
        "schema_version": 1,
        "evidence_id": "ffeeddccbbaa99887766554433221100",
        "artifact_commit_sha": COMMIT_SHA,
        "package_version": "0.1.0",
        "architecture": "x86_64",
        "kernel_release": "6.12.0-test",
        "logical_cpu_count": 8,
        "veth_xdp_mode": "generic",
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": NOW_MS + 86_400_000,
        "warm_up_complete": true,
        "measurement_complete": true,
        "measurement_noisy": false,
        "host_identity_stable": true,
        "trials": trials,
        "medians": {
            "baseline": {"packets_per_second": 0, "bytes_per_second": 0},
            "pass_through": {"packets_per_second": 0, "bytes_per_second": 0},
            "observe": {"packets_per_second": 0, "bytes_per_second": 0}
        },
        "pass_through_baseline_ratio_permille": 0,
        "observe_baseline_ratio_permille": 0,
        "daemon_cpu_time_ns": 0,
        "daemon_cpu_permille": 0,
        "peak_resident_memory_bytes": 0,
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
    });
    refresh_aggregates(&mut value);
    value
}

fn set_mode_duration(value: &mut Value, mode: &str, duration_ns: u64) {
    for trial in value["trials"].as_array_mut().unwrap() {
        if trial["mode"] == mode {
            let rate = rate_for_duration(duration_ns);
            trial["duration_ns"] = json!(duration_ns);
            trial["packets_per_second"] = json!(rate.packets_per_second);
            trial["bytes_per_second"] = json!(rate.bytes_per_second);
        }
    }
}

fn set_observe_rss_growth(value: &mut Value, first: u64, fifth: u64) {
    for trial in value["trials"].as_array_mut().unwrap() {
        if trial["mode"] == "observe" {
            trial["peak_resident_memory_bytes"] = if trial["trial_number"] == 1 {
                json!(first)
            } else if trial["trial_number"] == 5 {
                json!(fifth)
            } else {
                json!(first)
            };
        } else {
            trial["peak_resident_memory_bytes"] = json!(first);
        }
    }
}

fn refresh_aggregates(value: &mut Value) {
    for (mode, field) in [
        (PerformanceModeV1::Baseline, "baseline"),
        (PerformanceModeV1::PassThrough, "pass_through"),
        (PerformanceModeV1::Observe, "observe"),
    ] {
        let name = match mode {
            PerformanceModeV1::Baseline => "baseline",
            PerformanceModeV1::PassThrough => "pass_through",
            PerformanceModeV1::Observe => "observe",
        };
        let mut rates = value["trials"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|trial| trial["mode"] == name)
            .map(|trial| {
                (
                    trial["packets_per_second"].as_u64().unwrap(),
                    trial["bytes_per_second"].as_u64().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        rates.sort_unstable();
        value["medians"][field] = json!({
            "packets_per_second": rates[2].0,
            "bytes_per_second": rates[2].1
        });
    }
    let baseline = value["medians"]["baseline"].clone();
    let pass = value["medians"]["pass_through"].clone();
    let observe = value["medians"]["observe"].clone();
    value["pass_through_baseline_ratio_permille"] = json!(conservative_ratio(&pass, &baseline));
    value["observe_baseline_ratio_permille"] = json!(conservative_ratio(&observe, &baseline));

    let (total_duration, total_cpu, peak, first, fifth) = {
        let trials = value["trials"].as_array().unwrap();
        let total_duration = trials
            .iter()
            .map(|trial| trial["duration_ns"].as_u64().unwrap() as u128)
            .sum::<u128>();
        let total_cpu = trials
            .iter()
            .map(|trial| trial["daemon_cpu_time_ns"].as_u64().unwrap() as u128)
            .sum::<u128>();
        let peak = trials
            .iter()
            .map(|trial| trial["peak_resident_memory_bytes"].as_u64().unwrap())
            .max()
            .unwrap();
        let first = trials
            .iter()
            .find(|trial| trial["mode"] == "observe" && trial["trial_number"] == 1)
            .unwrap()["peak_resident_memory_bytes"]
            .as_u64()
            .unwrap();
        let fifth = trials
            .iter()
            .find(|trial| trial["mode"] == "observe" && trial["trial_number"] == 5)
            .unwrap()["peak_resident_memory_bytes"]
            .as_u64()
            .unwrap();
        (total_duration, total_cpu, peak, first, fifth)
    };
    value["daemon_cpu_time_ns"] = json!(u64::try_from(total_cpu).unwrap());
    value["daemon_cpu_permille"] =
        json!(u16::try_from(total_cpu * 1_000 / total_duration).unwrap());
    value["peak_resident_memory_bytes"] = json!(peak);
    value["rss_growth_bytes"] = json!(fifth.saturating_sub(first));
}

fn conservative_ratio(measured: &Value, baseline: &Value) -> u16 {
    let packet_ratio = measured["packets_per_second"].as_u64().unwrap() as u128 * 1_000
        / baseline["packets_per_second"].as_u64().unwrap() as u128;
    let byte_ratio = measured["bytes_per_second"].as_u64().unwrap() as u128 * 1_000
        / baseline["bytes_per_second"].as_u64().unwrap() as u128;
    u16::try_from(packet_ratio.min(byte_ratio)).unwrap()
}

fn rate_for_duration(duration_ns: u64) -> PerformanceRateV1 {
    PerformanceRateV1 {
        packets_per_second: u64::try_from(SENT_PACKETS * 1_000_000_000 / duration_ns as u128)
            .unwrap(),
        bytes_per_second: u64::try_from(SENT_BYTES * 1_000_000_000 / duration_ns as u128).unwrap(),
    }
}
