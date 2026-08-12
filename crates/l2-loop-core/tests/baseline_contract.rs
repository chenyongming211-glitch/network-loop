use l2_loop_core::{
    BASELINE_BYTE_NOISE_FLOOR_BPS, BASELINE_CAPACITY, BASELINE_METRIC_COUNT,
    BASELINE_MINIMUM_SAMPLES, BASELINE_PACKET_NOISE_FLOOR_PPS, BASELINE_SOURCE_WINDOW_MS,
    BASELINE_SUBJECT_COUNT, BASELINE_SUBJECTS_PER_HOOK, BaselineMetric, BaselineState,
    BaselineSubject, HookRole, OBSERVATION_SCHEMA_VERSION, RateIdentity, TrafficClass,
};

#[test]
fn fixed_baseline_contract_is_stable() {
    assert_eq!(BASELINE_SOURCE_WINDOW_MS, 10_000);
    assert_eq!(BASELINE_CAPACITY, 300);
    assert_eq!(BASELINE_MINIMUM_SAMPLES, 60);
    assert_eq!(BASELINE_PACKET_NOISE_FLOOR_PPS, 10);
    assert_eq!(BASELINE_BYTE_NOISE_FLOOR_BPS, 16_384);
    assert_eq!(BASELINE_SUBJECTS_PER_HOOK, 8);
    assert_eq!(BASELINE_SUBJECT_COUNT, 16);
    assert_eq!(BASELINE_METRIC_COUNT, 32);
    assert_eq!(OBSERVATION_SCHEMA_VERSION, 3);
}

#[test]
fn learning_report_has_fixed_subject_order_and_null_statistics() {
    let identity = RateIdentity::new(7, 11).unwrap();
    let report = l2_loop_core::BaselineReport::learning(identity, 1_000);

    assert_eq!(report.state, BaselineState::Learning);
    assert_eq!(report.evaluated_at_unix_ms, Some(1_000));
    assert_eq!(report.source_end_unix_ms, None);
    assert_eq!(report.last_successful_evaluation_at_unix_ms, None);
    assert_eq!(report.last_error_code, None);
    assert_eq!(report.learning_subject_count, 16);
    assert_eq!(report.elevated_metric_count, 0);
    assert_eq!(report.subjects.len(), BASELINE_SUBJECT_COUNT);
    assert!(report.validate().is_ok());

    let expected_subjects = [
        BaselineSubject::Total,
        BaselineSubject::TrafficClass {
            traffic_class: TrafficClass::L2Broadcast,
        },
        BaselineSubject::TrafficClass {
            traffic_class: TrafficClass::Ipv4Multicast,
        },
        BaselineSubject::TrafficClass {
            traffic_class: TrafficClass::Ipv6Multicast,
        },
        BaselineSubject::TrafficClass {
            traffic_class: TrafficClass::OtherL2Multicast,
        },
        BaselineSubject::TrafficClass {
            traffic_class: TrafficClass::LinkLocalControl,
        },
        BaselineSubject::TrafficClass {
            traffic_class: TrafficClass::UnicastOrUnclassified,
        },
        BaselineSubject::ParseErrors,
    ];

    for (hook_index, expected_hook) in [
        HookRole::ExternalXdpIngress,
        HookRole::PhysicalTcEgress,
    ]
    .into_iter()
    .enumerate()
    {
        for (subject_index, expected_subject) in expected_subjects.iter().enumerate() {
            let subject = &report.subjects[hook_index * BASELINE_SUBJECTS_PER_HOOK + subject_index];
            assert_eq!(subject.hook, expected_hook);
            assert_eq!(&subject.subject, expected_subject);
            assert_eq!(subject.state, BaselineState::Learning);
            assert_eq!(subject.sample_count, 0);
            assert_eq!(subject.latest_accepted_at_unix_ms, None);
            for metric in [&subject.packets, &subject.bytes] {
                assert_eq!(metric.current, None);
                assert_eq!(metric.median, None);
                assert_eq!(metric.mad, None);
                assert_eq!(metric.threshold, None);
                assert_eq!(metric.ratio_milli, None);
                assert_eq!(metric.elevated, None);
            }
        }
    }
}

#[test]
fn serialized_names_and_tagged_subjects_are_stable() {
    assert_eq!(serde_json::to_string(&BaselineState::WithinBaseline).unwrap(), "\"within_baseline\"");
    assert_eq!(serde_json::to_string(&BaselineMetric::Packets).unwrap(), "\"packets\"");
    assert_eq!(
        serde_json::to_value(BaselineSubject::Total).unwrap(),
        serde_json::json!({"kind": "total"})
    );
    assert_eq!(
        serde_json::to_value(BaselineSubject::TrafficClass {
            traffic_class: TrafficClass::Ipv6Multicast,
        })
        .unwrap(),
        serde_json::json!({"kind": "traffic_class", "traffic_class": "ipv6_multicast"})
    );
}

#[test]
fn interface_priority_never_hides_unavailable_or_elevated() {
    let identity = RateIdentity::new(7, 11).unwrap();
    let mut report = l2_loop_core::BaselineReport::learning(identity, 1_000);
    report.subjects[0].state = BaselineState::WithinBaseline;
    assert_eq!(l2_loop_core::aggregate_baseline_state(&report.subjects), BaselineState::Learning);

    report.subjects[1].state = BaselineState::Elevated;
    assert_eq!(l2_loop_core::aggregate_baseline_state(&report.subjects), BaselineState::Elevated);

    report.subjects[2].state = BaselineState::Unavailable;
    assert_eq!(l2_loop_core::aggregate_baseline_state(&report.subjects), BaselineState::Unavailable);
}
