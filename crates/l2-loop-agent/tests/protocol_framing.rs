use std::time::Duration;

use l2_loop_agent::protocol::{
    ControlRequest, ControlResponse, MAX_PAYLOAD_LEN, ProtocolError, decode_request,
    decode_response, encode_request, encode_response,
};
use l2_loop_core::{
    AgentCommand, AgentResult, ClassObservation, ClassRate, DetailedRateWindow, HookObservation,
    HookRate, HookRole, InterfaceName, OBSERVED_CLASS_COUNT, ObservationCounters,
    ObservationSnapshot, PolicyRequest, ProbeRequest, ProbeScope, RateCounters, RateWindowState,
    SamplingStatus, TrafficClass, VlanVisibility,
};

#[test]
fn request_frame_uses_big_endian_length_and_stable_tags() {
    let request = ControlRequest::new(AgentCommand::Observe {
        interface: InterfaceName::new("bond0").unwrap(),
    });
    let frame = encode_request(&request).unwrap();

    let payload_len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    assert_eq!(payload_len, frame.len() - 4);

    let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();
    assert_eq!(json["protocol_version"], 1);
    assert_eq!(json["kind"], "observe");
    assert_eq!(decode_request(&frame).unwrap(), request);
}

#[test]
fn every_request_variant_round_trips() {
    let interface = InterfaceName::new("bond0").unwrap();
    let probe = ProbeRequest::new(
        "bond0",
        ProbeScope::External,
        Some(100),
        Duration::from_secs(2),
    )
    .unwrap();
    let policy = PolicyRequest::new(
        "bond0",
        Some(100),
        TrafficClass::L2Broadcast,
        Some(1_000),
        None,
        Duration::from_secs(60),
    )
    .unwrap();

    let commands = [
        AgentCommand::Observe {
            interface: interface.clone(),
        },
        AgentCommand::Status {
            interface: Some(interface.clone()),
        },
        AgentCommand::Probe { request: probe },
        AgentCommand::ApplyPolicy { request: policy },
        AgentCommand::DisablePolicy {
            rule_id: "rule-1".into(),
        },
        AgentCommand::EvidenceList {
            interface: Some(interface),
        },
        AgentCommand::EvidenceShow {
            evidence_id: "evidence-1".into(),
        },
    ];

    for command in commands {
        let request = ControlRequest::new(command);
        let frame = encode_request(&request).unwrap();
        assert_eq!(decode_request(&frame).unwrap(), request);
    }
}

#[test]
fn response_round_trips_with_stable_success_tag() {
    let response = ControlResponse::success(AgentResult::Accepted);
    let frame = encode_response(&response).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();

    assert_eq!(json["protocol_version"], 1);
    assert_eq!(json["kind"], "success");
    assert_eq!(decode_response(&frame).unwrap(), response);
}

#[test]
fn schema_two_observation_round_trips_inside_protocol_one() {
    let response = ControlResponse::success(AgentResult::Observation {
        snapshot: observation(),
    });
    let frame = encode_response(&response).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();

    assert_eq!(json["protocol_version"], 1);
    assert_eq!(json["kind"], "success");
    assert_eq!(json["result"]["kind"], "observation");
    assert_eq!(json["result"]["snapshot"]["schema_version"], 2);
    assert_eq!(
        json["result"]["snapshot"]["rate_windows"][0]["elapsed_ns"],
        1_000_000_000_u64
    );
    assert_eq!(
        json["result"]["snapshot"]["rate_windows"][0]["hooks"][0]["total"]
            ["packet_delta"],
        7
    );
    assert_eq!(
        json["result"]["snapshot"]["rate_windows"][0]["hooks"][0]["total"]
            ["packets_per_second"],
        7
    );
    assert!(json["result"]["snapshot"]["rate_windows"][1]["hooks"].is_null());
    assert!(json["result"]["snapshot"]["rate_windows"][2]["elapsed_ns"].is_null());
    assert_eq!(decode_response(&frame).unwrap(), response);
}

#[test]
fn rejects_oversized_truncated_and_trailing_frames() {
    let oversized = ((MAX_PAYLOAD_LEN + 1) as u32).to_be_bytes();
    assert!(matches!(
        decode_request(&oversized),
        Err(ProtocolError::PayloadTooLarge { .. })
    ));

    assert!(matches!(
        decode_request(&[0, 0, 0]),
        Err(ProtocolError::MissingLengthPrefix)
    ));

    let request = ControlRequest::new(AgentCommand::Status { interface: None });
    let mut frame = encode_request(&request).unwrap();
    frame.pop();
    assert!(matches!(
        decode_request(&frame),
        Err(ProtocolError::LengthMismatch { .. })
    ));

    let mut frame = encode_request(&request).unwrap();
    frame.push(0);
    assert!(matches!(
        decode_request(&frame),
        Err(ProtocolError::LengthMismatch { .. })
    ));
}

#[test]
fn rejects_invalid_json_unknown_kind_and_protocol_version() {
    let invalid_utf8 = frame(&[0xff]);
    assert!(matches!(
        decode_request(&invalid_utf8),
        Err(ProtocolError::InvalidJson(_))
    ));

    let unknown_kind = frame(br#"{"protocol_version":1,"kind":"repeat_probe"}"#);
    assert!(matches!(
        decode_request(&unknown_kind),
        Err(ProtocolError::InvalidJson(_))
    ));

    let wrong_version = frame(br#"{"protocol_version":2,"kind":"status","interface":null}"#);
    assert!(matches!(
        decode_request(&wrong_version),
        Err(ProtocolError::UnsupportedVersion(2))
    ));
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
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
    ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        41,
        7,
        1_786_300_000_000,
        VlanVisibility::VerifiedVisible,
        [
            observation_hook(HookRole::ExternalXdpIngress),
            observation_hook(HookRole::PhysicalTcEgress),
        ],
        SamplingStatus::default(),
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
            non_ready_window(10_000, RateWindowState::WarmingUp, 1_000),
            non_ready_window(60_000, RateWindowState::Stale, 12_000),
        ],
    )
    .unwrap()
}

fn observation_hook(role: HookRole) -> HookObservation {
    HookObservation {
        role,
        total: ObservationCounters {
            packets: 21,
            bytes: 1_260,
        },
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

fn non_ready_window(
    window_ms: u64,
    state: RateWindowState,
    coverage_ms: u64,
) -> DetailedRateWindow {
    DetailedRateWindow {
        window_ms,
        state,
        coverage_ms,
        elapsed_ns: None,
        start_unix_ms: None,
        end_unix_ms: None,
        hooks: None,
    }
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
