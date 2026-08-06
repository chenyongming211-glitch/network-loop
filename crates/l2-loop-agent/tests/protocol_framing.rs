use std::time::Duration;

use l2_loop_agent::protocol::{
    ControlRequest, ControlResponse, MAX_PAYLOAD_LEN, ProtocolError, decode_request,
    decode_response, encode_request, encode_response,
};
use l2_loop_core::{
    AgentCommand, AgentResult, InterfaceName, PolicyRequest, ProbeRequest, ProbeScope, TrafficClass,
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
