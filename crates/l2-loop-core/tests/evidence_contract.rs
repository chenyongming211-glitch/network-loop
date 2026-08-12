use std::str::FromStr;

use l2_loop_core::{
    AlertCode, AlertSeverity, DetectionState, EventId, EvidenceCursor, EvidenceListQuery,
    EvidenceStatus, InterfaceName, EVIDENCE_LIST_DEFAULT_LIMIT, EVIDENCE_LIST_MAX_LIMIT,
    EVIDENCE_MAX_EVENT_BYTES, EVIDENCE_MAX_EVENTS, EVIDENCE_MAX_REVISION_BYTES,
    EVIDENCE_MAX_REVISIONS_PER_EVENT, EVIDENCE_MAX_STORE_BYTES, EVIDENCE_SCHEMA_VERSION,
    INCIDENT_OUTPUT_QUEUE_CAPACITY,
};

#[test]
fn event_id_is_exact_canonical_lower_hex_and_never_path_capable() {
    let text = "00112233445566778899aabbccddeeff";
    let id = EventId::from_str(text).unwrap();
    assert_eq!(id.to_string(), text);
    assert_eq!(id.bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{text}\""));
    assert_eq!(serde_json::from_str::<EventId>(&format!("\"{text}\"")).unwrap(), id);

    for invalid in [
        "", "00112233445566778899aabbccddeef", "00112233445566778899aabbccddeeff00",
        "00112233445566778899AABBCCDDEEFF", "../112233445566778899aabbccddeeff",
        "00112233445566778899aabbccddeef/", "00112233445566778899aabbccddeef.",
        "００１１２２３３４４５５６６７７８８９９ａａｂｂｃｃｄｄｅｅｆｆ",
    ] {
        assert!(EventId::from_str(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
fn incident_output_bounds_are_fixed_and_nonzero() {
    assert_eq!(EVIDENCE_SCHEMA_VERSION, 1);
    assert_eq!(EVIDENCE_MAX_STORE_BYTES, 1_073_741_824);
    assert_eq!(EVIDENCE_MAX_EVENTS, 1_000);
    assert_eq!(EVIDENCE_MAX_REVISIONS_PER_EVENT, 16);
    assert_eq!(EVIDENCE_MAX_REVISION_BYTES, 1_048_576);
    assert_eq!(EVIDENCE_MAX_EVENT_BYTES, 16_777_216);
    assert_eq!(INCIDENT_OUTPUT_QUEUE_CAPACITY, 32);
    assert_eq!(EVIDENCE_LIST_DEFAULT_LIMIT, 50);
    assert_eq!(EVIDENCE_LIST_MAX_LIMIT, 200);
}

#[test]
fn passive_states_have_fixed_alert_severity_without_confirmed_loop() {
    let cases = [
        (DetectionState::IngressStormConfirmed, AlertCode::StormConfirmed, AlertSeverity::Notice),
        (DetectionState::EgressStormConfirmed, AlertCode::StormConfirmed, AlertSeverity::Notice),
        (DetectionState::BidirectionalStormConfirmed, AlertCode::StormConfirmed, AlertSeverity::Notice),
        (DetectionState::ExternalLoopSuspected, AlertCode::ExternalLoopSuspected, AlertSeverity::Notice),
        (DetectionState::ExternalLoopHighConfidence, AlertCode::ExternalLoopHighConfidence, AlertSeverity::Warning),
        (DetectionState::Cooldown, AlertCode::IncidentCooldown, AlertSeverity::Information),
        (DetectionState::Normal, AlertCode::IncidentClosed, AlertSeverity::Information),
    ];
    for &(state, code, severity) in &cases {
        assert_eq!(AlertCode::for_state(state).unwrap(), code);
        assert_eq!(code.severity(), severity);
    }
    assert!(AlertCode::for_state(DetectionState::WarmingUp).is_none());
    let serialized = serde_json::to_string(&(cases, EvidenceStatus::Stored)).unwrap();
    for prohibited in ["confirmed_loop", "loop_confirmed", "error"] {
        assert!(!serialized.contains(prohibited));
    }
}

#[test]
fn evidence_list_query_enforces_limits_and_cursor_filter_binding() {
    let interface = InterfaceName::new("l2h0123456789").unwrap();
    let id = EventId::from_str("00112233445566778899aabbccddeeff").unwrap();
    let cursor = EvidenceCursor::new(Some(&interface), 1_234_567, id);
    let encoded = cursor.to_string();
    assert_eq!(EvidenceCursor::parse_for(&encoded, Some(&interface)).unwrap(), cursor);
    assert!(EvidenceCursor::parse_for(&encoded, None).is_err());
    assert!(EvidenceCursor::parse_for("../cursor", Some(&interface)).is_err());

    let query = EvidenceListQuery::new(Some(interface.clone()), None, Some(cursor)).unwrap();
    assert_eq!(query.limit, EVIDENCE_LIST_DEFAULT_LIMIT);
    assert!(EvidenceListQuery::new(Some(interface.clone()), Some(1), None).is_ok());
    assert!(EvidenceListQuery::new(Some(interface.clone()), Some(200), None).is_ok());
    assert!(EvidenceListQuery::new(Some(interface.clone()), Some(0), None).is_err());
    assert!(EvidenceListQuery::new(Some(interface), Some(201), None).is_err());
}

#[test]
fn public_contract_source_has_no_raw_identity_or_active_action() {
    let source = include_str!("../src/evidence.rs");
    for prohibited in [
        "source_mac", "destination_mac", "packet_bytes", "raw_fingerprint", "pcap",
        "ConfirmedLoop", "LoopConfirmed", "XDP_DROP", "TC_ACT_SHOT",
    ] {
        assert!(!source.contains(prohibited), "prohibited evidence API: {prohibited}");
    }
}
