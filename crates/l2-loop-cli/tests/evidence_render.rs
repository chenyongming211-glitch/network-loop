use l2_loop_agent::protocol::ControlResponse;
use l2_loop_cli::{OutputFormat, render_response};
use l2_loop_core::{
    AgentResult, AlertCode, AlertSeverity, DetectionState, EvidenceIntegrity, EvidenceListPageV1,
    EvidenceSummaryV1, EventId, InterfaceName,
};

fn summary() -> EvidenceSummaryV1 {
    EvidenceSummaryV1 {
        schema_version: 1,
        event_id: EventId::from_bytes([1; 16]),
        latest_revision: 2,
        interface: InterfaceName::new("l2h0123456789").unwrap(),
        ifindex: 42,
        interface_generation: 7,
        current_state: DetectionState::ExternalLoopSuspected,
        alert_code: AlertCode::ExternalLoopSuspected,
        severity: AlertSeverity::Notice,
        opened_at_unix_ms: 1_000,
        last_transition_at_unix_ms: 2_000,
        closed_at_unix_ms: None,
        bundle_bytes: 4_096,
        integrity: EvidenceIntegrity::Valid,
    }
}

#[test]
fn evidence_list_text_and_json_render_the_same_sanitized_page() {
    let page = EvidenceListPageV1 {
        items: vec![summary()],
        next_cursor: Some("cursor".to_owned()),
    };
    let text = render_response(
        ControlResponse::success(AgentResult::EvidenceList { page: page.clone() }),
        OutputFormat::Text,
    );
    let json = render_response(
        ControlResponse::success(AgentResult::EvidenceList { page }),
        OutputFormat::Json,
    );

    assert_eq!(text.exit_code, 0);
    assert!(text.stdout.contains("01010101010101010101010101010101"));
    assert!(text.stdout.contains("external_loop_suspected"));
    assert_eq!(json.exit_code, 0);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(value["items"][0]["latest_revision"], 2);
    for prohibited in ["source_mac", "destination_mac", "pin_path", "ownership"] {
        assert!(!text.stdout.contains(prohibited));
        assert!(!json.stdout.contains(prohibited));
    }
}
