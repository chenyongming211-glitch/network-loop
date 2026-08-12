#![cfg(target_os = "linux")]

use std::io;

use l2_loop_agent::{AlertIo, AlertPublishOutcome, AlertSink, LinuxAlertSink, SanitizedAlertV1};
use l2_loop_core::{
    AlertCode, AlertSeverity, DetectionState, DetectionTransitionReason, EventId, EvidenceStatus,
    InterfaceName,
};

#[derive(Default)]
struct FakeIo {
    journal: Vec<Vec<u8>>,
    stderr: Vec<Vec<u8>>,
    fail_journal: bool,
}

impl AlertIo for FakeIo {
    fn send_journal(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.journal.push(bytes.to_vec());
        if self.fail_journal {
            Err(io::Error::other("journal unavailable"))
        } else {
            Ok(())
        }
    }

    fn write_stderr(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stderr.push(bytes.to_vec());
        Ok(())
    }
}

fn alert(revision: u64, status: EvidenceStatus) -> SanitizedAlertV1 {
    SanitizedAlertV1 {
        event_id: EventId::from_bytes([1; 16]),
        evidence_status: status,
        revision,
        transition_sequence: revision,
        code: AlertCode::ExternalLoopSuspected,
        severity: AlertSeverity::Notice,
        previous_state: DetectionState::IngressStormConfirmed,
        current_state: DetectionState::ExternalLoopSuspected,
        transition_reason: DetectionTransitionReason::RelationshipSuspected,
        interface: InterfaceName::new("l2h0123456789").unwrap(),
        ifindex: 42,
        generation: 7,
        message: "passive L2 loop relationship suspected".to_owned(),
    }
}

#[test]
fn journald_payload_contains_only_fixed_sanitized_fields() {
    let mut sink = LinuxAlertSink::new(FakeIo::default());

    assert_eq!(
        sink.publish(&alert(1, EvidenceStatus::Stored)).unwrap(),
        AlertPublishOutcome::Journald
    );
    let io = sink.into_inner();
    assert_eq!(io.journal.len(), 1);
    assert!(io.stderr.is_empty());
    let payload = String::from_utf8(io.journal[0].clone()).unwrap();
    for expected in [
        "MESSAGE=passive L2 loop relationship suspected",
        "L2_LOOP_EVENT_ID=01010101010101010101010101010101",
        "L2_LOOP_EVIDENCE_STATUS=stored",
        "L2_LOOP_REVISION=1",
        "L2_LOOP_INTERFACE=l2h0123456789",
        "PRIORITY=5",
    ] {
        assert!(payload.contains(expected), "missing {expected}");
    }
    for forbidden in [
        "source_mac",
        "destination_mac",
        "fingerprint_value",
        "pin_path",
        "ownership",
        "error_chain",
        "pcap",
    ] {
        assert!(!payload.to_ascii_lowercase().contains(forbidden));
    }
}

#[test]
fn first_journal_failure_permanently_switches_to_one_json_line_per_alert() {
    let mut sink = LinuxAlertSink::new(FakeIo {
        fail_journal: true,
        ..FakeIo::default()
    });

    assert_eq!(
        sink.publish(&alert(1, EvidenceStatus::Unavailable))
            .unwrap(),
        AlertPublishOutcome::StderrJson
    );
    assert_eq!(
        sink.publish(&alert(2, EvidenceStatus::Stored)).unwrap(),
        AlertPublishOutcome::StderrJson
    );
    let io = sink.into_inner();
    assert_eq!(io.journal.len(), 1);
    assert_eq!(io.stderr.len(), 2);
    for line in io.stderr {
        assert_eq!(line.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert!(value.get("event_id").is_some());
        assert!(value.get("error").is_none());
    }
}

#[test]
fn output_health_warning_is_deduplicated_and_never_has_an_event_identity() {
    let mut sink = LinuxAlertSink::new(FakeIo {
        fail_journal: true,
        ..FakeIo::default()
    });

    assert!(sink.publish_output_health("OUTPUT_STORE_UNAVAILABLE"));
    assert!(!sink.publish_output_health("OUTPUT_STORE_UNAVAILABLE"));
    let io = sink.into_inner();
    assert_eq!(io.stderr.len(), 1);
    let line = String::from_utf8(io.stderr[0].clone()).unwrap();
    assert!(line.contains("OUTPUT_STORE_UNAVAILABLE"));
    assert!(!line.contains("event_id"));
    assert!(!line.contains("revision"));
}
