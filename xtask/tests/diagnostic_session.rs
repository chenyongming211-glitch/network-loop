use SessionStep::*;
use xtask::diagnostic_session::{DiagnosticBackend, SessionStep, run_session, validate_request};

fn request() -> serde_json::Value {
    serde_json::json!({"schema_version":1,"run_id":"0123456789abcdef0123456789abcdef",
        "profile":"counters","ifindex":41,"peer_ifindex":42,
        "host_mac":"02:00:00:00:00:01","peer_mac":"02:00:00:00:00:02",
        "namespace_device":4,"namespace_inode":123,"duration_seconds":30})
}

#[test]
fn accepts_only_bounded_generated_identity() {
    assert!(validate_request(&serde_json::to_vec(&request()).unwrap()).is_ok());
    for (key, value) in [
        ("schema_version", serde_json::json!(2)),
        ("run_id", serde_json::json!("../physical")),
        ("profile", serde_json::json!("production")),
        ("ifindex", serde_json::json!(0)),
        ("peer_ifindex", serde_json::json!(0)),
        ("host_mac", serde_json::json!("ff:ff:ff:ff:ff:ff")),
        ("peer_mac", serde_json::json!("00:00:00:00:00:00")),
        ("namespace_inode", serde_json::json!(0)),
        ("duration_seconds", serde_json::json!(0)),
        ("duration_seconds", serde_json::json!(121)),
        ("interface", serde_json::json!("eth0")),
    ] {
        let mut value_request = request();
        value_request[key] = value;
        assert!(
            validate_request(&serde_json::to_vec(&value_request).unwrap()).is_err(),
            "{key}"
        );
    }
    assert!(validate_request(br#"{"schema_version":1,"schema_version":1}"#).is_err());
    assert!(validate_request(&vec![b' '; 65537]).is_err());
}

struct KernelBoundary {
    faults: Vec<SessionStep>,
    calls: Vec<SessionStep>,
}

impl DiagnosticBackend for KernelBoundary {
    fn perform(&mut self, step: SessionStep) -> Result<(), String> {
        self.calls.push(step);
        if self.faults.contains(&step) {
            Err(format!("{step:?}"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn successful_session_cleans_in_reverse_before_finishing_lease() {
    let mut io = KernelBoundary {
        faults: vec![],
        calls: vec![],
    };
    assert_eq!(run_session(&mut io), Ok(()));
    assert_eq!(
        io.calls,
        [
            Prepare, AttachXdp, AttachTc, Verify, Activate, Observe, DetachTc, DetachXdp, Release,
            Finish
        ]
    );
}

#[test]
fn every_forward_fault_stops_forward_work_and_attempts_all_precise_cleanup() {
    let forward = [Prepare, AttachXdp, AttachTc, Verify, Activate, Observe];
    for (index, fault) in forward.iter().enumerate() {
        let mut io = KernelBoundary {
            faults: vec![*fault],
            calls: vec![],
        };
        let error = run_session(&mut io).unwrap_err();
        assert_eq!(error.primary, Some(format!("{fault:?}")));
        assert!(error.cleanup.is_empty());
        let expected = forward[..=index]
            .iter()
            .copied()
            .chain([DetachTc, DetachXdp, Release, Finish])
            .collect::<Vec<_>>();
        assert_eq!(io.calls, expected);
    }
}

#[test]
fn cleanup_faults_are_all_reported_and_lease_is_retained() {
    let mut io = KernelBoundary {
        faults: vec![Observe, DetachTc, DetachXdp, Release],
        calls: vec![],
    };
    let error = run_session(&mut io).unwrap_err();
    assert_eq!(error.primary.as_deref(), Some("Observe"));
    assert_eq!(error.cleanup, ["DetachTc", "DetachXdp", "Release"]);
    assert!(!io.calls.contains(&Finish));
}
