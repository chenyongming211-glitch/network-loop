use l2_loop_agent::protocol::{ControlResponse, ERROR_INTERNAL};
use l2_loop_cli::{EXIT_BLOCKED, EXIT_FAILURE, EXIT_SUCCESS, OutputFormat, render_response};
use l2_loop_core::{
    AgentResult, AttachmentState, BpfInspection, InterfaceInspection, InterfaceKind, InterfaceName,
    InterfaceRef, KernelInspection, MemlockInspection, PF_LIVE_INTERFACE, PinRootState,
    PreflightFinding, PreflightReport,
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
