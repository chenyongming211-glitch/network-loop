use std::{cell::RefCell, rc::Rc};

use l2_loop_agent::{PlatformInspector, PortError, PreflightService};
use l2_loop_core::{
    AgentResult, AttachmentState, BpfInspection, FindingSeverity, InterfaceInspection,
    InterfaceKind, InterfaceName, InterfaceRef, KernelInspection, MemlockInspection,
    PF_BOND_NO_ACTIVE_SLAVE, PF_INTERFACE_MISSING, PF_INTERFACE_UNSUPPORTED,
    PF_KERNEL_CAPABILITY, PF_LIVE_INTERFACE, PF_MEMLOCK_TOO_LOW, PF_PIN_ROOT_FOREIGN,
    PF_TC_HANDLE_COLLISION, PF_TC_STATE_UNKNOWN, PF_XDP_OCCUPIED, PF_XDP_STATE_UNKNOWN,
    PinRootState, PreflightDecision, PreflightFinding, PreflightReport,
};

#[test]
fn forwards_the_explicit_interface_and_rebuilds_report_invariants() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut report = valid_report("veth-test");
    report.decision = PreflightDecision::Ready;
    report.findings = vec![
        PreflightFinding::information("PF_Z_INFORMATION", "information"),
        PreflightFinding::warning("PF_B_WARNING", "warning"),
        PreflightFinding::blocker(PF_XDP_OCCUPIED, "XDP hook is occupied"),
        PreflightFinding::blocker(PF_INTERFACE_UNSUPPORTED, "interface is unsupported"),
    ];
    let inspector = FakeInspector::ok(calls.clone(), report);
    let mut service = PreflightService::new(inspector);
    let requested = InterfaceName::new("veth-test").unwrap();

    let report = extract_report(service.execute(&requested).unwrap());

    assert_eq!(calls.borrow().as_slice(), [requested]);
    assert_eq!(report.decision, PreflightDecision::Blocked);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| (finding.severity, finding.code.as_str()))
            .collect::<Vec<_>>(),
        [
            (FindingSeverity::Blocker, PF_INTERFACE_UNSUPPORTED),
            (FindingSeverity::Blocker, PF_XDP_OCCUPIED),
            (FindingSeverity::Warning, "PF_B_WARNING"),
            (FindingSeverity::Information, "PF_Z_INFORMATION"),
        ]
    );
}

#[test]
fn preserves_every_stable_blocker_code() {
    let codes = [
        PF_INTERFACE_MISSING,
        PF_INTERFACE_UNSUPPORTED,
        PF_BOND_NO_ACTIVE_SLAVE,
        PF_XDP_STATE_UNKNOWN,
        PF_XDP_OCCUPIED,
        PF_TC_STATE_UNKNOWN,
        PF_TC_HANDLE_COLLISION,
        PF_PIN_ROOT_FOREIGN,
        PF_MEMLOCK_TOO_LOW,
        PF_KERNEL_CAPABILITY,
        PF_LIVE_INTERFACE,
    ];
    let mut report = valid_report("veth-test");
    report.findings = codes
        .iter()
        .rev()
        .map(|code| PreflightFinding::blocker(*code, "blocked"))
        .collect();
    report.decision = PreflightDecision::Ready;
    let inspector = FakeInspector::ok(Rc::new(RefCell::new(Vec::new())), report);
    let mut service = PreflightService::new(inspector);

    let report = extract_report(
        service
            .execute(&InterfaceName::new("veth-test").unwrap())
            .unwrap(),
    );
    let mut expected = codes;
    expected.sort_unstable();

    assert_eq!(report.decision, PreflightDecision::Blocked);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn rejects_a_report_for_a_different_requested_interface() {
    let inspector = FakeInspector::ok(
        Rc::new(RefCell::new(Vec::new())),
        valid_report("other-veth"),
    );
    let mut service = PreflightService::new(inspector);

    assert_eq!(
        service.execute(&InterfaceName::new("veth-test").unwrap()),
        Err(PortError::InvalidReport(
            "requested interface does not match report".into(),
        ))
    );
}

#[test]
fn allows_a_zero_ifindex_when_the_report_contains_the_missing_interface_blocker() {
    let mut report = valid_report("missing-veth");
    report.interface.requested.ifindex = 0;
    report.interface.isolated = false;
    report.findings = vec![PreflightFinding::blocker(
        PF_INTERFACE_MISSING,
        "requested interface does not exist",
    )];
    let inspector = FakeInspector::ok(Rc::new(RefCell::new(Vec::new())), report);
    let mut service = PreflightService::new(inspector);

    let report = extract_report(
        service
            .execute(&InterfaceName::new("missing-veth").unwrap())
            .unwrap(),
    );

    assert_eq!(report.interface.requested.ifindex, 0);
    assert_eq!(report.decision, PreflightDecision::Blocked);
    assert_eq!(report.findings[0].code, PF_INTERFACE_MISSING);
}

#[test]
fn rejects_structurally_contradictory_reports() {
    let mut isolated_and_live = valid_report("veth-test");
    isolated_and_live.interface.live_shared = true;

    let mut bond_without_details = valid_report("veth-test");
    bond_without_details.interface.kind = InterfaceKind::Bond;

    let mut empty_code = valid_report("veth-test");
    empty_code.findings = vec![PreflightFinding::warning("   ", "warning")];

    let mut empty_message = valid_report("veth-test");
    empty_message.findings = vec![PreflightFinding::warning("PF_WARNING", "   ")];

    for (report, expected) in [
        (
            isolated_and_live,
            "interface cannot be both isolated and live/shared",
        ),
        (bond_without_details, "bond interface is missing bond details"),
        (empty_code, "finding code must not be empty"),
        (empty_message, "finding message must not be empty"),
    ] {
        let inspector = FakeInspector::ok(Rc::new(RefCell::new(Vec::new())), report);
        let mut service = PreflightService::new(inspector);

        assert_eq!(
            service.execute(&InterfaceName::new("veth-test").unwrap()),
            Err(PortError::InvalidReport(expected.into()))
        );
    }
}

#[test]
fn propagates_inspector_errors_without_using_attachment_ports() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let expected = PortError::Adapter("read-only inspection failed".into());
    let inspector = FakeInspector::error(calls.clone(), expected.clone());
    let mut service = PreflightService::new(inspector);
    let requested = InterfaceName::new("veth-test").unwrap();

    assert_eq!(service.execute(&requested), Err(expected));
    assert_eq!(calls.borrow().as_slice(), [requested]);
}

struct FakeInspector {
    calls: Rc<RefCell<Vec<InterfaceName>>>,
    outcome: Result<PreflightReport, PortError>,
}

impl FakeInspector {
    fn ok(calls: Rc<RefCell<Vec<InterfaceName>>>, report: PreflightReport) -> Self {
        Self {
            calls,
            outcome: Ok(report),
        }
    }

    fn error(calls: Rc<RefCell<Vec<InterfaceName>>>, error: PortError) -> Self {
        Self {
            calls,
            outcome: Err(error),
        }
    }
}

impl PlatformInspector for FakeInspector {
    fn inspect(&mut self, interface: &InterfaceName) -> Result<PreflightReport, PortError> {
        self.calls.borrow_mut().push(interface.clone());
        self.outcome.clone()
    }
}

fn extract_report(result: AgentResult) -> PreflightReport {
    match result {
        AgentResult::Preflight { report } => report,
        other => panic!("expected preflight result, got {other:?}"),
    }
}

fn valid_report(name: &str) -> PreflightReport {
    PreflightReport::new(
        InterfaceInspection {
            requested: InterfaceRef {
                name: InterfaceName::new(name).unwrap(),
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
        Vec::new(),
    )
}
