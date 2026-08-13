use std::{cell::RefCell, rc::Rc};

use l2_loop_agent::{
    DeploymentIoError, DeploymentPlatformInspector, PlatformInspector, PortError,
    linux::deployment_platform::{
        DeploymentCandidateSource, DeploymentConsumerSnapshotV1, DeploymentLinkSnapshotV1,
        LinuxDeploymentPlatformInspector,
    },
};
use l2_loop_core::{
    AttachmentState, BondInspection, BondMode, BpfInspection, DeploymentAuthorizationV1, Direction,
    InterfaceInspection, InterfaceKind, InterfaceName, InterfaceRef, KernelInspection,
    MemlockInspection, PF_INTERFACE_UNSUPPORTED, PF_LIVE_INTERFACE, PinRootState, PreflightFinding,
    PreflightReport, TcAttachment,
};

#[test]
fn exact_physical_empty_fixture_produces_one_sanitized_snapshot() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let preflight = FakePreflight::new(calls.clone(), physical_preflight());
    let source = FakeCandidate::passing(calls.clone());
    let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

    let snapshot = inspector
        .inspect_authorized_interface(&authorization())
        .unwrap();

    assert_eq!(snapshot.interface_name.as_str(), "spare0");
    assert_eq!(snapshot.ifindex, 7);
    assert_eq!(snapshot.kind, InterfaceKind::Physical);
    assert!(snapshot.administrative_up);
    assert!(snapshot.operational_up);
    assert_eq!(snapshot.master_ifindex, None);
    assert!(!snapshot.tc_clsact_present);
    assert!(!snapshot.address_present);
    assert!(!snapshot.route_present);
    assert!(!snapshot.neighbor_present);
    assert!(!snapshot.service_present);
    assert!(!snapshot.other_consumer_present);
    assert_eq!(snapshot.host.architecture, "x86_64");
    assert_eq!(snapshot.host.kernel_release, "6.12.0-test");
    assert_eq!(snapshot.host.logical_cpu_count, 8);
    assert_eq!(
        calls.borrow().as_slice(),
        [
            "identity",
            "preflight:spare0",
            "consumers:spare0:7",
            "identity",
        ]
    );
}

#[test]
fn authorization_name_or_ifindex_mismatch_stops_before_later_collection() {
    for first in [
        DeploymentLinkSnapshotV1 {
            name: InterfaceName::new("other0").unwrap(),
            ..physical_link()
        },
        DeploymentLinkSnapshotV1 {
            ifindex: 8,
            ..physical_link()
        },
    ] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let preflight = FakePreflight::new(calls.clone(), physical_preflight());
        let source = FakeCandidate::with_links(calls.clone(), first.clone(), first);
        let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

        assert_eq!(
            inspector.inspect_authorized_interface(&authorization()),
            Err(DeploymentIoError::Unavailable)
        );
        assert_eq!(calls.borrow().as_slice(), ["identity"]);
    }
}

#[test]
fn mixed_or_changing_identity_fails_closed() {
    let mutations: [fn(&mut DeploymentLinkSnapshotV1); 7] = [
        |link| link.name = InterfaceName::new("other0").unwrap(),
        |link| link.ifindex = 8,
        |link| link.kind = InterfaceKind::Veth,
        |link| link.administrative_up = false,
        |link| link.operational_up = false,
        |link| link.master_ifindex = Some(19),
        |link| link.peer_or_namespace_relation_present = true,
    ];

    for mutate in mutations {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let preflight = FakePreflight::new(calls.clone(), physical_preflight());
        let first = physical_link();
        let mut second = first.clone();
        mutate(&mut second);
        let source = FakeCandidate::with_links(calls, first, second);
        let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

        assert_eq!(
            inspector.inspect_authorized_interface(&authorization()),
            Err(DeploymentIoError::Unavailable)
        );
    }
}

#[test]
fn preflight_identity_must_describe_the_same_fresh_link() {
    let mutations: [fn(&mut InterfaceInspection); 6] = [
        |interface| interface.requested.name = InterfaceName::new("other0").unwrap(),
        |interface| interface.requested.ifindex = 8,
        |interface| interface.kind = InterfaceKind::Bridge,
        |interface| interface.admin_up = false,
        |interface| interface.oper_up = false,
        |interface| {
            interface.master = Some(InterfaceRef {
                name: InterfaceName::new("bond0").unwrap(),
                ifindex: 19,
            })
        },
    ];

    for mutate in mutations {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut report = physical_preflight();
        mutate(&mut report.interface);
        let preflight = FakePreflight::new(calls.clone(), report);
        let source = FakeCandidate::passing(calls);
        let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

        assert_eq!(
            inspector.inspect_authorized_interface(&authorization()),
            Err(DeploymentIoError::Unavailable)
        );
    }
}

#[test]
fn unsupported_link_shapes_are_preserved_without_fallback_classification() {
    for kind in [
        InterfaceKind::Bond,
        InterfaceKind::Bridge,
        InterfaceKind::OvsInternal,
        InterfaceKind::Tap,
        InterfaceKind::Veth,
        InterfaceKind::Unsupported,
    ] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut link = physical_link();
        link.kind = kind;
        let mut report = physical_preflight();
        report.interface.kind = kind;
        if kind == InterfaceKind::Bond {
            report.interface.bond = Some(BondInspection {
                mode: BondMode::Unsupported,
                slaves: Vec::new(),
                active_slave: None,
            });
        }
        let preflight = FakePreflight::new(calls.clone(), report);
        let source = FakeCandidate::with_links(calls, link.clone(), link);
        let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

        let snapshot = inspector
            .inspect_authorized_interface(&authorization())
            .unwrap();

        assert_eq!(snapshot.kind, kind);
    }
}

#[test]
fn stable_down_or_mastered_link_state_is_preserved_for_fail_closed_gating() {
    let mutations: [fn(&mut DeploymentLinkSnapshotV1); 3] = [
        |link: &mut DeploymentLinkSnapshotV1| link.administrative_up = false,
        |link: &mut DeploymentLinkSnapshotV1| link.operational_up = false,
        |link: &mut DeploymentLinkSnapshotV1| link.master_ifindex = Some(19),
    ];
    for mutate in mutations {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut link = physical_link();
        mutate(&mut link);
        let mut report = physical_preflight();
        report.interface.admin_up = link.administrative_up;
        report.interface.oper_up = link.operational_up;
        report.interface.master = link.master_ifindex.map(|ifindex| InterfaceRef {
            name: InterfaceName::new("master0").unwrap(),
            ifindex,
        });
        let preflight = FakePreflight::new(calls.clone(), report);
        let source = FakeCandidate::with_links(calls, link.clone(), link.clone());
        let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

        let snapshot = inspector
            .inspect_authorized_interface(&authorization())
            .unwrap();

        assert_eq!(snapshot.administrative_up, link.administrative_up);
        assert_eq!(snapshot.operational_up, link.operational_up);
        assert_eq!(snapshot.master_ifindex, link.master_ifindex);
    }
}

#[test]
fn every_reserved_port_consumer_is_preserved_as_a_boolean_only() {
    let mutations: [fn(&mut DeploymentConsumerSnapshotV1); 6] = [
        |facts: &mut DeploymentConsumerSnapshotV1| facts.tc_clsact_present = true,
        |facts: &mut DeploymentConsumerSnapshotV1| facts.address_present = true,
        |facts: &mut DeploymentConsumerSnapshotV1| facts.route_present = true,
        |facts: &mut DeploymentConsumerSnapshotV1| facts.neighbor_present = true,
        |facts: &mut DeploymentConsumerSnapshotV1| facts.service_present = true,
        |facts: &mut DeploymentConsumerSnapshotV1| facts.other_consumer_present = true,
    ];
    for mutate in mutations {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let preflight = FakePreflight::new(calls.clone(), physical_preflight());
        let mut source = FakeCandidate::passing(calls);
        mutate(&mut source.consumers);
        let expected = source.consumers;
        let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

        let snapshot = inspector
            .inspect_authorized_interface(&authorization())
            .unwrap();

        assert_eq!(snapshot.tc_clsact_present, expected.tc_clsact_present);
        assert_eq!(snapshot.address_present, expected.address_present);
        assert_eq!(snapshot.route_present, expected.route_present);
        assert_eq!(snapshot.neighbor_present, expected.neighbor_present);
        assert_eq!(snapshot.service_present, expected.service_present);
        assert_eq!(
            snapshot.other_consumer_present,
            expected.other_consumer_present
        );
    }
}

#[test]
fn peer_or_namespace_relation_is_folded_into_other_consumer_presence() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut link = physical_link();
    link.peer_or_namespace_relation_present = true;
    let preflight = FakePreflight::new(calls.clone(), physical_preflight());
    let source = FakeCandidate::with_links(calls, link.clone(), link);
    let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

    let snapshot = inspector
        .inspect_authorized_interface(&authorization())
        .unwrap();

    assert!(snapshot.other_consumer_present);
}

#[test]
fn hook_and_host_blockers_remain_in_the_sanitized_preflight_contract() {
    let mut variants = Vec::new();
    for state in [
        AttachmentState::Occupied { program_id: 41 },
        AttachmentState::Owned { program_id: 42 },
        AttachmentState::Unknown,
    ] {
        let mut native = physical_preflight();
        native.bpf.xdp_native = state;
        variants.push(native);
        let mut generic = physical_preflight();
        generic.bpf.xdp_generic = state;
        variants.push(generic);
    }
    for direction in [Direction::Ingress, Direction::Egress] {
        let mut occupied = physical_preflight();
        let attachment = TcAttachment {
            direction,
            priority: 49_714,
            handle: 0x4c32_0001,
            program_id: 43,
        };
        match direction {
            Direction::Ingress => occupied.bpf.tc_ingress.push(attachment),
            Direction::Egress => occupied.bpf.tc_egress.push(attachment),
        }
        variants.push(occupied);
    }
    let mut unknown_tc = physical_preflight();
    unknown_tc.bpf.relevant_objects_enumerable = false;
    unknown_tc.findings.push(PreflightFinding::blocker(
        "PF_TC_STATE_UNKNOWN",
        "traffic control state is unavailable",
    ));
    variants.push(unknown_tc);
    let mut unsupported_host = physical_preflight();
    unsupported_host.kernel.btf_readable = false;
    unsupported_host.bpf.bpffs_mounted = false;
    unsupported_host.bpf.relevant_objects_enumerable = false;
    unsupported_host.bpf.memlock.soft_bytes = Some(0);
    unsupported_host.findings.push(PreflightFinding::blocker(
        PF_INTERFACE_UNSUPPORTED,
        "sanitized additional blocker",
    ));
    variants.push(unsupported_host);

    for report in variants {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let expected = normalized(report);
        let preflight = FakePreflight::new(calls.clone(), expected.clone());
        let source = FakeCandidate::passing(calls);
        let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

        let snapshot = inspector
            .inspect_authorized_interface(&authorization())
            .unwrap();

        assert_eq!(snapshot.preflight, expected);
    }
}

#[test]
fn missing_or_additional_live_refusal_is_preserved_for_the_gate_service() {
    for findings in [
        Vec::new(),
        vec![PreflightFinding::blocker(
            PF_LIVE_INTERFACE,
            "live interface attachment is refused",
        )],
        vec![
            PreflightFinding::blocker(PF_LIVE_INTERFACE, "live interface attachment is refused"),
            PreflightFinding::blocker(PF_INTERFACE_UNSUPPORTED, "additional blocker"),
        ],
    ] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut report = physical_preflight();
        report.findings = findings;
        let expected = normalized(report);
        let preflight = FakePreflight::new(calls.clone(), expected.clone());
        let source = FakeCandidate::passing(calls);
        let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

        let snapshot = inspector
            .inspect_authorized_interface(&authorization())
            .unwrap();

        assert_eq!(snapshot.preflight.findings, expected.findings);
    }
}

#[test]
fn collector_errors_never_escape_the_single_sanitized_error_variant() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let preflight = FakePreflight::failing(calls.clone());
    let source = FakeCandidate::passing(calls);
    let mut inspector = LinuxDeploymentPlatformInspector::new(preflight, source);

    let error = inspector
        .inspect_authorized_interface(&authorization())
        .unwrap_err();

    assert_eq!(error, DeploymentIoError::Unavailable);
    let rendered = error.to_string();
    for prohibited in [
        "10.58.159.4",
        "aa:bb:cc:dd:ee:ff",
        "/secret/pin",
        "program_id",
        "machine-id",
    ] {
        assert!(!rendered.contains(prohibited));
    }
}

#[test]
fn linux_adapter_source_is_read_only_and_never_enumerates_as_fallback() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/linux/deployment_platform.rs"),
    )
    .unwrap();
    for prohibited in [
        ".add()",
        ".del()",
        ".set()",
        "attach(",
        "detach(",
        "aya::",
        "Command::new",
        "std::process",
        "handle.link().get().execute()",
    ] {
        assert!(!source.contains(prohibited), "found {prohibited}");
    }
    assert!(source.contains("match_name"));
    assert!(source.contains("MAX_PACKET_TABLE_BYTES"));
    assert!(source.contains("ExactSystemPreflightInspector"));
    assert!(!source.contains("SystemLinuxInspector"));
}

fn authorization() -> DeploymentAuthorizationV1 {
    serde_json::from_str(include_str!("fixtures/deployment/physical-empty.json")).unwrap()
}

fn physical_link() -> DeploymentLinkSnapshotV1 {
    DeploymentLinkSnapshotV1 {
        name: InterfaceName::new("spare0").unwrap(),
        ifindex: 7,
        kind: InterfaceKind::Physical,
        administrative_up: true,
        operational_up: true,
        master_ifindex: None,
        peer_or_namespace_relation_present: false,
    }
}

fn physical_preflight() -> PreflightReport {
    PreflightReport::new(
        InterfaceInspection {
            requested: InterfaceRef {
                name: InterfaceName::new("spare0").unwrap(),
                ifindex: 7,
            },
            kind: InterfaceKind::Physical,
            admin_up: true,
            oper_up: true,
            master: None,
            bond: None,
            proposed_targets: Vec::new(),
            isolated: false,
            live_shared: true,
        },
        KernelInspection {
            architecture: "x86_64".into(),
            release: "6.12.0-test".into(),
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
        vec![PreflightFinding::blocker(
            PF_LIVE_INTERFACE,
            "live interface attachment is refused",
        )],
    )
}

fn normalized(report: PreflightReport) -> PreflightReport {
    PreflightReport::new(report.interface, report.kernel, report.bpf, report.findings)
}

struct FakePreflight {
    calls: Rc<RefCell<Vec<String>>>,
    report: Result<PreflightReport, PortError>,
}

impl FakePreflight {
    fn new(calls: Rc<RefCell<Vec<String>>>, report: PreflightReport) -> Self {
        Self {
            calls,
            report: Ok(report),
        }
    }

    fn failing(calls: Rc<RefCell<Vec<String>>>) -> Self {
        Self {
            calls,
            report: Err(PortError::Adapter(
                "10.58.159.4 aa:bb:cc:dd:ee:ff /secret/pin program_id machine-id".into(),
            )),
        }
    }
}

impl PlatformInspector for FakePreflight {
    fn inspect(&mut self, interface: &InterfaceName) -> Result<PreflightReport, PortError> {
        self.calls
            .borrow_mut()
            .push(format!("preflight:{}", interface.as_str()));
        self.report.clone()
    }
}

struct FakeCandidate {
    calls: Rc<RefCell<Vec<String>>>,
    links: [DeploymentLinkSnapshotV1; 2],
    next_link: usize,
    consumers: DeploymentConsumerSnapshotV1,
}

impl FakeCandidate {
    fn passing(calls: Rc<RefCell<Vec<String>>>) -> Self {
        let link = physical_link();
        Self::with_links(calls, link.clone(), link)
    }

    fn with_links(
        calls: Rc<RefCell<Vec<String>>>,
        first: DeploymentLinkSnapshotV1,
        second: DeploymentLinkSnapshotV1,
    ) -> Self {
        Self {
            calls,
            links: [first, second],
            next_link: 0,
            consumers: DeploymentConsumerSnapshotV1 {
                tc_clsact_present: false,
                address_present: false,
                route_present: false,
                neighbor_present: false,
                service_present: false,
                other_consumer_present: false,
                logical_cpu_count: 8,
            },
        }
    }
}

impl DeploymentCandidateSource for FakeCandidate {
    fn inspect_identity(
        &mut self,
        _interface: &InterfaceName,
    ) -> Result<DeploymentLinkSnapshotV1, DeploymentIoError> {
        self.calls.borrow_mut().push("identity".into());
        let link = self.links[self.next_link].clone();
        self.next_link += 1;
        Ok(link)
    }

    fn inspect_consumers(
        &mut self,
        interface: &InterfaceName,
        ifindex: u32,
    ) -> Result<DeploymentConsumerSnapshotV1, DeploymentIoError> {
        self.calls
            .borrow_mut()
            .push(format!("consumers:{}:{ifindex}", interface.as_str()));
        Ok(self.consumers)
    }
}
