#![cfg(target_os = "linux")]

use std::{cell::RefCell, rc::Rc};

use l2_loop_agent::{
    PlatformInspector,
    linux::{
        bpf_inventory::{BtfSnapshot, PinRootSnapshot},
        inspector::{
            BpfQuery, BpfQuerySnapshot, CommandSource, FileSource, HostFileSnapshot,
            InspectorError, LinkSource, LinuxInspector, ObservedTcAttachment,
        },
        interface::{KernelLinkKind, LinkRecord},
    },
};
use l2_loop_core::{
    AttachmentState, Direction, FindingSeverity, HookRole, InterfaceKind, InterfaceName,
    PF_INTERFACE_MISSING, PF_INTERFACE_UNSUPPORTED, PF_KERNEL_CAPABILITY, PF_LIVE_INTERFACE,
    PF_MEMLOCK_TOO_LOW, PF_PIN_ROOT_FOREIGN, PF_TC_HANDLE_COLLISION, PF_TC_STATE_UNKNOWN,
    PF_XDP_OCCUPIED, PF_XDP_STATE_UNKNOWN, PinRootState, PreflightDecision, TcAttachment,
};

const REQUIRED_MEMLOCK_BYTES: u64 = 8 * 1024 * 1024;
const RESERVED_TC_INGRESS_HANDLE: u32 = 0x4c32_0001;

#[test]
fn produces_a_ready_report_for_an_isolated_veth() {
    let fixture = Fixture::ready("veth-test");
    let calls = fixture.calls.clone();
    let mut inspector = fixture.inspector();
    let requested = interface_name("veth-test");

    let report = inspector.inspect(&requested).unwrap();

    assert_eq!(report.decision, PreflightDecision::Ready);
    assert_eq!(report.interface.kind, InterfaceKind::Veth);
    assert!(report.interface.isolated);
    assert!(!report.interface.live_shared);
    assert_eq!(report.interface.proposed_targets.len(), 2);
    assert_eq!(
        report
            .interface
            .proposed_targets
            .iter()
            .map(|target| target.role)
            .collect::<Vec<_>>(),
        [HookRole::ExternalXdpIngress, HookRole::PhysicalTcEgress]
    );
    assert!(report.findings.is_empty());
    assert_eq!(
        calls.borrow().as_slice(),
        ["read:links", "read:files:veth-test", "query:bpf:7"]
    );
}

#[test]
fn reports_a_missing_interface_and_a_zero_ifindex_as_blockers() {
    for fixture in [Fixture::missing("missing0"), Fixture::zero_ifindex("zero0")] {
        let requested = fixture.requested.clone();
        let mut inspector = fixture.inspector();

        let report = inspector.inspect(&requested).unwrap();

        assert_eq!(report.decision, PreflightDecision::Blocked);
        assert_eq!(report.interface.requested.ifindex, 0);
        assert_has_blocker(&report, PF_INTERFACE_MISSING);
    }
}

#[test]
fn blocks_an_ambiguous_master_and_a_live_interface() {
    let mut fixture = Fixture::ready("veth-test");
    fixture.links[0].master_ifindex = Some(90);
    fixture.links[0].admin_up = true;
    fixture.links.extend([
        link("br-a", 90, Some(KernelLinkKind::Bridge)),
        link("br-b", 90, Some(KernelLinkKind::Bridge)),
    ]);
    let requested = fixture.requested.clone();
    let mut inspector = fixture.inspector();

    let report = inspector.inspect(&requested).unwrap();

    assert!(report.interface.master.is_none());
    assert!(!report.interface.isolated);
    assert!(report.interface.live_shared);
    assert_has_blocker(&report, PF_INTERFACE_UNSUPPORTED);
    assert_has_blocker(&report, PF_LIVE_INTERFACE);
}

#[test]
fn keeps_native_and_generic_xdp_state_separate() {
    let mut fixture = Fixture::ready("veth-test");
    fixture.bpf.xdp_native = AttachmentState::Unknown;
    fixture.bpf.xdp_generic = AttachmentState::Occupied { program_id: 42 };
    let requested = fixture.requested.clone();
    let mut inspector = fixture.inspector();

    let report = inspector.inspect(&requested).unwrap();

    assert_eq!(report.bpf.xdp_native, AttachmentState::Unknown);
    assert_eq!(
        report.bpf.xdp_generic,
        AttachmentState::Occupied { program_id: 42 }
    );
    assert_has_blocker(&report, PF_XDP_STATE_UNKNOWN);
    assert_has_blocker(&report, PF_XDP_OCCUPIED);
}

#[test]
fn blocks_unknown_tc_state_and_foreign_reserved_handle_collisions() {
    let mut fixture = Fixture::ready("veth-test");
    fixture.bpf.tc_state_known = false;
    fixture.bpf.tc_ingress = vec![ObservedTcAttachment {
        attachment: TcAttachment {
            direction: Direction::Ingress,
            priority: 10,
            handle: RESERVED_TC_INGRESS_HANDLE,
            program_id: 71,
        },
        owned: false,
    }];
    let requested = fixture.requested.clone();
    let mut inspector = fixture.inspector();

    let report = inspector.inspect(&requested).unwrap();

    assert_eq!(report.bpf.tc_ingress.len(), 1);
    assert_has_blocker(&report, PF_TC_STATE_UNKNOWN);
    assert_has_blocker(&report, PF_TC_HANDLE_COLLISION);
}

#[test]
fn blocks_a_nonempty_pin_root_without_valid_ownership() {
    let mut fixture = Fixture::ready("veth-test");
    fixture.files.pin_root = PinRootSnapshot::foreign(3);
    let requested = fixture.requested.clone();
    let mut inspector = fixture.inspector();

    let report = inspector.inspect(&requested).unwrap();

    assert_eq!(report.bpf.pin_root, PinRootState::Foreign);
    assert_has_blocker(&report, PF_PIN_ROOT_FOREIGN);
}

#[test]
fn distinguishes_raisable_memlock_from_a_hard_limit_blocker() {
    let mut raisable = Fixture::ready("veth-test");
    raisable.files.limits = include_str!("fixtures/proc/limits-raisable.txt").into();
    let requested = raisable.requested.clone();
    let mut inspector = raisable.inspector();

    let report = inspector.inspect(&requested).unwrap();

    assert_eq!(report.decision, PreflightDecision::ReadyWithWarnings);
    assert_eq!(report.bpf.memlock.required_bytes, REQUIRED_MEMLOCK_BYTES);
    assert!(report.bpf.memlock.can_raise);
    assert_has_finding(&report, PF_MEMLOCK_TOO_LOW, FindingSeverity::Warning);

    let mut blocked = Fixture::ready("veth-test");
    blocked.files.limits = include_str!("fixtures/proc/limits-blocked.txt").into();
    let requested = blocked.requested.clone();
    let mut inspector = blocked.inspector();

    let report = inspector.inspect(&requested).unwrap();

    assert!(!report.bpf.memlock.can_raise);
    assert_has_blocker(&report, PF_MEMLOCK_TOO_LOW);
}

#[test]
fn aggregates_missing_bpf_jit_btf_and_syscall_support() {
    let mut fixture = Fixture::ready("veth-test");
    fixture.files.bpf_jit = false;
    fixture.files.btf = BtfSnapshot {
        exists: false,
        regular_file: false,
        readable: false,
    };
    fixture.bpf.bpf_syscall = false;
    fixture.bpf.tc_clsact = false;
    let requested = fixture.requested.clone();
    let mut inspector = fixture.inspector();

    let report = inspector.inspect(&requested).unwrap();

    assert!(!report.kernel.bpf_syscall);
    assert!(!report.kernel.bpf_jit);
    assert!(!report.kernel.btf_readable);
    assert!(!report.kernel.tc_clsact);
    assert_has_blocker(&report, PF_KERNEL_CAPABILITY);
}

#[test]
fn assembles_bond_details_and_targets_only_the_active_slave() {
    let mut fixture = Fixture::ready("bond0");
    fixture.links = vec![
        link("bond0", 10, Some(KernelLinkKind::Bond)),
        physical_link("port-a", 11),
        physical_link("port-b", 12),
    ];
    fixture.files.bond = Some(include_str!("fixtures/bond/active-backup.txt").into());
    let requested = fixture.requested.clone();
    let mut inspector = fixture.inspector();

    let report = inspector.inspect(&requested).unwrap();

    let bond = report.interface.bond.unwrap();
    assert_eq!(bond.slaves.len(), 2);
    assert_eq!(bond.active_slave.unwrap().name, interface_name("port-b"));
    assert!(
        report
            .interface
            .proposed_targets
            .iter()
            .all(|target| target.interface.name == interface_name("port-b"))
    );
}

#[test]
fn uses_the_injected_ovs_query_without_a_shell_or_mutation_port() {
    let mut fixture = Fixture::ready("ovs0");
    fixture.links[0].kind = Some(KernelLinkKind::OpenVSwitch);
    fixture.ovs_bridge = Ok(Some(interface_name("br-int")));
    let calls = fixture.calls.clone();
    let requested = fixture.requested.clone();
    let mut inspector = fixture.inspector();

    let report = inspector.inspect(&requested).unwrap();

    assert_eq!(report.interface.kind, InterfaceKind::OvsInternal);
    assert_eq!(
        report.interface.master.unwrap().name,
        interface_name("br-int")
    );
    assert!(
        calls
            .borrow()
            .iter()
            .all(|call| call.starts_with("read:") || call.starts_with("query:"))
    );
    assert!(calls.borrow().contains(&"query:ovs:ovs0".into()));
}

struct Fixture {
    requested: InterfaceName,
    links: Vec<LinkRecord>,
    files: HostFileSnapshot,
    bpf: BpfQuerySnapshot,
    ovs_bridge: Result<Option<InterfaceName>, InspectorError>,
    calls: Rc<RefCell<Vec<String>>>,
}

impl Fixture {
    fn ready(name: &str) -> Self {
        Self {
            requested: interface_name(name),
            links: vec![link(name, 7, Some(KernelLinkKind::Veth))],
            files: HostFileSnapshot {
                architecture: "x86_64".into(),
                release: "6.6.0-test".into(),
                mounts: include_str!("fixtures/proc/mounts.txt").into(),
                limits:
                    "Max locked memory         unlimited            unlimited            bytes\n"
                        .into(),
                bpf_jit: true,
                btf: BtfSnapshot {
                    exists: true,
                    regular_file: true,
                    readable: true,
                },
                pin_root: PinRootSnapshot::absent(),
                bond: None,
            },
            bpf: BpfQuerySnapshot {
                bpf_syscall: true,
                relevant_objects_enumerable: true,
                xdp_native: AttachmentState::Empty,
                xdp_generic: AttachmentState::Empty,
                tc_state_known: true,
                tc_clsact: true,
                tc_ingress: Vec::new(),
                tc_egress: Vec::new(),
            },
            ovs_bridge: Ok(None),
            calls: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn missing(name: &str) -> Self {
        let mut fixture = Self::ready(name);
        fixture.links.clear();
        fixture
    }

    fn zero_ifindex(name: &str) -> Self {
        let mut fixture = Self::ready(name);
        fixture.links[0].ifindex = 0;
        fixture
    }

    fn inspector(
        &self,
    ) -> LinuxInspector<FakeLinkSource, FakeFileSource, FakeBpfQuery, FakeCommandSource> {
        LinuxInspector::new(
            FakeLinkSource {
                links: self.links.clone(),
                calls: self.calls.clone(),
            },
            FakeFileSource {
                snapshot: self.files.clone(),
                calls: self.calls.clone(),
            },
            FakeBpfQuery {
                snapshot: self.bpf.clone(),
                calls: self.calls.clone(),
            },
            FakeCommandSource {
                ovs_bridge: self.ovs_bridge.clone(),
                calls: self.calls.clone(),
            },
        )
    }
}

struct FakeLinkSource {
    links: Vec<LinkRecord>,
    calls: Rc<RefCell<Vec<String>>>,
}

impl LinkSource for FakeLinkSource {
    fn read_links(&mut self) -> Result<Vec<LinkRecord>, InspectorError> {
        self.calls.borrow_mut().push("read:links".into());
        Ok(self.links.clone())
    }
}

struct FakeFileSource {
    snapshot: HostFileSnapshot,
    calls: Rc<RefCell<Vec<String>>>,
}

impl FileSource for FakeFileSource {
    fn read_host_files(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<HostFileSnapshot, InspectorError> {
        self.calls
            .borrow_mut()
            .push(format!("read:files:{interface}"));
        Ok(self.snapshot.clone())
    }
}

struct FakeBpfQuery {
    snapshot: BpfQuerySnapshot,
    calls: Rc<RefCell<Vec<String>>>,
}

impl BpfQuery for FakeBpfQuery {
    fn query_bpf(&mut self, ifindexes: &[u32]) -> Result<BpfQuerySnapshot, InspectorError> {
        self.calls.borrow_mut().push(format!(
            "query:bpf:{}",
            ifindexes
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
        Ok(self.snapshot.clone())
    }
}

struct FakeCommandSource {
    ovs_bridge: Result<Option<InterfaceName>, InspectorError>,
    calls: Rc<RefCell<Vec<String>>>,
}

impl CommandSource for FakeCommandSource {
    fn query_ovs_bridge(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<Option<InterfaceName>, InspectorError> {
        self.calls
            .borrow_mut()
            .push(format!("query:ovs:{interface}"));
        self.ovs_bridge.clone()
    }
}

fn link(name: &str, ifindex: u32, kind: Option<KernelLinkKind>) -> LinkRecord {
    LinkRecord {
        name: interface_name(name),
        ifindex,
        kind,
        tun_mode: None,
        driver_present: false,
        master_ifindex: None,
        admin_up: false,
        oper_up: false,
    }
}

fn physical_link(name: &str, ifindex: u32) -> LinkRecord {
    LinkRecord {
        driver_present: true,
        ..link(name, ifindex, None)
    }
}

fn interface_name(name: &str) -> InterfaceName {
    InterfaceName::new(name).unwrap()
}

fn assert_has_blocker(report: &l2_loop_core::PreflightReport, code: &str) {
    assert_has_finding(report, code, FindingSeverity::Blocker);
}

fn assert_has_finding(
    report: &l2_loop_core::PreflightReport,
    code: &str,
    severity: FindingSeverity,
) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == code && finding.severity == severity),
        "missing {severity:?} finding {code}: {:?}",
        report.findings
    );
}
