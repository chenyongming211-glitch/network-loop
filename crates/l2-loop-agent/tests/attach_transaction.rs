#![cfg(target_os = "linux")]

use std::{cell::RefCell, rc::Rc};

use l2_loop_agent::{
    AttachmentTransaction, BpfObjectLoader, EphemeralOwnershipStore, LoadedBpfObject, MapPublisher,
    PlatformInspector, PortError, ResourceLimits, SafeTcPort, SafeXdpPort,
};
use l2_loop_agent::{
    linux::{tc::LoadedTc, xdp::LoadedXdp},
    ownership::{
        OWNED_MAP_NAMES, OwnedMapPin, OwnedTc, OwnedXdp, OwnershipRecord, RunId, TcHook,
        TestPinRoot, XdpAttachMode,
    },
};
use l2_loop_core::{
    AttachmentState, BpfInspection, InterfaceInspection, InterfaceKind, InterfaceName,
    InterfaceRef, InterfaceState, KernelInspection, MemlockInspection, PF_LIVE_INTERFACE,
    PF_TC_STATE_UNKNOWN, PinRootState, PreflightDecision, PreflightReport,
};

#[test]
fn commits_only_after_both_hooks_and_maps_are_verified() {
    let shared = Shared::new(None);
    let mut transaction = transaction(shared.clone(), report(InterfaceKind::Veth, true, false));

    let session = transaction
        .execute(&interface(), &run_id(), 1_754_521_600)
        .unwrap();

    assert_eq!(session.state, InterfaceState::Observing);
    assert_eq!(session.generation, 1);
    assert_eq!(session.ownership.generation, 1);
    assert_eq!(
        session.ownership.map_pins,
        expected_map_pins(&TestPinRoot::new(run_id()).unwrap())
    );
    assert_eq!(
        shared.events(),
        [
            "preflight",
            "raise_memlock",
            "load_and_validate_abi",
            "attach_xdp_no_replace",
            "verify_xdp",
            "attach_tc_explicit",
            "verify_tc",
            "initialize_maps",
            "save_ephemeral_journal",
            "publish_iface_config",
        ]
    );
}

#[test]
fn every_failure_rolls_back_only_completed_owned_operations_in_reverse() {
    let cases: &[(Operation, &[&str])] = &[
        (Operation::Preflight, &["preflight"]),
        (Operation::RaiseMemlock, &["preflight", "raise_memlock"]),
        (
            Operation::Load,
            &["preflight", "raise_memlock", "load_and_validate_abi"],
        ),
        (
            Operation::AttachXdp,
            &[
                "preflight",
                "raise_memlock",
                "load_and_validate_abi",
                "attach_xdp_no_replace",
                "unload_exact",
            ],
        ),
        (
            Operation::VerifyXdp,
            &[
                "preflight",
                "raise_memlock",
                "load_and_validate_abi",
                "attach_xdp_no_replace",
                "verify_xdp",
                "detach_xdp_exact",
                "unload_exact",
            ],
        ),
        (
            Operation::AttachTc,
            &[
                "preflight",
                "raise_memlock",
                "load_and_validate_abi",
                "attach_xdp_no_replace",
                "verify_xdp",
                "attach_tc_explicit",
                "detach_xdp_exact",
                "unload_exact",
            ],
        ),
        (
            Operation::VerifyTc,
            &[
                "preflight",
                "raise_memlock",
                "load_and_validate_abi",
                "attach_xdp_no_replace",
                "verify_xdp",
                "attach_tc_explicit",
                "verify_tc",
                "detach_tc_exact",
                "detach_xdp_exact",
                "unload_exact",
            ],
        ),
        (
            Operation::InitializeMaps,
            &[
                "preflight",
                "raise_memlock",
                "load_and_validate_abi",
                "attach_xdp_no_replace",
                "verify_xdp",
                "attach_tc_explicit",
                "verify_tc",
                "initialize_maps",
                "detach_tc_exact",
                "detach_xdp_exact",
                "unload_exact",
            ],
        ),
        (
            Operation::SaveJournal,
            &[
                "preflight",
                "raise_memlock",
                "load_and_validate_abi",
                "attach_xdp_no_replace",
                "verify_xdp",
                "attach_tc_explicit",
                "verify_tc",
                "initialize_maps",
                "save_ephemeral_journal",
                "rollback_maps_exact",
                "detach_tc_exact",
                "detach_xdp_exact",
                "unload_exact",
            ],
        ),
        (
            Operation::PublishConfig,
            &[
                "preflight",
                "raise_memlock",
                "load_and_validate_abi",
                "attach_xdp_no_replace",
                "verify_xdp",
                "attach_tc_explicit",
                "verify_tc",
                "initialize_maps",
                "save_ephemeral_journal",
                "publish_iface_config",
                "remove_ephemeral_journal_exact",
                "rollback_maps_exact",
                "detach_tc_exact",
                "detach_xdp_exact",
                "unload_exact",
            ],
        ),
    ];

    for (failure, expected) in cases {
        let shared = Shared::new(Some(*failure));
        let mut transaction = transaction(shared.clone(), report(InterfaceKind::Veth, true, false));

        let error = transaction
            .execute(&interface(), &run_id(), 1_754_521_600)
            .unwrap_err();

        assert_eq!(shared.events(), *expected, "failure at {failure:?}");
        assert!(error.cleanup_evidence().is_empty());
        assert!(
            !shared.events().contains(&"publish_iface_config")
                || *failure == Operation::PublishConfig
        );
    }
}

#[test]
fn cleanup_failures_are_aggregated_without_stopping_precise_rollback() {
    let shared = Shared::new(Some(Operation::PublishConfig));
    shared.fail_all_cleanup();
    let mut transaction = transaction(shared.clone(), report(InterfaceKind::Veth, true, false));

    let error = transaction
        .execute(&interface(), &run_id(), 1_754_521_600)
        .unwrap_err();

    assert_eq!(error.cleanup_evidence().len(), 5);
    assert!(shared.events().ends_with(&[
        "remove_ephemeral_journal_exact",
        "rollback_maps_exact",
        "detach_tc_exact",
        "detach_xdp_exact",
        "unload_exact",
    ]));
}

#[test]
fn rejects_every_non_isolated_target_before_memlock_or_bpf_work() {
    let cases = [
        InterfaceKind::Physical,
        InterfaceKind::Bond,
        InterfaceKind::Bridge,
        InterfaceKind::OvsInternal,
        InterfaceKind::Tap,
        InterfaceKind::Unsupported,
    ];

    for kind in cases {
        let shared = Shared::new(None);
        let mut transaction = transaction(shared.clone(), report(kind, false, false));

        let error = transaction
            .execute(&interface(), &run_id(), 1_754_521_600)
            .unwrap_err();

        assert_eq!(error.code(), PF_LIVE_INTERFACE);
        assert_eq!(shared.events(), ["preflight"]);
    }

    let shared = Shared::new(None);
    let mut transaction = transaction(shared.clone(), report(InterfaceKind::Veth, false, true));
    let error = transaction
        .execute(&interface(), &run_id(), 1_754_521_600)
        .unwrap_err();
    assert_eq!(error.code(), PF_LIVE_INTERFACE);
    assert_eq!(shared.events(), ["preflight"]);
}

#[test]
fn stable_adapter_codes_survive_transaction_rollback() {
    let shared = Shared::new(Some(Operation::AttachTc));
    shared.fail_with_code(PF_TC_STATE_UNKNOWN);
    let mut transaction = transaction(shared.clone(), report(InterfaceKind::Veth, true, false));

    let error = transaction
        .execute(&interface(), &run_id(), 1_754_521_600)
        .unwrap_err();

    assert_eq!(error.code(), PF_TC_STATE_UNKNOWN);
    assert!(
        shared
            .events()
            .ends_with(&["attach_tc_explicit", "detach_xdp_exact", "unload_exact",])
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Preflight,
    RaiseMemlock,
    Load,
    AttachXdp,
    VerifyXdp,
    AttachTc,
    VerifyTc,
    InitializeMaps,
    SaveJournal,
    PublishConfig,
}

#[derive(Clone)]
struct Shared(Rc<RefCell<SharedState>>);

struct SharedState {
    events: Vec<&'static str>,
    fail_at: Option<Operation>,
    failure_code: Option<&'static str>,
    fail_cleanup: bool,
}

impl Shared {
    fn new(fail_at: Option<Operation>) -> Self {
        Self(Rc::new(RefCell::new(SharedState {
            events: Vec::new(),
            fail_at,
            failure_code: None,
            fail_cleanup: false,
        })))
    }

    fn event(&self, event: &'static str, operation: Operation) -> Result<(), PortError> {
        let mut state = self.0.borrow_mut();
        state.events.push(event);
        if state.fail_at == Some(operation) {
            match state.failure_code {
                Some(code) => Err(PortError::coded_adapter(
                    code,
                    format!("injected failure at {event}"),
                )),
                None => Err(PortError::Adapter(format!("injected failure at {event}"))),
            }
        } else {
            Ok(())
        }
    }

    fn cleanup(&self, event: &'static str) -> Result<(), PortError> {
        let mut state = self.0.borrow_mut();
        state.events.push(event);
        if state.fail_cleanup {
            Err(PortError::Adapter(format!(
                "injected cleanup failure at {event}"
            )))
        } else {
            Ok(())
        }
    }

    fn events(&self) -> Vec<&'static str> {
        self.0.borrow().events.clone()
    }

    fn fail_all_cleanup(&self) {
        self.0.borrow_mut().fail_cleanup = true;
    }

    fn fail_with_code(&self, code: &'static str) {
        self.0.borrow_mut().failure_code = Some(code);
    }
}

struct FakeInspector {
    shared: Shared,
    report: PreflightReport,
}

impl PlatformInspector for FakeInspector {
    fn inspect(&mut self, _interface: &InterfaceName) -> Result<PreflightReport, PortError> {
        self.shared.event("preflight", Operation::Preflight)?;
        Ok(self.report.clone())
    }
}

struct FakeLimits(Shared);

impl ResourceLimits for FakeLimits {
    fn raise_memlock_to_infinity(&mut self) -> Result<(), PortError> {
        self.0.event("raise_memlock", Operation::RaiseMemlock)
    }
}

struct FakeLoader(Shared);

impl BpfObjectLoader for FakeLoader {
    fn load_and_validate_abi(&mut self, pins: &TestPinRoot) -> Result<LoadedBpfObject, PortError> {
        self.0.event("load_and_validate_abi", Operation::Load)?;
        Ok(LoadedBpfObject {
            xdp: LoadedXdp {
                program_fd: 11,
                program_id: 101,
                program_tag: [1; 8],
            },
            tc_egress: LoadedTc {
                program_fd: 12,
                program_id: 102,
            },
            map_pins: expected_map_pins(pins),
        })
    }

    fn unload_exact(&mut self, _loaded: &LoadedBpfObject) -> Result<(), PortError> {
        self.0.cleanup("unload_exact")
    }
}

struct FakeXdp(Shared);

impl SafeXdpPort for FakeXdp {
    fn attach_no_replace(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        loaded: LoadedXdp,
    ) -> Result<OwnedXdp, PortError> {
        self.0
            .event("attach_xdp_no_replace", Operation::AttachXdp)?;
        Ok(OwnedXdp {
            ifindex,
            mode,
            program_id: loaded.program_id,
            program_tag: loaded.program_tag,
            link_id: Some(201),
        })
    }

    fn verify_exact(&mut self, _owned: &OwnedXdp) -> Result<(), PortError> {
        self.0.event("verify_xdp", Operation::VerifyXdp)
    }

    fn detach_exact(&mut self, _owned: &OwnedXdp) -> Result<(), PortError> {
        self.0.cleanup("detach_xdp_exact")
    }
}

struct FakeTc(Shared);

impl SafeTcPort for FakeTc {
    fn attach_explicit(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        loaded: LoadedTc,
    ) -> Result<OwnedTc, PortError> {
        self.0.event("attach_tc_explicit", Operation::AttachTc)?;
        Ok(OwnedTc {
            ifindex,
            hook,
            priority: 49_600,
            handle: 0x4c32_0002,
            program_id: loaded.program_id,
            created_clsact: true,
        })
    }

    fn verify_exact(&mut self, _owned: &OwnedTc) -> Result<(), PortError> {
        self.0.event("verify_tc", Operation::VerifyTc)
    }

    fn detach_exact(&mut self, _owned: &OwnedTc) -> Result<(), PortError> {
        self.0.cleanup("detach_tc_exact")
    }
}

struct FakeMaps(Shared);

impl MapPublisher for FakeMaps {
    fn initialize_dependent(
        &mut self,
        _loaded: &LoadedBpfObject,
        _ifindex: u32,
        _generation: u64,
    ) -> Result<(), PortError> {
        self.0.event("initialize_maps", Operation::InitializeMaps)
    }

    fn publish_iface_config(
        &mut self,
        _loaded: &LoadedBpfObject,
        _ifindex: u32,
        _generation: u64,
    ) -> Result<(), PortError> {
        self.0
            .event("publish_iface_config", Operation::PublishConfig)
    }

    fn rollback_initialized_exact(
        &mut self,
        _loaded: &LoadedBpfObject,
        _ifindex: u32,
        _generation: u64,
    ) -> Result<(), PortError> {
        self.0.cleanup("rollback_maps_exact")
    }
}

struct FakeJournal(Shared);

impl EphemeralOwnershipStore for FakeJournal {
    fn save(&mut self, _record: &OwnershipRecord) -> Result<(), PortError> {
        self.0
            .event("save_ephemeral_journal", Operation::SaveJournal)
    }

    fn remove_exact(&mut self, _record: &OwnershipRecord) -> Result<(), PortError> {
        self.0.cleanup("remove_ephemeral_journal_exact")
    }
}

type Transaction = AttachmentTransaction<
    FakeInspector,
    FakeLimits,
    FakeLoader,
    FakeXdp,
    FakeTc,
    FakeMaps,
    FakeJournal,
>;

fn transaction(shared: Shared, report: PreflightReport) -> Transaction {
    AttachmentTransaction::new(
        FakeInspector {
            shared: shared.clone(),
            report,
        },
        FakeLimits(shared.clone()),
        FakeLoader(shared.clone()),
        FakeXdp(shared.clone()),
        FakeTc(shared.clone()),
        FakeMaps(shared.clone()),
        FakeJournal(shared),
    )
}

fn interface() -> InterfaceName {
    InterfaceName::new("l2lt0001").unwrap()
}

fn run_id() -> RunId {
    RunId::parse("0123456789abcdef0123456789abcdef").unwrap()
}

fn expected_map_pins(pins: &TestPinRoot) -> Vec<OwnedMapPin> {
    OWNED_MAP_NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| {
            OwnedMapPin::new(*name, pins.path().join(name), 301 + index as u32).unwrap()
        })
        .collect()
}

fn report(kind: InterfaceKind, isolated: bool, live_shared: bool) -> PreflightReport {
    let requested = InterfaceRef {
        name: interface(),
        ifindex: 17,
    };
    let interface = InterfaceInspection {
        requested,
        kind,
        admin_up: true,
        oper_up: true,
        master: None,
        bond: None,
        proposed_targets: Vec::new(),
        isolated,
        live_shared,
    };
    let kernel = KernelInspection {
        architecture: "x86_64".into(),
        release: "6.8.0".into(),
        bpf_syscall: true,
        bpf_jit: true,
        btf_readable: true,
        tc_clsact: true,
    };
    let bpf = BpfInspection {
        bpffs_mounted: true,
        relevant_objects_enumerable: true,
        pin_root: PinRootState::Absent,
        xdp_native: AttachmentState::Empty,
        xdp_generic: AttachmentState::Empty,
        tc_ingress: Vec::new(),
        tc_egress: Vec::new(),
        memlock: MemlockInspection {
            soft_bytes: Some(65_536),
            hard_bytes: None,
            required_bytes: 1_048_576,
            can_raise: true,
        },
    };
    let mut report = PreflightReport::new(interface, kernel, bpf, Vec::new());
    report.decision = PreflightDecision::Ready;
    report
}
