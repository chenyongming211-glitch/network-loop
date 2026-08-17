use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use l2_loop_agent::{
    BundleSnapshotV1, Clock, DeploymentFilesystem, DeploymentGateService, DeploymentIoError,
    DeploymentPlatformInspector, DeploymentPlatformSnapshotV1, DeploymentPrerequisitesV1,
    InstalledOwnershipSnapshotV1, LayoutSnapshotV1, ServiceUnitSnapshotV1,
};
use l2_loop_core::{
    AttachmentState, BpfInspection, DG_AUTH_IDENTITY, DG_INTERFACE_UNSUPPORTED,
    DG_NATIVE_XDP_UNVERIFIED, DG_PERFORMANCE_REGRESSION, DG_PERFORMANCE_UNAVAILABLE,
    DG_PLATFORM_BLOCKED, DG_REAL_JOURNALD_UNVERIFIED, DG_SYSTEMD_CONTRACT, DG_TC_NOT_EMPTY,
    DG_WORKLOAD_PERFORMANCE_UNVERIFIED, DG_XDP_NOT_EMPTY, DeploymentArtifactIdentityV1,
    DeploymentAuthorizationV1, DeploymentDecisionV1, DeploymentFindingSeverityV1,
    DeploymentHostCompatibilityV1, Direction, InterfaceInspection, InterfaceKind, InterfaceName,
    InterfaceRef, KernelInspection, MemlockInspection, PF_INTERFACE_UNSUPPORTED, PF_LIVE_INTERFACE,
    PerformanceEvidenceV1, PinRootState, PreflightFinding, PreflightReport, TcAttachment,
};
use serde_json::json;

const NOW_MS: u64 = 1_786_579_200_000;
const EXPIRES_MS: u64 = NOW_MS + 86_400_000;
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn staging_calls_read_only_gates_in_exact_order() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::passing(calls.clone());
    let platform = FakePlatform::passing(calls.clone());
    let clock = FixedClock;
    let mut service = DeploymentGateService::new(filesystem, platform, clock);
    let bundle = PathBuf::from("/tmp/exact-bundle");
    let root = PathBuf::from("/run/l2-loop/accept/00112233445566778899aabbccddeeff/staging-root");

    let report = service.staging(&bundle, &root).unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::StagingReady);
    assert!(report.interface.is_none());
    assert!(report.canary_plan.is_none());
    assert!(!report.mutations_performed);
    assert_eq!(
        calls.borrow().as_slice(),
        [
            "validate_staging_root",
            "inspect_bundle",
            "inspect_staged_layout",
            "inspect_staged_service",
            "load_staged_authorization",
            "load_staged_performance",
            "inspect_staged_prerequisites",
        ]
    );
}

#[test]
fn installed_verifies_exact_ownership_and_layout_without_interface_collection() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::passing(calls.clone());
    let platform = FakePlatform::passing(calls.clone());
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

    let report = service.installed().unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::InstalledVerified);
    assert!(report.interface.is_none());
    assert!(report.canary_plan.is_none());
    assert!(!report.mutations_performed);
    assert_eq!(
        calls.borrow().as_slice(),
        [
            "inspect_installed_ownership",
            "inspect_installed_layout",
            "inspect_installed_service",
            "load_installed_authorization",
            "load_installed_performance",
            "inspect_installed_prerequisites",
        ]
    );
    assert!(!calls.borrow().contains(&"inspect_authorized_interface"));
}

#[test]
fn inspect_calls_fixed_layout_gates_and_builds_non_executable_plan() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::passing(calls.clone());
    let platform = FakePlatform::passing(calls.clone());
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

    let report = service.inspect().unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::PhysicalCanaryReady);
    assert_eq!(report.interface.as_ref().unwrap().name, "spare0");
    assert!(!report.canary_plan.as_ref().unwrap().executable);
    assert_eq!(
        report.canary_plan.as_ref().unwrap().warning_codes,
        [
            DG_NATIVE_XDP_UNVERIFIED.to_owned(),
            DG_REAL_JOURNALD_UNVERIFIED.to_owned(),
            DG_WORKLOAD_PERFORMANCE_UNVERIFIED.to_owned(),
        ]
    );
    assert!(!report.mutations_performed);
    assert_eq!(
        calls.borrow().as_slice(),
        [
            "inspect_installed_ownership",
            "inspect_installed_layout",
            "inspect_installed_service",
            "load_installed_authorization",
            "load_installed_performance",
            "inspect_authorized_interface",
            "inspect_installed_prerequisites",
        ]
    );
}

#[test]
fn inspect_maps_noisy_or_incomplete_performance_to_unavailable() {
    for (field, replacement) in [
        ("warm_up_complete", json!(false)),
        ("measurement_complete", json!(false)),
        ("measurement_noisy", json!(true)),
        ("host_identity_stable", json!(false)),
    ] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let performance = task6_performance(field, replacement, "unavailable");
        let filesystem = FakeFilesystem::passing(calls.clone()).with_performance(performance);
        let platform = FakePlatform::passing(calls.clone());
        let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

        let report = service.inspect().unwrap();

        assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
        assert!(report.canary_plan.is_none());
        assert_eq!(report.findings[0].code, DG_PERFORMANCE_UNAVAILABLE);
        assert!(!calls.borrow().contains(&"inspect_installed_prerequisites"));
    }
}

#[test]
fn inspect_maps_fixed_threshold_failures_to_regression() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let performance = task6_performance("map_count_after", json!(7), "failed");
    let filesystem = FakeFilesystem::passing(calls.clone()).with_performance(performance);
    let platform = FakePlatform::passing(calls.clone());
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

    let report = service.inspect().unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
    assert!(report.canary_plan.is_none());
    assert_eq!(report.findings[0].code, DG_PERFORMANCE_REGRESSION);
    assert!(!calls.borrow().contains(&"inspect_installed_prerequisites"));
}

#[test]
fn staging_short_circuits_after_the_first_untrusted_stage() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::failing(calls.clone(), "inspect_staged_service");
    let platform = FakePlatform::passing(calls.clone());
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

    let report = service
        .staging(
            Path::new("/tmp/exact-bundle"),
            Path::new("/run/l2-loop/accept/00112233445566778899aabbccddeeff/staging-root"),
        )
        .unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].code, DG_SYSTEMD_CONTRACT);
    assert_eq!(
        report.findings[0].severity,
        DeploymentFindingSeverityV1::Blocker
    );
    assert_eq!(
        calls.borrow().as_slice(),
        [
            "validate_staging_root",
            "inspect_bundle",
            "inspect_staged_layout",
            "inspect_staged_service",
        ]
    );
}

#[test]
fn inspect_identity_mismatch_stops_before_prerequisite_read() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::passing(calls.clone());
    let platform = FakePlatform::with_snapshot(calls.clone(), platform_snapshot("other0"));
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

    let report = service.inspect().unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
    assert!(report.canary_plan.is_none());
    assert_eq!(report.findings[0].code, DG_AUTH_IDENTITY);
    assert_eq!(
        calls.borrow().as_slice(),
        [
            "inspect_installed_ownership",
            "inspect_installed_layout",
            "inspect_installed_service",
            "load_installed_authorization",
            "load_installed_performance",
            "inspect_authorized_interface",
        ]
    );
}

#[test]
fn inspect_rejects_every_authorized_private_identity_mismatch() {
    let mutations: [fn(&mut DeploymentPlatformSnapshotV1); 4] = [
        |snapshot| snapshot.mac_address_sha256 = "d".repeat(64),
        |snapshot| snapshot.driver = "other_driver".into(),
        |snapshot| snapshot.device_identity_sha256 = "e".repeat(64),
        |snapshot| snapshot.network_namespace_sha256 = "f".repeat(64),
    ];
    for mutate in mutations {
        let mut snapshot = platform_snapshot("spare0");
        mutate(&mut snapshot);
        assert_platform_code(snapshot, DG_AUTH_IDENTITY);
    }
}

#[test]
fn inspect_rejects_each_missing_physical_readiness_fact() {
    let mutations: [fn(&mut DeploymentPlatformSnapshotV1); 6] = [
        |snapshot| snapshot.capabilities_sufficient = false,
        |snapshot| snapshot.native_xdp_driver_ready = false,
        |snapshot| snapshot.receive_queue_count = 0,
        |snapshot| snapshot.offload_state_known = false,
        |snapshot| snapshot.preflight.kernel.btf_readable = false,
        |snapshot| snapshot.preflight.bpf.bpffs_mounted = false,
    ];
    for mutate in mutations {
        let mut snapshot = platform_snapshot("spare0");
        mutate(&mut snapshot);
        assert_platform_code(snapshot, DG_PLATFORM_BLOCKED);
    }
}

#[test]
fn inspect_report_never_exposes_raw_mac_pci_or_namespace_identity() {
    let report = inspect_snapshot(platform_snapshot("spare0"));
    let rendered = serde_json::to_string(&report).unwrap();
    for private in [
        "aa:bb:cc:dd:ee:ff",
        "0000:01:00.0",
        "net:[4026531993]",
        "/sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0",
    ] {
        assert!(!rendered.contains(private));
    }
}

#[test]
fn inspect_requires_exactly_the_existing_live_interface_blocker() {
    for findings in [
        Vec::new(),
        vec![
            PreflightFinding::blocker(PF_LIVE_INTERFACE, "live interface attachment is refused"),
            PreflightFinding::blocker(PF_INTERFACE_UNSUPPORTED, "additional blocker"),
        ],
    ] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let filesystem = FakeFilesystem::passing(calls.clone());
        let mut snapshot = platform_snapshot("spare0");
        snapshot.preflight = physical_preflight(findings);
        let platform = FakePlatform::with_snapshot(calls, snapshot);
        let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

        let report = service.inspect().unwrap();

        assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
        assert!(report.canary_plan.is_none());
        assert_eq!(report.findings[0].code, DG_PLATFORM_BLOCKED);
    }
}

#[test]
fn inspect_accepts_live_refusal_but_rejects_reserved_port_consumers() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::passing(calls.clone());
    let mut snapshot = platform_snapshot("spare0");
    snapshot.address_present = true;
    let platform = FakePlatform::with_snapshot(calls, snapshot);
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

    let report = service.inspect().unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
    assert!(report.canary_plan.is_none());
    assert_eq!(report.findings[0].code, DG_PLATFORM_BLOCKED);
}

#[test]
fn inspect_rejects_every_unsupported_or_unstable_interface_shape() {
    let kinds = [
        InterfaceKind::Bond,
        InterfaceKind::Veth,
        InterfaceKind::Bridge,
        InterfaceKind::OvsInternal,
        InterfaceKind::Tap,
        InterfaceKind::Unsupported,
    ];
    for kind in kinds {
        let mut snapshot = platform_snapshot("spare0");
        snapshot.kind = kind;
        snapshot.preflight.interface.kind = kind;
        assert_platform_code(snapshot, DG_INTERFACE_UNSUPPORTED);
    }

    let mutations: [fn(&mut DeploymentPlatformSnapshotV1); 3] = [
        |snapshot| {
            snapshot.administrative_up = false;
            snapshot.preflight.interface.admin_up = false;
        },
        |snapshot| {
            snapshot.operational_up = false;
            snapshot.preflight.interface.oper_up = false;
        },
        |snapshot| {
            snapshot.master_ifindex = Some(19);
            snapshot.preflight.interface.master = Some(InterfaceRef {
                name: InterfaceName::new("master0").unwrap(),
                ifindex: 19,
            });
        },
    ];
    for mutate in mutations {
        let mut snapshot = platform_snapshot("spare0");
        mutate(&mut snapshot);
        assert_platform_code(snapshot, DG_INTERFACE_UNSUPPORTED);
    }
}

#[test]
fn inspect_rejects_every_nonempty_or_unknown_xdp_state_without_identity_leakage() {
    for state in [
        AttachmentState::Occupied {
            program_id: 987_654_321,
        },
        AttachmentState::Owned { program_id: 42 },
        AttachmentState::Unknown,
    ] {
        for native in [true, false] {
            let mut snapshot = platform_snapshot("spare0");
            if native {
                snapshot.preflight.bpf.xdp_native = state;
            } else {
                snapshot.preflight.bpf.xdp_generic = state;
            }
            let report = inspect_snapshot(snapshot);
            let rendered = serde_json::to_string(&report).unwrap();
            assert_eq!(report.findings[0].code, DG_XDP_NOT_EMPTY);
            assert!(!rendered.contains("987654321"));
            assert!(!rendered.contains("program_id"));
        }
    }
}

#[test]
fn inspect_rejects_clsact_and_each_tc_filter_direction() {
    let mut clsact = platform_snapshot("spare0");
    clsact.tc_clsact_present = true;
    assert_platform_code(clsact, DG_TC_NOT_EMPTY);

    for direction in [Direction::Ingress, Direction::Egress] {
        let mut snapshot = platform_snapshot("spare0");
        let attachment = TcAttachment {
            direction,
            priority: 49_714,
            handle: 0x4c32_0001,
            program_id: 41,
        };
        match direction {
            Direction::Ingress => snapshot.preflight.bpf.tc_ingress.push(attachment),
            Direction::Egress => snapshot.preflight.bpf.tc_egress.push(attachment),
        }
        assert_platform_code(snapshot, DG_TC_NOT_EMPTY);
    }
}

#[test]
fn inspect_rejects_each_visible_reserved_port_consumer() {
    let mutations: [fn(&mut DeploymentPlatformSnapshotV1); 5] = [
        |snapshot| snapshot.address_present = true,
        |snapshot| snapshot.route_present = true,
        |snapshot| snapshot.neighbor_present = true,
        |snapshot| snapshot.service_present = true,
        |snapshot| snapshot.other_consumer_present = true,
    ];
    for mutate in mutations {
        let mut snapshot = platform_snapshot("spare0");
        mutate(&mut snapshot);
        assert_platform_code(snapshot, DG_PLATFORM_BLOCKED);
    }
}

#[test]
fn adapter_failures_are_sanitized_bounded_reports() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::failing(calls, "inspect_installed_layout");
    let platform = FakePlatform::passing(Rc::new(RefCell::new(Vec::new())));
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

    let report = service.inspect().unwrap();
    let rendered = serde_json::to_string(&report).unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
    assert!(rendered.len() < 1_048_576);
    assert!(!rendered.contains("/secret/customer/path"));
    assert!(!rendered.contains("adapter error chain"));
    assert!(!rendered.contains("hostname"));
}

fn assert_platform_code(snapshot: DeploymentPlatformSnapshotV1, expected: &'static str) {
    let report = inspect_snapshot(snapshot);
    assert_eq!(report.decision, DeploymentDecisionV1::Blocked);
    assert!(report.canary_plan.is_none());
    assert_eq!(report.findings[0].code, expected);
}

fn inspect_snapshot(
    snapshot: DeploymentPlatformSnapshotV1,
) -> l2_loop_core::DeploymentGateReportV1 {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::passing(calls.clone());
    let platform = FakePlatform::with_snapshot(calls, snapshot);
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);
    service.inspect().unwrap()
}

#[test]
fn deployment_service_source_has_no_writer_or_attachment_dependency() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(manifest_dir.join("src/deployment.rs")).unwrap();
    for prohibited in [
        "DeploymentWriter",
        "install(",
        "repair(",
        "chmod(",
        "chown(",
        "systemctl",
        "journalctl",
        "AttachmentTransaction",
        "HookManager",
        "BpfObjectLoader",
        "SafeXdpPort",
        "SafeTcPort",
    ] {
        assert!(!source.contains(prohibited));
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn monotonic_ns(&self) -> u64 {
        123
    }

    fn wall_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(NOW_MS)
    }
}

struct FakeFilesystem {
    calls: Rc<RefCell<Vec<&'static str>>>,
    fail_at: Option<&'static str>,
    performance: Option<PerformanceEvidenceV1>,
}

impl FakeFilesystem {
    fn passing(calls: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self {
            calls,
            fail_at: None,
            performance: None,
        }
    }

    fn failing(calls: Rc<RefCell<Vec<&'static str>>>, fail_at: &'static str) -> Self {
        Self {
            calls,
            fail_at: Some(fail_at),
            performance: None,
        }
    }

    fn with_performance(mut self, performance: PerformanceEvidenceV1) -> Self {
        self.performance = Some(performance);
        self
    }

    fn call(&self, name: &'static str) -> Result<(), DeploymentIoError> {
        self.calls.borrow_mut().push(name);
        if self.fail_at == Some(name) {
            Err(DeploymentIoError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl DeploymentFilesystem for FakeFilesystem {
    fn validate_staging_root(&mut self, _root: &Path) -> Result<(), DeploymentIoError> {
        self.call("validate_staging_root")
    }

    fn inspect_bundle(&mut self, _bundle: &Path) -> Result<BundleSnapshotV1, DeploymentIoError> {
        self.call("inspect_bundle")?;
        Ok(BundleSnapshotV1::new(artifact()))
    }

    fn inspect_staged_layout(
        &mut self,
        _root: &Path,
    ) -> Result<LayoutSnapshotV1, DeploymentIoError> {
        self.call("inspect_staged_layout")?;
        Ok(LayoutSnapshotV1::new(artifact()))
    }

    fn inspect_staged_service(
        &mut self,
        _root: &Path,
    ) -> Result<ServiceUnitSnapshotV1, DeploymentIoError> {
        self.call("inspect_staged_service")?;
        Ok(ServiceUnitSnapshotV1::valid())
    }

    fn load_staged_authorization(
        &mut self,
        _root: &Path,
    ) -> Result<DeploymentAuthorizationV1, DeploymentIoError> {
        self.call("load_staged_authorization")?;
        Ok(authorization())
    }

    fn load_staged_performance(
        &mut self,
        _root: &Path,
    ) -> Result<PerformanceEvidenceV1, DeploymentIoError> {
        self.call("load_staged_performance")?;
        Ok(self.performance.clone().unwrap_or_else(performance))
    }

    fn inspect_staged_prerequisites(
        &mut self,
        _root: &Path,
    ) -> Result<DeploymentPrerequisitesV1, DeploymentIoError> {
        self.call("inspect_staged_prerequisites")?;
        Ok(DeploymentPrerequisitesV1::ready())
    }

    fn inspect_installed_layout(&mut self) -> Result<LayoutSnapshotV1, DeploymentIoError> {
        self.call("inspect_installed_layout")?;
        Ok(LayoutSnapshotV1::new(artifact()))
    }

    fn inspect_installed_ownership(
        &mut self,
    ) -> Result<InstalledOwnershipSnapshotV1, DeploymentIoError> {
        self.call("inspect_installed_ownership")?;
        InstalledOwnershipSnapshotV1::new(
            "11223344556677889900aabbccddeeff",
            "00112233445566778899aabbccddeeff",
            artifact(),
        )
    }

    fn inspect_installed_service(&mut self) -> Result<ServiceUnitSnapshotV1, DeploymentIoError> {
        self.call("inspect_installed_service")?;
        Ok(ServiceUnitSnapshotV1::valid())
    }

    fn load_installed_authorization(
        &mut self,
    ) -> Result<DeploymentAuthorizationV1, DeploymentIoError> {
        self.call("load_installed_authorization")?;
        Ok(authorization())
    }

    fn load_installed_performance(&mut self) -> Result<PerformanceEvidenceV1, DeploymentIoError> {
        self.call("load_installed_performance")?;
        Ok(self.performance.clone().unwrap_or_else(performance))
    }

    fn inspect_installed_prerequisites(
        &mut self,
    ) -> Result<DeploymentPrerequisitesV1, DeploymentIoError> {
        self.call("inspect_installed_prerequisites")?;
        Ok(DeploymentPrerequisitesV1::ready())
    }
}

struct FakePlatform {
    calls: Rc<RefCell<Vec<&'static str>>>,
    snapshot: DeploymentPlatformSnapshotV1,
}

impl FakePlatform {
    fn passing(calls: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self::with_snapshot(calls, platform_snapshot("spare0"))
    }

    fn with_snapshot(
        calls: Rc<RefCell<Vec<&'static str>>>,
        snapshot: DeploymentPlatformSnapshotV1,
    ) -> Self {
        Self { calls, snapshot }
    }
}

impl DeploymentPlatformInspector for FakePlatform {
    fn inspect_authorized_interface(
        &mut self,
        _authorization: &DeploymentAuthorizationV1,
    ) -> Result<DeploymentPlatformSnapshotV1, DeploymentIoError> {
        self.calls.borrow_mut().push("inspect_authorized_interface");
        Ok(self.snapshot.clone())
    }
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn host() -> DeploymentHostCompatibilityV1 {
    DeploymentHostCompatibilityV1::new("x86_64", "6.12.0-test", 8).unwrap()
}

fn authorization() -> DeploymentAuthorizationV1 {
    serde_json::from_value(json!({
        "schema_version": 1,
        "authorization_id": "00112233445566778899aabbccddeeff",
        "artifact_commit_sha": COMMIT_SHA,
        "mode": "read_only_canary_candidate",
        "interface": {
            "name": "spare0",
            "ifindex": 7,
            "kind": "physical",
            "administrative_state": "up",
            "operational_state": "up",
            "master_ifindex": null,
            "mac_address_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "driver": "test_driver",
            "device_identity_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "network_namespace_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "xdp_native": "empty",
            "xdp_generic": "empty",
            "tc_clsact": false,
            "tc_ingress": [],
            "tc_egress": []
        },
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": EXPIRES_MS
    }))
    .unwrap()
}

fn platform_snapshot(name: &str) -> DeploymentPlatformSnapshotV1 {
    DeploymentPlatformSnapshotV1 {
        preflight: physical_preflight(vec![PreflightFinding::blocker(
            PF_LIVE_INTERFACE,
            "live interface attachment is refused",
        )]),
        interface_name: InterfaceName::new(name).unwrap(),
        ifindex: 7,
        kind: InterfaceKind::Physical,
        administrative_up: true,
        operational_up: true,
        master_ifindex: None,
        mac_address_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .into(),
        driver: "test_driver".into(),
        device_identity_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .into(),
        network_namespace_sha256:
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        tc_clsact_present: false,
        address_present: false,
        route_present: false,
        neighbor_present: false,
        service_present: false,
        other_consumer_present: false,
        capabilities_sufficient: true,
        native_xdp_driver_ready: true,
        receive_queue_count: 8,
        offload_state_known: true,
        host: host(),
    }
}

fn physical_preflight(findings: Vec<PreflightFinding>) -> PreflightReport {
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
        findings,
    )
}

fn performance() -> PerformanceEvidenceV1 {
    let orders = [
        ["baseline", "pass_through", "observe"],
        ["pass_through", "observe", "baseline"],
        ["observe", "baseline", "pass_through"],
        ["baseline", "observe", "pass_through"],
        ["pass_through", "baseline", "observe"],
    ];
    let mut trials = Vec::new();
    for (trial_index, order) in orders.iter().enumerate() {
        for mode in order {
            let (duration_ns, pps, bps) = match *mode {
                "baseline" => (196_608_000_u64, 1_000_000_u64, 696_666_666_u64),
                "pass_through" => (204_800_000_u64, 960_000_u64, 668_800_000_u64),
                "observe" => (216_052_747_u64, 910_000_u64, 633_966_667_u64),
                _ => unreachable!(),
            };
            trials.push(json!({
                "trial_number": trial_index + 1,
                "mode": mode,
                "frame_sizes": [64, 512, 1514],
                "frames_per_size": 65536,
                "duration_ns": duration_ns,
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "daemon_cpu_time_ns": 10_000_000,
                "peak_resident_memory_bytes": 67_108_864,
                "packet_drop_delta": 0,
                "packet_error_delta": 0
            }));
        }
    }
    serde_json::from_value(json!({
        "schema_version": 1,
        "evidence_id": "ffeeddccbbaa99887766554433221100",
        "artifact_commit_sha": COMMIT_SHA,
        "package_version": "0.1.0",
        "architecture": "x86_64",
        "kernel_release": "6.12.0-test",
        "logical_cpu_count": 8,
        "veth_xdp_mode": "generic",
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": EXPIRES_MS,
        "warm_up_complete": true,
        "measurement_complete": true,
        "measurement_noisy": false,
        "host_identity_stable": true,
        "trials": trials,
        "medians": {
            "baseline": {"packets_per_second": 1_000_000, "bytes_per_second": 696_666_666},
            "pass_through": {"packets_per_second": 960_000, "bytes_per_second": 668_800_000},
            "observe": {"packets_per_second": 910_000, "bytes_per_second": 633_966_667}
        },
        "pass_through_baseline_ratio_permille": 960,
        "observe_baseline_ratio_permille": 910,
        "daemon_cpu_time_ns": 150_000_000,
        "daemon_cpu_permille": 48,
        "peak_resident_memory_bytes": 67_108_864,
        "rss_growth_bytes": 0,
        "packet_drop_delta": 0,
        "packet_error_delta": 0,
        "process_count_before": 1,
        "process_count_after": 1,
        "map_count_before": 6,
        "map_count_after": 6,
        "program_count_before": 2,
        "program_count_after": 2,
        "pin_count_before": 6,
        "pin_count_after": 6,
        "namespace_count_before": 1,
        "namespace_count_after": 1,
        "forwarding_intact": true,
        "owned_cleanup_complete": true,
        "network_identity_restored": true,
        "ebpf_identity_restored": true,
        "result": "passed",
        "findings": []
    }))
    .unwrap()
}

fn task6_performance(
    field: &str,
    replacement: serde_json::Value,
    result: &str,
) -> PerformanceEvidenceV1 {
    let mut value = serde_json::to_value(performance()).unwrap();
    value["warm_up_complete"] = json!(true);
    value["measurement_complete"] = json!(true);
    value["measurement_noisy"] = json!(false);
    value["host_identity_stable"] = json!(true);
    value["process_count_before"] = json!(1);
    value["process_count_after"] = json!(1);
    value["map_count_before"] = json!(6);
    value["map_count_after"] = json!(6);
    value["program_count_before"] = json!(2);
    value["program_count_after"] = json!(2);
    value["pin_count_before"] = json!(6);
    value["pin_count_after"] = json!(6);
    value["namespace_count_before"] = json!(1);
    value["namespace_count_after"] = json!(1);
    value[field] = replacement;
    value["result"] = json!(result);
    value["findings"] = json!([if result == "failed" {
        DG_PERFORMANCE_REGRESSION
    } else {
        DG_PERFORMANCE_UNAVAILABLE
    }]);
    serde_json::from_value(value).unwrap()
}
