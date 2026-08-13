use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use l2_loop_agent::{
    BundleSnapshotV1, Clock, DeploymentFilesystem, DeploymentGateService, DeploymentIoError,
    DeploymentPlatformInspector, DeploymentPlatformSnapshotV1, DeploymentPrerequisitesV1,
    LayoutSnapshotV1, ServiceUnitSnapshotV1,
};
use l2_loop_core::{
    AttachmentState, BpfInspection, DG_AUTH_IDENTITY, DG_PLATFORM_BLOCKED, DG_SYSTEMD_CONTRACT,
    DeploymentArtifactIdentityV1, DeploymentAuthorizationV1, DeploymentDecisionV1,
    DeploymentFindingSeverityV1, DeploymentHostCompatibilityV1, InterfaceInspection, InterfaceKind,
    InterfaceName, InterfaceRef, KernelInspection, MemlockInspection, PF_INTERFACE_UNSUPPORTED,
    PF_LIVE_INTERFACE, PerformanceEvidenceV1, PinRootState, PreflightFinding, PreflightReport,
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
fn inspect_calls_fixed_layout_gates_and_builds_non_executable_plan() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let filesystem = FakeFilesystem::passing(calls.clone());
    let platform = FakePlatform::passing(calls.clone());
    let mut service = DeploymentGateService::new(filesystem, platform, FixedClock);

    let report = service.inspect().unwrap();

    assert_eq!(report.decision, DeploymentDecisionV1::CanaryCandidate);
    assert_eq!(report.interface.as_ref().unwrap().name, "spare0");
    assert!(!report.canary_plan.as_ref().unwrap().executable);
    assert!(!report.mutations_performed);
    assert_eq!(
        calls.borrow().as_slice(),
        [
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
            "inspect_installed_layout",
            "inspect_installed_service",
            "load_installed_authorization",
            "load_installed_performance",
            "inspect_authorized_interface",
        ]
    );
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

#[test]
fn deployment_service_source_has_no_writer_or_attachment_dependency() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = ["src/deployment.rs", "src/ports.rs"]
        .iter()
        .map(|path| std::fs::read_to_string(manifest_dir.join(path)).unwrap_or_default())
        .collect::<String>();
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
}

impl FakeFilesystem {
    fn passing(calls: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self {
            calls,
            fail_at: None,
        }
    }

    fn failing(calls: Rc<RefCell<Vec<&'static str>>>, fail_at: &'static str) -> Self {
        Self {
            calls,
            fail_at: Some(fail_at),
        }
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
        Ok(performance())
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
        Ok(performance())
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
        tc_clsact_present: false,
        address_present: false,
        route_present: false,
        neighbor_present: false,
        service_present: false,
        other_consumer_present: false,
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
            let (pps, bps) = match *mode {
                "baseline" => (1_000_000_u64, 696_320_000_u64),
                "pass_through" => (960_000_u64, 668_467_200_u64),
                "observe" => (910_000_u64, 633_651_200_u64),
                _ => unreachable!(),
            };
            trials.push(json!({
                "trial_number": trial_index + 1,
                "mode": mode,
                "frame_sizes": [64, 512, 1514],
                "frames_per_size": 65536,
                "duration_ns": 196_608_000,
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
        "trials": trials,
        "medians": {
            "baseline": {"packets_per_second": 1_000_000, "bytes_per_second": 696_320_000},
            "pass_through": {"packets_per_second": 960_000, "bytes_per_second": 668_467_200},
            "observe": {"packets_per_second": 910_000, "bytes_per_second": 633_651_200}
        },
        "pass_through_baseline_ratio_permille": 960,
        "observe_baseline_ratio_permille": 910,
        "daemon_cpu_time_ns": 150_000_000,
        "daemon_cpu_permille": 100,
        "peak_resident_memory_bytes": 67_108_864,
        "rss_growth_bytes": 1_048_576,
        "packet_drop_delta": 0,
        "packet_error_delta": 0,
        "forwarding_intact": true,
        "owned_cleanup_complete": true,
        "network_identity_restored": true,
        "ebpf_identity_restored": true,
        "result": "passed",
        "findings": []
    }))
    .unwrap()
}
