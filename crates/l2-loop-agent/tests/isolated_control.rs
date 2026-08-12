#![cfg(target_os = "linux")]

use std::sync::{Arc, Mutex};

use l2_loop_agent::{
    PlatformInspector, PortError, PreflightService,
    daemon::{DaemonDispatcher, IsolatedControl, IsolatedControlError, IsolatedSamplingOutcome},
    ownership::RunId,
    protocol::{ControlRequest, ResponseBody},
};
use l2_loop_core::{
    AgentCommand, AgentResult, AttachmentState, BpfInspection, ClassObservation, HookObservation,
    HookRole, InterfaceInspection, InterfaceKind, InterfaceName, InterfaceRef, InterfaceState,
    InterfaceStatus, KernelInspection, MemlockInspection, OBSERVED_CLASS_COUNT,
    ObservationCounters, ObservationHealth, ObservationSnapshot, PF_LIVE_INTERFACE, PinRootState,
    PreflightReport, SamplingStatus, TrafficClass, VlanVisibility, warming_detailed_rate_windows,
    warming_status_rate_windows,
};

const RUN_ID: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn dispatches_only_explicit_isolated_attach_and_detach_commands() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(FakeInspector::ready()),
        FakeControl::ok(calls.clone()),
    );

    let attach = dispatcher
        .dispatch(ControlRequest::new(AgentCommand::IsolatedAttach {
            interface: InterfaceName::new("veth-test").unwrap(),
            run_id: RUN_ID.to_owned(),
        }))
        .await;
    let detach = dispatcher
        .dispatch(ControlRequest::new(AgentCommand::IsolatedDetach {
            run_id: RUN_ID.to_owned(),
        }))
        .await;

    assert_eq!(success(&attach), &AgentResult::Accepted);
    assert_eq!(success(&detach), &AgentResult::Accepted);
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        [
            "attach:veth-test:0123456789abcdef0123456789abcdef",
            "detach:0123456789abcdef0123456789abcdef",
        ]
    );
}

#[tokio::test]
async fn observe_and_status_read_the_active_session_without_mutating_it() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let snapshot = fixture_snapshot();
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(FakeInspector::ready()),
        FakeControl::ok(calls.clone()),
    );

    let observe = dispatcher
        .dispatch(ControlRequest::new(AgentCommand::Observe {
            interface: interface(),
        }))
        .await;
    let status = dispatcher
        .dispatch(ControlRequest::new(AgentCommand::Status {
            interface: Some(interface()),
        }))
        .await;

    assert_eq!(
        success(&observe),
        &AgentResult::Observation {
            snapshot: snapshot.clone(),
        }
    );
    assert_eq!(
        success(&status),
        &AgentResult::Status {
            interfaces: vec![fixture_status(&snapshot)],
        }
    );
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        ["observe:l2h0123456789", "status:l2h0123456789"]
    );
}

#[tokio::test]
async fn observation_failures_expose_only_the_stable_obs_code() {
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(FakeInspector::ready()),
        FailingObservationControl,
    );

    let response = dispatcher
        .dispatch(ControlRequest::new(AgentCommand::Observe {
            interface: interface(),
        }))
        .await;

    assert_eq!(
        error(&response),
        ("OBS_MAP_IDENTITY_MISMATCH", "observation failed")
    );
    assert!(!format!("{response:?}").contains("private map path"));
}

#[tokio::test]
async fn daemon_rejects_invalid_run_ids_even_if_a_client_constructs_the_command() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(FakeInspector::ready()),
        FakeControl::ok(calls.clone()),
    );

    let response = dispatcher
        .dispatch(ControlRequest::new(AgentCommand::IsolatedDetach {
            run_id: "../unsafe".to_owned(),
        }))
        .await;

    assert_eq!(error(&response).0, "INVALID_REQUEST");
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn daemon_shutdown_invokes_exact_isolated_cleanup() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(FakeInspector::ready()),
        FakeControl::ok(calls.clone()),
    );

    dispatcher.shutdown_isolated().await.unwrap();

    assert_eq!(calls.lock().unwrap().as_slice(), ["shutdown"]);
}

#[tokio::test]
async fn blocked_non_veth_or_shared_targets_return_the_preflight_blocker() {
    for report in [
        report(InterfaceKind::Physical, true, false),
        report(InterfaceKind::Veth, false, false),
        report(InterfaceKind::Veth, true, true),
    ] {
        let dispatcher = DaemonDispatcher::with_isolated_control(
            PreflightService::new(FakeInspector::ready()),
            FakeControl::blocked(report),
        );
        let response = dispatcher
            .dispatch(ControlRequest::new(AgentCommand::IsolatedAttach {
                interface: InterfaceName::new("veth-test").unwrap(),
                run_id: RUN_ID.to_owned(),
            }))
            .await;

        assert_eq!(
            error(&response),
            (PF_LIVE_INTERFACE, "isolated attachment was blocked")
        );
    }
}

#[tokio::test]
async fn internal_attachment_failures_preserve_only_the_stable_stage_code() {
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(FakeInspector::ready()),
        FailingControl,
    );
    let response = dispatcher
        .dispatch(ControlRequest::new(AgentCommand::IsolatedAttach {
            interface: InterfaceName::new("veth-test").unwrap(),
            run_id: RUN_ID.to_owned(),
        }))
        .await;

    assert_eq!(
        error(&response),
        ("BPF_LOAD_FAILED", "isolated control failed")
    );
}

#[derive(Clone)]
struct FakeInspector {
    report: PreflightReport,
}

impl FakeInspector {
    fn ready() -> Self {
        Self {
            report: report(InterfaceKind::Veth, true, false),
        }
    }
}

impl PlatformInspector for FakeInspector {
    fn inspect(&mut self, _: &InterfaceName) -> Result<PreflightReport, PortError> {
        Ok(self.report.clone())
    }
}

struct FakeControl {
    calls: Arc<Mutex<Vec<String>>>,
    blocked: Option<PreflightReport>,
}

impl FakeControl {
    fn ok(calls: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            calls,
            blocked: None,
        }
    }

    fn blocked(report: PreflightReport) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            blocked: Some(report),
        }
    }
}

impl IsolatedControl for FakeControl {
    fn attach(
        &mut self,
        interface: &InterfaceName,
        run_id: &RunId,
    ) -> Result<(), IsolatedControlError> {
        if let Some(report) = &self.blocked {
            let inspected = &report.interface;
            if inspected.kind != InterfaceKind::Veth || !inspected.isolated || inspected.live_shared
            {
                return Err(IsolatedControlError::blocked(PF_LIVE_INTERFACE));
            }
        }
        self.calls.lock().unwrap().push(format!(
            "attach:{}:{}",
            interface.as_str(),
            run_id.as_str()
        ));
        Ok(())
    }

    fn detach(&mut self, run_id: &RunId) -> Result<(), IsolatedControlError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("detach:{}", run_id.as_str()));
        Ok(())
    }

    fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError> {
        Ok(IsolatedSamplingOutcome::Idle)
    }

    fn observe(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<ObservationSnapshot, IsolatedControlError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("observe:{}", interface.as_str()));
        Ok(fixture_snapshot())
    }

    fn status(
        &mut self,
        interface: Option<&InterfaceName>,
    ) -> Result<Vec<InterfaceStatus>, IsolatedControlError> {
        self.calls.lock().unwrap().push(format!(
            "status:{}",
            interface.map(InterfaceName::as_str).unwrap_or("all")
        ));
        let snapshot = fixture_snapshot();
        Ok(vec![fixture_status(&snapshot)])
    }

    fn shutdown(&mut self) -> Result<(), IsolatedControlError> {
        self.calls.lock().unwrap().push("shutdown".to_owned());
        Ok(())
    }
}

struct FailingControl;

impl IsolatedControl for FailingControl {
    fn attach(&mut self, _: &InterfaceName, _: &RunId) -> Result<(), IsolatedControlError> {
        Err(IsolatedControlError::internal("BPF_LOAD_FAILED"))
    }

    fn detach(&mut self, _: &RunId) -> Result<(), IsolatedControlError> {
        Ok(())
    }

    fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError> {
        Ok(IsolatedSamplingOutcome::Idle)
    }

    fn observe(&mut self, _: &InterfaceName) -> Result<ObservationSnapshot, IsolatedControlError> {
        Ok(fixture_snapshot())
    }

    fn status(
        &mut self,
        _: Option<&InterfaceName>,
    ) -> Result<Vec<InterfaceStatus>, IsolatedControlError> {
        Ok(Vec::new())
    }

    fn shutdown(&mut self) -> Result<(), IsolatedControlError> {
        Ok(())
    }
}

struct FailingObservationControl;

impl IsolatedControl for FailingObservationControl {
    fn attach(&mut self, _: &InterfaceName, _: &RunId) -> Result<(), IsolatedControlError> {
        Ok(())
    }

    fn detach(&mut self, _: &RunId) -> Result<(), IsolatedControlError> {
        Ok(())
    }

    fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError> {
        Ok(IsolatedSamplingOutcome::Idle)
    }

    fn observe(&mut self, _: &InterfaceName) -> Result<ObservationSnapshot, IsolatedControlError> {
        Err(IsolatedControlError::internal("OBS_MAP_IDENTITY_MISMATCH"))
    }

    fn status(
        &mut self,
        _: Option<&InterfaceName>,
    ) -> Result<Vec<InterfaceStatus>, IsolatedControlError> {
        Err(IsolatedControlError::internal("OBS_MAP_IDENTITY_MISMATCH"))
    }

    fn shutdown(&mut self) -> Result<(), IsolatedControlError> {
        Ok(())
    }
}

fn success(response: &l2_loop_agent::protocol::ControlResponse) -> &AgentResult {
    match &response.body {
        ResponseBody::Success { result } => result,
        ResponseBody::Error { .. } => panic!("expected success, got {response:?}"),
    }
}

fn error(response: &l2_loop_agent::protocol::ControlResponse) -> (&str, &str) {
    match &response.body {
        ResponseBody::Error { code, message } => (code, message),
        ResponseBody::Success { .. } => panic!("expected error, got {response:?}"),
    }
}

fn report(kind: InterfaceKind, isolated: bool, live_shared: bool) -> PreflightReport {
    PreflightReport::new(
        InterfaceInspection {
            requested: InterfaceRef {
                name: InterfaceName::new("veth-test").unwrap(),
                ifindex: 17,
            },
            kind,
            admin_up: false,
            oper_up: false,
            master: None,
            bond: None,
            proposed_targets: Vec::new(),
            isolated,
            live_shared,
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
                required_bytes: 8 * 1024 * 1024,
                can_raise: true,
            },
        },
        Vec::new(),
    )
}

const CLASS_ORDER: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

fn interface() -> InterfaceName {
    InterfaceName::new("l2h0123456789").unwrap()
}

fn fixture_snapshot() -> ObservationSnapshot {
    ObservationSnapshot::new(
        interface(),
        41,
        7,
        1_786_300_000_000,
        VlanVisibility::VerifiedVisible,
        [
            hook(HookRole::ExternalXdpIngress, 21, 1_260),
            hook(HookRole::PhysicalTcEgress, 18, 1_080),
        ],
        SamplingStatus::default(),
        warming_detailed_rate_windows(),
    )
    .unwrap()
}

fn hook(role: HookRole, packets: u64, bytes: u64) -> HookObservation {
    HookObservation {
        role,
        total: ObservationCounters { packets, bytes },
        classes: CLASS_ORDER.map(|traffic_class| ClassObservation {
            traffic_class,
            counters: ObservationCounters {
                packets: 1,
                bytes: 60,
            },
        }),
        parse_errors: ObservationCounters {
            packets: 0,
            bytes: 0,
        },
    }
}

fn fixture_status(snapshot: &ObservationSnapshot) -> InterfaceStatus {
    InterfaceStatus {
        interface: snapshot.interface.clone(),
        state: InterfaceState::Observing,
        generation: snapshot.generation,
        captured_at_unix_ms: snapshot.captured_at_unix_ms,
        health: ObservationHealth::Healthy,
        vlan_visibility: snapshot.vlan_visibility,
        xdp_ingress: snapshot.hooks[0].total,
        tc_egress: snapshot.hooks[1].total,
        sampling: snapshot.sampling.clone(),
        rate_windows: warming_status_rate_windows(),
        baseline: l2_loop_core::BaselineSummary::from_report(&snapshot.baseline),
        fingerprints: l2_loop_core::FingerprintSummary::from(&snapshot.fingerprints),
        detection: l2_loop_core::DetectionSummary::from(&snapshot.detection),
    }
}
