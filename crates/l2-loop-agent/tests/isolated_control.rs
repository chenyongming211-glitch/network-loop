#![cfg(target_os = "linux")]

use std::sync::{Arc, Mutex};

use l2_loop_agent::{
    PlatformInspector, PortError, PreflightService,
    daemon::{DaemonDispatcher, IsolatedControl, IsolatedControlError},
    ownership::RunId,
    protocol::{ControlRequest, ResponseBody},
};
use l2_loop_core::{
    AgentCommand, AgentResult, AttachmentState, BpfInspection, InterfaceInspection, InterfaceKind,
    InterfaceName, InterfaceRef, KernelInspection, MemlockInspection, PF_LIVE_INTERFACE,
    PinRootState, PreflightReport,
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
