#![cfg(target_os = "linux")]

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use l2_loop_agent::{
    PlatformInspector, PortError, PreflightService,
    daemon::{
        BoundedUnixServer, DaemonDispatcher, DaemonError, IsolatedControl, IsolatedControlError,
        IsolatedSamplingOutcome,
    },
    ownership::RunId,
    protocol::{
        ControlRequest, ControlResponse, ERROR_COMMAND_NOT_IMPLEMENTED, ERROR_INTERNAL,
        ResponseBody, decode_response, encode_request,
    },
    transport::{read_frame, write_frame},
};
use l2_loop_core::{
    AgentCommand, AgentResult, AttachmentState, BpfInspection, ClassObservation, HookObservation,
    HookRole, InterfaceInspection, InterfaceKind, InterfaceName, InterfaceRef, InterfaceStatus,
    KernelInspection, MemlockInspection, OBSERVED_CLASS_COUNT, ObservationCounters,
    ObservationSnapshot, PinRootState, PreflightReport, SamplingStatus, TrafficClass,
    VlanVisibility, warming_detailed_rate_windows,
};
use tokio::{net::UnixStream, sync::oneshot, task::JoinHandle};

#[tokio::test]
async fn dispatches_preflight_through_the_real_control_socket() {
    let socket = SocketFixture::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let report = valid_report("veth-test");
    let daemon = RunningDaemon::start(
        &socket.path,
        FakeInspector::ok(calls.clone(), report.clone()),
    )
    .await;

    let response = exchange(
        &socket.path,
        AgentCommand::Preflight {
            interface: InterfaceName::new("veth-test").unwrap(),
        },
    )
    .await;

    assert_eq!(
        response,
        ControlResponse::success(AgentResult::Preflight { report })
    );
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        [InterfaceName::new("veth-test").unwrap()]
    );
    daemon.stop().await;
    assert!(!socket.path.exists());
}

#[tokio::test]
async fn rejects_unwired_commands_with_a_stable_error() {
    let socket = SocketFixture::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let daemon = RunningDaemon::start(
        &socket.path,
        FakeInspector::ok(calls.clone(), valid_report("veth-test")),
    )
    .await;

    let response = exchange(&socket.path, AgentCommand::Status { interface: None }).await;

    assert_eq!(
        error(&response),
        (ERROR_COMMAND_NOT_IMPLEMENTED, "command is not implemented")
    );
    assert!(calls.lock().unwrap().is_empty());
    daemon.stop().await;
}

#[tokio::test]
async fn observe_round_trips_through_the_real_bounded_unix_server() {
    let socket = SocketFixture::new();
    let observation_calls = Arc::new(Mutex::new(Vec::new()));
    let snapshot = observation();
    let daemon = RunningDaemon::start_with_control(
        &socket.path,
        FakeInspector::ok(Arc::new(Mutex::new(Vec::new())), valid_report("veth-test")),
        ObserveControl {
            calls: observation_calls.clone(),
            snapshot: snapshot.clone(),
        },
    )
    .await;

    let response = exchange(
        &socket.path,
        AgentCommand::Observe {
            interface: InterfaceName::new("l2h0123456789").unwrap(),
        },
    )
    .await;

    assert_eq!(
        response,
        ControlResponse::success(AgentResult::Observation { snapshot })
    );
    assert_eq!(
        observation_calls.lock().unwrap().as_slice(),
        ["observe:l2h0123456789"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn dispatcher_sample_uses_spawn_blocking_and_returns_outcome() {
    let caller_thread = std::thread::current().id();
    let sampling_thread = Arc::new(Mutex::new(None));
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(FakeInspector::ok(
            Arc::new(Mutex::new(Vec::new())),
            valid_report("veth-test"),
        )),
        ThreadRecordingControl {
            sampling_thread: sampling_thread.clone(),
        },
    );

    let outcome = dispatcher.sample_isolated().await.unwrap();

    assert_eq!(outcome, IsolatedSamplingOutcome::Sampled);
    let sampling_thread = (*sampling_thread.lock().unwrap()).unwrap();
    assert_ne!(sampling_thread, caller_thread);
}

#[tokio::test]
async fn hides_inspector_error_details_from_control_responses() {
    let socket = SocketFixture::new();
    let daemon = RunningDaemon::start(
        &socket.path,
        FakeInspector::error("private adapter detail must not escape"),
    )
    .await;

    let response = exchange(
        &socket.path,
        AgentCommand::Preflight {
            interface: InterfaceName::new("veth-test").unwrap(),
        },
    )
    .await;

    assert_eq!(
        error(&response),
        (ERROR_INTERNAL, "preflight inspection failed")
    );
    assert!(!format!("{response:?}").contains("private adapter detail"));
    daemon.stop().await;
}

#[tokio::test]
async fn shutdown_never_removes_a_replacement_at_the_socket_path() {
    let socket = SocketFixture::new();
    let daemon = RunningDaemon::start(
        &socket.path,
        FakeInspector::ok(Arc::new(Mutex::new(Vec::new())), valid_report("veth-test")),
    )
    .await;
    std::fs::remove_file(&socket.path).unwrap();
    std::fs::write(&socket.path, b"replacement must survive").unwrap();

    daemon.stop().await;

    assert_eq!(
        std::fs::read(&socket.path).unwrap(),
        b"replacement must survive"
    );
}

#[derive(Clone)]
struct FakeInspector {
    calls: Arc<Mutex<Vec<InterfaceName>>>,
    outcome: Result<PreflightReport, PortError>,
}

impl FakeInspector {
    fn ok(calls: Arc<Mutex<Vec<InterfaceName>>>, report: PreflightReport) -> Self {
        Self {
            calls,
            outcome: Ok(report),
        }
    }

    fn error(message: &str) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            outcome: Err(PortError::Adapter(message.into())),
        }
    }
}

impl PlatformInspector for FakeInspector {
    fn inspect(&mut self, interface: &InterfaceName) -> Result<PreflightReport, PortError> {
        self.calls.lock().unwrap().push(interface.clone());
        self.outcome.clone()
    }
}

struct RunningDaemon {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), DaemonError>>,
}

impl RunningDaemon {
    async fn start(path: &Path, inspector: FakeInspector) -> Self {
        let server = BoundedUnixServer::bind(path).await.unwrap();
        let dispatcher = DaemonDispatcher::new(PreflightService::new(inspector));
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(server.serve(
            move |request| {
                let dispatcher = dispatcher.clone();
                async move { dispatcher.dispatch(request).await }
            },
            async move {
                let _ = receiver.await;
            },
        ));
        Self { shutdown, task }
    }

    async fn start_with_control<C>(path: &Path, inspector: FakeInspector, control: C) -> Self
    where
        C: IsolatedControl + 'static,
    {
        let server = BoundedUnixServer::bind(path).await.unwrap();
        let dispatcher =
            DaemonDispatcher::with_isolated_control(PreflightService::new(inspector), control);
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(server.serve(
            move |request| {
                let dispatcher = dispatcher.clone();
                async move { dispatcher.dispatch(request).await }
            },
            async move {
                let _ = receiver.await;
            },
        ));
        Self { shutdown, task }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        self.task.await.unwrap().unwrap();
    }
}

struct ObserveControl {
    calls: Arc<Mutex<Vec<String>>>,
    snapshot: ObservationSnapshot,
}

struct ThreadRecordingControl {
    sampling_thread: Arc<Mutex<Option<std::thread::ThreadId>>>,
}

impl IsolatedControl for ThreadRecordingControl {
    fn attach(&mut self, _: &InterfaceName, _: &RunId) -> Result<(), IsolatedControlError> {
        panic!("sampling must not invoke attach")
    }

    fn detach(&mut self, _: &RunId) -> Result<(), IsolatedControlError> {
        panic!("sampling must not invoke detach")
    }

    fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError> {
        *self.sampling_thread.lock().unwrap() = Some(std::thread::current().id());
        Ok(IsolatedSamplingOutcome::Sampled)
    }

    fn observe(&mut self, _: &InterfaceName) -> Result<ObservationSnapshot, IsolatedControlError> {
        panic!("sampling must not invoke observe")
    }

    fn status(
        &mut self,
        _: Option<&InterfaceName>,
    ) -> Result<Vec<InterfaceStatus>, IsolatedControlError> {
        panic!("sampling must not invoke status")
    }

    fn shutdown(&mut self) -> Result<(), IsolatedControlError> {
        Ok(())
    }
}

impl IsolatedControl for ObserveControl {
    fn attach(&mut self, _: &InterfaceName, _: &RunId) -> Result<(), IsolatedControlError> {
        panic!("observe must not invoke attach")
    }

    fn detach(&mut self, _: &RunId) -> Result<(), IsolatedControlError> {
        panic!("observe must not invoke detach")
    }

    fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError> {
        panic!("observe must not invoke a background sample")
    }

    fn observe(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<ObservationSnapshot, IsolatedControlError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("observe:{}", interface.as_str()));
        Ok(self.snapshot.clone())
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

struct SocketFixture {
    root: PathBuf,
    path: PathBuf,
}

impl SocketFixture {
    fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("l2-loop-dispatch-{}-{id}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("agent.sock");
        Self { root, path }
    }
}

impl Drop for SocketFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.root);
    }
}

async fn exchange(path: &Path, command: AgentCommand) -> ControlResponse {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let frame = encode_request(&ControlRequest::new(command)).unwrap();
    write_frame(&mut stream, &frame).await.unwrap();
    decode_response(&read_frame(&mut stream).await.unwrap()).unwrap()
}

fn error(response: &ControlResponse) -> (&str, &str) {
    match &response.body {
        ResponseBody::Error { code, message } => (code, message),
        ResponseBody::Success { .. } => panic!("expected error response, got {response:?}"),
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
            admin_up: false,
            oper_up: false,
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

fn observation() -> ObservationSnapshot {
    ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        41,
        7,
        1_786_300_000_000,
        VlanVisibility::VerifiedVisible,
        [
            observation_hook(HookRole::ExternalXdpIngress),
            observation_hook(HookRole::PhysicalTcEgress),
        ],
        SamplingStatus::default(),
        warming_detailed_rate_windows(),
    )
    .unwrap()
}

fn observation_hook(role: HookRole) -> HookObservation {
    HookObservation {
        role,
        total: ObservationCounters {
            packets: 21,
            bytes: 1_260,
        },
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
