#![cfg(target_os = "linux")]

use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use l2_loop_agent::{
    PlatformInspector, PortError, PreflightService,
    daemon::{
        BoundedUnixServer, DaemonDispatcher, IsolatedControl, IsolatedControlError,
        IsolatedSamplingOutcome,
    },
    ownership::RunId,
    protocol::{ControlRequest, ControlResponse, decode_request, encode_response},
    transport::{read_frame, write_frame},
};
use l2_loop_cli::{
    ClientError, EXIT_FAILURE, EXIT_SUCCESS, OutputFormat, RenderedOutput, UnixControlClient,
    render_response,
};
use l2_loop_core::{
    AgentCommand, AgentResult, ClassObservation, ClassRate, DetailedRateWindow, HookObservation,
    HookRate, HookRole, InterfaceName, InterfaceState, InterfaceStatus, OBSERVED_CLASS_COUNT,
    ObservationCounters, ObservationSnapshot, PreflightReport, RateCounters, RateWindowState,
    SamplingStatus, StatusRateWindow, TrafficClass, VlanVisibility,
};
use tokio::{io::AsyncReadExt, net::UnixListener, sync::oneshot};

#[tokio::test]
async fn sends_one_framed_request_and_reads_one_framed_response() {
    let socket = SocketFixture::new();
    let listener = UnixListener::bind(&socket.path).unwrap();
    let expected = AgentCommand::Preflight {
        interface: InterfaceName::new("veth-test").unwrap(),
    };
    let server_expected = expected.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = decode_request(&read_frame(&mut stream).await.unwrap()).unwrap();
        assert_eq!(request, ControlRequest::new(server_expected));
        let response = encode_response(&ControlResponse::success(AgentResult::Accepted)).unwrap();
        write_frame(&mut stream, &response).await.unwrap();

        let mut trailing = [0_u8; 1];
        assert_eq!(stream.read(&mut trailing).await.unwrap(), 0);
    });

    let response = UnixControlClient::new(&socket.path)
        .execute(expected)
        .await
        .unwrap();

    assert_eq!(response, ControlResponse::success(AgentResult::Accepted));
    server.await.unwrap();
}

#[tokio::test]
async fn observe_round_trips_from_the_cli_client_through_the_daemon_dispatcher() {
    let socket = SocketFixture::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let snapshot = observation();
    let server = BoundedUnixServer::bind(&socket.path).await.unwrap();
    let dispatcher = DaemonDispatcher::with_isolated_control(
        PreflightService::new(PanicInspector),
        ObserveControl {
            calls: calls.clone(),
            snapshot: snapshot.clone(),
        },
    );
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

    let response = UnixControlClient::new(&socket.path)
        .execute(AgentCommand::Observe {
            interface: InterfaceName::new("l2h0123456789").unwrap(),
        })
        .await
        .unwrap();

    assert_eq!(
        response,
        ControlResponse::success(AgentResult::Observation {
            snapshot: snapshot.clone(),
        })
    );
    let observe_text = render_response(response.clone(), OutputFormat::Text);
    let observe_json = render_response(response, OutputFormat::Json);
    assert_eq!(observe_text.exit_code, EXIT_SUCCESS);
    assert!(observe_text.stdout.contains("window: 1s"));
    assert!(observe_text.stdout.contains("pps: 7"));
    let observe_value: serde_json::Value = serde_json::from_str(&observe_json.stdout).unwrap();
    assert_eq!(observe_value["schema_version"], 2);
    assert_eq!(
        observe_value["rate_windows"][0]["hooks"][0]["total"]["bytes_per_second"],
        700
    );

    let status_response = UnixControlClient::new(&socket.path)
        .execute(AgentCommand::Status {
            interface: Some(InterfaceName::new("l2h0123456789").unwrap()),
        })
        .await
        .unwrap();
    assert_eq!(
        status_response,
        ControlResponse::success(AgentResult::Status {
            interfaces: vec![status_from(&snapshot)],
        })
    );
    let status_text = render_response(status_response, OutputFormat::Text);
    assert_eq!(status_text.exit_code, EXIT_SUCCESS);
    assert!(status_text.stdout.contains("window: 10s"));
    assert!(status_text.stdout.contains("state: warming_up"));
    assert!(status_text.stdout.contains("window: 60s"));
    assert!(status_text.stdout.contains("state: stale"));
    assert!(!status_text.stdout.contains("traffic_class:"));

    assert_eq!(
        calls.lock().unwrap().as_slice(),
        ["observe:l2h0123456789", "status:l2h0123456789"]
    );
    let _ = shutdown.send(());
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn transport_failures_render_with_exit_code_one() {
    let socket = SocketFixture::new();
    let error = UnixControlClient::new(&socket.path)
        .execute(AgentCommand::Preflight {
            interface: InterfaceName::new("veth-test").unwrap(),
        })
        .await
        .unwrap_err();

    assert!(matches!(error, ClientError::Connect(_)));
    let rendered = RenderedOutput::failure(error.to_string());
    assert_eq!(rendered.exit_code, EXIT_FAILURE);
    assert!(rendered.stdout.is_empty());
    assert!(!rendered.stderr.is_empty());
}

struct PanicInspector;

impl PlatformInspector for PanicInspector {
    fn inspect(&mut self, _: &InterfaceName) -> Result<PreflightReport, PortError> {
        panic!("observe must not invoke preflight")
    }
}

struct ObserveControl {
    calls: Arc<Mutex<Vec<String>>>,
    snapshot: ObservationSnapshot,
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
        interface: Option<&InterfaceName>,
    ) -> Result<Vec<InterfaceStatus>, IsolatedControlError> {
        self.calls.lock().unwrap().push(format!(
            "status:{}",
            interface.map_or("all", InterfaceName::as_str)
        ));
        Ok(vec![status_from(&self.snapshot)])
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
        let root = std::env::temp_dir().join(format!("l2-loop-cli-{}-{id}", std::process::id()));
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
        detailed_rate_windows(),
    )
    .unwrap()
}

fn status_from(snapshot: &ObservationSnapshot) -> InterfaceStatus {
    InterfaceStatus {
        interface: snapshot.interface.clone(),
        state: InterfaceState::Observing,
        generation: snapshot.generation,
        captured_at_unix_ms: snapshot.captured_at_unix_ms,
        health: snapshot.health,
        vlan_visibility: snapshot.vlan_visibility,
        xdp_ingress: snapshot.hooks[0].total,
        tc_egress: snapshot.hooks[1].total,
        sampling: snapshot.sampling.clone(),
        rate_windows: status_rate_windows(),
    }
}

fn detailed_rate_windows() -> [DetailedRateWindow; 3] {
    [
        DetailedRateWindow {
            window_ms: 1_000,
            state: RateWindowState::Ready,
            coverage_ms: 1_000,
            elapsed_ns: Some(1_000_000_000),
            start_unix_ms: Some(1_786_299_999_000),
            end_unix_ms: Some(1_786_300_000_000),
            hooks: Some([
                hook_rate(HookRole::ExternalXdpIngress, rate_counters(7, 700)),
                hook_rate(HookRole::PhysicalTcEgress, rate_counters(5, 500)),
            ]),
        },
        non_ready_detailed(10_000, RateWindowState::WarmingUp, 1_000),
        non_ready_detailed(60_000, RateWindowState::Stale, 12_000),
    ]
}

fn non_ready_detailed(
    window_ms: u64,
    state: RateWindowState,
    coverage_ms: u64,
) -> DetailedRateWindow {
    DetailedRateWindow {
        window_ms,
        state,
        coverage_ms,
        elapsed_ns: None,
        start_unix_ms: None,
        end_unix_ms: None,
        hooks: None,
    }
}

fn status_rate_windows() -> [StatusRateWindow; 3] {
    [
        StatusRateWindow {
            window_ms: 1_000,
            state: RateWindowState::Ready,
            coverage_ms: 1_000,
            elapsed_ns: Some(1_000_000_000),
            start_unix_ms: Some(1_786_299_999_000),
            end_unix_ms: Some(1_786_300_000_000),
            xdp_ingress: Some(rate_counters(7, 700)),
            tc_egress: Some(rate_counters(5, 500)),
        },
        non_ready_status(10_000, RateWindowState::WarmingUp, 1_000),
        non_ready_status(60_000, RateWindowState::Stale, 12_000),
    ]
}

fn non_ready_status(
    window_ms: u64,
    state: RateWindowState,
    coverage_ms: u64,
) -> StatusRateWindow {
    StatusRateWindow {
        window_ms,
        state,
        coverage_ms,
        elapsed_ns: None,
        start_unix_ms: None,
        end_unix_ms: None,
        xdp_ingress: None,
        tc_egress: None,
    }
}

fn hook_rate(role: HookRole, total: RateCounters) -> HookRate {
    HookRate {
        role,
        total,
        classes: CLASS_ORDER.map(|traffic_class| ClassRate {
            traffic_class,
            counters: rate_counters(1, 100),
        }),
        parse_errors: rate_counters(1, 100),
    }
}

fn rate_counters(packets: u64, bytes: u64) -> RateCounters {
    RateCounters {
        packet_delta: packets,
        byte_delta: bytes,
        packets_per_second: packets,
        bytes_per_second: bytes,
    }
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
