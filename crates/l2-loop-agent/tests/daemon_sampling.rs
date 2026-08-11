#![cfg(target_os = "linux")]

use std::{
    future::pending,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use l2_loop_agent::{
    PlatformInspector, PortError, PreflightService,
    daemon::{
        DaemonDispatcher, DaemonError, IsolatedControl, IsolatedControlError,
        IsolatedSamplingOutcome, coordinate_daemon, run_sampling_loop_with_period,
    },
    ownership::RunId,
};
use l2_loop_core::{InterfaceName, InterfaceStatus, ObservationSnapshot, PreflightReport};
use tokio::sync::{oneshot, watch};

#[tokio::test]
async fn sampling_loop_never_overlaps_a_slow_tick() {
    let state = Arc::new(SamplerState::default());
    let dispatcher = dispatcher(SamplerControl::new(
        state.clone(),
        TickBehavior::Slow(Duration::from_millis(30)),
    ));
    let (shutdown, receiver) = watch::channel(false);
    let sampler = tokio::spawn(run_sampling_loop_with_period(
        dispatcher,
        receiver,
        Duration::from_millis(5),
    ));

    wait_for_count(&state.calls, 2).await;
    shutdown.send(true).unwrap();
    sampler.await.unwrap().unwrap();

    assert_eq!(state.max_active.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sampling_loop_stops_without_starting_another_tick() {
    let state = Arc::new(SamplerState::default());
    let gate = Arc::new(BlockingGate::default());
    let dispatcher = dispatcher(SamplerControl::new(
        state.clone(),
        TickBehavior::Gate(gate.clone()),
    ));
    let (shutdown, receiver) = watch::channel(false);
    let sampler = tokio::spawn(run_sampling_loop_with_period(
        dispatcher,
        receiver,
        Duration::from_millis(5),
    ));
    wait_for_count(&state.calls, 1).await;

    shutdown.send(true).unwrap();
    gate.release();
    sampler.await.unwrap().unwrap();

    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sampling_loop_does_not_replay_missed_ticks() {
    let state = Arc::new(SamplerState::default());
    let gate = Arc::new(BlockingGate::default());
    let dispatcher = dispatcher(SamplerControl::new(
        state.clone(),
        TickBehavior::Gate(gate.clone()),
    ));
    let (shutdown, receiver) = watch::channel(false);
    let sampler = tokio::spawn(run_sampling_loop_with_period(
        dispatcher,
        receiver,
        Duration::from_millis(100),
    ));
    wait_for_count(&state.calls, 1).await;

    tokio::time::sleep(Duration::from_millis(220)).await;
    gate.release();
    wait_for_count(&state.completed, 1).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    shutdown.send(true).unwrap();
    sampler.await.unwrap().unwrap();
}

#[tokio::test]
async fn sampler_failure_stops_server_and_invokes_shutdown_once() {
    let state = Arc::new(SamplerState::default());
    let dispatcher = dispatcher(SamplerControl::new(state.clone(), TickBehavior::Failure));
    let server_stops = Arc::new(AtomicUsize::new(0));
    let (shutdown, receiver) = watch::channel(false);
    let sampler = tokio::spawn(run_sampling_loop_with_period(
        dispatcher.clone(),
        receiver.clone(),
        Duration::from_millis(5),
    ));

    let result = coordinate_daemon(
        dispatcher,
        server_until_cancelled(receiver, server_stops.clone()),
        sampler,
        shutdown,
        pending(),
    )
    .await;

    assert!(matches!(result, Err(DaemonError::Sampler)));
    assert_eq!(server_stops.load(Ordering::SeqCst), 1);
    assert_eq!(state.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ordinary_rejected_sample_does_not_stop_daemon_or_cleanup() {
    let state = Arc::new(SamplerState::default());
    let dispatcher = dispatcher(SamplerControl::new(state.clone(), TickBehavior::Rejected));
    let server_stops = Arc::new(AtomicUsize::new(0));
    let (shutdown, receiver) = watch::channel(false);
    let sampler = tokio::spawn(run_sampling_loop_with_period(
        dispatcher.clone(),
        receiver.clone(),
        Duration::from_millis(5),
    ));
    let (signal, signalled) = oneshot::channel();
    let coordinator = tokio::spawn(coordinate_daemon(
        dispatcher,
        server_until_cancelled(receiver, server_stops.clone()),
        sampler,
        shutdown,
        async move {
            let _ = signalled.await;
        },
    ));

    wait_for_count(&state.calls, 2).await;
    assert_eq!(server_stops.load(Ordering::SeqCst), 0);
    assert_eq!(state.shutdowns.load(Ordering::SeqCst), 0);

    signal.send(()).unwrap();
    coordinator.await.unwrap().unwrap();
    assert_eq!(server_stops.load(Ordering::SeqCst), 1);
    assert_eq!(state.shutdowns.load(Ordering::SeqCst), 1);
}

#[derive(Default)]
struct SamplerState {
    calls: AtomicUsize,
    completed: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    shutdowns: AtomicUsize,
}

enum TickBehavior {
    Slow(Duration),
    Gate(Arc<BlockingGate>),
    Rejected,
    Failure,
}

struct SamplerControl {
    state: Arc<SamplerState>,
    behavior: TickBehavior,
}

impl SamplerControl {
    fn new(state: Arc<SamplerState>, behavior: TickBehavior) -> Self {
        Self { state, behavior }
    }
}

impl IsolatedControl for SamplerControl {
    fn attach(&mut self, _: &InterfaceName, _: &RunId) -> Result<(), IsolatedControlError> {
        panic!("sampler must not invoke attach")
    }

    fn detach(&mut self, _: &RunId) -> Result<(), IsolatedControlError> {
        panic!("sampler must not invoke detach")
    }

    fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError> {
        self.state.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.state.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.state.max_active.fetch_max(active, Ordering::SeqCst);

        let result = match &self.behavior {
            TickBehavior::Slow(duration) => {
                std::thread::sleep(*duration);
                Ok(IsolatedSamplingOutcome::Sampled)
            }
            TickBehavior::Gate(gate) => {
                gate.wait();
                Ok(IsolatedSamplingOutcome::Sampled)
            }
            TickBehavior::Rejected => Ok(IsolatedSamplingOutcome::Rejected),
            TickBehavior::Failure => Err(IsolatedControlError::internal("SAMPLER_TEST_FAILURE")),
        };

        self.state.active.fetch_sub(1, Ordering::SeqCst);
        self.state.completed.fetch_add(1, Ordering::SeqCst);
        result
    }

    fn observe(
        &mut self,
        _: &InterfaceName,
    ) -> Result<ObservationSnapshot, IsolatedControlError> {
        panic!("sampler must not invoke observe")
    }

    fn status(
        &mut self,
        _: Option<&InterfaceName>,
    ) -> Result<Vec<InterfaceStatus>, IsolatedControlError> {
        panic!("sampler must not invoke status")
    }

    fn shutdown(&mut self) -> Result<(), IsolatedControlError> {
        self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
struct BlockingGate {
    released: Mutex<bool>,
    changed: Condvar,
}

impl BlockingGate {
    fn wait(&self) {
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct PanicInspector;

impl PlatformInspector for PanicInspector {
    fn inspect(&mut self, _: &InterfaceName) -> Result<PreflightReport, PortError> {
        panic!("sampler must not invoke preflight")
    }
}

fn dispatcher(control: SamplerControl) -> DaemonDispatcher<PanicInspector> {
    DaemonDispatcher::with_isolated_control(PreflightService::new(PanicInspector), control)
}

async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while counter.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sampler did not reach the expected count");
}

async fn server_until_cancelled(
    mut receiver: watch::Receiver<bool>,
    stops: Arc<AtomicUsize>,
) -> Result<(), DaemonError> {
    loop {
        if *receiver.borrow() {
            break;
        }
        if receiver.changed().await.is_err() {
            break;
        }
    }
    stops.fetch_add(1, Ordering::SeqCst);
    Ok(())
}
