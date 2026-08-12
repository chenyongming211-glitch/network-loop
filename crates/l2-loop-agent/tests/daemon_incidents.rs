#![cfg(target_os = "linux")]

use std::{
    sync::{Arc, Condvar, Mutex, mpsc as std_mpsc},
    time::Duration,
};

use l2_loop_agent::{
    EventIdSource, IncidentIdentity, IncidentOutputBackend, IncidentOutputError,
    IncidentOutputShutdown, IncidentOutputSubmitError, IncidentOutputWorker, IncidentRecorder,
    IncidentRecorderError, IncidentWriteJob,
};
use l2_loop_core::{
    AlertSinkMode, ClassObservation, DetectionState, DetectionTransition, DetectionTransitionReason,
    EventId, EvidenceStatus, HookObservation, HookRole, InterfaceName, ObservationCounters,
    ObservationSnapshot, SamplingStatus, TrafficClass, VlanVisibility,
    warming_detailed_rate_windows,
};

struct FixedId(EventId);

impl EventIdSource for FixedId {
    fn next_id(&mut self) -> Result<EventId, IncidentRecorderError> {
        Ok(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Persist(u64),
    Alert(u64, EvidenceStatus),
}

struct RecordingBackend {
    calls: Arc<Mutex<Vec<Call>>>,
    fail_revision: Option<u64>,
    entered: Option<std_mpsc::Sender<()>>,
    gate: Option<Arc<(Mutex<bool>, Condvar)>>,
}

impl IncidentOutputBackend for RecordingBackend {
    fn persist(&mut self, job: &IncidentWriteJob) -> Result<(), IncidentOutputError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Persist(job.revision.revision));
        if let Some(entered) = self.entered.take() {
            entered.send(()).unwrap();
        }
        if let Some(gate) = &self.gate {
            let (lock, changed) = &**gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = changed.wait(open).unwrap();
            }
        }
        if self.fail_revision == Some(job.revision.revision) {
            Err(IncidentOutputError::StoreUnavailable)
        } else {
            Ok(())
        }
    }

    fn alert(
        &mut self,
        job: &IncidentWriteJob,
        evidence_status: EvidenceStatus,
    ) -> AlertSinkMode {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Alert(job.revision.revision, evidence_status));
        AlertSinkMode::StderrJson
    }
}

fn job(revision: u64) -> IncidentWriteJob {
    let identity =
        IncidentIdentity::new(InterfaceName::new("l2h0123456789").unwrap(), 42, 7).unwrap();
    let mut recorder = IncidentRecorder::new(identity, FixedId(EventId::from_bytes([1; 16])));
    let mut job = recorder
        .record(
            &DetectionTransition {
                sequence: 1,
                previous_state: DetectionState::Normal,
                current_state: DetectionState::IngressStormConfirmed,
                reason: DetectionTransitionReason::StormAsserted,
                occurred_at_unix_ms: 1_001,
            },
            &snapshot(),
        )
        .unwrap()
        .unwrap();
    job.revision.revision = revision;
    job.revision.transition_sequence = revision;
    job.revision.occurred_at_unix_ms = 1_000 + revision;
    job
}

fn snapshot() -> ObservationSnapshot {
    const CLASSES: [TrafficClass; 6] = [
        TrafficClass::L2Broadcast,
        TrafficClass::Ipv4Multicast,
        TrafficClass::Ipv6Multicast,
        TrafficClass::OtherL2Multicast,
        TrafficClass::LinkLocalControl,
        TrafficClass::UnicastOrUnclassified,
    ];
    let hook = |role| HookObservation {
        role,
        total: ObservationCounters {
            packets: 21,
            bytes: 1_260,
        },
        classes: CLASSES.map(|traffic_class| ClassObservation {
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
    };
    ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        42,
        7,
        1_000,
        VlanVisibility::VerifiedVisible,
        [
            hook(HookRole::ExternalXdpIngress),
            hook(HookRole::PhysicalTcEgress),
        ],
        SamplingStatus::default(),
        warming_detailed_rate_windows(),
    )
    .unwrap()
}

#[tokio::test]
async fn worker_preserves_order_and_publishes_only_after_each_persistence_attempt() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backend = RecordingBackend {
        calls: calls.clone(),
        fail_revision: Some(2),
        entered: None,
        gate: None,
    };
    let (output, worker) = IncidentOutputWorker::start(backend);

    output.try_submit(job(1)).unwrap();
    output.try_submit(job(2)).unwrap();
    output.try_submit(job(3)).unwrap();
    assert_eq!(
        worker.shutdown(Duration::from_secs(5)).await,
        IncidentOutputShutdown::Drained
    );

    assert_eq!(
        calls.lock().unwrap().as_slice(),
        [
            Call::Persist(1),
            Call::Alert(1, EvidenceStatus::Stored),
            Call::Persist(2),
            Call::Alert(2, EvidenceStatus::Unavailable),
            Call::Persist(3),
            Call::Alert(3, EvidenceStatus::Stored),
        ]
    );
    let health = output.health();
    assert!(!health.store_available);
    assert_eq!(
        health.last_error_code.as_deref(),
        Some("OUTPUT_STORE_UNAVAILABLE")
    );
}

#[tokio::test]
async fn full_queue_degrades_without_waiting_or_widening_the_capacity() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (entered_tx, entered_rx) = std_mpsc::channel();
    let backend = RecordingBackend {
        calls,
        fail_revision: None,
        entered: Some(entered_tx),
        gate: Some(gate.clone()),
    };
    let (output, worker) = IncidentOutputWorker::start(backend);

    output.try_submit(job(1)).unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || entered_rx.recv()),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    for revision in 2..=33 {
        output.try_submit(job(revision)).unwrap();
    }
    assert_eq!(
        output.try_submit(job(34)),
        Err(IncidentOutputSubmitError::QueueFull)
    );
    assert_eq!(output.health().dropped_job_count, 1);

    let (lock, changed) = &*gate;
    *lock.lock().unwrap() = true;
    changed.notify_all();
    assert_eq!(
        worker.shutdown(Duration::from_secs(5)).await,
        IncidentOutputShutdown::Drained
    );
}
