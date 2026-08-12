#![cfg(target_os = "linux")]

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use l2_loop_agent::{
    LoadedBpfObject, MapPublisher, ObservationReadPurpose, ObservationReader, PortError,
    RawObservation, SafeTcPort,
    linux::{
        acceptance_fault::{
            AcceptanceFault, FaultInjectingMaps, FaultInjectingObservation,
            FaultInjectingObservationReader, FaultInjectingTc,
        },
        observation::ObservationIo,
        tc::LoadedTc,
        xdp::LoadedXdp,
    },
    ownership::{OwnedMapPin, OwnedTc, OwnershipRecord, TcHook},
};
use l2_loop_common::{
    CounterValue, InterfaceConfig, StatsKey, agent_mode, hook_role, vlan_visibility,
};
use l2_loop_core::FingerprintEvidence;

#[test]
fn accepts_only_the_authorized_fault_stages() {
    assert_eq!(AcceptanceFault::parse(None).unwrap(), AcceptanceFault::None);
    assert_eq!(
        AcceptanceFault::parse(Some("tc-attach")).unwrap(),
        AcceptanceFault::TcAttach
    );
    assert_eq!(
        AcceptanceFault::parse(Some("map-initialize")).unwrap(),
        AcceptanceFault::MapInitialize
    );
    assert_eq!(
        AcceptanceFault::parse(Some("observation-map-read")).unwrap(),
        AcceptanceFault::ObservationMapRead
    );
    assert_eq!(
        AcceptanceFault::parse(Some("rate-sampling-map-read")).unwrap(),
        AcceptanceFault::RateSamplingMapRead
    );
    assert_eq!(
        AcceptanceFault::parse(Some("baseline-sampling-map-read-recovery")).unwrap(),
        AcceptanceFault::BaselineSamplingMapReadRecovery
    );

    for invalid in ["", "xdp-attach", "tc-detach", "map-publish", "foreign"] {
        assert!(AcceptanceFault::parse(Some(invalid)).is_err());
    }
}

#[test]
fn baseline_sampling_recovery_fault_is_bounded_and_request_transparent() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut observation = FaultInjectingObservationReader::new(
        FakePurposeReader(calls.clone()),
        AcceptanceFault::BaselineSamplingMapReadRecovery,
    );
    let ownership = ownership();

    for _ in 0..75 {
        let error = observation
            .read_exact(&ownership, ObservationReadPurpose::BackgroundSample)
            .unwrap_err();
        assert!(error.to_string().contains("delegated request read"));
    }
    for _ in 0..8 {
        let error = observation
            .read_exact(&ownership, ObservationReadPurpose::BackgroundSample)
            .unwrap_err();
        assert!(error.to_string().contains("OBS_MAP_UNAVAILABLE"));
    }
    let recovered = observation
        .read_exact(&ownership, ObservationReadPurpose::BackgroundSample)
        .unwrap_err();
    assert!(recovered.to_string().contains("delegated request read"));
    let request = observation
        .read_exact(&ownership, ObservationReadPurpose::Request)
        .unwrap_err();
    assert!(request.to_string().contains("delegated request read"));
}

#[test]
fn rate_sampling_fault_fails_only_background_reads() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut observation = FaultInjectingObservationReader::new(
        FakePurposeReader(calls.clone()),
        AcceptanceFault::RateSamplingMapRead,
    );
    let ownership = ownership();

    let background_error = observation
        .read_exact(&ownership, ObservationReadPurpose::BackgroundSample)
        .unwrap_err();
    assert!(background_error.to_string().contains("OBS_MAP_UNAVAILABLE"));
    assert!(calls.lock().unwrap().is_empty());

    let request_error = observation
        .read_exact(&ownership, ObservationReadPurpose::Request)
        .unwrap_err();
    assert!(request_error.to_string().contains("delegated request read"));
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        [ObservationReadPurpose::Request]
    );
}

#[test]
fn observation_map_fault_fails_only_the_config_read() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut observation = FaultInjectingObservation::new(
        FakeObservation(calls.clone()),
        AcceptanceFault::ObservationMapRead,
    );
    let ownership = ownership();
    let pin = config_pin();
    let key = StatsKey::total(1, 17, hook_role::EXTERNAL_XDP_INGRESS);

    observation.verify_hooks(&ownership).unwrap();
    assert_eq!(observation.fresh_map_id(&pin).unwrap(), 301);
    let error = observation.read_config(&pin, 17).unwrap_err();
    assert!(matches!(error, PortError::Adapter(_)));
    assert!(observation.read_counter(&pin, &key).unwrap().is_some());
    assert!(observation.current_keys(&pin).unwrap().is_empty());

    assert_eq!(
        calls.lock().unwrap().as_slice(),
        [
            "verify-hooks",
            "fresh-map-id",
            "read-counter",
            "current-keys"
        ]
    );
}

#[test]
fn tc_fault_fails_before_the_inner_attach_and_preserves_cleanup_calls() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut tc = FaultInjectingTc::new(FakeTc(calls.clone()), AcceptanceFault::TcAttach);

    let error = tc
        .attach_explicit(
            17,
            TcHook::Egress,
            LoadedTc {
                program_fd: 12,
                program_id: 102,
            },
        )
        .unwrap_err();

    assert!(matches!(error, PortError::Adapter(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    tc.detach_exact(&owned_tc()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn map_fault_fails_before_initialization_but_never_blocks_exact_rollback() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut maps = FaultInjectingMaps::new(FakeMaps(calls.clone()), AcceptanceFault::MapInitialize);
    let loaded = loaded();

    let error = maps.initialize_dependent(&loaded, 17, 1).unwrap_err();

    assert!(matches!(error, PortError::Adapter(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    maps.rollback_initialized_exact(&loaded, 17, 1).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn no_fault_delegates_without_changing_normal_behavior() {
    let tc_calls = Arc::new(AtomicUsize::new(0));
    let map_calls = Arc::new(AtomicUsize::new(0));
    let observation_calls = Arc::new(Mutex::new(Vec::new()));
    let mut tc = FaultInjectingTc::new(FakeTc(tc_calls.clone()), AcceptanceFault::None);
    let mut maps = FaultInjectingMaps::new(FakeMaps(map_calls.clone()), AcceptanceFault::None);
    let mut observation = FaultInjectingObservation::new(
        FakeObservation(observation_calls.clone()),
        AcceptanceFault::None,
    );

    tc.attach_explicit(
        17,
        TcHook::Egress,
        LoadedTc {
            program_fd: 12,
            program_id: 102,
        },
    )
    .unwrap();
    maps.initialize_dependent(&loaded(), 17, 1).unwrap();
    assert_eq!(
        observation.read_config(&config_pin(), 17).unwrap(),
        interface_config()
    );

    assert_eq!(tc_calls.load(Ordering::SeqCst), 1);
    assert_eq!(map_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        observation_calls.lock().unwrap().as_slice(),
        ["read-config"]
    );
}

struct FakeTc(Arc<AtomicUsize>);

impl SafeTcPort for FakeTc {
    fn attach_explicit(
        &mut self,
        _ifindex: u32,
        _hook: TcHook,
        _loaded: LoadedTc,
    ) -> Result<OwnedTc, PortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(owned_tc())
    }

    fn verify_exact(&mut self, _owned: &OwnedTc) -> Result<(), PortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn detach_exact(&mut self, _owned: &OwnedTc) -> Result<(), PortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FakeMaps(Arc<AtomicUsize>);

impl MapPublisher for FakeMaps {
    fn initialize_dependent(
        &mut self,
        _loaded: &LoadedBpfObject,
        _ifindex: u32,
        _generation: u64,
    ) -> Result<(), PortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn publish_iface_config(
        &mut self,
        _loaded: &LoadedBpfObject,
        _ifindex: u32,
        _generation: u64,
    ) -> Result<(), PortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn rollback_initialized_exact(
        &mut self,
        _loaded: &LoadedBpfObject,
        _ifindex: u32,
        _generation: u64,
    ) -> Result<(), PortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FakeObservation(Arc<Mutex<Vec<&'static str>>>);

struct FakePurposeReader(Arc<Mutex<Vec<ObservationReadPurpose>>>);

impl ObservationReader for FakePurposeReader {
    fn read_exact(
        &mut self,
        _ownership: &OwnershipRecord,
        purpose: ObservationReadPurpose,
    ) -> Result<RawObservation, PortError> {
        self.0.lock().unwrap().push(purpose);
        Err(PortError::Adapter("delegated request read".to_owned()))
    }
}

impl ObservationIo for FakeObservation {
    fn verify_hooks(&mut self, _ownership: &OwnershipRecord) -> Result<(), PortError> {
        self.0.lock().unwrap().push("verify-hooks");
        Ok(())
    }

    fn fresh_map_id(&mut self, _pin: &OwnedMapPin) -> Result<u32, PortError> {
        self.0.lock().unwrap().push("fresh-map-id");
        Ok(301)
    }

    fn read_config(
        &mut self,
        _pin: &OwnedMapPin,
        _ifindex: u32,
    ) -> Result<InterfaceConfig, PortError> {
        self.0.lock().unwrap().push("read-config");
        Ok(interface_config())
    }

    fn read_counter(
        &mut self,
        _pin: &OwnedMapPin,
        _key: &StatsKey,
    ) -> Result<Option<Vec<CounterValue>>, PortError> {
        self.0.lock().unwrap().push("read-counter");
        Ok(Some(vec![CounterValue {
            packets: 1,
            bytes: 60,
        }]))
    }

    fn current_keys(&mut self, _pin: &OwnedMapPin) -> Result<Vec<StatsKey>, PortError> {
        self.0.lock().unwrap().push("current-keys");
        Ok(Vec::new())
    }

    fn read_fingerprints(
        &mut self,
        _pin: &OwnedMapPin,
    ) -> Result<Vec<FingerprintEvidence>, PortError> {
        self.0.lock().unwrap().push("read-fingerprints");
        Ok(Vec::new())
    }
}

fn owned_tc() -> OwnedTc {
    OwnedTc {
        ifindex: 17,
        hook: TcHook::Egress,
        priority: 49_600,
        handle: 0x4c32_0002,
        program_id: 102,
        created_clsact: true,
    }
}

fn loaded() -> LoadedBpfObject {
    LoadedBpfObject {
        xdp: LoadedXdp {
            program_fd: 11,
            program_id: 101,
            program_tag: [1; 8],
        },
        tc_egress: LoadedTc {
            program_fd: 12,
            program_id: 102,
        },
        map_pins: Vec::new(),
    }
}

fn ownership() -> OwnershipRecord {
    OwnershipRecord {
        schema_version: 2,
        abi_version: 1,
        generation: 1,
        ifindex: 17,
        xdp: None,
        tc: Vec::new(),
        map_pins: Vec::new(),
        created_at_unix_seconds: 1,
    }
}

fn config_pin() -> OwnedMapPin {
    OwnedMapPin::new(
        "IFACE_CONFIG",
        PathBuf::from("/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef/IFACE_CONFIG"),
        301,
    )
    .unwrap()
}

fn interface_config() -> InterfaceConfig {
    InterfaceConfig::new(
        1,
        0,
        17,
        agent_mode::OBSERVE,
        hook_role::EXTERNAL_XDP_INGRESS,
        vlan_visibility::UNKNOWN,
        0,
    )
}
