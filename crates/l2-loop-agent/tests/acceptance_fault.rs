#![cfg(target_os = "linux")]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use l2_loop_agent::{
    LoadedBpfObject, MapPublisher, PortError, SafeTcPort,
    linux::{
        acceptance_fault::{AcceptanceFault, FaultInjectingMaps, FaultInjectingTc},
        tc::LoadedTc,
        xdp::LoadedXdp,
    },
    ownership::{OwnedTc, TcHook},
};

#[test]
fn accepts_only_the_two_authorized_fault_stages() {
    assert_eq!(AcceptanceFault::parse(None).unwrap(), AcceptanceFault::None);
    assert_eq!(
        AcceptanceFault::parse(Some("tc-attach")).unwrap(),
        AcceptanceFault::TcAttach
    );
    assert_eq!(
        AcceptanceFault::parse(Some("map-initialize")).unwrap(),
        AcceptanceFault::MapInitialize
    );

    for invalid in ["", "xdp-attach", "tc-detach", "map-publish", "foreign"] {
        assert!(AcceptanceFault::parse(Some(invalid)).is_err());
    }
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
    let mut tc = FaultInjectingTc::new(FakeTc(tc_calls.clone()), AcceptanceFault::None);
    let mut maps = FaultInjectingMaps::new(FakeMaps(map_calls.clone()), AcceptanceFault::None);

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

    assert_eq!(tc_calls.load(Ordering::SeqCst), 1);
    assert_eq!(map_calls.load(Ordering::SeqCst), 1);
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
        pin_paths: Vec::new(),
    }
}
