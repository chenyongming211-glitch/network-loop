#![cfg(target_os = "linux")]

use std::collections::VecDeque;

use l2_loop_agent::{
    linux::xdp::{
        LoadedXdp, SafeXdp, XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE,
        XDP_FLAGS_UPDATE_IF_NOEXIST, XdpDetachOutcome, XdpInventory, XdpIo, XdpIoError,
        XdpRollback, XdpSlot, XdpState, classify_inventory, encode_attach_request,
        encode_detach_request,
    },
    ownership::{OwnedXdp, XdpAttachMode, XdpKernelIdentity},
};
use l2_loop_core::{PF_XDP_OCCUPIED, PF_XDP_STATE_UNKNOWN};
use netlink_packet_route::link::{LinkAttribute, LinkXdp};

#[test]
fn classifies_empty_owned_foreign_unknown_and_cross_mode_occupancy() {
    let owned = owned_xdp(17, XdpAttachMode::Generic, 101, [1; 8]);

    assert_eq!(classify_inventory(&XdpInventory::empty(), None), XdpState::Empty);
    assert_eq!(
        classify_inventory(
            &XdpInventory::only(XdpAttachMode::Generic, XdpSlot::Attached(owned.into())),
            Some(&owned),
        ),
        XdpState::Owned
    );
    assert_eq!(
        classify_inventory(
            &XdpInventory::only(XdpAttachMode::Generic, XdpSlot::Attached(owned.into())),
            None,
        ),
        XdpState::Foreign
    );
    assert_eq!(
        classify_inventory(
            &XdpInventory::only(XdpAttachMode::Native, XdpSlot::Attached(owned.into())),
            None,
        ),
        XdpState::Foreign,
        "native occupancy must block a generic attach and vice versa"
    );
    assert_eq!(
        classify_inventory(
            &XdpInventory::only(XdpAttachMode::Generic, XdpSlot::Unknown),
            None,
        ),
        XdpState::Unknown
    );
}

#[test]
fn attach_message_always_encodes_mode_and_atomic_no_replace() {
    let generic = encode_attach_request(17, XdpAttachMode::Generic, 7);
    assert_eq!(generic.header.index, 17);
    assert_xdp_attributes(
        &generic.attributes,
        7,
        XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
        None,
    );

    let native = encode_attach_request(18, XdpAttachMode::Native, 8);
    assert_xdp_attributes(
        &native.attributes,
        8,
        XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
        None,
    );
}

#[test]
fn detach_message_uses_expected_fd_and_never_uses_no_replace() {
    let message = encode_detach_request(17, XdpAttachMode::Generic, 9);
    assert_xdp_attributes(&message.attributes, -1, XDP_FLAGS_SKB_MODE, Some(9));
}

#[test]
fn only_empty_inventory_reaches_attach() {
    for (inventory, expected_code) in [
        (
            XdpInventory::only(
                XdpAttachMode::Generic,
                XdpSlot::Attached(identity(17, XdpAttachMode::Generic, 201, [2; 8])),
            ),
            PF_XDP_OCCUPIED,
        ),
        (
            XdpInventory::only(XdpAttachMode::Generic, XdpSlot::Unknown),
            PF_XDP_STATE_UNKNOWN,
        ),
    ] {
        let io = FakeXdpIo::with_queries([Ok(inventory)]);
        let calls = io.calls.clone();
        let error = SafeXdp::new(io)
            .attach(17, XdpAttachMode::Generic, loaded())
            .unwrap_err();

        assert_eq!(error.code(), expected_code);
        assert_eq!(calls.borrow().as_slice(), [Call::Query(17)]);
    }
}

#[test]
fn query_error_blocks_as_unknown_before_attach() {
    let io = FakeXdpIo::with_queries([Err(XdpIoError::Failed("query failed".into()))]);
    let calls = io.calls.clone();
    let error = SafeXdp::new(io)
        .attach(17, XdpAttachMode::Generic, loaded())
        .unwrap_err();

    assert_eq!(error.code(), PF_XDP_STATE_UNKNOWN);
    assert_eq!(calls.borrow().as_slice(), [Call::Query(17)]);
}

#[test]
fn eexist_is_one_attempt_and_never_retried_without_no_replace() {
    let mut io = FakeXdpIo::with_queries([Ok(XdpInventory::empty())]);
    io.attach_result = Err(XdpIoError::Exists);
    let calls = io.calls.clone();
    let error = SafeXdp::new(io)
        .attach(17, XdpAttachMode::Generic, loaded())
        .unwrap_err();

    assert_eq!(error.code(), PF_XDP_OCCUPIED);
    assert_eq!(
        calls.borrow().as_slice(),
        [
            Call::Query(17),
            Call::Attach {
                ifindex: 17,
                mode: XdpAttachMode::Generic,
                program_fd: 7,
            },
        ]
    );
}

#[test]
fn verification_mismatch_rolls_back_only_the_new_program_id() {
    let loaded = loaded();
    let same_id_wrong_tag = identity(17, XdpAttachMode::Generic, 101, [9; 8]);
    let io = FakeXdpIo::with_queries([
        Ok(XdpInventory::empty()),
        Ok(XdpInventory::only(
            XdpAttachMode::Generic,
            XdpSlot::Attached(same_id_wrong_tag),
        )),
    ]);
    let calls = io.calls.clone();
    let error = SafeXdp::new(io)
        .attach(17, XdpAttachMode::Generic, loaded)
        .unwrap_err();

    assert_eq!(error.rollback(), Some(XdpRollback::Completed));
    assert_eq!(
        calls.borrow().last(),
        Some(&Call::Detach {
            ifindex: 17,
            mode: XdpAttachMode::Generic,
            expected_program_id: 101,
        })
    );
}

#[test]
fn verification_mismatch_retains_a_different_current_program() {
    let foreign = identity(17, XdpAttachMode::Generic, 202, [2; 8]);
    let io = FakeXdpIo::with_queries([
        Ok(XdpInventory::empty()),
        Ok(XdpInventory::only(
            XdpAttachMode::Generic,
            XdpSlot::Attached(foreign),
        )),
    ]);
    let calls = io.calls.clone();
    let error = SafeXdp::new(io)
        .attach(17, XdpAttachMode::Generic, loaded())
        .unwrap_err();

    assert_eq!(error.rollback(), Some(XdpRollback::RetainedIdentityMismatch));
    assert!(!calls.borrow().iter().any(|call| matches!(call, Call::Detach { .. })));
}

#[test]
fn detach_requires_a_fresh_exact_identity_match() {
    let owned = owned_xdp(17, XdpAttachMode::Generic, 101, [1; 8]);
    let exact = FakeXdpIo::with_queries([Ok(XdpInventory::only(
        XdpAttachMode::Generic,
        XdpSlot::Attached(owned.into()),
    ))]);
    let exact_calls = exact.calls.clone();
    assert_eq!(
        SafeXdp::new(exact).detach(&owned).unwrap(),
        XdpDetachOutcome::Detached
    );
    assert!(matches!(exact_calls.borrow().last(), Some(Call::Detach { .. })));

    let changed = FakeXdpIo::with_queries([Ok(XdpInventory::only(
        XdpAttachMode::Generic,
        XdpSlot::Attached(identity(17, XdpAttachMode::Generic, 999, [9; 8])),
    ))]);
    let changed_calls = changed.calls.clone();
    assert_eq!(
        SafeXdp::new(changed).detach(&owned).unwrap(),
        XdpDetachOutcome::RetainedIdentityMismatch
    );
    assert_eq!(changed_calls.borrow().as_slice(), [Call::Query(17)]);
}

fn assert_xdp_attributes(
    attributes: &[LinkAttribute],
    expected_fd: i32,
    expected_flags: u32,
    expected_previous_fd: Option<u32>,
) {
    let xdp = attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::Xdp(values) => Some(values),
            _ => None,
        })
        .expect("missing IFLA_XDP");
    assert!(xdp.contains(&LinkXdp::Fd(expected_fd)));
    assert!(xdp.contains(&LinkXdp::Flags(expected_flags)));
    assert_eq!(
        xdp.iter().find_map(|value| match value {
            LinkXdp::ExpectedFd(fd) => Some(*fd),
            _ => None,
        }),
        expected_previous_fd
    );
}

fn loaded() -> LoadedXdp {
    LoadedXdp {
        program_fd: 7,
        program_id: 101,
        program_tag: [1; 8],
    }
}

fn owned_xdp(ifindex: u32, mode: XdpAttachMode, program_id: u32, tag: [u8; 8]) -> OwnedXdp {
    OwnedXdp {
        ifindex,
        mode,
        program_id,
        program_tag: tag,
        link_id: None,
    }
}

fn identity(
    ifindex: u32,
    mode: XdpAttachMode,
    program_id: u32,
    program_tag: [u8; 8],
) -> XdpKernelIdentity {
    XdpKernelIdentity {
        ifindex,
        mode,
        program_id,
        program_tag,
        link_id: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Query(u32),
    Attach {
        ifindex: u32,
        mode: XdpAttachMode,
        program_fd: i32,
    },
    Detach {
        ifindex: u32,
        mode: XdpAttachMode,
        expected_program_id: u32,
    },
}

struct FakeXdpIo {
    queries: VecDeque<Result<XdpInventory, XdpIoError>>,
    attach_result: Result<(), XdpIoError>,
    detach_result: Result<(), XdpIoError>,
    calls: std::rc::Rc<std::cell::RefCell<Vec<Call>>>,
}

impl FakeXdpIo {
    fn with_queries(queries: impl IntoIterator<Item = Result<XdpInventory, XdpIoError>>) -> Self {
        Self {
            queries: queries.into_iter().collect(),
            attach_result: Ok(()),
            detach_result: Ok(()),
            calls: Default::default(),
        }
    }
}

impl XdpIo for FakeXdpIo {
    fn query(&mut self, ifindex: u32) -> Result<XdpInventory, XdpIoError> {
        self.calls.borrow_mut().push(Call::Query(ifindex));
        self.queries.pop_front().expect("unexpected query")
    }

    fn attach_no_replace(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        program_fd: i32,
    ) -> Result<(), XdpIoError> {
        self.calls.borrow_mut().push(Call::Attach {
            ifindex,
            mode,
            program_fd,
        });
        self.attach_result.clone()
    }

    fn detach_if_matches(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        expected_program_id: u32,
    ) -> Result<(), XdpIoError> {
        self.calls.borrow_mut().push(Call::Detach {
            ifindex,
            mode,
            expected_program_id,
        });
        self.detach_result.clone()
    }
}
