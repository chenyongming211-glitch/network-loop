#![cfg(target_os = "linux")]

use std::collections::VecDeque;

use l2_loop_agent::{
    linux::tc::{
        LoadedTc, SafeTc, TC_EGRESS_HANDLE, TC_INGRESS_HANDLE, TC_PRIORITY_FIRST, TC_PRIORITY_LAST,
        TcClsactState, TcDetachOutcome, TcFilterSlot, TcInventory, TcIo, TcIoError, TcRollback,
        TcState, attach_request_flags, classify_inventory, encode_attach_request,
        encode_detach_request,
    },
    ownership::{OwnedTc, TcHook, TcKernelIdentity},
};
use l2_loop_core::{PF_TC_HANDLE_COLLISION, PF_TC_STATE_UNKNOWN};
use rtnetlink::{
    packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST},
    packet_route::tc::{TcAttribute, TcBpfFlags, TcFilterBpfOption, TcOption},
};

#[test]
fn classifies_empty_owned_foreign_and_unknown_slots() {
    let owned = owned_tc(17, TcHook::Egress, TC_PRIORITY_FIRST, TC_EGRESS_HANDLE, 101);

    assert_eq!(
        classify_inventory(
            &TcInventory::empty(TcClsactState::Absent),
            TcHook::Egress,
            None,
        ),
        TcState::Empty {
            priority: TC_PRIORITY_FIRST,
            clsact_present: false,
        }
    );
    assert_eq!(
        classify_inventory(
            &TcInventory::only(TcClsactState::Present, TcFilterSlot::Bpf(owned.into()),),
            TcHook::Egress,
            Some(&owned),
        ),
        TcState::Owned
    );
    assert_eq!(
        classify_inventory(
            &TcInventory::only(TcClsactState::Present, TcFilterSlot::Bpf(owned.into()),),
            TcHook::Egress,
            None,
        ),
        TcState::Foreign
    );
    assert_eq!(
        classify_inventory(
            &TcInventory::only(
                TcClsactState::Present,
                TcFilterSlot::Unknown(TcHook::Egress),
            ),
            TcHook::Egress,
            None,
        ),
        TcState::Unknown
    );
    assert_eq!(
        classify_inventory(
            &TcInventory::empty(TcClsactState::Unknown),
            TcHook::Egress,
            None,
        ),
        TcState::Unknown
    );
}

#[test]
fn preserves_unrelated_filters_and_selects_the_first_free_priority() {
    let inventory = TcInventory::new(
        TcClsactState::Present,
        vec![
            TcFilterSlot::Other {
                hook: TcHook::Egress,
                priority: TC_PRIORITY_FIRST,
                handle: 0x1000_0001,
            },
            TcFilterSlot::Bpf(identity(
                17,
                TcHook::Ingress,
                TC_PRIORITY_FIRST + 1,
                0x2000_0001,
                300,
            )),
        ],
    );

    assert_eq!(
        classify_inventory(&inventory, TcHook::Egress, None),
        TcState::Empty {
            priority: TC_PRIORITY_FIRST + 1,
            clsact_present: true,
        }
    );
}

#[test]
fn reserved_handle_collision_and_exhausted_priorities_are_foreign() {
    let collision = TcInventory::only(
        TcClsactState::Present,
        TcFilterSlot::Other {
            hook: TcHook::Ingress,
            priority: TC_PRIORITY_FIRST,
            handle: TC_INGRESS_HANDLE,
        },
    );
    assert_eq!(
        classify_inventory(&collision, TcHook::Ingress, None),
        TcState::Foreign
    );

    let full = TcInventory::new(
        TcClsactState::Present,
        (TC_PRIORITY_FIRST..=TC_PRIORITY_LAST)
            .map(|priority| TcFilterSlot::Other {
                hook: TcHook::Egress,
                priority,
                handle: u32::from(priority),
            })
            .collect(),
    );
    assert_eq!(
        classify_inventory(&full, TcHook::Egress, None),
        TcState::Foreign
    );
}

#[test]
fn attach_message_uses_explicit_identity_and_exclusive_create() {
    let message = encode_attach_request(
        17,
        TcHook::Egress,
        TC_PRIORITY_FIRST + 2,
        TC_EGRESS_HANDLE,
        7,
    );

    assert_eq!(message.header.index, 17);
    assert_eq!(u32::from(message.header.handle), TC_EGRESS_HANDLE);
    assert_eq!(message.header.parent.major, u16::MAX);
    assert_eq!(message.header.parent.minor, 0xfff3);
    assert_eq!((message.header.info >> 16) as u16, TC_PRIORITY_FIRST + 2);
    assert_eq!(message.header.info as u16, 0x0003u16.to_be());
    assert_bpf_attributes(&message.attributes, Some(7));

    let flags = attach_request_flags();
    assert_eq!(
        flags & (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    assert_eq!(flags & NLM_F_REPLACE, 0);
}

#[test]
fn detach_message_never_uses_a_wildcard_handle_or_priority() {
    let owned = owned_tc(
        17,
        TcHook::Ingress,
        TC_PRIORITY_FIRST,
        TC_INGRESS_HANDLE,
        101,
    );
    let message = encode_detach_request(TcKernelIdentity::from(owned));

    assert_eq!(message.header.index, 17);
    assert_eq!(u32::from(message.header.handle), TC_INGRESS_HANDLE);
    assert_eq!((message.header.info >> 16) as u16, TC_PRIORITY_FIRST);
    assert_eq!(message.header.info as u16, 0x0003u16.to_be());
    assert_ne!(message.header.handle, Default::default());
    assert_bpf_attributes(&message.attributes, None);
}

#[test]
fn only_an_empty_owned_slot_reaches_attach() {
    for (inventory, expected_code) in [
        (
            TcInventory::only(
                TcClsactState::Present,
                TcFilterSlot::Bpf(identity(
                    17,
                    TcHook::Egress,
                    TC_PRIORITY_FIRST,
                    TC_EGRESS_HANDLE,
                    201,
                )),
            ),
            PF_TC_HANDLE_COLLISION,
        ),
        (
            TcInventory::only(
                TcClsactState::Present,
                TcFilterSlot::Unknown(TcHook::Egress),
            ),
            PF_TC_STATE_UNKNOWN,
        ),
    ] {
        let io = FakeTcIo::with_queries([Ok(inventory)]);
        let calls = io.calls.clone();
        let error = SafeTc::new(io)
            .attach(17, TcHook::Egress, loaded())
            .unwrap_err();

        assert_eq!(error.code(), expected_code);
        assert_eq!(calls.borrow().as_slice(), [Call::Query(17)]);
    }
}

#[test]
fn query_error_blocks_as_unknown_before_mutation() {
    let io = FakeTcIo::with_queries([Err(TcIoError::Failed("query failed".into()))]);
    let calls = io.calls.clone();
    let error = SafeTc::new(io)
        .attach(17, TcHook::Egress, loaded())
        .unwrap_err();

    assert_eq!(error.code(), PF_TC_STATE_UNKNOWN);
    assert_eq!(calls.borrow().as_slice(), [Call::Query(17)]);
}

#[test]
fn clsact_is_created_only_when_absent_and_is_never_removed() {
    let expected = owned_tc(17, TcHook::Egress, TC_PRIORITY_FIRST, TC_EGRESS_HANDLE, 101);
    let io = FakeTcIo::with_queries([
        Ok(TcInventory::empty(TcClsactState::Absent)),
        Ok(TcInventory::only(
            TcClsactState::Present,
            TcFilterSlot::Bpf(expected.into()),
        )),
    ]);
    let calls = io.calls.clone();

    let attached = SafeTc::new(io)
        .attach(17, TcHook::Egress, loaded())
        .unwrap();

    assert!(attached.created_clsact);
    assert_eq!(
        calls.borrow().as_slice(),
        [
            Call::Query(17),
            Call::EnsureClsact(17),
            Call::Attach {
                ifindex: 17,
                hook: TcHook::Egress,
                priority: TC_PRIORITY_FIRST,
                handle: TC_EGRESS_HANDLE,
                program_fd: 7,
            },
            Call::Query(17),
        ]
    );
}

#[test]
fn clsact_creation_failure_has_a_stable_stage_code() {
    let mut io = FakeTcIo::with_queries([Ok(TcInventory::empty(TcClsactState::Absent))]);
    io.clsact_result = Err(TcIoError::Failed("injected clsact failure".into()));

    let error = SafeTc::new(io)
        .attach(17, TcHook::Egress, loaded())
        .unwrap_err();

    assert_eq!(error.code(), "TC_CLSACT_CREATE_FAILED");
}

#[test]
fn filter_creation_failure_has_a_stable_stage_code() {
    let mut io = FakeTcIo::with_queries([Ok(TcInventory::empty(TcClsactState::Present))]);
    io.attach_result = Err(TcIoError::Failed("injected filter failure".into()));

    let error = SafeTc::new(io)
        .attach(17, TcHook::Egress, loaded())
        .unwrap_err();

    assert_eq!(error.code(), "TC_FILTER_CREATE_FAILED");
}

#[test]
fn eexist_is_one_filter_attempt_and_never_retried() {
    let mut io = FakeTcIo::with_queries([Ok(TcInventory::empty(TcClsactState::Present))]);
    io.attach_result = Err(TcIoError::Exists);
    let calls = io.calls.clone();
    let error = SafeTc::new(io)
        .attach(17, TcHook::Egress, loaded())
        .unwrap_err();

    assert_eq!(error.code(), PF_TC_HANDLE_COLLISION);
    assert_eq!(
        calls.borrow().as_slice(),
        [
            Call::Query(17),
            Call::Attach {
                ifindex: 17,
                hook: TcHook::Egress,
                priority: TC_PRIORITY_FIRST,
                handle: TC_EGRESS_HANDLE,
                program_fd: 7,
            },
        ]
    );
}

#[test]
fn verification_mismatch_rolls_back_only_the_exact_new_identity() {
    let exact = identity(17, TcHook::Egress, TC_PRIORITY_FIRST, TC_EGRESS_HANDLE, 101);
    let io = FakeTcIo::with_queries([
        Ok(TcInventory::empty(TcClsactState::Present)),
        Ok(TcInventory::new(
            TcClsactState::Present,
            vec![
                TcFilterSlot::Bpf(exact),
                TcFilterSlot::Unknown(TcHook::Ingress),
            ],
        )),
    ]);
    let calls = io.calls.clone();
    let error = SafeTc::new(io)
        .attach(17, TcHook::Egress, loaded())
        .unwrap_err();

    assert_eq!(error.rollback(), Some(TcRollback::Completed));
    assert_eq!(calls.borrow().last(), Some(&Call::Detach(exact)));
}

#[test]
fn verification_mismatch_retains_a_changed_current_program() {
    let changed = identity(17, TcHook::Egress, TC_PRIORITY_FIRST, TC_EGRESS_HANDLE, 202);
    let io = FakeTcIo::with_queries([
        Ok(TcInventory::empty(TcClsactState::Present)),
        Ok(TcInventory::only(
            TcClsactState::Present,
            TcFilterSlot::Bpf(changed),
        )),
    ]);
    let calls = io.calls.clone();
    let error = SafeTc::new(io)
        .attach(17, TcHook::Egress, loaded())
        .unwrap_err();

    assert_eq!(error.rollback(), Some(TcRollback::RetainedIdentityMismatch));
    assert!(
        !calls
            .borrow()
            .iter()
            .any(|call| matches!(call, Call::Detach(_)))
    );
}

#[test]
fn detach_requires_a_fresh_complete_identity_match() {
    let owned = owned_tc(17, TcHook::Egress, TC_PRIORITY_FIRST, TC_EGRESS_HANDLE, 101);
    let exact = FakeTcIo::with_queries([Ok(TcInventory::only(
        TcClsactState::Present,
        TcFilterSlot::Bpf(owned.into()),
    ))]);
    let exact_calls = exact.calls.clone();
    assert_eq!(
        SafeTc::new(exact).detach(&owned).unwrap(),
        TcDetachOutcome::Detached
    );
    assert_eq!(
        exact_calls.borrow().last(),
        Some(&Call::Detach(owned.into()))
    );

    let changed = FakeTcIo::with_queries([Ok(TcInventory::only(
        TcClsactState::Present,
        TcFilterSlot::Bpf(identity(
            17,
            TcHook::Egress,
            TC_PRIORITY_FIRST,
            TC_EGRESS_HANDLE,
            999,
        )),
    ))]);
    let changed_calls = changed.calls.clone();
    assert_eq!(
        SafeTc::new(changed).detach(&owned).unwrap(),
        TcDetachOutcome::RetainedIdentityMismatch
    );
    assert_eq!(changed_calls.borrow().as_slice(), [Call::Query(17)]);
}

fn assert_bpf_attributes(attributes: &[TcAttribute], expected_fd: Option<u32>) {
    assert!(attributes.contains(&TcAttribute::Kind("bpf".to_owned())));
    let options = attributes
        .iter()
        .find_map(|attribute| match attribute {
            TcAttribute::Options(options) => Some(options),
            _ => None,
        })
        .expect("missing TCA_OPTIONS");
    assert_eq!(
        options.iter().find_map(|option| match option {
            TcOption::Bpf(TcFilterBpfOption::ProgFd(fd)) => Some(*fd),
            _ => None,
        }),
        expected_fd
    );
    if expected_fd.is_some() {
        assert!(options.contains(&TcOption::Bpf(TcFilterBpfOption::Flags(
            TcBpfFlags::DirectAction,
        ))));
    }
}

fn loaded() -> LoadedTc {
    LoadedTc {
        program_fd: 7,
        program_id: 101,
    }
}

fn owned_tc(ifindex: u32, hook: TcHook, priority: u16, handle: u32, program_id: u32) -> OwnedTc {
    OwnedTc {
        ifindex,
        hook,
        priority,
        handle,
        program_id,
        created_clsact: false,
    }
}

fn identity(
    ifindex: u32,
    hook: TcHook,
    priority: u16,
    handle: u32,
    program_id: u32,
) -> TcKernelIdentity {
    TcKernelIdentity {
        ifindex,
        hook,
        priority,
        handle,
        program_id,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Query(u32),
    EnsureClsact(u32),
    Attach {
        ifindex: u32,
        hook: TcHook,
        priority: u16,
        handle: u32,
        program_fd: i32,
    },
    Detach(TcKernelIdentity),
}

struct FakeTcIo {
    queries: VecDeque<Result<TcInventory, TcIoError>>,
    clsact_result: Result<(), TcIoError>,
    attach_result: Result<(), TcIoError>,
    detach_result: Result<(), TcIoError>,
    calls: std::rc::Rc<std::cell::RefCell<Vec<Call>>>,
}

impl FakeTcIo {
    fn with_queries(queries: impl IntoIterator<Item = Result<TcInventory, TcIoError>>) -> Self {
        Self {
            queries: queries.into_iter().collect(),
            clsact_result: Ok(()),
            attach_result: Ok(()),
            detach_result: Ok(()),
            calls: Default::default(),
        }
    }
}

impl TcIo for FakeTcIo {
    fn query(&mut self, ifindex: u32) -> Result<TcInventory, TcIoError> {
        self.calls.borrow_mut().push(Call::Query(ifindex));
        self.queries.pop_front().expect("unexpected query")
    }

    fn ensure_clsact_exclusive(&mut self, ifindex: u32) -> Result<(), TcIoError> {
        self.calls.borrow_mut().push(Call::EnsureClsact(ifindex));
        self.clsact_result.clone()
    }

    fn attach_exclusive(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        priority: u16,
        handle: u32,
        program_fd: i32,
    ) -> Result<(), TcIoError> {
        self.calls.borrow_mut().push(Call::Attach {
            ifindex,
            hook,
            priority,
            handle,
            program_fd,
        });
        self.attach_result.clone()
    }

    fn detach_exact(&mut self, identity: TcKernelIdentity) -> Result<(), TcIoError> {
        self.calls.borrow_mut().push(Call::Detach(identity));
        self.detach_result.clone()
    }
}
