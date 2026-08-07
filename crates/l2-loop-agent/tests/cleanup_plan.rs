#![cfg(target_os = "linux")]

use std::path::PathBuf;

use l2_loop_agent::{
    linux::cleanup::{
        CleanupOperation, CleanupSnapshot, IfaceConfigIdentity, PinIdentity, plan_owned_cleanup,
    },
    ownership::{
        OWNERSHIP_SCHEMA_VERSION, OwnedTc, OwnedXdp, OwnershipRecord, TcHook, TcKernelIdentity,
        XdpAttachMode, XdpKernelIdentity,
    },
};
use l2_loop_common::ABI_VERSION;

#[test]
fn journal_confirmed_cleanup_is_ordered_in_exact_reverse_creation_order() {
    let record = ownership();
    let snapshot = matching_snapshot(&record);

    let plan = plan_owned_cleanup(&record, &snapshot);

    assert!(plan.retained.is_empty());
    assert_eq!(
        plan.operations,
        [
            CleanupOperation::RemoveJournal,
            CleanupOperation::RemoveIfaceConfig(IfaceConfigIdentity {
                ifindex: 17,
                generation: 41,
            }),
            CleanupOperation::RemoveDependentMapEntries(IfaceConfigIdentity {
                ifindex: 17,
                generation: 41,
            }),
            CleanupOperation::UnpinMap(PinIdentity {
                path: pin("HOOK_STATS"),
                map_id: 302,
            }),
            CleanupOperation::UnpinMap(PinIdentity {
                path: pin("IFACE_CONFIG"),
                map_id: 301,
            }),
            CleanupOperation::DetachTc(record.tc[0]),
            CleanupOperation::DetachXdp(record.xdp.unwrap()),
        ]
    );
}

#[test]
fn fresh_identity_mismatches_are_retained_and_never_become_cleanup_operations() {
    let record = ownership();
    let mut snapshot = matching_snapshot(&record);
    snapshot.xdp = Some(XdpKernelIdentity {
        program_id: 999,
        ..snapshot.xdp.unwrap()
    });
    snapshot.tc[0].program_id = 998;
    snapshot.iface_config = Some(IfaceConfigIdentity {
        ifindex: 17,
        generation: 99,
    });
    snapshot.pins[0].map_id = 997;
    snapshot.journal = None;

    let plan = plan_owned_cleanup(&record, &snapshot);

    assert_eq!(plan.retained.len(), 5);
    assert!(!plan.operations.contains(&CleanupOperation::RemoveJournal));
    assert!(
        !plan
            .operations
            .iter()
            .any(|operation| matches!(operation, CleanupOperation::RemoveIfaceConfig(_)))
    );
    assert!(
        !plan
            .operations
            .iter()
            .any(|operation| matches!(operation, CleanupOperation::DetachTc(_)))
    );
    assert!(
        !plan
            .operations
            .iter()
            .any(|operation| matches!(operation, CleanupOperation::DetachXdp(_)))
    );
    assert!(
        !plan
            .operations
            .contains(&CleanupOperation::UnpinMap(PinIdentity {
                path: pin("IFACE_CONFIG"),
                map_id: 997,
            }))
    );
    assert!(
        plan.operations
            .contains(&CleanupOperation::UnpinMap(PinIdentity {
                path: pin("HOOK_STATS"),
                map_id: 302,
            }))
    );
}

#[test]
fn foreign_pin_paths_are_never_cleanup_candidates() {
    let record = ownership();
    let mut snapshot = matching_snapshot(&record);
    snapshot.pins.push(PinIdentity {
        path: PathBuf::from("/sys/fs/bpf/foreign/root"),
        map_id: 302,
    });

    let plan = plan_owned_cleanup(&record, &snapshot);

    assert!(
        !plan
            .operations
            .iter()
            .any(|operation| matches!(operation, CleanupOperation::UnpinMap(pin) if pin.path == PathBuf::from("/sys/fs/bpf/foreign/root")))
    );
}

fn ownership() -> OwnershipRecord {
    OwnershipRecord {
        schema_version: OWNERSHIP_SCHEMA_VERSION,
        abi_version: ABI_VERSION,
        generation: 41,
        ifindex: 17,
        xdp: Some(OwnedXdp {
            ifindex: 17,
            mode: XdpAttachMode::Generic,
            program_id: 101,
            program_tag: [1; 8],
            link_id: None,
        }),
        tc: vec![OwnedTc {
            ifindex: 17,
            hook: TcHook::Egress,
            priority: 49_600,
            handle: 0x4c32_0002,
            program_id: 102,
            created_clsact: true,
        }],
        pin_paths: vec![pin("IFACE_CONFIG"), pin("HOOK_STATS")],
        created_at_unix_seconds: 1_754_521_600,
    }
}

fn matching_snapshot(record: &OwnershipRecord) -> CleanupSnapshot {
    CleanupSnapshot {
        journal: Some(record.clone()),
        xdp: record.xdp.map(Into::into),
        tc: record
            .tc
            .iter()
            .copied()
            .map(TcKernelIdentity::from)
            .collect(),
        iface_config: Some(IfaceConfigIdentity {
            ifindex: record.ifindex,
            generation: record.generation,
        }),
        pins: vec![
            PinIdentity {
                path: pin("IFACE_CONFIG"),
                map_id: 301,
            },
            PinIdentity {
                path: pin("HOOK_STATS"),
                map_id: 302,
            },
        ],
        owned_program_map_ids: vec![(101, vec![301, 302]), (102, vec![301, 302])],
    }
}

fn pin(name: &str) -> PathBuf {
    PathBuf::from("/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef").join(name)
}
