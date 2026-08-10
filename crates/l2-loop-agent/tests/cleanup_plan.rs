#![cfg(target_os = "linux")]

use std::path::PathBuf;

use l2_loop_agent::{
    linux::cleanup::{
        CleanupOperation, CleanupSnapshot, IfaceConfigIdentity, PinIdentity, plan_owned_cleanup,
    },
    ownership::{
        OWNED_MAP_NAMES, OWNERSHIP_SCHEMA_VERSION, OwnedMapPin, OwnedTc, OwnedXdp, OwnershipRecord,
        TcHook, TcKernelIdentity, XdpAttachMode, XdpKernelIdentity,
    },
};
use l2_loop_common::ABI_VERSION;

#[test]
fn journal_confirmed_cleanup_is_ordered_in_exact_reverse_creation_order() {
    let record = ownership();
    let snapshot = matching_snapshot(&record);

    let plan = plan_owned_cleanup(&record, &snapshot);

    assert!(plan.retained.is_empty());
    assert_eq!(plan.operations[0], CleanupOperation::RemoveJournal);
    assert_eq!(
        plan.operations[1],
        CleanupOperation::RemoveIfaceConfig(IfaceConfigIdentity {
            ifindex: 17,
            generation: 41,
        })
    );
    assert_eq!(
        plan.operations[2],
        CleanupOperation::RemoveDependentMapEntries(IfaceConfigIdentity {
            ifindex: 17,
            generation: 41,
        })
    );
    let actual_pins = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            CleanupOperation::UnpinMap(pin) => Some(pin.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let expected_pins = record
        .map_pins
        .iter()
        .rev()
        .map(|pin| PinIdentity {
            path: pin.path.clone(),
            map_id: pin.map_id,
        })
        .collect::<Vec<_>>();
    assert_eq!(actual_pins, expected_pins);
    assert_eq!(
        &plan.operations[plan.operations.len() - 2..],
        [
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
            .any(|operation| matches!(operation, CleanupOperation::UnpinMap(pin) if pin.path == std::path::Path::new("/sys/fs/bpf/foreign/root")))
    );
}

#[test]
fn replaced_pin_is_retained_even_when_an_owned_program_reports_the_new_map_id() {
    let record = ownership();
    let mut snapshot = matching_snapshot(&record);
    snapshot.pins[0].map_id = 999;
    snapshot.owned_program_map_ids[0].1.push(999);

    let plan = plan_owned_cleanup(&record, &snapshot);

    assert!(
        !plan
            .operations
            .contains(&CleanupOperation::UnpinMap(PinIdentity {
                path: record.map_pins[0].path.clone(),
                map_id: 999,
            }))
    );
    assert!(
        plan.retained
            .iter()
            .any(|retained| retained.resource.contains("IFACE_CONFIG"))
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
        map_pins: owned_map_pins(),
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
        pins: record
            .map_pins
            .iter()
            .map(|pin| PinIdentity {
                path: pin.path.clone(),
                map_id: pin.map_id,
            })
            .collect(),
        owned_program_map_ids: vec![
            (101, record.map_pins.iter().map(|pin| pin.map_id).collect()),
            (102, record.map_pins.iter().map(|pin| pin.map_id).collect()),
        ],
    }
}

fn owned_map_pins() -> Vec<OwnedMapPin> {
    OWNED_MAP_NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| OwnedMapPin::new(*name, pin(name), 301 + index as u32).unwrap())
        .collect()
}

fn pin(name: &str) -> PathBuf {
    PathBuf::from("/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef").join(name)
}
