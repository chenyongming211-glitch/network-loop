#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use l2_loop_agent::ownership::{
    OWNED_MAP_NAMES, OWNERSHIP_SCHEMA_VERSION, OwnedMapPin, OwnershipError, OwnershipRecord,
};
use l2_loop_common::ABI_VERSION;

const RUN_ROOT: &str = "/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef";

#[test]
fn schema_two_requires_the_exact_fixed_owned_map_set() {
    assert_eq!(OWNERSHIP_SCHEMA_VERSION, 2);
    assert_eq!(
        OWNED_MAP_NAMES,
        [
            "IFACE_CONFIG",
            "HOOK_STATS",
            "FINGERPRINTS",
            "PROBE_REGISTRY",
            "PROBE_STATS",
            "RATE_POLICY",
        ]
    );

    fixture_record(valid_map_pins()).validate_owned_maps().unwrap();
}

#[test]
fn owned_map_pin_rejects_unknown_zero_relative_and_name_mismatched_identities() {
    assert!(matches!(
        OwnedMapPin::new("FOREIGN", pin("FOREIGN"), 301),
        Err(OwnershipError::IdentityMismatch(_))
    ));
    assert!(matches!(
        OwnedMapPin::new("HOOK_STATS", pin("HOOK_STATS"), 0),
        Err(OwnershipError::IdentityMismatch(_))
    ));
    assert!(matches!(
        OwnedMapPin::new("HOOK_STATS", PathBuf::from("HOOK_STATS"), 301),
        Err(OwnershipError::IdentityMismatch(_))
    ));
    assert!(matches!(
        OwnedMapPin::new("HOOK_STATS", pin("IFACE_CONFIG"), 301),
        Err(OwnershipError::IdentityMismatch(_))
    ));
}

#[test]
fn record_rejects_missing_duplicate_name_duplicate_id_and_duplicate_path() {
    let mut missing = valid_map_pins();
    missing.pop();
    assert!(matches!(
        fixture_record(missing).validate_owned_maps(),
        Err(OwnershipError::IdentityMismatch(_))
    ));

    let mut duplicate_name = valid_map_pins();
    duplicate_name[1].name = duplicate_name[0].name.clone();
    assert!(matches!(
        fixture_record(duplicate_name).validate_owned_maps(),
        Err(OwnershipError::IdentityMismatch(_))
    ));

    let mut duplicate_id = valid_map_pins();
    duplicate_id[1].map_id = duplicate_id[0].map_id;
    assert!(matches!(
        fixture_record(duplicate_id).validate_owned_maps(),
        Err(OwnershipError::IdentityMismatch(_))
    ));

    let mut duplicate_path = valid_map_pins();
    duplicate_path[1].path = duplicate_path[0].path.clone();
    assert!(matches!(
        fixture_record(duplicate_path).validate_owned_maps(),
        Err(OwnershipError::IdentityMismatch(_))
    ));
}

fn fixture_record(map_pins: Vec<OwnedMapPin>) -> OwnershipRecord {
    OwnershipRecord {
        schema_version: OWNERSHIP_SCHEMA_VERSION,
        abi_version: ABI_VERSION,
        generation: 41,
        ifindex: 17,
        xdp: None,
        tc: Vec::new(),
        map_pins,
        created_at_unix_seconds: 1_787_000_000,
    }
}

fn valid_map_pins() -> Vec<OwnedMapPin> {
    OWNED_MAP_NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| OwnedMapPin::new(*name, pin(name), 301 + index as u32).unwrap())
        .collect()
}

fn pin(name: &str) -> PathBuf {
    Path::new(RUN_ROOT).join(name)
}
