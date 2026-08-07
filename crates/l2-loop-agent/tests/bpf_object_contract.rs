#![cfg(target_os = "linux")]

use l2_loop_agent::linux::bpf_object::{
    MapKind, ObjectContractError, ProgramKind, expected_object_description,
    validate_object_description,
};
use l2_loop_common::ABI_VERSION;

#[test]
fn abi_v1_contract_contains_every_exact_public_program_and_map() {
    let description = expected_object_description();

    assert_eq!(description.abi_version, ABI_VERSION);
    assert_eq!(
        description
            .programs
            .iter()
            .map(|program| (program.name.as_str(), program.kind))
            .collect::<Vec<_>>(),
        [
            ("l2_loop_tc_egress", ProgramKind::SchedClassifier),
            ("l2_loop_tc_path_egress", ProgramKind::SchedClassifier),
            ("l2_loop_tc_path_ingress", ProgramKind::SchedClassifier),
            ("l2_loop_xdp_ingress", ProgramKind::Xdp),
        ]
    );
    assert_eq!(
        description
            .maps
            .iter()
            .map(|map| {
                (
                    map.name.as_str(),
                    map.kind,
                    map.key_size,
                    map.value_size,
                    map.max_entries,
                )
            })
            .collect::<Vec<_>>(),
        [
            ("FINGERPRINTS", MapKind::LruHash, 32, 48, 8192),
            ("HOOK_STATS", MapKind::PerCpuHash, 16, 16, 4096),
            ("IFACE_CONFIG", MapKind::Hash, 4, 32, 64),
            ("PROBE_REGISTRY", MapKind::Hash, 32, 32, 128),
            ("PROBE_STATS", MapKind::PerCpuHash, 32, 16, 128),
            ("RATE_POLICY", MapKind::Hash, 16, 40, 256),
        ]
    );
    validate_object_description(&description).unwrap();
}

#[test]
fn rejects_every_abi_name_layout_type_and_capacity_mismatch() {
    let mut cases = Vec::new();

    let mut wrong_abi = expected_object_description();
    wrong_abi.abi_version = ABI_VERSION + 1;
    cases.push((wrong_abi, ObjectContractError::AbiVersion));

    let mut missing_program = expected_object_description();
    missing_program.programs.pop();
    cases.push((missing_program, ObjectContractError::ProgramSet));

    let mut wrong_program_type = expected_object_description();
    wrong_program_type.programs[0].kind = ProgramKind::Xdp;
    cases.push((wrong_program_type, ObjectContractError::ProgramType));

    let mut extra_map = expected_object_description();
    extra_map.maps.push(extra_map.maps[0].clone());
    extra_map.maps.last_mut().unwrap().name = "UNEXPECTED".into();
    cases.push((extra_map, ObjectContractError::MapSet));

    let mut wrong_map_type = expected_object_description();
    wrong_map_type.maps[0].kind = MapKind::Hash;
    cases.push((wrong_map_type, ObjectContractError::MapType));

    let mut wrong_key_size = expected_object_description();
    wrong_key_size.maps[1].key_size += 1;
    cases.push((wrong_key_size, ObjectContractError::MapLayout));

    let mut wrong_value_size = expected_object_description();
    wrong_value_size.maps[2].value_size += 1;
    cases.push((wrong_value_size, ObjectContractError::MapLayout));

    let mut insufficient_capacity = expected_object_description();
    insufficient_capacity.maps[3].max_entries -= 1;
    cases.push((insufficient_capacity, ObjectContractError::MapCapacity));

    for (description, expected) in cases {
        assert_eq!(
            validate_object_description(&description).unwrap_err(),
            expected
        );
    }
}

#[test]
fn permits_capacity_growth_without_permitting_abi_shape_changes() {
    let mut description = expected_object_description();
    for map in &mut description.maps {
        map.max_entries *= 2;
    }

    validate_object_description(&description).unwrap();
}
