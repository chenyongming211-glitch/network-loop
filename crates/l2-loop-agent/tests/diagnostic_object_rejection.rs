#![cfg(target_os = "linux")]

use std::{fs, path::Path};

use aya_obj::{Object, ProgramSection};
use l2_loop_agent::linux::bpf_object::{
    MapDescription, MapKind, ObjectContractError, ObjectDescription, ProgramDescription,
    ProgramKind, validate_object_description,
};

fn description(object: &Object) -> ObjectDescription {
    ObjectDescription {
        abi_version: 1,
        programs: object.programs.iter().map(|(name, program)| ProgramDescription {
            name: name.clone(),
            kind: match program.section {
                ProgramSection::Xdp { .. } => ProgramKind::Xdp,
                ProgramSection::SchedClassifier => ProgramKind::SchedClassifier,
                _ => panic!("unexpected program kind"),
            },
        }).collect(),
        maps: object.maps.iter().map(|(name, map)| MapDescription {
            name: name.clone(),
            kind: match map.map_type() {
                1 => MapKind::Hash,
                5 => MapKind::PerCpuHash,
                9 => MapKind::LruHash,
                _ => panic!("unexpected map kind"),
            },
            key_size: map.key_size(),
            value_size: map.value_size(),
            max_entries: map.max_entries(),
        }).collect(),
    }
}

fn instructions(object: &Object, name: &str) -> Vec<(u8, u8, u8, i16, i32)> {
    let key = object.programs[name].function_key();
    object.functions[&key].instructions.iter().map(|insn| {
        (insn.code, insn.dst_reg(), insn.src_reg(), insn.off, insn.imm)
    }).collect()
}

#[test]
#[ignore = "requires exact objects built in the GitHub eBPF job; no kernel loading"]
fn actual_diagnostics_are_rejected_by_product_contract_and_full_path_is_identical() {
    let root = std::env::var("L2_LOOP_DIAGNOSTIC_ROOT").expect("explicit artifact root required");
    let ordinary_path = std::env::var("L2_LOOP_ORDINARY_OBJECT").expect("ordinary object required");
    let ordinary = Object::parse(&fs::read(ordinary_path).unwrap()).unwrap();
    validate_object_description(&description(&ordinary)).unwrap();
    for (profile, stem) in [
        ("hooks_only", "hooks-only"),
        ("config_lookup", "config-lookup"),
        ("counters", "counters"),
        ("fingerprints", "fingerprints"),
    ] {
        let bytes = fs::read(Path::new(&root).join(profile).join(format!("l2-loop-diag-{stem}.o"))).unwrap();
        let diagnostic = Object::parse(&bytes).unwrap();
        assert_eq!(validate_object_description(&description(&diagnostic)), Err(ObjectContractError::ProgramSet));
        if profile == "fingerprints" {
            assert_eq!(instructions(&diagnostic, "l2d_full_xdp"), instructions(&ordinary, "l2_loop_xdp_ingress"));
            assert_eq!(instructions(&diagnostic, "l2d_full_tc"), instructions(&ordinary, "l2_loop_tc_egress"));
        }
    }
}
