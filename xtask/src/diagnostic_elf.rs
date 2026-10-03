//! Offline diagnostic ELF contract. No kernel syscalls or attachment authority.

use std::{collections::BTreeMap, path::Path};

use aya_obj::{Object, ProgramSection};
use serde::Serialize;
use thiserror::Error;

use crate::{bundle::read_bounded_single_link_regular, diagnostic::DiagnosticProfile};

#[derive(Debug, Error)]
#[error("DX_ELF: diagnostic ELF contract rejected ({0})")]
pub struct DiagnosticElfError(pub &'static str);

#[derive(Debug, Serialize)]
pub struct DiagnosticElfReport {
    programs: Vec<String>,
    maps: Vec<String>,
    helpers: BTreeMap<String, Vec<i32>>,
    elf_inventory_verified: bool,
    load_authorized: bool,
    deployment_gate_evidence: bool,
}

pub fn verify_diagnostic_elf(
    path: &Path,
    profile: DiagnosticProfile,
) -> Result<DiagnosticElfReport, DiagnosticElfError> {
    let bytes = read_bounded_single_link_regular(path, 16 * 1024 * 1024)
        .map_err(|_| DiagnosticElfError("input"))?;
    inspect_diagnostic_elf(&bytes, profile)
}

pub fn inspect_diagnostic_elf(
    bytes: &[u8],
    profile: DiagnosticProfile,
) -> Result<DiagnosticElfReport, DiagnosticElfError> {
    // ELF64, little endian, current version, relocatable, EM_BPF.
    if bytes.len() < 64
        || bytes.len() > 16 * 1024 * 1024
        || &bytes[..7] != b"\x7fELF\x02\x01\x01"
        || bytes[16..20] != [1, 0, 247, 0]
    {
        return Err(DiagnosticElfError("header"));
    }
    let mut object = Object::parse(bytes).map_err(|_| DiagnosticElfError("parse"))?;
    let (_, xdp, tc) = profile.declaration();
    let mut programs = object.programs.keys().cloned().collect::<Vec<_>>();
    programs.sort();
    let mut expected = vec![xdp.to_owned(), tc.to_owned()];
    expected.sort();
    if programs != expected {
        return Err(DiagnosticElfError("program set"));
    }
    // The ordinary product already calls this shared parser out of line. Do not
    // change its inlining just to satisfy a diagnostic inspection assumption.
    let is_parser = |name: &str| {
        name.starts_with("_RNvNtCs") && name.ends_with("_14l2_loop_common6packet13parse_l2_word")
    };
    if object.functions.values().any(|function| {
        function.name != xdp
            && function.name != tc
            && !matches!(function.name.as_str(), "memcpy" | "memmove" | "memset")
            && !is_parser(&function.name)
    }) {
        return Err(DiagnosticElfError("unexpected support function"));
    }
    let parsers = object
        .functions
        .values()
        .filter(|function| is_parser(&function.name))
        .collect::<Vec<_>>();
    let needs_parser = matches!(
        profile,
        DiagnosticProfile::Counters | DiagnosticProfile::Fingerprints
    ) || profile.is_fingerprint_stage();
    if parsers.len() != usize::from(needs_parser) {
        return Err(DiagnosticElfError("parser set"));
    }
    let parser_code = parsers
        .first()
        .map(|function| function.instructions.clone())
        .unwrap_or_default();
    if parser_code.iter().any(|insn| insn.code == 0x85) {
        return Err(DiagnosticElfError(
            "parser must not call helpers or functions",
        ));
    }
    let entry_lengths = object
        .programs
        .iter()
        .map(|(name, program)| {
            object
                .functions
                .get(&program.function_key())
                .map(|function| (name.clone(), function.instructions.len()))
                .ok_or(DiagnosticElfError("function"))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let text_sections = object
        .functions
        .keys()
        .map(|(section, _)| *section)
        .collect();
    object
        .relocate_calls(&text_sections)
        .map_err(|_| DiagnosticElfError("call relocation"))?;
    let xdp_program = &object.programs[xdp];
    let tc_program = &object.programs[tc];
    if !matches!(
        xdp_program.section,
        ProgramSection::Xdp { frags: false, .. }
    ) || !matches!(tc_program.section, ProgramSection::SchedClassifier)
    {
        return Err(DiagnosticElfError("program type"));
    }
    let mut map_contract = vec![
        ("FINGERPRINTS", 9, 32, 48, 8192),
        ("HOOK_STATS", 5, 16, 16, 4096),
        ("IFACE_CONFIG", 1, 4, 32, 64),
        ("PROBE_REGISTRY", 1, 32, 32, 128),
        ("PROBE_STATS", 5, 32, 16, 128),
        ("RATE_POLICY", 1, 16, 40, 256),
    ];
    if profile.is_fingerprint_stage() {
        map_contract.insert(0, ("DIAG_RESULTS", 5, 4, 64, 2));
    }
    let mut maps = object.maps.keys().cloned().collect::<Vec<_>>();
    maps.sort();
    if maps
        .iter()
        .map(String::as_str)
        .ne(map_contract.iter().map(|item| item.0))
    {
        return Err(DiagnosticElfError("map set"));
    }
    for (name, kind, key, value, capacity) in map_contract {
        let map = &object.maps[name];
        if (
            map.map_type(),
            map.key_size(),
            map.value_size(),
            map.max_entries(),
        ) != (kind, key, value, capacity)
            || map.map_flags() != 0
            || map.pinning() as u32 != 0
        {
            return Err(DiagnosticElfError("map layout"));
        }
    }
    let mut helpers = BTreeMap::new();
    for (name, program, verdict) in [(xdp, xdp_program, 2), (tc, tc_program, 0)] {
        let function = object
            .functions
            .get(&program.function_key())
            .ok_or(DiagnosticElfError("function"))?;
        let mut calls = Vec::new();
        let mut exits = 0;
        let entry_length = entry_lengths[name];
        let linked_tail = &function.instructions[entry_length..];
        if linked_tail.len() != parser_code.len()
            || linked_tail.iter().zip(&parser_code).any(|(left, right)| {
                (
                    left.code,
                    left.dst_reg(),
                    left.src_reg(),
                    left.off,
                    left.imm,
                ) != (
                    right.code,
                    right.dst_reg(),
                    right.src_reg(),
                    right.off,
                    right.imm,
                )
            })
        {
            eprintln!(
                "DX_LINK: program={name} entry={entry_length} tail={} parser={} calls={:?}",
                linked_tail.len(),
                parser_code.len(),
                function.instructions.iter().enumerate().filter(|(_, instruction)| instruction.code == 0x85).map(|(index, instruction)| (index, instruction.src_reg(), instruction.imm)).collect::<Vec<_>>()
            );
            return Err(DiagnosticElfError("linked parser"));
        }
        for (index, insn) in function.instructions[..entry_length].iter().enumerate() {
            if insn.code == 0x85 {
                if insn.src_reg() == 0 {
                    calls.push(insn.imm);
                } else if insn.src_reg() != 1
                    || !needs_parser
                    || index as i64 + 1 + i64::from(insn.imm) != entry_length as i64
                {
                    return Err(DiagnosticElfError("non-helper call"));
                }
            }
            if insn.code == 0x95 {
                exits += 1;
                let previous = index
                    .checked_sub(1)
                    .and_then(|index| function.instructions.get(index))
                    .ok_or(DiagnosticElfError("exit"))?;
                if !matches!(previous.code, 0xb7 | 0xb4)
                    || previous.dst_reg() != 0
                    || previous.imm != verdict
                {
                    return Err(DiagnosticElfError("verdict"));
                }
            }
        }
        if exits == 0 {
            return Err(DiagnosticElfError("missing exit"));
        }
        let valid = match profile {
            DiagnosticProfile::HooksOnly => calls.is_empty() && function.instructions.len() == 2,
            DiagnosticProfile::ConfigLookup => calls == [1],
            DiagnosticProfile::Counters => calls.len() >= 3 && calls.iter().all(|id| *id == 1),
            DiagnosticProfile::Fingerprints => {
                calls.contains(&1)
                    && calls.contains(&2)
                    && calls.contains(&5)
                    && calls.iter().all(|id| matches!(id, 1 | 2 | 5))
            }
            DiagnosticProfile::FpHash | DiagnosticProfile::FpMetadata => {
                calls.len() >= 5 && calls.iter().all(|id| *id == 1)
            }
            DiagnosticProfile::FpClock => {
                calls.contains(&1)
                    && calls.iter().filter(|id| **id == 5).count() == 1
                    && calls.iter().all(|id| matches!(id, 1 | 5))
            }
            DiagnosticProfile::FpMap => {
                calls.contains(&1)
                    && calls.contains(&2)
                    && calls.iter().filter(|id| **id == 5).count() == 1
                    && calls.iter().all(|id| matches!(id, 1 | 2 | 5))
            }
        };
        if !valid {
            return Err(DiagnosticElfError("helper layer"));
        }
        helpers.insert(name.to_owned(), calls);
    }
    Ok(DiagnosticElfReport {
        programs,
        maps,
        helpers,
        elf_inventory_verified: true,
        load_authorized: false,
        deployment_gate_evidence: false,
    })
}
