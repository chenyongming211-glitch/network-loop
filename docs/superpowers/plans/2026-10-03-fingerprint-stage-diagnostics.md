# Selected fingerprint stage diagnostics implementation plan

> **For agentic workers:** Use executing-plans inline. Main only, no branches/worktrees/subagents; compile and automated code tests only on GitHub.

**Goal:** Distinguish selected-packet hash, metadata, clock and fingerprint Map work without shipping a speculative product optimization.

**Architecture:** Extend the existing acceptance-only object/loader pipeline with four fixed cumulative profiles. Each has a private unpinned `DIAG_RESULTS` per-CPU hash Map (u32 key, 64-byte value, capacity 2), identically recording selected count and the most recent stage output. This observer prevents dead-code removal and is common to all four stages, not a production Map ABI change. Existing four profiles and the ordinary binary retain their inventories and behavior. Differences include generated-code effects and observer interactions, not exact nanoseconds of individual helpers.

**Tech Stack:** Rust/Aya eBPF and xtask; Python measurement analysis; GitHub Actions; authorized ostack7 generated-veth transport.

**Spec:** User-approved continuation and short design in this conversation; safety boundaries and prior evidence in `../../performance-diagnostics-2026-10-02.md`.

## Global constraints

- No installation, systemd, physical/business interface, global sysctl/profiling, CPU/IRQ affinity or foreign BPF mutation.
- Retain exact object digest/commit allowlists, empty-hook refusal, private Maps and identity-exact cleanup; only generated namespace/veth contexts.
- No changes to ordinary hashing, selection, Map ABI, counters, generation or formal 950/900-permille thresholds.
- Diagnostic frames remain bounded ARP, actual generated MACs, selected corpus, 0.5-second/100,000-packet warm-up and 5-second/2,000,000-packet measurement per direction.
- Identical observer shape for all four stages; reports are never deployment-gate evidence. Extra configuration/parser work is common diagnostic overhead, not part of a claim about the ordinary path.
- Five blocks, alternating `[hash, metadata, clock, map, hash]` and `[hash, map, clock, metadata, hash]`, 25 trials total. Hash anchors estimate within-block drift; use the adjacent hash anchor for metadata comparison. No rerun-until-pass or outlier removal.
- Noise envelope is max(1%, all absolute same-stage anchor ratios minus 1). A contrast is resolved only if all five ratios lie strictly on the same side beyond that envelope; otherwise unresolved. This is a conservative diagnostic rule, not a confidence interval. No production optimization follows unresolved evidence.

## Task 1: Identity and noise-aware measurement contracts

**Files:** `xtask/tests/diagnostic_identity.rs`, `xtask/src/diagnostic.rs`, `scripts/diagnostic_pairs.py`, `scripts/tests/test_diagnostic_pairs.py`, `.github/workflows/ci.yml`.

**Interfaces:** Four fixed profiles `fp_hash`, `fp_metadata`, `fp_clock`, `fp_map`; `schedule() -> list[list[str]]`; `summarize(blocks) -> dict` with exactly five scheduled blocks and duration-complete, intact forwarding records.

- [x] RED on GitHub: new profile declaration must succeed without granting load authority; schedule must equal the five explicit blocks; 0.9 ratios under 1% noise resolve lower throughput, 20% anchor drift forces unresolved, malformed/censored records raise ValueError.
- [x] GREEN: fixed enum/declarations, fail-closed input validation, retained ratios and same-stage anchors; no host commands in analysis module.

## Task 2: Real stage objects, loader and kernel evidence

**Files:** `ebpf/l2-loop-ebpf/Cargo.toml`, four `src/bin/fp_*.rs`, diagnostic-only `src/fingerprint_stages.rs`, cfg-only module declaration in `src/programs.rs`; `xtask/src/diagnostic_{build,elf,runtime}.rs`; artifact/runtime tests; CI digest exports.

**Interfaces:** `fingerprint_stages::{xdp,tc}::<1..4>`; observer words `[hash, packed_l2, source_mac_protocol, destination_mac, now_ns, selected_packets, 0, 0]`. Word 1 packs VLAN/EtherType/length/direction/depth; source word packs MAC/protocol/subtype. Hash stage zeros metadata/time; metadata zeros time; clock/map retain kernel time. Stop report includes nonzero per-CPU observer records grouped by hook.

- [x] Extend actual ELF tests before implementation: exact seven-Map layout, profile cross-rejection, forbidden helper mutation, fixed pass verdict and ordinary-product rejection. Existing full-profile/ordinary instruction identity test remains mandatory.
- [x] Implement feature-gated stages; no unused calculations accepted as measurements. Map stage performs the same lookup/update/insert semantics as the original and records results after operation.
- [x] Kernel tests: independent FNV oracle checks selected hashes and packed metadata; selected totals exactly 192 per hook for the fixed fixture, unselected frames produce no observer records, only map stage creates the expected 192 fingerprint entries across both hooks. Existing foreign-TC/lease/digest/exit tests remain.
- [x] Full GitHub CI including MUSL; record exact eligible artifact identity before node use.

## Task 3: Bounded paired measurement and report

**Files:** ignored task-local controller/raw report; `docs/performance-diagnostics-2026-10-03.md`, README and this checklist.

**Interfaces:** Reuse verified generated-veth lifecycle and authorization-specific generated-port LLDP restoration. Each row supplies `profile`, actual packets, combined elapsed_ns, duration_complete, forwarding_intact and drop/error deltas to `summarize`.

- [x] Review the exact controller before execution; do not modify a running controller. Bind source/artifact hashes and selected counts. Pair same endpoints/corpus; preserve all 25 rows and all failures.
- [x] Run only after full CI GREEN. Stop on identity, forwarding, ownership or cleanup mismatch.
- [x] Report adjacent-stage ratios, same-stage noise envelope and unresolved findings honestly. Restore LLDP and measured network/BPF identities and verify zero generated residue.
- [x] Choose a later optimization only from resolved evidence; do not claim product gain or change production admission in this increment.

## Completion evidence

Completed on `main` without local compilation or subagents. Code/artifact commit
`aab228021e09bbaef61319c4d75d34d6f166e2e9` passed all five jobs in GitHub run
`37084538550`. Authorized ostack7 run `5f31ff5d190d47a0a05f5b75b0bf6f8a`
completed all 25 scheduled trials and exact cleanup. Noise envelope 2.42496%; all
three contrasts unresolved, so no production optimization was selected. A preceding
control-script failure and identity-checked cleanup recovery are retained in the
[full report](../../performance-diagnostics-2026-10-03.md). Review was inline under
the explicit no-subagent constraint. Ordinary hot-path changes are limited to a
feature-gated diagnostic module declaration; the ordinary instruction-identity
regression passed. Production admission remains unchanged.
