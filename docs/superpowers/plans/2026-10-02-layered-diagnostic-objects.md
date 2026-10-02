# Layered diagnostic objects implementation plan

> **For agentic workers:** Execute inline using executing-plans and test-driven-development. Main only; no subagents, worktrees or local compilation/tests.

**Goal:** Build four separately named diagnostic ELF objects and verify their actual program/Map inventories before any future isolated loader is introduced.

**Architecture:** A required-feature diagnostic binary per profile reuses the existing packet path. Compile-time specialization disables fingerprint work for counters. Ordinary entry points are excluded from diagnostic builds; building the ordinary binary with the diagnostic feature fails closed. Build outputs use a separate target directory and new output directory. A read-only ELF verifier uses the already locked aya-obj/object parsers without kernel loading.

**Tech Stack:** Existing pinned Rust/eBPF toolchains; aya-obj 0.3.0 and object 0.39.1 already in Cargo.lock; Python standard-library integration tests on GitHub.

**Spec:** Approved four-layer attribution and `2026-10-02-layered-diagnostic-identity.md`.

## Contract

- Preserve the ordinary four program names, six Map layouts, packet semantics, fixed fingerprint sampling and ten-file release bundle.
- Four diagnostic binaries: `l2-loop-diag-hooks-only`, `l2-loop-diag-config-lookup`, `l2-loop-diag-counters`, `l2-loop-diag-fingerprints`; object/program declarations exactly match the existing identity contract.
- Hooks-only returns XDP_PASS/TC_ACT_OK without Map lookups. Config-lookup adds one IFACE_CONFIG lookup. Counters reuses classification, totals, errors and VLAN visibility but no fingerprint helpers. Fingerprints uses the full existing path.
- `cargo xtask build-diagnostic-ebpf --profile <PROFILE> --commit-sha <SHA> --output <NEW_DIR>` builds one profile with the fixed nightly, --locked, release and bpfel target into a separate target directory. Refuse preexisting output before compilation. Emit only its object and `diagnostic.json`, after ELF checks; no overwrite.
- `cargo xtask verify-diagnostic-elf --object <PATH> --profile <PROFILE>` checks ELF64 little-endian relocatable EM_BPF, exact two names/types, six exact Map layouts/capacities/flags, bounded input, helper strata and constant pass/continue exits. It reports no kernel verification, trusted provenance, attachment authority or deployment evidence.
- ELF checking does not replace byte-identity verification or future host ownership checks. It is a build contract, not an arbitrary bytecode security proof. No server access, BPF syscall, attach, production option or threshold change.
- The pinned linker retains `memcpy`, `memmove` and `memset` support functions in `.text`; these are not attachable programs. The existing product also calls the shared `l2_loop_common::packet::parse_l2_word` out of line. Permit only these names in addition to the two exact entry points. Resolve calls offline with Aya; counters/full may call only the appended exact parser body, which itself must have no calls. Hooks/config may make no function calls. Memory support functions must remain unreachable. Evidence: failed runs `37015312746` and `37015771243`, plus the preserved ordinary object from `8f4dca2` contains the same parser symbol. No product inlining change is made to accommodate the diagnostic checker.
- The ordinary runtime object contract must reject each actual diagnostic program set. Test it using the same validator without invoking Ebpf::load (which can create Maps).

## Task: build and inspect actual objects

Files: `ebpf/l2-loop-ebpf/Cargo.toml`, `src/main.rs`, `src/programs.rs`, four `src/bin/` entry points; `xtask/src/diagnostic*.rs`, `xtask/src/main.rs`, parser dependencies/lock; `scripts/tests/test_diagnostic_artifacts.py`; `.github/workflows/ci.yml`; actual-contract integration test in agent tests.

- [x] RED: integration tests invoke the real xtask build/ELF commands. Run `37014338733`, eBPF job `110861400614`: all four tests failed with usage exit 2 for missing commands, after the ordinary object built successfully.
- [x] GREEN: implement fixed argument parsing, compile-time profiles, bounded ELF inspection and exclusive output creation. Four real-artifact integration tests passed in run `37016853803`, job `110869729059`; output identities, no-overwrite, unchanged ordinary object bytes, mismatched profiles, invalid inputs, mutated Map layout/helper/verdict/support names and forbidden product-with-diagnostics compilation are covered.
- [x] Add actual ELF program-set rejection test through `validate_object_description`. Run `37016853803`, job `110869729059`: one explicit actual-object test passed, proving ordinary contract acceptance, four diagnostic program-set rejections, and full-profile entry/support-function instruction equality with the ordinary object. Cargo test receives absolute workspace artifact paths; no kernel loading occurs.
- [x] Verify full CI: commit `2e1885a18bcd2eea2e2dd6df66a5d042d7c083cf`, [run 37016853803](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37016853803), all five jobs succeeded (Userspace, eBPF, Script safety, Windows PowerShell safety, Bundle). The separate diagnostic artifact is `l2-loop-layered-diagnostics-2e1885a18bcd2eea2e2dd6df66a5d042d7c083cf`, artifact ID `11231735058`; ordinary bundle construction and generated-root installation acceptance also passed.
- [x] Inline review completed under the user's no-subagent requirement. Only two dependency edges to the already locked aya-obj 0.3.0 were added; no versions or Map ABI changed, no product runtime diagnostic flag/loader was added, and ordinary packet operations remain the full specialization. The checker distinguishes attachable programs from linker support/parser functions; it is not a bytecode security proof. No node was contacted, no BPF object was loaded into a kernel, and no performance improvement is claimed.

## Verified static strata and remaining work

Each hook has these helper IDs in its compiled entry: hooks `[]`; config `[1]`;
counters `[1,1,1,1,1]`; fingerprints `[1,1,1,1,1,5,1,2]`. IDs 1/2/5 are map lookup,
map update and monotonic clock helpers. These are static call sites, not counts per
packet. Counters/full call only the existing shared L2 parser after offline call
resolution. All objects preserve the six exact Map definitions.

The next increment was an acceptance-only diagnostic loader with byte/provenance checks,
exact generated namespace/veth ownership, empty-hook refusal and precise reverse
rollback and bounded paired measurements using the exact accepted artifact.
That [follow-up](2026-10-02-isolated-diagnostic-loader.md) is now complete at
`34c152e517b7a77f90655a0f20d343a323f87485`: actual kernel loading, live packet
counters and all 25 layered measurements passed their safety/accounting checks.
No throughput improvement, physical-interface permission or production readiness
is implied; see the [measurement report](../../performance-diagnostics-2026-10-02.md#completed-isolated-five-layer-attribution).

## Test interface

```text
cargo build --locked --package xtask
python3 -m unittest discover -s scripts/tests -p 'test_diagnostic_artifacts.py' -v
L2_LOOP_DIAGNOSTIC_ROOT=<test-created-root> cargo test --locked --package l2-loop-agent --test diagnostic_object_rejection
```

The Python suite uses a generated temporary directory, then preserves verified profile outputs in `.artifacts/layered-diagnostics` for the subsequent actual-contract test and upload. Failed profile build/validation must not publish diagnostic outputs. An upload is not runtime acceptance: later workflow steps may fail, so node use requires the whole successful run. Build/validation exit 1; malformed command usage exit 2; success exit 0.
