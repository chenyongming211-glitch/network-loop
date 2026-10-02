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
- The ordinary runtime object contract must reject each actual diagnostic program set. Test it using the same validator without invoking Ebpf::load (which can create Maps).

## Task: build and inspect actual objects

Files: `ebpf/l2-loop-ebpf/Cargo.toml`, `src/main.rs`, `src/programs.rs`, four `src/bin/` entry points; `xtask/src/diagnostic*.rs`, `xtask/src/main.rs`, parser dependencies/lock; `scripts/tests/test_diagnostic_artifacts.py`; `.github/workflows/ci.yml`; actual-contract integration test in agent tests.

- [ ] RED: integration tests invoke the real xtask build/ELF commands. Correct builds must emit two files per profile and a matching digest, unchanged ordinary object bytes, strict profile mismatch/ordinary-object/invalid-ELF rejection, and no overwrite. Run after the ordinary eBPF build on GitHub; absent commands must fail assertions.
- [ ] GREEN: implement fixed argument parsing, compile-time profiles, bounded ELF inspection and exclusive output creation. Keep ordinary wrapper semantics, and prevent product-with-diagnostics feature combinations.
- [ ] Add actual ELF program-set rejection test through `validate_object_description`; run with paths to the four artifacts in the GitHub eBPF job, no kernel loading.
- [ ] Verify full CI, inspect actual helper/Map inventories, upload diagnostic artifacts under a separate commit-bound name only after checks. Existing ordinary bundle path is unchanged.
- [ ] Inline review and record exact commit/run, remaining loader/measurement scope. No performance improvement claim.

## Test interface

```text
cargo build --locked --package xtask
python3 -m unittest discover -s scripts/tests -p 'test_diagnostic_artifacts.py' -v
L2_LOOP_DIAGNOSTIC_ROOT=<test-created-root> cargo test --locked --package l2-loop-agent --test diagnostic_object_rejection
```

The Python suite uses a generated temporary directory, then preserves verified profile outputs in `.artifacts/layered-diagnostics` for the subsequent actual-contract test and upload. Failure must not publish a diagnostic artifact. Build/validation exit 1; malformed command usage exit 2; success exit 0.
