# Layered diagnostic identity contract implementation plan

> **For agentic workers:** Use executing-plans inline. User requirements override workflow defaults: main only, no branches/worktrees/subagents; compilation and automated tests only on GitHub.

**Goal:** Establish a strict, read-only byte-identity verification boundary for future isolated layered eBPF diagnostic artifacts.

**Architecture:** A separate diagnostic manifest binds a fixed profile, distinct object filename and declared program names to an expected commit and SHA-256 payload. A build-tool-only verifier checks this declaration and byte identity without loading BPF, authorizing attachment, or creating release/deployment evidence. Existing release packaging and product commands remain unchanged.

**Tech Stack:** Existing Rust xtask, serde/serde_json, sha2, existing bounded stable-file reader; no new dependencies.

**Spec:** User-approved layered attribution in this conversation and Task 3 of `2026-10-02-performance-diagnostics.md`.

## Global constraints

- Four profiles: `hooks_only`, `config_lookup`, `counters`, `fingerprints`. No runtime product flag, physical-interface operation or kernel change.
- Schema 1, purpose `isolated_layered_diagnostic`, `deployment_gate_evidence: false`, ABI 1, target `bpfel-unknown-none`; reject unknown, missing and duplicate fields, including nested fields.
- Commit is exactly 40 lowercase hex characters; payload digest is exactly 64 lowercase hex characters. Both caller-specified commit/profile and actual object basename must match the manifest.
- Manifest bound 65,536 bytes; object bound 16 MiB and nonempty. Reuse the stable regular-file reader with an explicit single-link policy for diagnostics; preserve the existing release-reader behavior. Diagnostic verification fails closed on non-Unix platforms, where this reader cannot establish the same identity guarantees. Verifier performs no writes and reports no load authorization.
- The SHA-256 verifier is not an ELF inventory, kernel-verifier or host-ownership check. Those are mandatory later layers before any diagnostic attachment. A correctly bound arbitrary byte fixture may pass this step without being loadable.
- A caller-supplied commit and matching digest do not establish trusted CI provenance. Artifact origin must be verified independently before a later loader may consume it.

## Task: Read-only diagnostic manifest verifier

**Files:** create `xtask/src/diagnostic.rs`, `xtask/tests/diagnostic_identity.rs`; update `xtask/src/lib.rs`, `xtask/src/main.rs`, bounded-reader visibility in `xtask/src/bundle.rs`, and the existing pinned CI userspace job.

**Interface:** `cargo xtask verify-diagnostic-identity --manifest <PATH> --object <PATH> --commit-sha <SHA> --profile <PROFILE>`. Exit 0 emits JSON with `payload_sha256_verified: true`, `load_authorized: false`, `deployment_gate_evidence: false`, verified profile and commit. Exit 1 uses `DX_SCHEMA`, `DX_BINDING`, `DX_DIGEST` or `DX_INPUT`; malformed CLI usage exits 2.

| Profile | Object basename | XDP declaration | TC declaration |
| --- | --- | --- | --- |
| hooks_only | l2-loop-diag-hooks-only.o | l2d_hooks_xdp | l2d_hooks_tc |
| config_lookup | l2-loop-diag-config-lookup.o | l2d_config_xdp | l2d_config_tc |
| counters | l2-loop-diag-counters.o | l2d_count_xdp | l2d_count_tc |
| fingerprints | l2-loop-diag-fingerprints.o | l2d_full_xdp | l2d_full_tc |

- [x] Commit behavioral CLI tests before implementation. Positive fixtures use independently known SHA-256 of `abc`; mutation cases reject schema drift, relabeled profiles, production names, changed bytes, unsafe file kinds and size overflow.
- [x] Verify RED on GitHub with `cargo test --locked --package xtask --test diagnostic_identity`. Run `37011025828`, Userspace job `110850515054`: all six tests failed as expected because the existing xtask rejected the new command (usage exit 2).
- [x] Implement strict Deserialize models and validation, reuse the bounded reader without changing release behavior, and wire only the xtask verifier command. No loader or diagnostic object is introduced in this increment.
- [ ] Verify GREEN for the same tests, then full formatting, lint, tests, ordinary eBPF build and unchanged MUSL bundle checks on GitHub.
- [ ] Record exact CI evidence and remaining scope. Do not claim layered measurements or throughput improvements from the identity verifier.

## Subsequent independently reviewed deliverables

Next add a separate diagnostic eBPF build artifact whose actual ELF inventory agrees with these declarations and cannot satisfy the ordinary loader's program inventory. Then add an acceptance-only loader using exact generated-veth ownership and rollback, followed by bounded paired measurement. Only after these layers are tested may the new diagnostic objects be attached. The original formal pass-through path, ten-file release bundle, six-Map ABI, production CLI and performance gate must remain unchanged.
