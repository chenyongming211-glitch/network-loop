# Delivery D Bounded Fingerprint Relationships Implementation Plan

**Goal:** Implement the approved isolated, fail-open fingerprint sampling and privacy-reduced ingress/egress relationship vertical slice.

**Design:** `docs/superpowers/specs/2026-08-12-bounded-fingerprint-relationships-design.md`

**Execution constraints:** Work directly on `main`; do not create a branch or worktree; do not use subagents; do not compile Rust locally. Every Rust RED/GREEN result is produced by GitHub CI. Host acceptance uses only the exact checksum-verified artifact and only generated namespace/veth resources on the authorized node.

## Task 1: Freeze the Fingerprint Hash and Normalization Contract

- Add RED tests in `l2-loop-common` for fixed FNV-1a vectors, length separation, maximum 64-byte prefix, deterministic shift-4 selection, post-tag EtherType, VLAN depth, protocol, and subtype.
- Extend the allocation-free packet contract with the required normalized metadata and fixed fingerprint helper.
- Push RED and record the expected focused GitHub failure; implement GREEN and require all five CI jobs.

## Task 2: Activate the Fail-Open eBPF LRU Path

- Add static and behavioral tests for fixed `sample_shift=4` publication, selected-only updates, direction-independent hashes, exact key fields, saturating counters, and pass-only returns.
- Activate `FINGERPRINTS` from XDP ingress and TC egress after cumulative accounting.
- Keep all insert/update errors ignored and every data-plane return pass/ok.
- Verify RED then GREEN only through GitHub.

## Task 3: Implement Pure Bounded Relationship Domain Types

- Add Schema 4 fingerprint states, raw internal evidence types, the privacy-reduced report/summary, and deterministic relation analysis.
- Test identity validation, grouping without direction, order classification, repeat evidence, ratios, empty/unavailable states, entry/group limits, overflow rejection, and absence of raw identifiers from serialized output.
- Verify RED then GREEN through GitHub.

## Task 4: Implement the Aya Fingerprint Reader

- Extend the injectable Linux observation I/O with request-only `FINGERPRINTS` enumeration.
- Validate the exact journal name/path/kernel Map ID and every bounded entry.
- Return hard identity failures separately from recoverable iteration failures.
- Prove background sampling never enumerates the LRU.
- Verify RED then GREEN through GitHub.

## Task 5: Compose SamplingService, Health, and Lifecycle

- Carry request-purpose raw fingerprint evidence into the pure relation builder.
- Add the complete report to `ObservationSnapshot` and summary to `InterfaceStatus`.
- Degrade health only for unavailable fingerprint evidence; preserve rate/baseline state.
- Prove request-local recovery and exact generation reset.
- Verify RED then GREEN through GitHub.

## Task 6: Complete Protocol and CLI Schema 4 Rendering

- Render the complete fingerprint report in `observe` and the summary in `status` for text and JSON.
- Keep protocol version 1 and exact-artifact pairing.
- Add real Unix socket round-trip tests and privacy assertions forbidding fingerprints, MACs, raw keys/timestamps, and packet bytes.
- Verify RED then GREEN through GitHub.

## Task 7: Extend the Isolated Host Harness

- Add `FingerprintRelationship`, `FingerprintReadFailure`, and `FingerprintGenerationReset`.
- Generate deterministic selected/unselected frames without exposing raw evidence in CLI output.
- Add a request-only acceptance fault for one bounded LRU iteration failure and prove recovery.
- Preserve all existing snapshot, forwarding, exact cleanup, and residue gates.
- Verify RED then GREEN through GitHub.

## Task 8: Final Audit, Documentation, and Exact-Artifact Acceptance

- Update README and development/design documentation to Schema 4 and the exact Delivery D boundary.
- Run the final tracked-file safety audit: retired identifier zero, secrets zero, no drop/probe/policy activation, immutable CI, fixed capacities, no public sampling controls, and no raw fingerprint/MAC output.
- Require a final five-job GitHub success and exact MUSL artifact.
- Run all eleven host scenarios against that exact commit, retrying only after a concurrent foreign-state refusal proves clean residue.
- Finish with an independent residue audit, clean `main`, `HEAD == origin/main`, and a 100% Delivery D report.
