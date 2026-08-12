# Dynamic Baseline and Observation Health Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bounded generation-scoped median/MAD baseline and separate observation-health reporting over the existing fixed 10-second passive rate window.

**Architecture:** A pure-domain `BaselineEngine` owns 16 fixed subject histories and publishes deterministic schema-3 reports. The existing serial `SamplingService` invokes it only after a successful background tick and caches the result; request-time `observe/status` only copy that cache.

**Tech Stack:** Rust 2024, serde, thiserror, existing Aya userspace/eBPF observation path, PowerShell isolated-host harness, GitHub Actions-only Rust compilation.

## Global Constraints

- Develop directly on `main`; do not create a branch or worktree.
- Do not use subagents.
- Do not run Cargo, rustfmt, Clippy, Rust tests, or Rust compilation locally; all Rust verification runs in GitHub Actions.
- Use TDD for every behavior: commit and push RED tests, require the expected GitHub failure, then implement GREEN and require all five GitHub jobs.
- Use only exact successful GitHub artifacts for authorized-host acceptance.
- Host acceptance may operate only on generated isolated namespace/veth identities and must preserve all foreign network and eBPF identity.
- Keep the eBPF programs, Map ABI, ownership journal schema, attach transaction, protocol version 1, and fail-open forwarding unchanged.
- Keep all baseline state memory-only and generation-scoped.
- Aggregate baseline state with the exact priority `unavailable > elevated > learning > within_baseline`.
- Do not add caller-selected baseline controls, loop/storm verdicts, fingerprints, probes, drops, policies, persistence, or production-interface attachment.
- Do not reintroduce the retired identifier or commit target/key material.

---

### Task 1: Schema 3 Baseline Domain Contract

**Files:**

- Create: `crates/l2-loop-core/src/baseline.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Modify: `crates/l2-loop-core/src/observation.rs`
- Modify: `crates/l2-loop-core/src/command.rs`
- Create: `crates/l2-loop-core/tests/baseline_contract.rs`
- Modify: existing fixture constructors under `crates/l2-loop-core/tests`, `crates/l2-loop-agent/tests`, and `crates/l2-loop-cli/tests` only as needed by the schema constructor.

**Interfaces:**

- Produces fixed constants `BASELINE_SOURCE_WINDOW_MS`, `BASELINE_CAPACITY`, `BASELINE_MINIMUM_SAMPLES`, `BASELINE_PACKET_NOISE_FLOOR_PPS`, `BASELINE_BYTE_NOISE_FLOOR_BPS`, `BASELINE_SUBJECTS_PER_HOOK`, `BASELINE_SUBJECT_COUNT`, and `BASELINE_METRIC_COUNT`.
- Produces `BaselineState`, `BaselineSubject`, `BaselineMetric`, `BaselineMetricReport`, `BaselineSubjectReport`, `BaselineReport`, `BaselineElevatedIdentifier`, `BaselineSubjectSampleCount`, and `BaselineSummary`.
- Adds `baseline: BaselineReport` to `ObservationSnapshot` and `baseline: BaselineSummary` to `InterfaceStatus`.
- Advances `OBSERVATION_SCHEMA_VERSION` to `3`; protocol version remains `1`.

- [ ] **Step 1: Add RED contract tests**

Create tests that require exact numeric constants, fixed subject ordering, snake-case serialization, 16 detailed subjects, a maximum of 32 elevated identifiers, strict null evidence shapes, aggregate priority, and schema version 3. The wished-for constructor is:

```rust
let report = BaselineReport::learning(RateIdentity::new(7, 11).unwrap(), 1_000);
assert_eq!(report.state, BaselineState::Learning);
assert_eq!(report.subjects.len(), BASELINE_SUBJECT_COUNT);
assert!(report.validate().is_ok());
```

- [ ] **Step 2: Push RED and verify expected GitHub failure**

Commit `test: specify dynamic baseline schema` and push `main`. Require Script safety and Windows PowerShell safety to pass, and Userspace to fail because baseline domain exports and schema-3 constructor parameters do not exist. Do not implement production code before this failure is observed.

- [ ] **Step 3: Implement the fixed domain types and validators**

Use fixed arrays rather than caller-sized vectors wherever the cardinality is fixed. `BaselineSubject` must serialize as a tagged value and preserve total, existing traffic-class ABI order, then parse-errors. `BaselineMetricReport` must provide explicit constructors for learning, evaluated, and unavailable evidence so invalid mixed shapes cannot be emitted accidentally.

The aggregate function is exactly:

```rust
pub fn aggregate_baseline_state(subjects: &[BaselineSubjectReport; BASELINE_SUBJECT_COUNT]) -> BaselineState {
    if subjects.iter().any(|value| value.state == BaselineState::Unavailable) {
        BaselineState::Unavailable
    } else if subjects.iter().any(|value| value.state == BaselineState::Elevated) {
        BaselineState::Elevated
    } else if subjects.iter().any(|value| value.state == BaselineState::Learning) {
        BaselineState::Learning
    } else {
        BaselineState::WithinBaseline
    }
}
```

- [ ] **Step 4: Push GREEN and require all five GitHub jobs**

Commit `feat: add dynamic baseline schema` and require Script safety, Windows PowerShell safety, Userspace, eBPF, and Bundle to succeed for the exact SHA.

---

### Task 2: Deterministic Bounded Baseline Series

**Files:**

- Modify: `crates/l2-loop-core/src/baseline.rs`
- Create: `crates/l2-loop-core/tests/baseline_series.rs`

**Interfaces:**

- Produces pure `BaselineSeries` with one bounded history of atomic `(packets_per_second, bytes_per_second, accepted_at_unix_ms)` samples.
- Produces `BaselineSeries::evaluate(current_packets, current_bytes)` and `BaselineSeries::accept(...)`.
- Produces deterministic upper median, upper MAD, clamped threshold, and `ratio_milli` helpers.

- [ ] **Step 1: Add RED statistical tests**

Cover odd/even upper median, upper MAD, 59/60 learning transition, 300-capacity eviction, strict equality at threshold, zero median, both noise floors, `u64::MAX` inputs, fixed-point ratios, and metric-independent elevated flags.

Required boundary examples include:

```rust
assert!(!evaluate_metric(10, 0, 0, BASELINE_PACKET_NOISE_FLOOR_PPS).elevated);
assert!(evaluate_metric(11, 0, 0, BASELINE_PACKET_NOISE_FLOOR_PPS).elevated);
assert_eq!(evaluate_metric(400, 100, 0, 10).elevated, false);
assert_eq!(evaluate_metric(401, 100, 0, 10).elevated, true);
assert_eq!(evaluate_metric(5, 0, 0, 10).ratio_milli, None);
```

- [ ] **Step 2: Push RED and verify expected GitHub failure**

Commit `test: specify bounded baseline statistics`; require Userspace failure for missing series/statistical implementation.

- [ ] **Step 3: Implement minimal deterministic series**

Store at most 300 atomic sample pairs. Sort copied `u64` values for median/MAD; do not mutate history order. Use `u128` for `median + 6 * mad`, `4 * median`, and ratio multiplication, then clamp public values to `u64::MAX`. Evaluation never mutates; acceptance is a separate operation.

- [ ] **Step 4: Push GREEN and require all five jobs**

Commit `feat: implement bounded baseline statistics` and require the exact run to be fully green.

---

### Task 3: Fixed-Order Baseline Engine and Anti-Contamination

**Files:**

- Modify: `crates/l2-loop-core/src/baseline.rs`
- Create: `crates/l2-loop-core/tests/baseline_engine.rs`

**Interfaces:**

- Produces `BaselineEngine::new(identity, started_at_unix_ms)`.
- Produces `BaselineEngine::evaluate_ready_window(&DetailedRateWindow, evaluated_at_unix_ms) -> Result<BaselineReport, BaselineError>`.
- Produces `BaselineEngine::unavailable(evaluated_at_unix_ms, code)` retaining histories.
- Produces `BaselineEngine::clear_integrity(identity, evaluated_at_unix_ms, code)` clearing all histories.
- Produces a cached `BaselineReport` in exact hook/subject order.

- [ ] **Step 1: Add RED engine tests**

Require exactly 16 subjects, subject-atomic PPS/BPS rejection, sibling acceptance, total/class independence, hook independence, elevated evidence without history growth, recovery to within-baseline, duplicate/regressed source-end rejection, transient unavailable retention, integrity clear, and new-generation learning.

- [ ] **Step 2: Push RED and verify expected GitHub failure**

Commit `test: specify dynamic baseline engine`; require the expected Userspace failure.

- [ ] **Step 3: Implement the engine**

Validate the source window is exactly 10 seconds, ready, and carries both hooks/classes in fixed order. Compare every subject before accepting any subject. For each subject, reject the complete pair when packet or byte is elevated, but accept all non-elevated siblings. Publish one report only after all subject decisions complete.

Duplicate or regressed `end_unix_ms`, invalid shape, or identity mismatch returns a stable `BaselineError` and clears complete engine history before the caller publishes unavailable.

- [ ] **Step 4: Push GREEN and require all five jobs**

Commit `feat: add generation scoped baseline engine` and require the exact run to be fully green.

---

### Task 4: SamplingService Baseline Integration

**Files:**

- Modify: `crates/l2-loop-agent/src/observation.rs`
- Modify: `crates/l2-loop-agent/tests/observation_service.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_sampling.rs`

**Interfaces:**

- `SamplingService` owns `Option<BaselineEngine>` and the engine's cached report through the existing single-session lifecycle.
- Successful background ticks update RateHistory first, then read index 1 of the fixed windows, then update baseline only when it is ready and trustworthy.
- Request `observe/status` copies cached baseline state without mutation.
- Adds stable baseline error codes distinct from `SamplingStatus.last_error_code`.

- [ ] **Step 1: Add RED service tests**

Use injected reader/clock fixtures to prove: request reads never change subject counts; two requests between ticks are identical; each background endpoint is processed once; a source window is not learned before ready; transient failure retains counts and publishes unavailable; recovery compares before accept; pause retains but makes unavailable; clock/counter/identity failures clear; clear destroys both histories.

- [ ] **Step 2: Push RED and verify expected GitHub failure**

Commit `test: specify baseline sampling lifecycle`; require the expected Userspace failure.

- [ ] **Step 3: Integrate engine in the serial tick**

Preserve the exact sampling read-purpose distinction. On successful `RateHistory::record_success`, calculate detailed windows once, use only the 10-second window, and publish the engine report. On transient read failure call retain-unavailable. On identity, clock, counter, or baseline invariant failure clear baseline history and publish the independent stable baseline code.

Compose health so elevated and learning remain healthy while baseline unavailable is degraded.

- [ ] **Step 4: Push GREEN and require all five jobs**

Commit `feat: integrate baseline sampling lifecycle` and require the exact run to be fully green.

---

### Task 5: Daemon Session Lifecycle and Schema-3 Status

**Files:**

- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_dispatch.rs`
- Modify: `crates/l2-loop-agent/tests/isolated_control.rs`

**Interfaces:**

- Attach starts RateHistory and BaselineEngine for the exact ownership identity.
- Detach, failed attach rollback, daemon shutdown, and active-session replacement destroy both histories.
- `InterfaceStatus.baseline` is derived from the same cached detailed report returned by observe.

- [ ] **Step 1: Add RED lifecycle tests**

Prove first attach starts learning, status/observe share generation and baseline timestamps, detach removes cached state, reattach with a new generation has 16 zero-count learning subjects, ownership mismatch cannot expose the prior report, and shutdown leaves no session state.

- [ ] **Step 2: Push RED and verify expected GitHub failure**

Commit `test: specify daemon baseline lifecycle`; require expected Userspace failure.

- [ ] **Step 3: Implement lifecycle wiring and summary conversion**

Keep all mutation in the existing daemon session owner. Build `BaselineSummary` from `BaselineReport` in core or agent conversion code without recomputing thresholds. Preserve fixed elevated identifier order and reject more than 32 entries as an invariant failure.

- [ ] **Step 4: Push GREEN and require all five jobs**

Commit `feat: wire baseline daemon lifecycle` and require the exact run to be fully green.

---

### Task 6: CLI Text/JSON and Unix-Socket Round Trips

**Files:**

- Modify: `crates/l2-loop-cli/src/render.rs`
- Modify: `crates/l2-loop-cli/tests/render.rs`
- Modify: `crates/l2-loop-cli/tests/socket_round_trip.rs`

**Interfaces:**

- Existing `observe` renders complete `BaselineReport` under schema 3.
- Existing `status` renders `BaselineSummary`.
- JSON is direct serde output; text rendering only prints domain values.

- [ ] **Step 1: Add RED renderer and socket tests**

Require text and JSON to include state, fixed configuration, three cache timestamps, baseline error, subject sample counts, complete metric evidence, learning/elevated counts, and fixed elevated identifiers. Require unavailable output to contain null current/statistics while retaining counts and last-success time.

- [ ] **Step 2: Push RED and verify expected GitHub failure**

Commit `test: specify schema 3 baseline output`; require expected Userspace failure.

- [ ] **Step 3: Implement rendering without calculations**

Render detailed subjects in their array order and summary identifiers in their domain order. Use `B/s`, `pps`, and `ratio_milli` labels exactly. Do not derive state, threshold, ratio, or counts in the CLI.

- [ ] **Step 4: Push GREEN and require all five jobs**

Commit `feat: render dynamic baseline evidence` and require the exact run to be fully green.

---

### Task 7: Isolated Exact-Artifact Baseline Harness

**Files:**

- Modify: `scripts/verify-isolated-host.ps1`
- Modify: `scripts/tests/verify-isolated-host.Tests.ps1`

**Interfaces:**

- Adds scenarios `BaselineLifecycle`, `BaselineSamplingRecovery`, and `BaselineGenerationReset` to the existing exact-artifact harness.
- Reuses only generated namespace/veth, bounded raw frames, exact ownership detach, component-hash snapshots, and independent cleanup.

- [ ] **Step 1: Add RED static harness contracts**

Require all three scenario names, fixed 70-second learning bound, bounded high-rate frame counts, schema 3 fields, 16/32 cardinalities, subject-atomic sample-count assertions, unavailable retention, compare-before-accept recovery, generation reset, and exact cleanup. Continue rejecting package installation, production interface selection, host route/address mutation, unbounded loops, and destructive cleanup.

- [ ] **Step 2: Push RED and verify expected GitHub failure**

Commit `test: require isolated baseline acceptance`; require Script safety and Windows PowerShell safety to fail only for missing harness scenario behavior while Rust jobs remain unchanged.

- [ ] **Step 3: Implement bounded scenarios**

`BaselineLifecycle` learns stable low traffic for the bounded readiness interval, records every subject count, injects a bounded elevated matrix, proves only affected subjects reject while siblings advance, then waits for elevated traffic to leave the 10-second source window and proves within-baseline recovery.

`BaselineSamplingRecovery` establishes a ready baseline, injects the existing background-only read fault, proves degraded/unavailable with retained counts and continued request/forwarding, then uses a bounded recovery control path that affects only the acceptance test process and proves compare-before-accept.

`BaselineGenerationReset` establishes generation one, performs ownership-exact detach, symmetrically restores generated-link state, attaches generation two, proves all 16 counts reset, and independently advances the new generation.

- [ ] **Step 4: Push GREEN and require all five jobs plus artifact**

Commit `test: verify isolated dynamic baseline` and require five successful jobs and one non-expired `l2-loop-linux-x86_64-<full-sha>` artifact.

---

### Task 8: Exact-Artifact Host Acceptance

**Files:**

- Execute without repository modification: `scripts/verify-isolated-host.ps1`

**Interfaces:**

- Consumes the exact Task 7 GREEN artifact and task-scoped authorized target/key inputs without printing them.
- Produces eight scenario pass markers and an independent fixed residue marker.

- [ ] **Step 1: Run the five existing regression scenarios**

Run `Success`, `PassiveObservation`, `RateWindows`, `RateSamplingFailure`, and `RateGenerationReset` with the same full SHA and a bounded timeout.

- [ ] **Step 2: Run the three baseline scenarios**

Run `BaselineLifecycle`, `BaselineSamplingRecovery`, and `BaselineGenerationReset` with the same full SHA. Any failure must trigger exact cleanup before diagnosis.

- [ ] **Step 3: Run independent read-only residue audit**

Require absence of `/run/l2-loop`, `/sys/fs/bpf/l2-loop`, generated `l2ns-*` namespaces, and generated `l2h*/l2n*` veth names. Print only the fixed clean marker.

---

### Task 9: Final Safety Audit and Documentation

**Files:**

- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`
- Modify: `docs/superpowers/specs/2026-08-12-dynamic-baseline-observation-health-design.md`

**Interfaces:**

- Produces accurate schema-3/operator documentation and the final exact GitHub artifact.
- Reports Delivery progress as 9/9 and 100% only after all gates pass.

- [ ] **Step 1: Correct documentation**

Document the fixed 10-second source, 300/60 bounds, 10 pps and 16 KiB/s floors, upper median/MAD, deterministic integer thresholds, startup blind spot, four baseline states, cache timestamps, observation-health separation, retain-versus-clear matrix, and eight isolated scenarios. Explicitly preserve every excluded capability.

- [ ] **Step 2: Run non-compiling local safety audits**

Run `git diff --check` and quiet scans for retired identifier, incomplete markers, target/key material, eBPF drops, mutable Actions, write permissions, untracked lockfile, temporary workflows, caller baseline controls, and production enablement. Assert exact baseline/rate constants and all eight scenario names.

- [ ] **Step 3: Commit documentation and require final CI/artifact**

Commit `docs: record dynamic baseline delivery`, push `main`, require exactly five successful jobs and one non-expired exact artifact.

- [ ] **Step 4: Repeat all eight scenarios with the final documentation SHA artifact**

Documentation changes alter the exact artifact identity. Repeat the complete host matrix against this final SHA, then repeat the independent residue audit.

- [ ] **Step 5: Verify final synchronization**

Require `HEAD == origin/main`, current branch `main`, empty working tree, normal repository rather than linked worktree, five final jobs successful, exact artifact present, eight host scenarios successful, residue clean, and prohibited/sensitive scans clean.
