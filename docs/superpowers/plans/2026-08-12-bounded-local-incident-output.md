# Bounded Local Incident Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every material Schema 5 passive-detection incident transition as bounded, privacy-reduced local evidence and expose sanitized status/list/show output without changing detection or packet behavior.

**Architecture:** A pure `IncidentRecorder` consumes new typed detection transitions and produces bounded write jobs. A Linux filesystem adapter atomically commits immutable revisions and reconstructs an indexed view; a capacity-32 daemon worker serializes blocking output, then sends a sanitized journald/fallback alert. Control requests read sanitized index models only.

**Tech Stack:** Rust 2024, serde/serde_json, sha2, nix Linux filesystem primitives, Tokio bounded channels and `spawn_blocking`, existing Unix protocol/CLI, PowerShell exact-artifact harness.

## Global Constraints

- Develop directly on `main`; no branch, worktree, PR, or subagent.
- Do not run Cargo, rustc, rustfmt, Clippy, or Rust tests locally; compilation is GitHub-only.
- Every behavior change follows RED commit/push/observed expected GitHub failure, then GREEN commit/push/full five-job success.
- Keep protocol version 1; evidence schema is 1 and observation schema remains 5.
- Keep eBPF and Map ABI unchanged and fail-open; zero `XDP_DROP`/`TC_ACT_SHOT` in eBPF sources.
- No probe, confirmed-loop state, raw evidence, PCAP, policy, production attachment, remote delivery, or implicit filesystem repair.
- Fixed bounds are 1 GiB, 1,000 events, 16 revisions/event, 1 MiB/revision, 16 MiB/event, 30 days, max(512 MiB, 5%) reserve, queue 32, list default 50/max 200.
- Host acceptance uses only generated namespace/veth and generated acceptance evidence roots from one checksum-verified artifact.

---

### Task 1: Evidence Domain and Query Contracts

**Files:**
- Create: `crates/l2-loop-core/src/evidence.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Test: `crates/l2-loop-core/tests/evidence_contract.rs`

**Interfaces:**
- Consumes: `DetectionState`, `DetectionTransitionReason`, `DetectionReport`, `BaselineSummary`, `FingerprintWindowReport`, `StatusRateWindow`.
- Produces: `EventId`, `IncidentRevisionV1`, `EvidenceManifestV1`, `EvidenceSummaryV1`, `EvidenceDetailV1`, `OutputHealth`, `EvidenceListQuery`, `EvidenceCursor`, stable alert/evidence enums and fixed constants.

- [ ] **Step 1: Write RED domain tests**

Test canonical 32-lower-hex parsing, `../`/uppercase/Unicode rejection, exact fixed constants, severity mapping with no error/confirmed-loop variant, revision/manifest validation, privacy serialization scans, descending ordering, limit 0/201 rejection, and cursor filter binding. The wished-for parser is:

```rust
let id: EventId = "00112233445566778899aabbccddeeff".parse()?;
assert_eq!(id.to_string(), "00112233445566778899aabbccddeeff");
assert!("../00112233445566778899aabbccdd".parse::<EventId>().is_err());
```

- [ ] **Step 2: Commit and verify RED only in GitHub**

Commit `test: specify bounded incident evidence contracts`; require Userspace failure caused only by missing evidence API while eBPF and script safety stay green.

- [ ] **Step 3: Implement minimal validated models**

Use `[u8; 16]` internally for `EventId`, fixed lowercase encoding without path-capable characters, checked counts, and serde models containing only the approved reduced fields. `EvidenceListQuery::new(interface, limit, cursor)` must enforce `1..=200` before allocation.

- [ ] **Step 4: Commit and verify GREEN**

Commit `feat: add bounded incident evidence contracts`; require all five GitHub jobs successful.

### Task 2: Pure Incident Recorder

**Files:**
- Create: `crates/l2-loop-agent/src/incident.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Test: `crates/l2-loop-agent/tests/incident_recorder.rs`

**Interfaces:**
- Consumes: one generation identity, `ObservationSnapshot`, and unseen `DetectionTransition` values.
- Produces: `IncidentWriteJob { revision: IncidentRevisionV1, alert: PendingAlertV1 }` and recorder status; no I/O.

- [ ] **Step 1: Write RED lifecycle tests**

Cover no event for warming/normal, event open on first anomaly, same ID for upgrade/unavailable/cooldown, close on normal, `generation_ended`, new ID after close, generation mismatch clear, duplicate transition suppression, sequence gaps rejected, and 16-transition bound. Inject deterministic IDs through:

```rust
pub trait EventIdSource { fn next_id(&mut self) -> Result<EventId, IncidentError>; }
```

- [ ] **Step 2: Commit and observe RED GitHub failure**

Commit `test: specify passive incident lifecycle` and require the missing recorder API to be the Userspace failure.

- [ ] **Step 3: Implement the pure recorder**

Track `last_consumed_transition_sequence`, optional active `(EventId, next_revision, opened_at)`, and suppressed duplicate count. Copy only fixed snapshot summaries; never retain raw Aya evidence or ownership paths.

- [ ] **Step 4: Commit and require GREEN**

Commit `feat: record passive detection incidents`; require full GitHub success.

### Task 3: Atomic Filesystem Store and Recovery

**Files:**
- Create: `crates/l2-loop-agent/src/evidence_store.rs`
- Modify: `crates/l2-loop-agent/Cargo.toml`
- Test: `crates/l2-loop-agent/tests/evidence_store.rs`

**Interfaces:**
- Produces `EvidenceStore` port with `put`, `get`, `list`, `health`, `recover`; `LinuxEvidenceStore<I: EvidenceIo>` adapter and injectable failure steps.

- [ ] **Step 1: Write RED filesystem tests**

Use one private temporary test root. Cover missing/unsafe root refusal, modes 0700/0600, symlink and traversal refusal, every write/fsync/rename failure, no-replace collision, exact SHA/length validation, prior revision survival, restart index reconstruction, corrupt/incomplete/unknown preservation, scan bounds, and three random-ID collision attempts.

- [ ] **Step 2: Commit and verify expected RED**

Commit `test: specify atomic incident evidence store`; GitHub Userspace must fail only for missing store APIs.

- [ ] **Step 3: Implement minimal atomic store**

Serialize first and reject bytes above 1 MiB. Hash with existing `sha2`; create files with no-follow/exclusive semantics, fsync evidence then manifest then directory, and publish a canonical 16-digit revision with Linux no-replace rename. Rebuild a `BTreeMap` index from validated manifests only.

- [ ] **Step 4: Commit and verify GREEN**

Commit `feat: persist immutable incident evidence`; require five-job success and unchanged lock policy.

### Task 4: Retention and Fixed Resource Bounds

**Files:**
- Modify: `crates/l2-loop-agent/src/evidence_store.rs`
- Test: `crates/l2-loop-agent/tests/evidence_retention.rs`

**Interfaces:**
- Adds `StoreUsage`, injected `FilesystemCapacity`, and deterministic `enforce_retention(now_ms, incoming_bytes)`.

- [ ] **Step 1: RED tests for every boundary**

Test exact and plus-one store/event/revision/count/age/free-space limits, closed ordering `(closed_at, event_id)`, active/corrupt/unknown protection, whole-event deletion only, and unavailable result when no eligible deletion can satisfy reserve.

- [ ] **Step 2: RED GitHub commit**

Commit `test: specify bounded evidence retention` and confirm expected Userspace failure.

- [ ] **Step 3: GREEN implementation**

Calculate with checked `u64`; delete only index-confirmed canonical closed event directories using descriptor-relative exact names; stop on the first identity disagreement and degrade rather than widening deletion.

- [ ] **Step 4: GREEN GitHub commit**

Commit `feat: bound incident evidence retention`; require full green.

### Task 5: Bounded Output Worker and Daemon Lifecycle

**Files:**
- Modify: `crates/l2-loop-agent/src/observation.rs`
- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Test: `crates/l2-loop-agent/tests/daemon_incidents.rs`

**Interfaces:**
- `SamplingService::take_incident_jobs()` drains only newly produced bounded jobs.
- `IncidentOutputWorker` owns `tokio::sync::mpsc::channel::<IncidentWriteJob>(32)` and one blocking store worker.

- [ ] **Step 1: RED integration tests**

Prove one job per new transition, no job on requests, no duplicate jobs, queue-full degradation without sampling blockage, ordered writes, persistence-before-alert, detach closure, failed detach state preservation, shutdown closure, store-unavailable detection independence, and generation reset.

- [ ] **Step 2: RED GitHub commit**

Commit `test: specify bounded daemon incident output`; verify expected Userspace failure.

- [ ] **Step 3: GREEN daemon wiring**

After each successful background evaluation, copy newly appended transitions into the pure recorder and `try_send` jobs. Use `spawn_blocking` for store work. Shutdown closes the channel and waits a fixed five-second drain; timeout degrades output but never blocks owned cleanup.

- [ ] **Step 4: GREEN GitHub commit**

Commit `feat: connect incident output lifecycle`; require all jobs green.

### Task 6: Sanitized Alert Sink and Fallback

**Files:**
- Create: `crates/l2-loop-agent/src/alert.rs`
- Modify: `crates/l2-loop-agent/Cargo.toml`
- Test: `crates/l2-loop-agent/tests/alert_sink.rs`

**Interfaces:**
- `AlertSink::publish(&SanitizedAlertV1)`; `LinuxAlertSink` chooses journald when available and permanently falls back to one JSON line on stderr after a send failure.

- [ ] **Step 1: RED alert tests**

Assert exact fields/message templates, persistence status truthfulness, severity, no raw/prohibited fields or error chains, fallback JSON, one deduplicated output-health warning, and no recursive evidence job.

- [ ] **Step 2: RED GitHub commit**

Commit `test: specify sanitized local incident alerts` and verify failure for missing sink.

- [ ] **Step 3: GREEN sink implementation**

Build fields only from validated domain enums and IDs. Keep alert delivery best effort; never propagate sink failure into sampling, state, attachment, or cleanup.

- [ ] **Step 4: GREEN GitHub commit**

Commit `feat: publish sanitized local incident alerts`; require full green and dependency-policy checks.

### Task 7: Protocol, Status, CLI List and Show

**Files:**
- Modify: `crates/l2-loop-core/src/command.rs`
- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-cli/src/args.rs`
- Modify: `crates/l2-loop-cli/src/convert.rs`
- Modify: `crates/l2-loop-cli/src/render.rs`
- Test: `crates/l2-loop-cli/tests/cli.rs`
- Test: `crates/l2-loop-cli/tests/render.rs`
- Test: `crates/l2-loop-cli/tests/socket_round_trip.rs`

**Interfaces:**
- Replace placeholder evidence commands/results atomically with bounded query/result types; extend `InterfaceStatus` with output health and optional active event metadata.

- [ ] **Step 1: RED CLI/socket tests**

Cover default 50/max 200, zero/201 rejection, canonical ID parsing before transport, cursor forwarding/mismatch, stable error/exit codes, descending list, detail, text/JSON parity, empty store, 1 MiB frame edge, status health, and prohibited-field scans.

- [ ] **Step 2: RED GitHub commit**

Commit `test: specify local evidence CLI` and require expected Userspace failure.

- [ ] **Step 3: GREEN control implementation**

Bound list before serialization; return sanitized index/detail models only. Keep root-only socket mode 0600 and protocol version 1. CLI performs rendering only and never reads the store path.

- [ ] **Step 4: GREEN GitHub commit**

Commit `feat: expose bounded local incident evidence`; require all five jobs green.

### Task 8: Exact-Artifact Isolated Acceptance

**Files:**
- Modify: `scripts/verify-isolated-host.ps1`
- Modify: `scripts/tests/verify-isolated-host.Tests.ps1`

**Interfaces:**
- Adds `IncidentLifecycle`, `IncidentPersistenceFailure`, and `IncidentRestartRecovery` scenarios using an exact generated acceptance evidence root.

- [ ] **Step 1: RED safety assertions**

Require all scenario names, Schema 5, evidence schema 1, exact generated evidence paths, 0700/0600 checks, list/show/status, restart recovery, persistence failure, privacy scans, pre/post host identity, and exact cleanup. Continue forbidding `/var/lib` writes, host journald mutation, wildcard cleanup, package/service/sysctl commands, and production interfaces.

- [ ] **Step 2: RED GitHub commit**

Commit `test: specify isolated incident output acceptance`; require both script-safety jobs to fail for missing scenarios while Rust/eBPF remain green.

- [ ] **Step 3: GREEN harness implementation**

Trigger real adaptive and relationship incidents inside generated veth resources, verify immutable revision growth and sanitized CLI output, restart the daemon against the same generated root, inject one store failure, and prove forwarding plus exact cleanup.

- [ ] **Step 4: GREEN GitHub and host verification**

Commit `test: verify isolated incident output`; require exact five-job green, then run the three scenarios on the authorized node against that checksum-verified SHA.

### Task 9: Final Audit, Documentation, and Complete Matrix

**Files:**
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`
- Modify: `docs/superpowers/specs/2026-08-06-local-alert-evidence-output-design.md` to mark it superseded

**Interfaces:**
- Produces final Delivery F operational and safety documentation.

- [ ] **Step 1: Document actual behavior and boundaries**

Document incident lifecycle, fixed bounds, atomicity/recovery, alert truthfulness, CLI, root-only access, retention, privacy, failure semantics, and explicit absence of raw evidence/PCAP/probes/drops/policies/production attachment.

- [ ] **Step 2: Run non-compiling audits**

Require retired identifier and sensitive target/key zero; eBPF drop actions zero; confirmed-loop API zero; raw serialized identity zero; no public bound/path/threshold controls; immutable Actions; exact constants; unchanged eBPF/Map ABI; safe generated cleanup.

- [ ] **Step 3: Final commit and exact CI**

Commit `docs: finalize bounded incident output`; push `main`, require exact five-job green, exact manifest SHA, and checksum 5/5.

- [ ] **Step 4: Run complete exact-artifact matrix and residue audit**

Run the existing 15 scenarios plus the three incident scenarios against the final SHA. Require 18/18 pass, forwarding intact, pre/post network/eBPF identity equality, generated evidence cleanup, no namespace/veth/journal/pin/evidence residue, clean worktree, and `HEAD == origin/main`.

## Self-Review

- Spec coverage: all eight design sections map to Tasks 1 through 9; production-root/group/journald host mutation, raw evidence, and PCAP are explicitly deferred rather than silently omitted.
- Placeholder scan: the plan contains no deferred implementation placeholder; every task names files, interfaces, RED evidence, GREEN behavior, commits, and gates.
- Type consistency: `EventId`, `IncidentRevisionV1`, `IncidentWriteJob`, `EvidenceStore`, `AlertSink`, `OutputHealth`, and evidence query/result names are defined once and consumed consistently.
