# Delivery E Passive Detection State Machine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Subagents and worktrees are forbidden by the project owner for this delivery; execute inline on `main`.

**Goal:** Add a generation-scoped Schema 5 passive storm and external-loop confidence state machine driven by fixed 1 Hz rate/baseline evidence and fixed 10-second bounded fingerprint deltas.

**Architecture:** Pure `l2-loop-core` components validate fingerprint scan endpoints, derive fixed storm/relationship signals, and maintain bounded transitions. `SamplingService` owns those components and selects a full identity-confirmed analysis read only when a monotonic 10-second deadline is due; requests copy cached detection state. The Linux adapter, daemon, protocol, CLI, and isolated harness expose and verify the new report without changing eBPF, Map ABI, forwarding, or attachment scope.

**Tech Stack:** Rust 1.97.1, Aya 0.13.1, Tokio 1.50, Serde, Clap, PowerShell 5.1/7, GitHub Actions, MUSL, Linux network namespaces/veth.

## Global Constraints

- Work directly on `main`; do not create a branch, worktree, pull request, or subagent.
- Do not run Cargo, rustc, rustfmt, Clippy, or Rust tests locally. Every Rust RED/GREEN observation comes from the exact GitHub commit.
- Use test-first RED commits. A RED run must fail for the named missing contract while eBPF and both script-safety jobs remain green before production code is written.
- eBPF and the six-Map ABI remain byte-for-byte unchanged. Every data-plane result stays fail-open.
- The only mutable host resources are unique generated namespace/veth, journal, pin, socket, and run-root objects on the authorized test node.
- Fixed contracts are: 1-second rate ticks, 10,000–15,000 ms fingerprint coverage, 1,000 pps/1,048,576 B/s adaptive floors, 100,000 pps/104,857,600 B/s absolute thresholds, 800-milli BUM/dominance ratios, 16 ingress samples, 4,000-milli amplification, 3 assertion ticks, 10 clearing ticks, 30,000 ms cooldown, and 16 retained transitions.
- Passive output stops at `external_loop_high_confidence`; no confirmed-loop enum, probe, drop, policy, persistence, alert sink, topology attribution, or production attachment is introduced.
- The retired identifier, test target, and key material remain absent from all tracked paths and contents.

---

### Task 1: Freeze Schema 5 Detection Types and Serialization

**Files:**
- Create: `crates/l2-loop-core/src/detection.rs`
- Create: `crates/l2-loop-core/src/fingerprint_window.rs`
- Create: `crates/l2-loop-core/tests/detection_contract.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Modify: `crates/l2-loop-core/src/observation.rs`
- Modify: `crates/l2-loop-core/src/command.rs`
- Modify: `crates/l2-loop-core/tests/observation_snapshot.rs`
- Modify: `xtask/tests/public_ebpf_contract.rs`

**Interfaces:**
- Consumes: `RateIdentity`, `HookRole`, `TrafficClass`, `FingerprintState`, existing Schema 4 snapshot/status models.
- Produces: all fixed `DETECTION_*` constants, `FingerprintWindowState`, the serializable `FingerprintWindowReport`, `DetectionState`, `DetectionTransitionReason`, `DetectionTransition`, `DetectionSignals`, `DetectionReport`, and `DetectionSummary`; Schema 5 snapshot/status fields used by every later task.

- [ ] **Step 1: Write the RED contract tests**

Create tests that import the wished-for API and assert exact constants and snake-case serialization:

```rust
assert_eq!(DETECTION_FINGERPRINT_WINDOW_MS, 10_000);
assert_eq!(DETECTION_FINGERPRINT_FRESHNESS_MS, 15_000);
assert_eq!(DETECTION_ADAPTIVE_PACKET_FLOOR_PPS, 1_000);
assert_eq!(DETECTION_ADAPTIVE_BYTE_FLOOR_BPS, 1_048_576);
assert_eq!(DETECTION_ABSOLUTE_PACKET_THRESHOLD_PPS, 100_000);
assert_eq!(DETECTION_ABSOLUTE_BYTE_THRESHOLD_BPS, 104_857_600);
assert_eq!(DETECTION_BUM_RATIO_MILLI, 800);
assert_eq!(DETECTION_DOMINANT_RATIO_MILLI, 800);
assert_eq!(DETECTION_MINIMUM_INGRESS_SAMPLES, 16);
assert_eq!(DETECTION_AMPLIFICATION_RATIO_MILLI, 4_000);
assert_eq!(DETECTION_ASSERT_TICKS, 3);
assert_eq!(DETECTION_CLEAR_TICKS, 10);
assert_eq!(DETECTION_COOLDOWN_MS, 30_000);
assert_eq!(DETECTION_TRANSITION_CAPACITY, 16);
assert_eq!(OBSERVATION_SCHEMA_VERSION, 5);
```

Cover all nine public states, legal/illegal retained states, error-code validation, transition ordering/capacity, fixed configuration validation, `DetectionSummary::from(&report)`, and the absence of a confirmed-loop variant. Update snapshot/status fixtures to require a warming detection value. Add a static assertion that no eBPF source or Map contract changed.

- [ ] **Step 2: Push RED and verify the expected GitHub failure**

Commit and push:

```text
test: specify passive detection schema
```

Require Script safety, Windows PowerShell safety, and eBPF to succeed. Require Userspace to fail because `detection` and the Schema 5 types/constants do not exist. Record the exact run URL and failure step.

- [ ] **Step 3: Implement the minimal domain model**

Define the public enum without a confirmed state:

```rust
pub enum DetectionState {
    WarmingUp,
    Normal,
    IngressStormConfirmed,
    EgressStormConfirmed,
    BidirectionalStormConfirmed,
    ExternalLoopSuspected,
    ExternalLoopHighConfidence,
    Cooldown,
    Unavailable,
}
```

Implement fixed constructors `FingerprintWindowReport::warming`, `FingerprintWindowReport::unavailable`, `DetectionReport::warming(identity, evaluated_at_unix_ms)`, and `DetectionReport::unavailable(...)`, complete validation, and summary conversion. Add `detection` to `ObservationSnapshot` and `InterfaceStatus`, initialize warming state in `ObservationSnapshot::new`, and bump only the observation schema to 5 while control protocol remains 1.

- [ ] **Step 4: Push GREEN and require five successful jobs**

Commit and push:

```text
feat: add passive detection schema
```

Require Userspace format, Clippy, tests, and default-member check plus eBPF, both script jobs, and Bundle to succeed for the exact SHA.

### Task 2: Implement the Bounded Fingerprint Delta Window

**Files:**
- Create: `crates/l2-loop-core/tests/fingerprint_window.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Modify: `crates/l2-loop-core/src/detection.rs`

**Interfaces:**
- Consumes: validated `FingerprintEvidence`, `RateIdentity`, fixed 8,192-entry capacity.
- Produces: `FingerprintWindowError` and `FingerprintWindowHistory::{new, record_scan, unavailable, cached_report, clear}` over the Task 1 report types.

- [ ] **Step 1: Write RED endpoint and delta tests**

Use real `FingerprintKey`/`FingerprintValue` values and assert:

```rust
let mut history = FingerprintWindowHistory::new(identity);
assert_eq!(history.record_scan(1_000_000_000, 1_000, first)?.state,
           FingerprintWindowState::WarmingUp);
let report = history.record_scan(11_000_000_000, 11_000, second)?;
assert_eq!(report.state, FingerprintWindowState::Ready);
assert_eq!(report.coverage_ms, 10_000);
assert_eq!(report.ingress.packets, expected_ingress_delta);
```

Cover 9,999/10,000/15,000/15,001 ms, early endpoint retention, long-gap reset, new and evicted keys, positive deltas only, repeated/correlated/egress-first relations, dominant share, directional amplification, duplicate exact keys, immutable-field mutation, counter/last-seen/clock regression, identity mismatch, 8,192/8,193 entries, arithmetic overflow, unavailable recovery, and raw-field serialization scans.

- [ ] **Step 2: Push RED and inspect only the expected Userspace failure**

Commit `test: specify fingerprint analysis windows`. Require the failure to name the missing window API; do not implement if an unrelated test or safety job fails.

- [ ] **Step 3: Implement a private bounded endpoint map**

Use a `BTreeMap<ExactFingerprintKey, FingerprintEndpoint>` capped at 8,192. Validate every scan before replacing state. Existing keys use checked subtraction; new keys contribute current counters; missing keys are eviction. Build only privacy-reduced aggregates and store no public raw key. Earlier-than-10-second scans retain the first endpoint; later-than-15-second scans replace it and return warming. Any integrity error clears both endpoints and returns a stable typed error.

- [ ] **Step 4: Push GREEN and require all five jobs**

Commit `feat: add bounded fingerprint analysis windows`. Confirm no eBPF object or manifest contract changes beyond the commit identity.

### Task 3: Derive Fixed Storm and Relationship Signals

**Files:**
- Modify: `crates/l2-loop-core/src/detection.rs`
- Create: `crates/l2-loop-core/tests/detection_signals.rs`

**Interfaces:**
- Consumes: `[DetailedRateWindow; 3]`, `BaselineReport`, cached `FingerprintWindowReport`.
- Produces: `DetectionSignals::derive(...) -> Result<DetectionSignals, DetectionError>` and internal `StormCandidate` ordering.

- [ ] **Step 1: Write RED fixed-signal tests**

Build complete real rate/baseline fixtures. Assert BUM is exactly the first four fixed classes and excludes link-local/unicast. Test every adaptive and absolute packet/byte threshold at minus one, equality, and plus one. Test checked BUM sums, BUM/total ratios with zero totals, source-window identity/end-time consistency, baseline learning/unavailable behavior, fingerprint freshness, suspected requirements one at a time, high-confidence egress-first plus directional 4x, and egress-only refusal.

- [ ] **Step 2: Push RED**

Commit `test: specify passive detection signals`. Require the focused missing-derivation failure on GitHub.

- [ ] **Step 3: Implement pure checked derivation**

Find rate windows by their fixed array positions. Locate baseline subjects by exact hook/subject identity rather than array guesses. Use `u128` for ratios and return an integrity error on impossible totals, mismatched source endpoints, or overflow. Produce separate ingress/egress adaptive and absolute flags plus a strongest current target; never serialize raw fingerprint identity.

- [ ] **Step 4: Push GREEN**

Commit `feat: derive passive detection signals` and require the exact five-job green run.

### Task 4: Implement the Generation-Scoped Detection Engine

**Files:**
- Modify: `crates/l2-loop-core/src/detection.rs`
- Create: `crates/l2-loop-core/tests/detection_engine.rs`

**Interfaces:**
- Consumes: identity, monotonic/wall time, trustworthy `DetectionSignals`, unavailable codes.
- Produces: `DetectionEngine::{new, evaluate, unavailable, pause, cached_report, clear}` with a 16-entry transition deque.

- [ ] **Step 1: Write RED state-machine tests**

Drive the engine with deterministic timestamps and assert:

- warming cannot become normal until both hooks' eight BUM subjects are ready;
- absolute evidence can assert during baseline learning;
- exactly three equal non-empty candidate ticks assert ingress, egress, or bidirectional storm;
- changing candidate kind resets the assertion streak;
- ready fingerprint evidence upgrades confirmed ingress/bidirectional storm to suspected/high-confidence, never confirmed;
- ten trustworthy lower/clear ticks are required for demotion;
- clear enters cooldown, 29,999 ms remains cooldown, and 30,000 ms becomes normal;
- reappearance during cooldown requires three ticks and retains sequence continuity;
- transient unavailable retains the last anomaly, integrity unavailable clears streak/window state, and unavailable time advances no counter;
- transition sequence starts at one, evicts entry 17 while retaining sequence 17, rejects sequence overflow, and resets on a new generation.

- [ ] **Step 2: Push RED**

Commit `test: specify passive detection transitions` and require the missing engine behavior to fail on GitHub.

- [ ] **Step 3: Implement deterministic transition precedence**

Use monotonic nanoseconds for durations and wall milliseconds only for display. Apply precedence `high_confidence > suspected > bidirectional > ingress > egress > normal`. Record a transition only when public state changes. Validate state-specific retained values and keep all counters bounded (`u8` for streaks, `VecDeque` capacity 16, checked `u64` sequence).

- [ ] **Step 4: Push GREEN**

Commit `feat: add passive detection transitions` and require all five jobs.

### Task 5: Integrate Analysis Scheduling into SamplingService

**Files:**
- Modify: `crates/l2-loop-agent/src/ports.rs`
- Modify: `crates/l2-loop-agent/src/observation.rs`
- Modify: `crates/l2-loop-agent/tests/observation_service.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_sampling.rs`

**Interfaces:**
- Consumes: `FingerprintWindowHistory`, `DetectionEngine`, existing clock/reader and ownership identity.
- Produces: `ObservationReadPurpose::BackgroundAnalysis`, monotonic `next_analysis_at_ns`, cached Schema 5 detection on observe/status.

- [ ] **Step 1: Write RED scheduling and lifecycle tests**

Use sequenced fake clock/reader events to require read purposes:

```text
background_sample x9
background_analysis x1
background_sample x9
background_analysis x1
```

Assert the deadline starts 10 seconds after attach, an interval jump causes one analysis read and schedules the next future deadline without catch-up, request reads never mutate detection, request-local LRU failure is isolated, analysis LRU failure follows the unavailable contract, and start/pause/clear/identity/counter/clock paths update all four histories consistently.

- [ ] **Step 2: Push RED**

Commit `test: specify background detection sampling`. Require Userspace to fail on the missing purpose/cache while eBPF and script safety remain green.

- [ ] **Step 3: Extend SamplingService in strict order**

On every tick choose purpose before the read, then process cumulative rate, baseline, due fingerprint window, and detection. Use checked deadline arithmetic and set the next deadline strictly after `now`; never loop over missed deadlines. Background analysis `RawFingerprints::Unavailable` must leave the valid cumulative sample available. Add cached detection to request snapshots/status and include detection unavailable in observation-health degradation.

- [ ] **Step 4: Push GREEN**

Commit `feat: integrate passive detection sampling` and require the exact green artifact.

### Task 6: Wire the Linux Reader and Daemon Lifecycle

**Files:**
- Modify: `crates/l2-loop-agent/src/linux/observation.rs`
- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/src/linux/acceptance_fault.rs`
- Modify: `crates/l2-loop-agent/tests/observation_reader.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_dispatch.rs`
- Modify: `crates/l2-loop-agent/tests/acceptance_fault.rs`

**Interfaces:**
- Consumes: `BackgroundAnalysis` and existing exact journal/Map identity checks.
- Produces: request and analysis LRU enumeration with distinct one-shot acceptance faults; exact daemon start/pause/clear behavior.

- [ ] **Step 1: Write RED adapter/daemon tests**

Assert `BackgroundSample` reads no LRU, `BackgroundAnalysis` validates the confirmed `FINGERPRINTS` name/path/kernel Map ID and iterates at most 8,192 entries, and request/analysis failures use separate fault names. Assert attach initializes detection before publishing active session; detach/shutdown pause before cleanup and clear only after successful exact cleanup; failed cleanup retains unavailable state.

- [ ] **Step 2: Push RED**

Commit `test: specify Linux detection lifecycle` and inspect the focused GitHub failure.

- [ ] **Step 3: Reuse the existing bounded Aya enumeration**

Route `Request` and `BackgroundAnalysis` through the same validated map-read helper, preserving their separate fault injection. Keep `BackgroundSample` as counters-only. Do not add a thread, timer, Map, pin, attachment mode, or eBPF instruction.

- [ ] **Step 4: Push GREEN**

Commit `feat: wire passive detection lifecycle` and require five successful jobs.

### Task 7: Render Schema 5 through the Real Unix Socket

**Files:**
- Modify: `crates/l2-loop-cli/src/render.rs`
- Modify: `crates/l2-loop-cli/tests/render.rs`
- Modify: `crates/l2-loop-cli/tests/socket_round_trip.rs`
- Modify: `crates/l2-loop-agent/tests/protocol_framing.rs`

**Interfaces:**
- Consumes: validated `DetectionReport` and `DetectionSummary` embedded in existing results.
- Produces: stable text sections and direct JSON serialization; no new command or argument.

- [ ] **Step 1: Write RED rendering/privacy tests**

Require `observe` text to render state, retained state, timestamps, fixed signals, fingerprint-window aggregates, streaks, sequence, and transitions in domain order. Require `status` to render only the summary. Round-trip warming, high-confidence, cooldown, and unavailable values through a real Unix socket. Scan text/JSON for prohibited raw fingerprint, MAC, key, packet-byte, monotonic timestamp, confirmed-loop, and caller-control fields.

- [ ] **Step 2: Push RED**

Commit `test: specify passive detection output` and require the focused output failure.

- [ ] **Step 3: Implement calculation-free rendering**

Add label-only helpers for state/reason/window state and append values exactly as supplied by the domain. Keep protocol version 1 and the one-MiB frame bound. Do not add detection CLI flags.

- [ ] **Step 4: Push GREEN**

Commit `feat: render passive detection state` and require all five jobs and an exact MUSL artifact.

### Task 8: Extend Exact-Artifact Isolated Host Acceptance

**Files:**
- Modify: `scripts/verify-isolated-host.ps1`
- Modify: `scripts/tests/verify-isolated-host.Tests.ps1`

**Interfaces:**
- Consumes: exact green artifact and existing generated namespace/veth harness.
- Produces: four new bounded scenarios and a fifteen-scenario final matrix.

- [ ] **Step 1: Write RED script-safety assertions**

Require all four exact scenario names, fixed thresholds/periods, bounded frame totals, bounded polling deadlines, analysis-only fault injection, Schema 5 fields, forwarding checks, pre/post snapshots, generation reset, and exact cleanup. Continue rejecting package installation, service control, sysctl/offload/route/address mutation, physical/OVS/bond/tap selection, wildcard cleanup, unbounded loops, and target/key literals.

- [ ] **Step 2: Push RED and observe only script-job failures**

Commit `test: specify isolated passive detection`. Require Script safety and Windows PowerShell safety to fail for missing scenarios while Userspace/eBPF remain green.

- [ ] **Step 3: Implement bounded traffic and assertions**

Add `DetectionAdaptiveLifecycle`, `DetectionAbsoluteStartup`, `DetectionRelationshipConfidence`, and `DetectionFailureGenerationReset`. Generate frames only through the existing remote Python process inside generated namespace/veth resources. Cap each burst, overall scenario frames, polling attempts, and runtime. Query JSON without deriving state in PowerShell; assert exact domain fields and refuse any confirmed-loop value.

- [ ] **Step 4: Push GREEN and require the exact artifact**

Commit `test: verify isolated passive detection`. Require five successful jobs and the non-expired `l2-loop-linux-x86_64-<full-sha>` artifact.

- [ ] **Step 5: Run the four new scenarios on the authorized node**

Use only task-scoped environment variables for target/key, never print them, and run the checksum-verified exact SHA. If a scenario fails, use systematic debugging and reproduce with the narrowest deterministic scenario before any fix.

### Task 9: Final Documentation, Audit, and Fifteen-Scenario Acceptance

**Files:**
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`
- Modify: `docs/superpowers/specs/2026-08-12-passive-detection-state-machine-design.md` only if implementation evidence reveals a real specification mismatch.

**Interfaces:**
- Consumes: completed Schema 5 implementation and host evidence.
- Produces: final Delivery E documentation, exact artifact identity, and completion audit.

- [ ] **Step 1: Correct documentation to actual behavior**

Document every fixed threshold and duration, two-rate-path startup behavior, 10-second delta/freshness rules, state precedence, retain/clear matrix, privacy boundary, fifteen scenarios, and the explicit absence of confirmed loops, persistence, alerts, probes, drops, policies, topology, and production attachment.

- [ ] **Step 2: Run non-compiling local safety audits**

Run `git diff --check`, the Linux/Windows PowerShell safety scripts, and quiet tracked scans proving: retired identifier zero; target/key zero; `XDP_DROP`/`TC_ACT_SHOT` zero; mutable Actions zero; public detection controls zero; confirmed-loop state zero; raw fingerprint/MAC output zero; fixed constants exact; no eBPF/Map ABI diff; and clean generated-name cleanup rules.

- [ ] **Step 3: Commit final docs and require exact five-job green**

Commit `docs: finalize passive detection delivery`, push `main`, and wait for all five jobs. Verify manifest SHA and all five checksum entries locally without compiling.

- [ ] **Step 4: Run all fifteen host scenarios against that final SHA**

Run the existing eleven scenarios plus the four new detection scenarios. Every scenario must report pass, forwarding must remain intact, and pre/post network and eBPF state must match.

- [ ] **Step 5: Run independent read-only residue and repository audits**

Prove no generated `l2ns-*`, `l2h*`, `l2n*`, `/run/l2-loop`, or `/sys/fs/bpf/l2-loop` object remains on the node. Prove local `HEAD == origin/main`, tracked worktree clean, exact CI SHA/status, exact manifest SHA, and checksum 5/5.

- [ ] **Step 6: Report Delivery E 100% without claiming whole-product completion**

Report the final SHA, GitHub run URL, artifact identity, 15/15 host scenarios, residue result, and remaining product boundary. Continue automatically to the bounded local alert/evidence delivery unless a real safety-boundary conflict is discovered.
