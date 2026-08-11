# Bounded Daemon Sampler and Rate Windows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This repository's approved execution choice is inline `executing-plans`; do not create a branch, worktree, or subagent.

**Goal:** Add one generation-scoped, memory-only 1 Hz daemon sampler and externally verifiable 1-second, 10-second, and 60-second PPS/B/s windows to the existing isolated observation path.

**Architecture:** A pure `l2-loop-core` rate module owns fixed public models and a 64-sample history. The existing agent observation service becomes a sampling service that owns the only reader, clock, and history; daemon ticks and client requests serialize through the existing isolated-control mutex. Client reads remain current and identity-confirmed but never enter rate history, while one Tokio loop supplies the only background samples.

**Tech Stack:** Rust `1.97.1`, Tokio, serde/serde_json, Aya, PowerShell 5.1/7, GitHub Actions, the existing MUSL bundle, and the isolated namespace/veth host harness.

## Global Constraints

- Work directly on `main`; do not create a branch, worktree, pull request, or subagent.
- Do not run Cargo, rustc, rustfmt, Clippy, `bpf-linker`, or Rust tests on the local authoring host.
- All automated tests and builds run through the repository's GitHub Actions workflow with locked inputs.
- Use TDD: push one intentional RED test commit, verify its exact expected GitHub failure, then push the smallest GREEN implementation commit for each task.
- Wait for each exact commit's GitHub run before pushing the next commit because workflow concurrency cancels earlier `main` runs.
- Keep control protocol version 1 and advance only `ObservationSnapshot.schema_version` to 2.
- Keep the eBPF ABI, six owned Map identities/layouts, ownership journal schema, program entry points, and fail-open actions unchanged.
- Sampling period is exactly 1 second; windows are exactly 1, 10, and 60 seconds; stale age is strictly greater than 3 seconds.
- Rate history is memory-only, generation-scoped, and capped at 64 successful samples.
- Rates are integer packets per second and bytes per second; text renders `pps` and `B/s`.
- Never interpolate, synthesize, backlog, overlap, persist, or client-drive samples.
- Never attach to a physical or business interface. Authorized runtime acceptance uses only generated namespace/veth state and the exact GitHub artifact.
- Never print or commit the authorized target, key path, raw ownership evidence, pin paths, kernel object IDs, or credential material.
- Do not introduce packet drops, probes, policing, dynamic baselines, fingerprints, loop verdicts, events, or alerts.

## File Responsibility Map

- `crates/l2-loop-core/src/rate.rs`: fixed rate constants, public rate output types, internal sample/history types, checked calculation, freshness, and bounded diagnostics.
- `crates/l2-loop-core/src/observation.rs`: schema-2 `ObservationSnapshot` construction with detailed rate windows.
- `crates/l2-loop-core/src/command.rs`: `InterfaceStatus` extension with summarized rate windows.
- `crates/l2-loop-agent/src/ports.rs`: request/background read-purpose contract.
- `crates/l2-loop-agent/src/observation.rs`: `SamplingService`, reader failure classification, request/current-read integration, and stable rate errors.
- `crates/l2-loop-agent/src/daemon.rs`: isolated sampling lifecycle, dispatcher tick adapter, serialized daemon sampler, and fatal sampler coordination.
- `crates/l2-loop-agent/src/main.rs`: one cancellation-aware sampler loop wired beside the Unix server.
- `crates/l2-loop-cli/src/render.rs`: stable detailed and summary text output while JSON remains schema-derived.
- `crates/l2-loop-agent/src/linux/acceptance_fault.rs`: test-only background-read fault that cannot fail a request read.
- `scripts/verify-isolated-host.ps1`: three bounded authorized rate scenarios.
- `scripts/tests/verify-isolated-host.Tests.ps1`: Linux/Windows static safety contract for the new scenarios.
- `README.md` and `docs/development.md`: implemented user/developer rate semantics and exact acceptance procedure.

---

### Task 1: Define Schema-2 Rate Output Contracts

**Files:**

- Create: `crates/l2-loop-core/src/rate.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Modify: `crates/l2-loop-core/src/observation.rs`
- Modify: `crates/l2-loop-core/src/command.rs`
- Modify: `crates/l2-loop-core/tests/observation_snapshot.rs`
- Modify: all existing Rust fixtures that directly construct `ObservationSnapshot` or `InterfaceStatus`

**Interfaces:**

- Consumes: existing `ObservationCounters`, `HookObservation`, `HookRole`, `ClassObservation`, `TrafficClass`, and fixed hook/class counts.
- Produces: `RATE_WINDOW_COUNT`, `RATE_WINDOW_MS`, `RATE_HISTORY_CAPACITY`, `RATE_SAMPLE_PERIOD_NS`, `RATE_STALE_AFTER_NS`, `RateWindowState`, `RateCounters`, `SamplingStatus`, `ClassRate`, `HookRate`, `DetailedRateWindow`, `StatusRateWindow`, schema-2 snapshots, and summarized status fields.

- [ ] **Step 1: Add the public contract tests without production types**

In `crates/l2-loop-core/tests/observation_snapshot.rs`, import the new names and assert these exact constants:

```rust
assert_eq!(RATE_WINDOW_COUNT, 3);
assert_eq!(RATE_WINDOW_MS, [1_000, 10_000, 60_000]);
assert_eq!(RATE_HISTORY_CAPACITY, 64);
assert_eq!(RATE_SAMPLE_PERIOD_NS, 1_000_000_000);
assert_eq!(RATE_STALE_AFTER_NS, 3_000_000_000);
assert_eq!(OBSERVATION_SCHEMA_VERSION, 2);
```

Add `schema_two_has_fixed_unambiguous_rate_fields` with one ready 1-second window and warming 10/60-second windows. Require the serialized snapshot keys to be exactly:

```rust
[
    "captured_at_unix_ms",
    "generation",
    "health",
    "hooks",
    "ifindex",
    "interface",
    "rate_windows",
    "sampling",
    "schema_version",
    "vlan_visibility",
]
```

Require ready JSON to contain `packet_delta`, `byte_delta`, `packets_per_second`, `bytes_per_second`, and `elapsed_ns`, and require warming JSON rate fields to be `null`. Assert fixed XDP/TC role order and fixed class order in the rate model.

- [ ] **Step 2: Commit and verify the intentional RED GitHub failure**

Use only static local inspection:

```powershell
git diff --check
git add crates/l2-loop-core/tests/observation_snapshot.rs
git commit -m "test: require schema two rate contracts"
git push origin main
```

Find the run for the exact RED SHA and watch it:

```powershell
$RedCommit = git rev-parse HEAD
$RedRun = gh run list --repo chenyongming211-glitch/network-loop `
    --workflow CI --branch main --commit $RedCommit --limit 1 `
    --json databaseId,headSha,status,conclusion,url | ConvertFrom-Json
gh run watch $RedRun.databaseId `
    --repo chenyongming211-glitch/network-loop --exit-status
```

Expected: Userspace fails because the new constants/types do not exist and the schema is still 1. Script safety and eBPF remain unaffected; Bundle does not become accepted evidence.

- [ ] **Step 3: Implement the fixed public types**

Create `rate.rs` with these public constants and shapes:

```rust
pub const RATE_WINDOW_COUNT: usize = 3;
pub const RATE_WINDOW_MS: [u64; RATE_WINDOW_COUNT] = [1_000, 10_000, 60_000];
pub const RATE_HISTORY_CAPACITY: usize = 64;
pub const RATE_SAMPLE_PERIOD_NS: u64 = 1_000_000_000;
pub const RATE_STALE_AFTER_NS: u64 = 3_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateWindowState {
    WarmingUp,
    Ready,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateCounters {
    pub packet_delta: u64,
    pub byte_delta: u64,
    pub packets_per_second: u64,
    pub bytes_per_second: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingStatus {
    pub latest_success_at_unix_ms: Option<u64>,
    pub last_error_code: Option<String>,
    pub consecutive_failures: u32,
    pub sampling_paused: bool,
}
```

Define `ClassRate` with `traffic_class` and `RateCounters`; `HookRate` with `role`, total, six fixed classes, and parse errors. Define `DetailedRateWindow` with fixed `window_ms`, state, coverage, optional exact elapsed/endpoints, and optional two-hook rates. Define `StatusRateWindow` with the same evidence fields and optional XDP/TC aggregate rates.

Every constructor validates the fixed window, hook, and class order and rejects rate values outside `Ready` or absent rate values inside `Ready` with `DomainError::InvalidObservation`.

- [ ] **Step 4: Advance snapshot and status models**

Export `rate::*` from `lib.rs`, set `OBSERVATION_SCHEMA_VERSION` to 2, and extend the snapshot constructor to consume:

```rust
sampling: SamplingStatus,
rate_windows: [DetailedRateWindow; RATE_WINDOW_COUNT],
```

Extend `InterfaceStatus` with:

```rust
pub sampling: SamplingStatus,
pub rate_windows: [StatusRateWindow; RATE_WINDOW_COUNT],
```

Update every existing fixture constructor with a healthy not-paused status and fixed warming windows. Do not change cumulative counter fields or their meaning.

- [ ] **Step 5: Push GREEN and require five successful GitHub jobs**

```powershell
git diff --check
git add crates/l2-loop-core/src crates/l2-loop-core/tests crates/l2-loop-agent crates/l2-loop-cli
git commit -m "feat: define fixed rate output contracts"
git push origin main
```

Expected GitHub result: Script safety, Windows PowerShell safety, Userspace, eBPF, and Bundle all succeed; schema 2 serializes only the approved bounded fields.

---

### Task 2: Implement the Pure 64-Sample Rate History

**Files:**

- Modify: `crates/l2-loop-core/src/rate.rs`
- Create: `crates/l2-loop-core/tests/rate_history.rs`

**Interfaces:**

- Consumes: Task 1 rate types and existing fixed `HookObservation` arrays.
- Produces: `RateIdentity`, `RateSample`, `RateHistory`, `RateHistoryError`, `insert`, `validate_current`, `detailed_windows`, `status_windows`, `clear_at`, and inspection-only `sample_count`.

- [ ] **Step 1: Write deterministic RED tests for selection and arithmetic**

Create helpers that generate two hooks whose aggregate, six classes, and parse-error counters all increase by distinct known amounts. Add tests named:

```text
first_sample_keeps_all_windows_warming
exact_endpoints_make_each_fixed_window_ready
selection_uses_the_closest_sample_not_later_than_the_target
rates_use_actual_elapsed_nanoseconds_and_round_down
all_hook_class_and_parse_error_deltas_are_calculated
missing_intermediate_samples_need_no_interpolation
sixty_fifth_sample_evicts_exactly_the_oldest
full_ring_without_sixty_seconds_stays_warming
wall_clock_changes_do_not_change_rates
identity_or_counter_regression_clears_before_output
request_validation_never_inserts_a_sample
```

For a 1-second aggregate example, assert exact evidence:

```rust
assert_eq!(rate.packet_delta, 7);
assert_eq!(rate.byte_delta, 700);
assert_eq!(rate.packets_per_second, 7);
assert_eq!(rate.bytes_per_second, 700);
assert_eq!(window.elapsed_ns, Some(1_000_000_000));
```

- [ ] **Step 2: Push RED and verify only the missing history API fails**

Commit `test: require bounded rate history`, push, and watch the exact GitHub run. Expected Userspace failure: unresolved `RateHistory`, `RateSample`, or required methods. No eBPF or harness contract changes.

- [ ] **Step 3: Implement identity, sample, and checked traversal**

Use a private `VecDeque<RateSample>` with capacity enforcement. The public constructor is:

```rust
pub fn new(
    identity: RateIdentity,
    history_epoch_started_at_monotonic_ns: u64,
) -> Result<Self, DomainError>
```

`RateIdentity::new` rejects zero ifindex/generation. `insert` requires exact identity and strictly increasing monotonic timestamps, validates every cumulative counter against the newest sample, pushes one sample, and pops one oldest sample only when length exceeds 64.

Implement counter traversal with fixed arrays rather than dynamic lookup or maps. A helper must apply the same checked delta/rate formula to aggregate, each class, and parse errors.

- [ ] **Step 4: Implement exact window selection and projections**

For each fixed duration, choose the newest `A` with `A.monotonic_ns <= B.monotonic_ns - window_ns`. Calculate with `u128`, integer division, and checked `u64` conversion. `detailed_windows(now)` and `status_windows(now)` must use the same internal calculation result so summaries cannot diverge from detailed totals.

`validate_current` compares identity and every counter against the newest sample without insertion. On counter regression, clear the samples at the supplied monotonic time and return `RateHistoryError::CounterRegression`.

- [ ] **Step 5: Push GREEN and verify all fixed-history tests**

Commit `feat: calculate bounded rate windows`, push, and require the exact five-job GitHub run to pass.

---

### Task 3: Add Bounded Sampling Diagnostics and Failure Semantics

**Files:**

- Modify: `crates/l2-loop-core/src/rate.rs`
- Modify: `crates/l2-loop-core/tests/rate_history.rs`

**Interfaces:**

- Consumes: Task 2 `RateHistory` and error results.
- Produces: `record_success`, `record_transient_failure`, `record_identity_failure`, `record_rate_failure`, `pause`, `sampling_status`, strict 3-second freshness, and stable diagnostic semantics.

- [ ] **Step 1: Add RED tests for diagnostics and state transitions**

Add exact tests for:

```text
transient_failure_retains_samples_and_saturates_failure_count
identity_failure_clears_history_immediately
clock_counter_and_calculation_failures_start_a_new_epoch
successful_sample_clears_transient_diagnostics
age_equal_to_three_seconds_is_fresh
age_greater_than_three_seconds_is_stale_and_has_no_rates
empty_epoch_warms_for_three_seconds_then_becomes_stale
pause_clears_history_and_is_immediately_stale
```

Require `last_error_code` to contain only the supplied stable code, never evidence text. Require every warming/stale window's elapsed/endpoints/rates to be absent.

- [ ] **Step 2: Push RED and verify the missing diagnostic API**

Commit `test: require bounded sampling diagnostics`, push, and verify the exact Userspace failure names the missing methods or incorrect freshness state.

- [ ] **Step 3: Implement diagnostics inside `RateHistory`**

Store only:

```rust
latest_success_at_unix_ms: Option<u64>,
last_error_code: Option<String>,
consecutive_failures: u32,
sampling_paused: bool,
history_epoch_started_at_monotonic_ns: u64,
```

Transient failure retains samples and increments with `saturating_add(1)`. Identity and rate failures call `clear_at(now)` before recording the code. `pause` clears, records `OBS_RATE_SAMPLER_PAUSED`, and sets paused. A successful insert updates latest-success wall time, clears last error/failure count, and cannot unpause a paused history.

Freshness uses monotonic time. If paused, every window is stale immediately. Otherwise, latest age `<= RATE_STALE_AFTER_NS` can be ready; age `>` is stale. An empty epoch follows the same boundary from its epoch start.

- [ ] **Step 4: Push GREEN and require all diagnostic boundary tests**

Commit `feat: track bounded sampler health`, push, and require five successful GitHub jobs.

---

### Task 4: Replace Direct Observation Service with `SamplingService`

**Files:**

- Modify: `crates/l2-loop-agent/src/ports.rs`
- Modify: `crates/l2-loop-agent/src/observation.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Replace tests in: `crates/l2-loop-agent/tests/observation_service.rs`
- Modify: `crates/l2-loop-agent/tests/observation_reader.rs`

**Interfaces:**

- Consumes: `ObservationReader`, `Clock`, ownership records, Task 3 `RateHistory`, and schema-2 constructors.
- Produces: `ObservationReadPurpose::{Request, BackgroundSample}`, `SamplingTickOutcome::{Sampled, Rejected}`, and `SamplingService<R,C>` with `start`, `sample_tick`, `observe`, `status`, `pause`, and `clear`.

- [ ] **Step 1: Write RED service tests with a sequenced fake reader and mutable fake clock**

The fake reader records every purpose and returns a queue of `RawObservation` results. The fake clock independently controls monotonic nanoseconds and wall time. Add tests proving:

```text
background_tick_inserts_exactly_one_sample
request_observe_reads_current_maps_but_does_not_insert_history
request_status_summarizes_the_same_rate_windows
request_and_background_read_purposes_are_distinct
transient_background_error_retains_history
identity_background_error_clears_history
current_counter_regression_clears_before_response_rates
request_read_error_never_falls_back_to_cached_cumulative_data
```

Require reader purpose order to be exactly `[BackgroundSample, Request, Request]` for one tick, observe, and status sequence.

- [ ] **Step 2: Push RED and verify the new service contract fails**

Commit `test: require generation scoped sampling service`, push, and verify Userspace fails because `SamplingService` and read purposes are absent.

- [ ] **Step 3: Add explicit read purpose to the reader port**

Define:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationReadPurpose {
    Request,
    BackgroundSample,
}

pub trait ObservationReader: Send {
    fn read_exact(
        &mut self,
        ownership: &OwnershipRecord,
        purpose: ObservationReadPurpose,
    ) -> Result<RawObservation, PortError>;
}
```

Update `Box<T>` forwarding and `LinuxObservationReader`; production Linux reading ignores the purpose. Update every fake reader explicitly so test-only injection cannot accidentally affect production semantics.

- [ ] **Step 4: Implement `SamplingService` and stable errors**

Export these exact codes:

```rust
pub const OBS_RATE_CLOCK_REGRESSION: &str = "OBS_RATE_CLOCK_REGRESSION";
pub const OBS_RATE_COUNTER_REGRESSION: &str = "OBS_RATE_COUNTER_REGRESSION";
pub const OBS_RATE_CALCULATION_FAILED: &str = "OBS_RATE_CALCULATION_FAILED";
pub const OBS_RATE_SAMPLER_PAUSED: &str = "OBS_RATE_SAMPLER_PAUSED";
```

`sample_tick` performs one background read, validates raw identity, converts wall time, inserts or classifies the failure, and returns a nonfatal outcome. `observe/status` perform purpose `Request`, validate current counters without insertion, derive windows at current monotonic time, and build health `Degraded` only for stale/paused/unresolved-error state.

Retain all existing request-level codes and evidence minimization. Request failures remain `Result::Err`; background data failures become `SamplingTickOutcome::Rejected` and remain inside the active session.

- [ ] **Step 5: Push GREEN and require service/read-purpose coverage**

Commit `feat: integrate generation scoped sampling service`, push, and require all five GitHub jobs to pass.

---

### Task 5: Bind Sampling History to the Isolated Attachment Lifecycle

**Files:**

- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/tests/isolated_control.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_dispatch.rs`

**Interfaces:**

- Consumes: Task 4 `SamplingService` and existing exact attach/detach ownership transaction.
- Produces: `IsolatedControl::sample_tick`, `IsolatedSamplingOutcome::{Idle, Sampled, Rejected}`, generation start/reset, pause-before-detach, and exact retry behavior.

- [ ] **Step 1: Add RED lifecycle tests**

Extend fake controls and add tests named:

```text
tick_without_active_session_is_idle_and_does_not_read
attach_starts_an_empty_history_for_committed_identity
tick_uses_the_canonical_journal_before_reader_io
successful_detach_clears_sampling_state
failed_detach_pauses_and_clears_but_preserves_active_ownership
reattach_uses_a_new_empty_generation
shutdown_serializes_sampling_before_exact_cleanup
```

The failed-detach test must retry with the same exact run ID and prove no sampler read occurs while paused.

- [ ] **Step 2: Push RED and verify trait/lifecycle failures**

Commit `test: require isolated sampler lifecycle`, push, and expect Userspace compile failures for the missing trait method/outcome and lifecycle assertions.

- [ ] **Step 3: Extend the isolated control trait and implementation**

Add:

```rust
fn sample_tick(&mut self) -> Result<IsolatedSamplingOutcome, IsolatedControlError>;
```

No active session returns `Idle`. An active tick loads and compares canonical ownership before calling the service. Data read failures return `Rejected` without becoming an `IsolatedControlError`; lock/journal inconsistency retains the existing internal identity failure.

After successful attach, call `sampling.start` only after the transaction and ownership journal are complete. During detach, hold the same control lock, call `pause`, then call `detach_exact`. On success clear active state. On failure leave the active attachment and canonical journal for an exact retry while keeping sampling paused.

- [ ] **Step 4: Update every `IsolatedControl` fake explicitly**

Each fake must implement `sample_tick`; read-only dispatch fakes return `Idle`, tick-specific fakes record `sample_tick`, and panic fakes prove observe/status never call tick themselves.

- [ ] **Step 5: Push GREEN and require all lifecycle regressions**

Commit `feat: bind sampler to isolated lifecycle`, push, and require five successful GitHub jobs.

---

### Task 6: Run One Cancellation-Aware Daemon Sampler

**Files:**

- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Create: `crates/l2-loop-agent/tests/daemon_sampling.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_dispatch.rs`

**Interfaces:**

- Consumes: Task 5 `IsolatedControl::sample_tick` and existing `Arc<Mutex<Box<dyn IsolatedControl>>>`.
- Produces: `DaemonDispatcher::sample_isolated`, `run_sampling_loop`, one-second skip interval, shared cancellation, and fatal sampler shutdown coordination.

- [ ] **Step 1: Add RED orchestration tests**

Use a fake isolated control with atomic counters and a bounded blocking gate. Test:

```text
dispatcher_sample_uses_spawn_blocking_and_returns_outcome
sampling_loop_never_overlaps_a_slow_tick
sampling_loop_stops_without_starting_another_tick
sampling_loop_does_not_replay_missed_ticks
sampler_failure_stops_server_and_invokes_shutdown_once
ordinary_rejected_sample_does_not_stop_daemon_or_cleanup
```

Tests use short deterministic intervals supplied to a test-only loop parameter. The production wrapper always passes exactly one second and sets `MissedTickBehavior::Skip`.

- [ ] **Step 2: Push RED and verify missing loop/coordinator behavior**

Commit `test: require one bounded daemon sampler`, push, and verify the exact Userspace failure.

- [ ] **Step 3: Implement one serialized dispatcher tick**

`DaemonDispatcher::sample_isolated` clones the isolated control, performs one `spawn_blocking` lock/method call, and distinguishes:

```text
Idle/Sampled/Rejected → nonfatal successful loop iteration
mutex poison/join failure/unexpected control failure → fatal sampler error
```

Do not spawn a tick unless the previous call has completed.

- [ ] **Step 4: Implement cancellation and main coordination**

Use `tokio::sync::watch` from the existing Tokio dependency. The signal coordinator sends one shutdown value observed by both the Unix server and sampler. `run_sampling_loop` selects between cancellation and the next tick, then awaits exactly one dispatcher sample.

Main monitors server and sampler completion. Unexpected sampler failure signals shutdown, waits for the server, invokes `shutdown_isolated`, and returns a new `DaemonError::Sampler`. Normal signal shutdown cancels future ticks, waits for the current serialized operation, then invokes existing exact cleanup.

- [ ] **Step 5: Push GREEN and require daemon concurrency tests**

Commit `feat: run one bounded daemon sampler`, push, and require five successful GitHub jobs.

---

### Task 7: Render Schema-2 Observe/Status over the Real Socket

**Files:**

- Modify: `crates/l2-loop-cli/src/render.rs`
- Modify: `crates/l2-loop-cli/tests/render.rs`
- Modify: `crates/l2-loop-cli/tests/socket_round_trip.rs`
- Modify: `crates/l2-loop-agent/tests/protocol_framing.rs`
- Modify: `crates/l2-loop-agent/tests/unix_transport.rs`

**Interfaces:**

- Consumes: schema-2 detailed/summary output from Tasks 1-6.
- Produces: stable text labels `1s/10s/60s`, `pps`, `B/s`, warming/stale null behavior, unchanged JSON field names, and protocol-v1 round trips.

- [ ] **Step 1: Add RED render and framing fixtures**

Build one ready 1-second window, one warming 10-second window, and one stale 60-second window. Require text to contain:

```text
window: 1s
state: ready
pps: 7
B/s: 700
window: 10s
state: warming_up
window: 60s
state: stale
```

Require text not to print `pps: 0` or `B/s: 0` for warming/stale. Require JSON full names, exact deltas/elapsed, and null rates. Require protocol version 1 and observation schema 2 in a real framed Unix socket response.

- [ ] **Step 2: Push RED and verify renderer expectations fail**

Commit `test: require rate window socket output`, push, and verify Userspace fails only the new render/protocol assertions.

- [ ] **Step 3: Add explicit observation and status text renderers**

Keep JSON as `serde_json::to_string_pretty`. Replace generic text rendering only for `AgentResult::Observation` and `AgentResult::Status` with fixed-order functions. Render cumulative fields first, then sampling status, then windows in the array's validated order. Render detailed classes only for observe and hook aggregates only for status.

Use literal `pps` and `B/s` labels. For warming/stale, render state, coverage, latest-success/error summary, and no numeric rate line.

- [ ] **Step 4: Preserve bounds and error behavior**

Run every response through existing `MAX_PAYLOAD_LEN` encoding. Keep CLI exit 0 for successful warming/stale, exit 1 for `OBS_*` response errors, exit 2 for usage, and exit 4 only for preflight blocked decisions.

- [ ] **Step 5: Push GREEN and require real socket round trips**

Commit `feat: render fixed rate windows`, push, and require all five GitHub jobs.

---

### Task 8: Extend the Isolated Host Harness with Three Rate Scenarios

**Files:**

- Modify: `crates/l2-loop-agent/src/linux/acceptance_fault.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Modify: `crates/l2-loop-agent/tests/acceptance_fault.rs`
- Modify: `scripts/verify-isolated-host.ps1`
- Modify: `scripts/tests/verify-isolated-host.Tests.ps1`

**Interfaces:**

- Consumes: exact schema-2 CLI JSON, `ObservationReadPurpose`, existing traffic-matrix helpers, generated names, exact artifact download, and before/after host snapshots.
- Produces: `RateWindows`, `RateSamplingFailure`, and `RateGenerationReset` scenarios plus a background-only fault mode.

- [ ] **Step 1: Extend static harness tests first**

Require the PowerShell `ValidateSet` and remote shell allowlist to contain exactly the three new scenario names. Require fixed markers for:

```text
RATE_SAMPLE_ITERATIONS=65
RATE_FRAMES_PER_DIRECTION=9
rate-sampling-map-read
packets_per_second
bytes_per_second
packet_delta
byte_delta
elapsed_ns
warming_up
ready
stale
```

Add safety assertions that the script contains no address/route/sysctl/offload mutation, no wildcard cleanup, and no unbounded loop. Keep Linux PowerShell 7 and Windows PowerShell 5.1 compatibility.

- [ ] **Step 2: Add RED Rust tests for a background-only fault**

Add `AcceptanceFault::RateSamplingMapRead`, parsed only from `rate-sampling-map-read`. Wrap the complete `ObservationReader` rather than `ObservationIo` so the fault returns `OBS_MAP_UNAVAILABLE` only for `ObservationReadPurpose::BackgroundSample` and delegates request reads unchanged.

Push `test: require isolated rate acceptance`, then verify Script safety and Userspace fail for the missing scenarios/fault while eBPF remains unchanged.

- [ ] **Step 3: Implement `RateWindows`**

Use the existing generated namespace/veth and exact attachment path. Send the fixed nine-frame classification matrix in both directions once per second for 65 iterations, paced by monotonic time. The total frame count is fixed at 1,170.

Query JSON after the initial interval, after at least 10 seconds, and after at least 60 seconds. Validate state transitions, fixed order, forwarding, and for every ready counter:

```text
reported_rate == delta * 1_000_000_000 / elapsed_ns
elapsed_ns >= window_ms * 1_000_000
```

Do not assert an exact scheduler-dependent rate; assert exact arithmetic from returned evidence and non-zero expected matrix counters.

- [ ] **Step 4: Implement `RateSamplingFailure`**

Launch the daemon with only the background-read fault. Attach normally, wait more than three seconds, and prove request-time cumulative reads still succeed while all windows are stale with null rates, degraded health, stable error code, and positive bounded failure count. Send/receive traffic throughout and prove the fault does not invoke detach or cleanup.

- [ ] **Step 5: Implement `RateGenerationReset`**

Attach, obtain a ready 1-second window, detach exactly, then attach the same generated veth under a second generated run ID so the transaction publishes a new generation. Require every new window to start warming and contain no old endpoint/delta/rate. Drive the new 1-second window ready, then detach exactly.

- [ ] **Step 6: Preserve snapshot equality and exact cleanup**

Every scenario must use existing pre/post `l2-loop-hostcheck` plus link/route snapshots, exact generated-name assertions, bounded cleanup convergence, and checksum verification. Extend static tests to reject broad removal and host mutation in the new branches.

- [ ] **Step 7: Push GREEN and require the complete CI artifact**

Commit `test: verify isolated rate windows`, push, and require Script safety, Windows PowerShell safety, Userspace, eBPF, and Bundle to succeed. CI must not contact the authorized node.

---

### Task 9: Final Safety Audit, Documentation, and Exact-Artifact Acceptance

**Files:**

- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`
- Modify: `docs/superpowers/specs/2026-08-11-bounded-daemon-rate-windows-design.md`
- Execute without repository modification: `scripts/verify-isolated-host.ps1`

**Interfaces:**

- Consumes: all GREEN code, the final exact GitHub artifact, and task-scoped authorized target/key environment inputs.
- Produces: accurate documentation, five-scenario runtime regression evidence, independent residue evidence, and a clean synchronized `main`.

- [ ] **Step 1: Correct all current semantics documentation**

Document:

- memory-only, generation-scoped history;
- 1 Hz sampling and fixed 1/10/60-second windows;
- 64 successful samples and strict greater-than-three-second stale rule;
- request-time cumulative reads versus background rate endpoints;
- packets per second and bytes per second (`B/s`);
- ready/warming/stale/null semantics;
- schema 2 with protocol version 1;
- detailed observe versus summarized status;
- sampling failure, pause, and exact cleanup behavior;
- the absence of 100 ms sampling, persistence, baseline, verdict, probe, drop, and production attachment.

Change the design status to:

```text
**Status:** Implemented; final exact-artifact acceptance gated by Section 15
```

- [ ] **Step 2: Run non-compiling local safety audits**

Run `git diff --check`, then quiet scans that fail without printing matching content for:

- the retired identifier;
- incomplete markers;
- target/credential material;
- `XDP_DROP` or `TC_ACT_SHOT` in eBPF;
- mutable Action references or write-capable workflows;
- missing tracked `Cargo.lock`;
- temporary lock-bootstrap workflow;
- any unbounded rate window/capacity CLI option;
- any production-interface enablement.

Also statically assert the exact period/window/capacity/stale constants and all three harness scenario names.

- [ ] **Step 3: Commit documentation and require the final exact CI run**

```powershell
git add README.md docs/development.md docs/l2-loop-agent-design.md `
    docs/superpowers/specs/2026-08-11-bounded-daemon-rate-windows-design.md
git commit -m "docs: record bounded rate window delivery"
git push origin main
```

Wait for the exact final SHA. Require exactly five successful jobs and one non-expired release artifact named `l2-loop-linux-x86_64-<full-final-sha>`.

- [ ] **Step 4: Run exact-artifact host regression without printing task inputs**

Require exactly one task-scoped key and set the already authorized target/key environment inputs without echoing them. For the same final SHA, run:

```powershell
foreach ($Scenario in @(
    'Success',
    'PassiveObservation',
    'RateWindows',
    'RateSamplingFailure',
    'RateGenerationReset'
)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File scripts/verify-isolated-host.ps1 `
        -Commit $FinalCommit -Scenario $Scenario -TimeoutSeconds 360
    if ($LASTEXITCODE -ne 0) {
        throw "rate-window acceptance failed: $Scenario"
    }
}
```

Capture failure output only after replacing target/key values with fixed redaction labels.

- [ ] **Step 5: Perform an independent read-only residue audit**

Through an exact SSH argument array and stdin script, require absence of:

```text
/run/l2-loop
/sys/fs/bpf/l2-loop
l2ns-* namespaces
l2h?????????? generated host-veth names
l2n?????????? generated peer-veth names
```

The remote command may only inspect paths, namespaces, and links and must return one fixed clean marker.

- [ ] **Step 6: Verify final synchronization and report completion**

Fetch `origin/main` and require:

```text
HEAD == origin/main
current branch == main
working tree empty
normal repository, not linked worktree
five final GitHub jobs successful
exact final artifact present
all five host scenarios successful
independent residue audit clean
```

The final handoff reports Delivery progress as 9/9 and 100%, the full commit SHA, GitHub run URL, exact artifact name, fixed sampling contract, host scenario summary, and the boundary that dynamic baseline/loop decisions remain absent.

The next separate delivery after completion is dynamic baseline and observation-health logic over these fixed trustworthy windows.
