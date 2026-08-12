# Dynamic Baseline and Observation Health Design

**Date:** 2026-08-12  
**Status:** Approved for implementation

## 1. Goal

This delivery adds a bounded, generation-scoped dynamic baseline over the existing trustworthy fixed rate windows. It describes whether the latest trustworthy passive rate evidence is still being learned, is within the learned range, or is elevated relative to that range. It also separates traffic deviation from observation health.

The delivery remains observation-only. It does not identify a storm or loop, fingerprint packets, infer topology, create an event, send a probe, drop or police traffic, change eBPF programs or Map ABI, persist history, or widen attachment beyond the generated isolated namespace/veth path.

## 2. Fixed Architecture

`RateHistory` remains responsible only for generation-scoped cumulative samples and the fixed 1, 10, and 60 second rate windows.

A pure-domain `BaselineEngine` owns bounded baseline histories and deterministic statistical evaluation. `SamplingService` drives it serially from the existing one-second background tick and publishes one cached `BaselineReport`. Request-time `observe` and `status` reads never learn, mutate, or recompute a baseline.

The update order is fixed:

```text
successful background cumulative read
  -> RateHistory accepts the sample
  -> RateHistory produces the fixed 10-second window
  -> validate readiness and sampling trust
  -> BaselineEngine compares against the prior baseline
  -> reject an elevated subject or accept a non-elevated subject
  -> atomically replace the cached BaselineReport
  -> observe/status only copy the cached report
```

No additional thread, task, queue, channel, mutex, or persistent store is introduced. One daemon session continues to own all observation state.

## 3. Fixed Subjects and Metrics

Baselines are independent for every fixed `hook x subject` pair.

Hooks retain their ABI order:

1. `external_xdp_ingress`
2. `physical_tc_egress`

Subjects retain a fixed order within each hook:

1. `total`
2. the six existing traffic classes in their ABI order
3. `parse_errors`

There are exactly 16 subjects. Every subject stores packet rate and byte rate as one atomic sample pair, producing at most 32 independently elevated metric identifiers.

`total` does not freeze its child classes. One class does not freeze its siblings. One hook does not freeze the other hook.

## 4. Fixed Learning Contract

- Source window: exactly `10_000 ms`.
- Maximum accepted samples per subject: exactly `300`.
- Minimum accepted samples before evaluation: exactly `60`.
- Each successful background tick may process at most one new source window endpoint.
- Duplicate or regressed source endpoints are rejected as integrity failures.
- All state is memory-only and belongs to one exact `(ifindex, generation)` identity.
- Generation or ownership identity change clears the complete baseline immediately.
- Detach and daemon shutdown destroy the complete baseline.

The 10-second source window first becomes ready after approximately ten seconds. Sixty overlapping one-second-spaced source windows are then required, so initial baseline readiness occurs approximately 69 to 70 seconds after attach, not after 60 seconds.

The 1-second window remains immediate context. The 60-second window remains longer context. Neither is learned by this delivery.

## 5. Deterministic Statistics

For an ordered set of values, median is the upper middle value. For even cardinality this is the value at index `len / 2` after ascending sort; the two middle values are never averaged.

MAD is computed by taking the absolute distance of every sample from the median and then taking the upper median of those distances.

All threshold intermediates use `u128`. Public results are clamped to `u64::MAX`. Floating-point arithmetic is forbidden.

The public ratio is `ratio_milli`:

- `1000` means 1.000 times the median;
- `4000` means 4.000 times the median;
- a zero median produces `null` rather than an infinite or synthetic ratio.

Fixed noise floors are:

- packets: `10 pps`;
- bytes: `16_384 B/s`.

For each metric:

```text
threshold = max(
  median + 6 * MAD,
  4 * median,
  metric_noise_floor
)

elevated = current > threshold
```

The comparison is strictly greater than. These noise floors are statistical anti-noise bounds, not device safety limits or loop thresholds. They are domain constants and cannot be selected by a caller or CLI option.

## 6. State Semantics

`BaselineState` has exactly four serialized values:

- `learning`: the trustworthy subject has fewer than 60 accepted samples;
- `within_baseline`: a ready subject has no elevated metric;
- `elevated`: at least one metric for the subject exceeds its threshold;
- `unavailable`: current baseline evidence cannot be trusted.

`within_baseline` means only that the current value is within the baseline learned for this generation. It does not mean safe, normal, below hardware capacity, free of a storm, or free of a loop.

During learning, all trustworthy samples are accepted. A session that starts during a sustained abnormal condition can therefore learn that condition. This startup blind spot is explicit and must later be addressed by absolute safety signals and the separate loop state machine.

After a subject becomes ready, packet and byte metrics are evaluated independently. If either metric is elevated, the complete packet/byte sample pair for that subject is rejected. The elevated evidence is published, but does not update its own baseline. Non-elevated subjects from the same source window continue learning.

There is no baseline-layer duration, consecutive-count, cooldown, or recovery hysteresis. A trustworthy source window is evaluated immediately. Temporal escalation belongs to the later loop-state delivery.

## 7. Observation Health

Traffic deviation and data trust are orthogonal:

- `observation_health` remains `healthy` for `learning`, `within_baseline`, and `elevated` when sampling evidence is trustworthy.
- `observation_health` is `degraded` when sampling is paused, has an unresolved read error, is stale, or baseline integrity is unavailable.
- An elevated rate never degrades observation health by itself.

Interface baseline state aggregation uses this strict priority:

```text
unavailable > elevated > learning > within_baseline
```

An elevated subject is therefore never hidden by a different subject that is still learning. Summary output also exposes learning-subject and elevated-metric counts.

## 8. Failure and Retention Matrix

Transient Map or background sampling failures retain all accepted baseline histories, stop learning, publish `unavailable`, clear all current/statistical evidence from the public baseline result, and preserve per-subject sample counts and latest accepted timestamps. Recovery compares the first trustworthy source window against the retained baseline before deciding whether to accept it.

Sampling pause and stale source evidence follow the same retain-but-unavailable rule.

The following integrity failures clear the complete baseline history:

- generation or ownership identity change;
- source endpoint regression or duplication;
- monotonic clock regression;
- cumulative counter regression inherited from RateHistory;
- fixed subject order or shape mismatch;
- any internal baseline invariant failure.

An integrity failure publishes `unavailable` with an independent stable baseline error code. The next trustworthy background tick starts at `learning`; it cannot immediately reuse the discarded history.

Every failure remains fail-open for forwarding and cumulative observation. A baseline failure never attaches, detaches, repairs, adopts, drops, or applies policy.

## 9. Schema 3 Domain Contract

`ObservationSnapshot.schema_version` advances from 2 to 3. The local control framing protocol remains version 1.

The detailed baseline report is equivalent to:

```text
BaselineReport
  source_window_ms: 10000
  capacity: 300
  minimum_samples: 60
  packet_noise_floor_pps: 10
  byte_noise_floor_bps: 16384
  state: BaselineState
  evaluated_at_unix_ms: optional u64
  source_end_unix_ms: optional u64
  last_successful_evaluation_at_unix_ms: optional u64
  last_error_code: optional stable string
  learning_subject_count: u16
  elevated_metric_count: u16
  subjects: fixed 16 BaselineSubjectReport values

BaselineSubjectReport
  hook: HookRole
  subject: BaselineSubject
  state: BaselineState
  sample_count: u16
  latest_accepted_at_unix_ms: optional u64
  packets: BaselineMetricReport
  bytes: BaselineMetricReport

BaselineMetricReport
  current: optional u64
  median: optional u64
  mad: optional u64
  threshold: optional u64
  ratio_milli: optional u64
  elevated: optional bool
```

`BaselineSubject` is a stable tagged enum containing `total`, the six existing traffic-class values, and `parse_errors`.

Evidence shape is strict:

- `learning` may expose `current`, subject sample count, and latest accepted time; median, MAD, threshold, ratio, and elevated are null.
- `within_baseline` and `elevated` expose complete current, median, MAD, threshold, and elevated evidence; ratio alone may be null when median is zero.
- `unavailable` exposes no current or statistical values. Sample count and latest accepted time remain available to prove retained history.

`evaluated_at_unix_ms` is when the cached report was published, including an unavailable transition. `source_end_unix_ms` identifies the trustworthy 10-second window endpoint represented by current values and is null when there is no current trustworthy source. `last_successful_evaluation_at_unix_ms` survives transient unavailability.

Baseline `current` is the most recent background evaluation, not a request-time recomputation. Existing cumulative counters and rate-window request semantics remain unchanged.

## 10. Status Summary

`observe` returns the complete fixed-order baseline report.

Each `InterfaceStatus` returns a `BaselineSummary` containing:

- overall state;
- evaluated, source-end, and last-successful timestamps;
- last baseline error code;
- learning subject count;
- elevated metric count;
- per-subject sample counts in fixed order;
- up to 32 fixed-order elevated identifiers containing hook, subject, and metric.

The 32-entry bound cannot truncate the current fixed model because 16 subjects each have exactly two metrics.

JSON serializes domain values directly. Text rendering performs no calculation and displays the cache timestamps so operators cannot confuse cached baseline evidence with request-time cumulative evidence.

## 11. CLI and Configuration Boundary

No new caller-selected period, window, capacity, minimum sample count, multiplier, MAD factor, noise floor, retention query, or reset option is added.

Existing `observe` and `status` commands carry schema 3. No new command is required.

## 12. Tests

Pure-domain tests cover:

- upper median for odd and even sets;
- upper MAD;
- 60-sample transition and 300-sample eviction;
- packet and byte evaluation independence;
- zero median and both noise floors;
- strict threshold boundary;
- `u128` intermediates and `u64` clamping;
- fixed-point ratio and zero-median null;
- subject-atomic rejection and sibling acceptance;
- elevated samples not contaminating history;
- fixed subject ordering and aggregate priority;
- transient unavailable retention;
- integrity failure clearing;
- identity and generation reset.

Service and daemon tests cover:

- only background ticks update a baseline;
- each source endpoint is processed at most once;
- request reads are baseline-pure;
- update and cached publication ordering;
- sampling failure, recovery, pause, detach, shutdown, and generation changes;
- baseline health and sampling health composition.

Unix-socket and CLI tests cover schema 3 detailed and summary JSON/text output without renderer-side calculation.

## 13. Authorized Isolated-Host Acceptance

Acceptance continues to use only the exact successful GitHub MUSL artifact on a generated namespace/veth pair. Existing scenarios remain mandatory:

1. `Success`
2. `PassiveObservation`
3. `RateWindows`
4. `RateSamplingFailure`
5. `RateGenerationReset`

Three scenarios are added:

6. `BaselineLifecycle` proves `learning -> within_baseline -> elevated -> within_baseline`, noise-floor behavior, subject-atomic rejection, sibling learning, and recovery after elevated traffic leaves the source window.
7. `BaselineSamplingRecovery` proves retained sample counts, immediate unavailable output, degraded observation health, continued cumulative reads and forwarding, and compare-before-accept recovery.
8. `BaselineGenerationReset` proves exact detach/reattach changes generation, clears every subject, returns to learning, and independently advances the new generation.

Every scenario verifies exact artifact identity, checksum manifest, forwarding, ownership-exact rollback, full before/after foreign network and eBPF identity equality, and absence of owned runtime, pin, namespace, and veth residue.

## 14. Delivery Boundary

This delivery ends with trustworthy baseline-relative evidence and observation-health reporting. It intentionally does not implement:

- absolute hardware or operational safety ceilings;
- loop, storm, or anomaly verdicts;
- duration, hysteresis, cooldown, or event state;
- fingerprints or packet capture;
- topology inference;
- active probes;
- packet drop, rate limiting, or policy;
- production, physical, bond, bridge, OVS, tap, or shared-interface attachment.

The next separate delivery may consume schema 3 evidence to design absolute safety signals and a loop-state machine without changing the baseline learning contract.

## 15. Implementation and Acceptance Record

This specification is implemented on `main`. The delivered code preserves the fixed 10-second source, 300/60 bounds, 10 pps and 16,384 B/s floors, upper-median/upper-MAD integer evaluation, subject-atomic rejection, request-pure cache semantics, retain-versus-clear matrix, four public states, and observation-health separation described above. No eBPF program or Map ABI change was required.

GitHub CI compiles, formats, lints, tests, builds the eBPF object, and produces the exact static MUSL bundle. Authorized-host acceptance uses only that exact checksum-verified artifact. The required matrix contains `Success`, `PassiveObservation`, `RateWindows`, `RateSamplingFailure`, `RateGenerationReset`, `BaselineLifecycle`, `BaselineSamplingRecovery`, and `BaselineGenerationReset`. Each scenario uses only a generated namespace/veth pair and requires before/after foreign network/eBPF identity equality plus zero owned runtime, pin, namespace, and veth residue. A concurrent foreign identity change is a hard refusal and is never normalized away.
