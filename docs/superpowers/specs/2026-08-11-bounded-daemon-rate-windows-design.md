# Bounded Daemon Sampler and Rate Windows Design

**Date:** 2026-08-11
**Status:** Approved for implementation
**Parent:** `docs/superpowers/specs/2026-08-10-isolated-passive-observation-design.md`

## 1. Goal

This delivery adds one bounded daemon background sampler and explicit packet-per-second and byte-per-second windows derived from the existing generation-scoped cumulative eBPF counters.

The delivery remains observation-only. It does not infer a storm or loop, establish a baseline, retain history on disk, change an eBPF program or Map ABI, send a frame, drop traffic, apply a policy, or widen attachment beyond the generated isolated namespace/veth path.

All compilation, formatting, linting, automated tests, and Rust dependency resolution continue to run only in GitHub Actions. Development continues directly on `main`, and authorized-host acceptance uses only the exact successful GitHub artifact.

## 2. Fixed Product Semantics

The first rate-window delivery has these fixed semantics:

- the background sampling period is one second;
- the rate windows are exactly 1 second, 10 seconds, and 60 seconds;
- history exists only in daemon memory;
- history is scoped to one exact interface generation;
- each history contains at most 64 successful samples;
- the daemon has at most one active sampler because it has at most one active isolated session;
- packet rate is packets per second;
- byte rate is bytes per second and is rendered as `B/s`;
- a client request never changes the background sampling sequence;
- incomplete windows are explicit and never presented as zero rates;
- samples from different generations are never compared.

## 3. Non-Goals

This delivery does not add:

- a 100 millisecond burst sampler;
- caller-selected periods, windows, retention, or history queries;
- aligned wall-clock buckets;
- interpolation or synthetic samples;
- persistent samples, a database, or journal history;
- a dynamic baseline or threshold;
- fingerprints, topology evidence, loop decisions, events, or alerts;
- active probes, packet drops, policing, or automatic remediation;
- attachment to a physical, business, shared, bridge, bond, OVS, or tap interface;
- a new eBPF Map, Map layout, Map capacity, program entry point, or ownership journal schema;
- a control protocol version change;
- byte-for-byte reproducible-build claims.

## 4. Safety Invariants

1. Every sample revalidates the active session, canonical ownership journal, hook identities, and all required journal-confirmed Map identities before reading counters.
2. Background sampling is read-only and cannot call attach, detach, repair, adopt, cleanup, policy, or probe operations.
3. At most one Map read is in flight for the active session.
4. A missed tick is skipped. It is never queued or replayed.
5. Client requests may perform their existing current Map read but do not insert a rate-history sample.
6. Rate calculations use monotonic time only. Wall time is display evidence and cannot affect a rate.
7. A generation, ifindex, ownership, hook, or Map identity mismatch prevents cross-identity output.
8. A cumulative-counter regression clears rate history before any rate is returned.
9. Warming and stale windows contain no rate values.
10. Detach and shutdown serialize with sampling before exact owned cleanup.
11. No sampling failure changes forwarding behavior or triggers cleanup.
12. All arrays, histories, tasks, reads, responses, and diagnostic state are statically bounded.

## 5. Architecture

### 5.1 `RateHistory`

`RateHistory` is a pure domain component. It owns no I/O, thread, timer, lock, or kernel handle. It accepts validated samples, keeps a fixed-capacity sequence, enforces identity and monotonicity, and derives the three fixed windows.

It exposes operations equivalent to:

```text
start(identity, history_epoch_started_at_monotonic_ns)
insert(sample)
validate_current(raw_observation)
windows(now_monotonic_ns)
record_failure(classified_error, now_monotonic_ns)
pause(stable_error_code)
clear()
```

The concrete Rust API may use stronger types, but it must not expose an operation that changes the fixed period, windows, or capacity.

### 5.2 `SamplingService`

`SamplingService` owns the existing `ObservationReader`, an injectable clock, and one `RateHistory`. It provides three distinct paths:

- `sample_tick`: performs the background identity-confirmed read and may insert one successful sample;
- `observe`: performs the existing request-time identity-confirmed cumulative read and combines it with derived detailed windows without inserting a history sample;
- `status`: performs the same current read and returns summarized hook windows without inserting a history sample.

Keeping the request read separate preserves Delivery C's request-time Map identity validation. Keeping it out of the history ensures that one or many clients cannot alter the 1 Hz sample sequence.

### 5.3 `TransactionIsolatedControl`

`TransactionIsolatedControl` remains the only active-session and ownership authority. It owns the sampling service through the same mutex already used by attach, detach, observe, and status.

After attach and journal commit succeed, it creates an empty history epoch for the exact ifindex and generation. Before detach it pauses sampling while holding the control lock. Successful detach destroys the history and active session. Failed detach clears history, leaves the canonical ownership evidence intact, and keeps the session paused for an exact retry.

### 5.4 Daemon sampling loop

The daemon owns one Tokio interval with a one-second period and `MissedTickBehavior::Skip`. Each tick calls one dispatcher sampling method through `spawn_blocking` and awaits completion before considering another tick.

The loop exists for the daemon lifetime. With no active session, a tick returns an idle outcome and does not read a Map. The loop does not create a per-interface, per-client, or per-request worker.

The daemon coordinator monitors the Unix server, signal shutdown, and sampler task. An unexpected sampler task panic or exit initiates controlled server shutdown, waits for the current serialized operation, invokes existing exact isolated cleanup, and returns a non-zero daemon result.

## 6. Sample Model and Fixed Storage

One successful internal sample contains:

```text
ifindex
generation
captured_at_monotonic_ns
captured_at_unix_ms
vlan_visibility
two fixed HookObservation values
```

Hook order remains XDP ingress followed by TC egress. Class order remains Layer 2 broadcast, IPv4 multicast, IPv6 multicast, other Layer 2 multicast, link-local control, and unicast or unclassified. Parse-error counters remain separate.

The ring stores at most 64 successful samples. Failures are diagnostic state and do not consume ring capacity. Inserting the sixty-fifth successful sample removes exactly the oldest sample.

The ring does not assume that 64 samples always cover 60 seconds. If actual successful sample timestamps do not cover a requested duration, that window remains warming even when the ring is full.

## 7. Window Selection and Arithmetic

For a window duration `W`:

1. let `B` be the latest successful sample;
2. calculate the monotonic target `B.time - W` using checked arithmetic;
3. select `A`, the most recent retained sample whose monotonic time is not later than the target;
4. if no such `A` exists, the window is warming;
5. require `B.time > A.time` and `B.time - A.time >= W`;
6. require every cumulative counter in `B` to be greater than or equal to its corresponding counter in `A`;
7. subtract all cumulative counters using checked arithmetic;
8. calculate each rate from the exact elapsed nanoseconds.

The formulas are:

```text
packets_per_second = packet_delta * 1_000_000_000 / elapsed_ns
bytes_per_second   = byte_delta   * 1_000_000_000 / elapsed_ns
```

Intermediate multiplication uses `u128`. Division is integer division and therefore rounds down. The final value must convert to `u64` without loss. No floating-point arithmetic is used.

A missing intermediate sample does not require interpolation. If two successful endpoints still cover the full window and all identity and counter checks pass, the window is valid and the exact elapsed denominator naturally includes the gap.

## 8. Window State and Freshness

The public states are:

```text
warming_up
ready
stale
```

Their definitions are:

- `warming_up`: no valid endpoints cover the complete requested duration;
- `ready`: valid endpoints cover the duration and the latest successful sample is no more than three seconds old;
- `stale`: the latest successful sample is more than three seconds old, or the session sampler is paused.

The three-second boundary is inclusive for freshness: an age equal to three seconds is not stale. If the current history epoch has not produced a successful sample, it is warming for its first three seconds and stale afterward. Any safety-mandated history clear starts a new empty history epoch without changing the interface generation.

Warming is an expected lifecycle state. Stale is a concrete non-fatal limitation. A successful current cumulative request may therefore return health `degraded` with stale rate windows, while every stale window contains `null` rates.

An unresolved sampler error or paused sampler also makes the successful cumulative result degraded. A later successful background sample clears the consecutive failure count and last transient error. It may immediately restore a window to ready when retained trustworthy endpoints cover the full duration.

## 9. Public Domain Model

`ObservationSnapshot.schema_version` advances from 1 to 2. The control framing protocol remains version 1.

The public model is equivalent to:

```text
RateWindowState
  warming_up | ready | stale

RateCounters
  packet_delta: u64
  byte_delta: u64
  packets_per_second: u64
  bytes_per_second: u64

SamplingStatus
  latest_success_at_unix_ms: optional u64
  last_error_code: optional stable string
  consecutive_failures: u32
  sampling_paused: bool

DetailedRateWindow
  window_ms: u64
  state: RateWindowState
  coverage_ms: u64
  elapsed_ns: optional u64
  start_unix_ms: optional u64
  end_unix_ms: optional u64
  hooks: optional fixed detailed hook rates

StatusRateWindow
  window_ms: u64
  state: RateWindowState
  coverage_ms: u64
  elapsed_ns: optional u64
  start_unix_ms: optional u64
  end_unix_ms: optional u64
  xdp_ingress: optional RateCounters
  tc_egress: optional RateCounters
```

Detailed hook rates contain aggregate, six fixed classes, and parse-error rate counters. Status windows contain only the two hook aggregates.

The fixed public window order is 1 second, 10 seconds, then 60 seconds. Ready windows contain elapsed time, endpoints, and rates. Warming and stale windows contain `null` elapsed time, endpoints, and rates. `coverage_ms` reports the trustworthy retained coverage currently available and may be less than, equal to, or greater than the requested duration.

The snapshot's existing `captured_at_unix_ms` continues to identify the request-time cumulative read. Each ready rate window has its own endpoint times, so the API never implies that cached background rates and current cumulative values were captured simultaneously.

## 10. Request-Time Behavior

`observe` and `status` keep their current commands and exit-code behavior:

```text
l2-loopctl observe --interface <IFACE> [--json]
l2-loopctl status [--interface <IFACE>] [--json]
```

Each request:

1. verifies the active interface and canonical ownership record;
2. performs the current exact ObservationReader read;
3. verifies that the current ifindex and generation match the active session;
4. compares current cumulative counters with the newest retained sample without inserting the current read;
5. clears rate history if current counters regress;
6. derives rate windows at the request's current monotonic time;
7. constructs schema-2 detailed or summarized output.

`observe` returns cumulative aggregate, class, parse-error, VLAN visibility, sampling status, and detailed rate windows. `status` returns zero or one current session with cumulative hook aggregates, sampling status, and summarized rate windows.

Warming and stale are successful observations and retain CLI exit code 0. A request-time reader, identity, clock, or snapshot failure retains exit code 1. Usage failures retain exit code 2. No stale cumulative snapshot is used as a fallback when a request-time read fails.

## 11. Failure Classification

### 11.1 Transient sampling failures

A transient Map read failure:

- records the stable existing code such as `OBS_MAP_UNAVAILABLE`;
- increments a saturating consecutive-failure counter;
- leaves trustworthy same-generation samples in the ring;
- inserts no synthetic sample;
- never changes network or attachment state;
- eventually makes windows stale through the ordinary three-second freshness rule.

### 11.2 Identity failures

An ownership, hook, generation, ifindex, pin, Map-name, or kernel-Map-ID mismatch:

- records the existing stable identity error;
- clears the complete rate history immediately;
- inserts no sample;
- never adopts the observed state;
- does not detach or clean the session as an error response.

A request-time identity failure still refuses the entire observation through the existing error path.

### 11.3 Rate-specific failures

The delivery adds these stable rate error codes:

| Code | Meaning |
|---|---|
| `OBS_RATE_CLOCK_REGRESSION` | a new monotonic timestamp does not advance |
| `OBS_RATE_COUNTER_REGRESSION` | a current cumulative counter is below retained same-generation evidence |
| `OBS_RATE_CALCULATION_FAILED` | checked endpoint, delta, elapsed, or conversion arithmetic failed |
| `OBS_RATE_SAMPLER_PAUSED` | exact detach was attempted and the active session remains paused |

Clock regression, counter regression, and calculation failure clear the complete history, start a new empty history epoch, record the stable error, and return no numeric rate. The windows then follow the ordinary warming-to-stale rules for that new history epoch. No arithmetic path panics or wraps.

### 11.4 Daemon-level sampler failure

Reader failures are data-plane observation outcomes and do not kill the sampler task. A task panic, join failure, poisoned shared control, or unexpected loop exit is a daemon-level orchestration failure. The daemon stops accepting new requests, performs its existing exact owned cleanup, and exits non-zero.

## 12. Concurrency, Shutdown, and Bounds

The existing isolated control mutex serializes sampling with attach, detach, observe, status, and shutdown. A tick calls one blocking operation and awaits it. No second tick starts while it is running.

Signal shutdown follows this order:

1. stop accepting new Unix socket work;
2. cancel future sampler ticks;
3. wait for the current serialized tick or request;
4. perform existing exact isolated detach and cleanup;
5. remove only the owned Unix socket inode;
6. return the combined server, sampler, and cleanup result.

The fixed resource bounds are:

- one sampler loop;
- one active session;
- one in-flight Map read;
- 64 successful samples;
- three windows;
- two hooks;
- six classes per detailed hook;
- one fixed sampling diagnostic record;
- existing bounded Unix handlers and response frame limit.

## 13. Output and Information Minimization

Text output shows fixed window labels, state, coverage, endpoints when ready, and `pps`/`B/s` values. It does not print absent numeric values as zero.

JSON uses unambiguous full names such as `packets_per_second` and `bytes_per_second`. It includes deltas and exact elapsed nanoseconds so an operator or acceptance harness can independently recompute every ready rate.

Sampling diagnostics expose only a stable error code, a bounded failure count, timestamps, and a paused flag. They do not expose raw journal content, pin paths, kernel Map IDs, program IDs, link IDs, credentials, target identities, or internal error strings.

## 14. Test Strategy

All automated tests execute in GitHub Actions. The local authoring host performs static inspection only.

### 14.1 Domain tests

Deterministic tests with injected samples and clocks cover:

- fixed 1-second, 10-second, and 60-second order;
- first-sample and incomplete-window warming;
- exact-boundary readiness;
- more-than-three-second staleness;
- actual elapsed-time division and downward rounding;
- packet and byte deltas;
- all hook aggregate, class, and parse-error counters;
- missing intermediate samples without interpolation;
- a 64-sample capacity and exact oldest eviction;
- a full ring that still lacks 60 seconds of coverage;
- generation, ifindex, and identity reset;
- monotonic clock regression;
- wall-clock forward and backward changes without rate impact;
- counter regression in every counter position;
- checked arithmetic and conversion refusal;
- current request validation without history insertion.

### 14.2 Service and orchestration tests

Fake readers, clocks, and isolated controls prove:

- idle ticks perform no read;
- exactly one successful sample is inserted per successful tick;
- failed reads insert no sample;
- transient failures retain history;
- identity failures clear history;
- success resets transient failure diagnostics;
- client requests do not change sample count;
- overlapping ticks cannot occur;
- missed ticks are skipped;
- attach starts an empty generation;
- detach success clears history;
- detach failure pauses and clears history while preserving ownership for retry;
- sampler task failure causes controlled shutdown and exact cleanup.

### 14.3 Protocol and CLI tests

Tests cover:

- observation schema 2 serialization;
- protocol version 1 framing;
- detailed observe and summarized status models;
- fixed window ordering;
- ready, warming, stale, and paused rendering;
- `null` numeric rates outside ready state;
- independent delta/elapsed rate recomputation;
- text and JSON Unix socket round trips;
- bounded response encoding;
- unchanged command arguments and exit codes.

All existing attachment, ownership, Map identity, passive observation, forwarding, cleanup, and build-supply-chain tests remain required.

## 15. Authorized Isolated-Host Acceptance

Acceptance uses the exact successful GitHub MUSL artifact and only a generated namespace/veth pair on the authorized node.

### 15.1 `RateWindows`

The harness sends bounded low-rate traffic for approximately 65 seconds. It verifies:

- 1-second, 10-second, and 60-second transitions from warming to ready;
- fixed hook and class ordering;
- non-zero expected traffic rates;
- exact integer recomputation from every returned delta and `elapsed_ns`;
- endpoint elapsed time at least equal to the requested window;
- request-time cumulative counters remain monotonic;
- traffic continues to reach the peer.

### 15.2 `RateSamplingFailure`

A test-only bounded fault adapter fails background observation reads. The harness verifies:

- no synthetic samples appear;
- windows become stale after the fixed freshness threshold;
- stale rate fields are null;
- health is degraded and diagnostics contain only a stable code/count;
- request-time reads retain their existing success or refusal behavior;
- forwarding continues;
- no failure triggers detach or cleanup.

### 15.3 `RateGenerationReset`

The harness performs exact detach followed by a new generated attach and verifies:

- the generation changes;
- every new window begins warming;
- no old endpoint, delta, or rate appears in the new generation;
- the new session can independently reach ready state;
- both sessions perform identity-exact owned cleanup.

Every scenario compares full before/after network and eBPF identity snapshots. A final independent residue audit requires no generated namespace, veth, runtime directory, bpffs directory, journal, owned hook, or sampler process state to remain.

## 16. Delivery and Verification Order

Implementation proceeds test-first in bounded layers:

1. rate domain types and fixed window contracts;
2. pure `RateHistory` insertion and calculation;
3. sampling diagnostics and failure classification;
4. `SamplingService` integration with current observation reads;
5. isolated-control generation lifecycle;
6. daemon interval, cancellation, and fatal-task coordination;
7. schema-2 protocol and CLI rendering;
8. isolated-host rate scenarios and fault adapter;
9. final safety audit, documentation correction, and exact-artifact acceptance.

Each code layer first produces an intentional RED GitHub result for the missing behavior, then the smallest GREEN implementation. No Cargo, rustc, rustfmt, Clippy, linker, or Rust test command runs on the local authoring host.

## 17. Acceptance Criteria

This delivery is complete only when:

1. the sampler period, window set, capacity, stale threshold, hook order, and class order are fixed constants;
2. all rate history is memory-only and generation-scoped;
3. request reads cannot alter the background sample sequence;
4. all rate arithmetic is checked, integer-only, monotonic-time based, and externally recomputable;
5. warming and stale windows never contain numeric rates;
6. transient and identity failures follow their distinct retention rules;
7. sampling never overlaps, backlogs, attaches, detaches, repairs, adopts, or cleans;
8. observation schema 2 and protocol version 1 pass text/JSON round trips;
9. every existing GitHub job and permanent supply-chain gate passes for one exact commit;
10. the exact artifact passes `RateWindows`, `RateSamplingFailure`, and `RateGenerationReset` on the authorized isolated node;
11. forwarding and foreign network/eBPF identity remain unchanged in every scenario;
12. exact cleanup, independent residue audit, prohibited-identifier audit, credential-material audit, and repository synchronization are clean.

After this delivery, the next separate design stage is dynamic baseline and observation-health logic over these trustworthy fixed windows. It remains distinct from fingerprints and loop-state decisions.
