# Delivery E Passive Detection State Machine Design

## 1. Scope

Delivery E adds a generation-scoped, observation-only detection state machine to the isolated L2 Loop Detection Agent. It consumes the fixed 1/10/60-second rate windows, the 10-second dynamic-baseline report, and bounded fingerprint relationships delivered by Schema 4. It publishes a cached Schema 5 detection report through `observe` and a summary through `status`.

This delivery does not change the eBPF programs or Map ABI. It does not send probes, drop or police traffic, persist events, publish alerts, inspect production interfaces, discover topology, or widen attachment beyond generated namespace/veth sessions. Passive evidence may reach `external_loop_high_confidence`; only a separately approved active or external-topology signal may ever produce a confirmed-loop state.

## 2. Alternatives and Selected Architecture

Three approaches were considered:

1. Request-time classification was rejected because CLI request frequency would drive duration, recovery, and cooldown.
2. Enumerating the complete 8,192-entry fingerprint LRU every second was rejected because it would put the most expensive bounded Map read in the 1 Hz sampling path.
3. A hybrid background analyzer is selected. Rate and baseline evaluation remain at 1 Hz. Every fixed 10 seconds, the same sampling service performs one identity-confirmed fingerprint scan, computes a bounded delta window, and feeds a pure state machine. Requests only copy cached detection state and retain their existing request-time cumulative fingerprint report.

The 10-second analysis schedule uses monotonic deadlines and skipped missed intervals. It never catches up by running multiple scans. The first scan establishes an endpoint; the second scan can produce the first ready fingerprint window, so passive loop confidence cannot appear before approximately 20 seconds. Absolute storm protection can become ready after the 1-second rate window and the fixed assertion duration.

## 3. Fixed Contracts

All constants are compile-time product contracts and have no CLI, socket, environment, or configuration override:

| Contract | Value |
|---|---:|
| Rate evaluation period | 1 second |
| Fingerprint delta window | 10,000 ms |
| Fingerprint freshness | 15,000 ms |
| Adaptive BUM packet floor | 1,000 pps |
| Adaptive BUM byte floor | 1,048,576 B/s |
| Absolute BUM packet threshold | 100,000 pps |
| Absolute BUM byte threshold | 104,857,600 B/s |
| BUM share for loop suspicion | 800 milli (80%) |
| Dominant ingress fingerprint share | 800 milli (80%) |
| Minimum ingress fingerprint samples | 16 packets |
| Ingress/egress amplification ratio | 4,000 milli (4x) |
| Storm assertion | 3 consecutive trustworthy ticks |
| Demotion/recovery | 10 consecutive trustworthy ticks |
| Cooldown | 30,000 ms |
| Retained transitions | 16 |

BUM is exactly the sum of `l2_broadcast`, `ipv4_multicast`, `ipv6_multicast`, and `other_l2_multicast`. `link_local_control` and `unicast_or_unclassified` are never included in BUM. Rates use the existing checked integer arithmetic; ratio calculations use `u128`, truncate toward zero, and saturate public `u64` values.

## 4. Bounded Fingerprint Delta History

`FingerprintWindowHistory` is a pure domain component with exactly one interface identity and at most 8,192 exact direction keys. It receives a monotonic capture time, wall-clock capture time, and one fully validated raw LRU scan.

The first scan publishes `warming_up` and becomes the previous endpoint. A subsequent scan for the same identity produces deltas only when monotonic time advances and covers at least 10,000 ms. Existing-key packet and byte counters and last-seen time must not regress; immutable fields and first-seen time must not change. A newly observed key contributes its current counters because it was absent from the prior complete bounded enumeration; this also tolerates normal concurrent LRU insertion. Keys missing from the newer scan are treated as bounded LRU eviction and contribute no delta. Duplicate keys, capacity overflow, identity mismatch, clock regression, counter regression, or impossible source timing make the window unavailable and clear both endpoints. eBPF first/last-seen timestamps are compared only with each other and are never compared with the daemon clock because they are not guaranteed to share the same origin.

A ready `FingerprintWindowReport` contains only privacy-reduced aggregates:

- fixed window and actual coverage;
- captured and delta relation counts;
- ingress and egress sampled packet/byte deltas;
- repeated relation count;
- egress-first correlated relation count;
- dominant ingress packet share in milli;
- maximum directional ingress-to-egress packet ratio in milli.

A relation contributes to a ready window only when it has a positive packet delta on at least one side. A repeated relation has more than one sampled packet on either side during that window. A correlated relation requires positive deltas on both sides. Directional amplification is `ingress_delta * 1000 / egress_delta`; it is never computed from cumulative lifetime totals. Raw fingerprints, MAC addresses, packet bytes, raw keys, and raw boot-monotonic timestamps remain internal and are not serialized.

An LRU iteration failure publishes `unavailable` with a stable uppercase error code. It does not block cumulative counter sampling, baseline learning, forwarding, or request-time recovery. The next scheduled successful scan starts a new warming pair; it does not compare across the failed interval.

## 5. Signal Derivation

For each hook, an adaptive storm candidate requires all of:

1. the fixed 10-second rate window is ready;
2. at least one BUM class for that hook is baseline-elevated in packets or bytes;
3. aggregate BUM is at least 1,000 pps or 1,048,576 B/s.

An absolute storm candidate requires the fixed 1-second window to be ready and aggregate BUM to be at least 100,000 pps or 104,857,600 B/s. It is independent of baseline readiness and closes the startup-learning blind spot. A hook candidate is the logical OR of its adaptive and absolute candidates.

The hook candidate pair maps to no storm, ingress storm, egress storm, or bidirectional storm. A storm becomes confirmed only after the same non-empty candidate is observed on three consecutive trustworthy 1 Hz ticks.

`external_loop_suspected` requires a confirmed ingress or bidirectional storm plus one fresh ready fingerprint window satisfying all of:

- ingress BUM share is at least 800 milli in the ready 10-second rate window;
- at least 16 sampled ingress packets are present;
- at least one relation is repeated in the window;
- the dominant ingress relation contains at least 800 milli of sampled ingress packets.

`external_loop_high_confidence` additionally requires at least one correlated relation whose egress side was observed first and a maximum directional ingress-to-egress packet ratio of at least 4,000 milli. This is lower-bound passive evidence of a locally emitted seed returning with amplification; it is not confirmation of causality.

An egress-only storm never becomes an external-loop result. The current two-hook slice cannot classify local, internal, hybrid, or topology-specific loops.

## 6. State Machine and Hysteresis

The public states are:

```text
warming_up
normal
ingress_storm_confirmed
egress_storm_confirmed
bidirectional_storm_confirmed
external_loop_suspected
external_loop_high_confidence
cooldown
unavailable
```

The engine is created at successful attach and destroyed at successful detach or shutdown. It is bound to `(ifindex, generation)`. It never compares different generations.

Storm assertion requires the fixed three-tick streak. A ready fingerprint window may immediately upgrade an already-confirmed ingress/bidirectional storm to suspected or high-confidence. Upgrades always choose the strongest currently proven state. Moving to a weaker anomaly or clearing an anomaly requires ten consecutive trustworthy ticks. Clearing enters `cooldown` while retaining the last anomalous state. Thirty seconds of continuously clear trustworthy evidence completes cooldown and returns to `normal`. A candidate that reappears during cooldown must still satisfy the three-tick assertion, but it remains in the same in-memory incident timeline.

`warming_up` means neither adaptive evidence nor the absolute path can yet prove an anomaly. Normal is published only when the fixed 10-second window is ready, all eight BUM baseline subjects across both hooks are no longer learning or unavailable, and no anomaly is present. The absolute path may assert a storm while the adaptive path is still warming. Missing, stale, paused, identity-invalid, counter-invalid, clock-invalid, or fingerprint-invalid evidence cannot advance assertion, recovery, or cooldown.

An integrity failure clears rate, baseline, fingerprint-window, and detection streak state and publishes `unavailable`. A transient read failure preserves bounded histories but publishes `unavailable` with the last trustworthy anomalous state retained separately. Recovery starts from fresh trustworthy evidence; an unavailable interval never counts toward assertion or clearing. Generation change creates a new `warming_up` engine with sequence zero and an empty transition history.

## 7. Schema 5 Domain Model

`OBSERVATION_SCHEMA_VERSION` becomes `5`. `ObservationSnapshot` adds a complete `DetectionReport`; `InterfaceStatus` adds `DetectionSummary`.

`DetectionReport` contains:

- current state and optional retained anomalous state;
- evaluation, state-start, and last-trustworthy wall-clock times;
- fixed threshold values;
- current ingress/egress BUM pps, B/s, and ratio evidence when available;
- adaptive and absolute candidate flags;
- the cached privacy-reduced fingerprint-window report;
- candidate and clear streak counts;
- transition sequence and at most 16 typed transitions;
- optional stable error code.

Each transition records sequence, previous state, current state, reason, and wall-clock occurrence time. Sequence starts at one and increments with checked arithmetic. When the 16-entry deque is full, the oldest transition is evicted; sequence never resets within a generation. Continuing samples that do not change public state create no transition.

`DetectionSummary` omits the transition list and detailed thresholds but retains state, retained anomalous state, sequence, state-start time, last-trustworthy time, current candidate class, fingerprint-window state, and stable error code. Both models validate fixed configuration, representable counts, monotonic sequence order, legal retained states, and state-specific optional fields before serialization.

CLI text rendering performs no threshold, ratio, or state calculation. JSON serializes validated domain models directly. Neither output contains raw fingerprints, MAC addresses, packet bytes, raw Map keys, raw boot-monotonic timestamps, or caller-controlled detection parameters.

## 8. Service and Failure Semantics

`ObservationReadPurpose` gains `BackgroundAnalysis`. On a due analysis tick, the Linux reader validates the same ownership journal, hook identities, six Map identities, and complete LRU bound used by request reads. It returns cumulative counters plus available or unavailable fingerprints. Non-analysis background ticks retain `BackgroundSample` and never enumerate the LRU.

`SamplingService` owns rate history, baseline engine, fingerprint-window history, detection engine, and the next analysis deadline. A successful tick first validates and records the rate sample, then evaluates the baseline, then consumes a due fingerprint scan, then evaluates detection. Requests validate current cumulative state and return cached rate, baseline, and detection evidence; request-time fingerprint reads remain independent and do not mutate any history or transition.

Fingerprint analysis failure degrades detection but does not erase rate/baseline output. When the last trustworthy state is normal or a rate-only storm, trustworthy rate evidence may continue publishing that rate-only state with fingerprint-window state `unavailable`; it cannot upgrade to a loop state. When the last trustworthy state is suspected or high-confidence, losing its required fingerprint evidence publishes detection state `unavailable` and retains that loop state separately rather than falsely demoting it. Detection-unavailable makes overall observation health degraded even if the request-time fingerprint read succeeds. A later scheduled analysis must establish a new two-endpoint window before loop confidence can recover.

Pause marks detection unavailable. Successful detach, shutdown, and exact cleanup destroy all detection state. Failed detach preserves ownership and paused/unavailable diagnostic state, matching the existing fail-safe lifecycle.

## 9. Test and Acceptance Contract

Pure domain tests cover:

- first/second fingerprint endpoints, exact 10-second coverage, eviction, new keys, duplicate keys, identity and immutable-field mismatches, clock/counter regression, capacity, overflow, ratio truncation, and privacy;
- fixed BUM membership and exclusion of link-local/unicast traffic;
- adaptive and absolute candidates at equality and just above/below every threshold;
- three-tick assertion, candidate-kind changes, ten-tick demotion, 30-second cooldown, reappearance, unavailable retention, recovery, transition eviction, sequence overflow, and generation reset;
- suspected/high-confidence requirements and refusal to confirm a loop from passive evidence.

Service tests prove that only every due 10-second tick uses `BackgroundAnalysis`, missed deadlines do not cause catch-up scans, request reads do not mutate detection, a request-local fingerprint failure does not corrupt background state, and every pause/clear/identity-failure path follows the retain-versus-clear contract.

Protocol and CLI tests cover real Unix socket Schema 5 `observe/status` text and JSON, exact transition ordering, no public threshold controls, and prohibited-field scans.

The isolated host harness adds four exact-artifact scenarios:

1. `DetectionAdaptiveLifecycle`: complete baseline learning, assert a sustained adaptive ingress BUM anomaly, stop it, observe cooldown, and return to normal.
2. `DetectionAbsoluteStartup`: cross the fixed absolute BUM threshold during baseline learning and confirm the startup guard after three ticks.
3. `DetectionRelationshipConfidence`: create deterministic selected egress-first and amplified ingress evidence, then reach external-loop high-confidence without a confirmed-loop result.
4. `DetectionFailureGenerationReset`: inject one background-analysis LRU failure, require unavailable and two-endpoint recovery, then reattach with a new generation and prove all detection state resets.

All traffic is generated only inside unique namespace/veth resources. Each scenario preserves forwarding, checksum-verifies the exact GitHub artifact, captures pre/post host network and eBPF state, uses bounded traffic counts and timeouts, and performs exact identity cleanup. The final matrix contains the existing eleven scenarios plus these four scenarios.

## 10. Delivery Boundary

Delivery E completes in-memory, observation-only passive storm and external-loop confidence transitions for one isolated interface generation. It intentionally stops below confirmed loop, local/internal topology attribution, durable evidence, journald alerts, active probes, packet drops, policing, and production attachment.

The next delivery may connect typed transitions to the already designed bounded evidence and local alert pipeline. Topology discovery, active confirmation, and mitigation remain separate approvals because they change trust or mutation boundaries.
