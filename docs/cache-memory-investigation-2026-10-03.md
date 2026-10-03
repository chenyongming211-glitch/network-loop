# Cache and memory stall investigation

On 2026-10-03, all 24 fixed isolated trials completed on ostack7. The 32 counted
directional windows had full counter coverage. L2/L3-miss-associated stalls were
small relative to total execution stalls, weakening a lower-level memory-wait
explanation for the sampled fluctuations. Sibling activity remains associated
with execution cost but does not uniquely explain it. L1-related waiting,
execution-resource contention and other pipeline effects remain unresolved.
No product speedup, product-code change or production-admission change is claimed.

## Scope and measurement contract

This follow-up on ostack7 uses the same frozen `fp_hash` diagnostic artifact,
selected synthetic ARP corpus, timeout sender and CPU 29 as the preceding
[aligned accounting experiment](aligned-accounting-investigation-2026-10-03.md).
CPU 9 is the sibling hardware thread. Neither thread is reserved; other agents
continue running. Only newly launched senders have their own affinity set. There
are no physical-interface, foreign-process, IRQ, NUMA, frequency, scheduler or
global performance-counter changes.

The node identifies as Intel Xeon Silver 4210, family 6, model 85, stepping 7.
The disposable launcher checks that identity for CPU 29 and the raw PMU type
before opening model-specific counters. Generic `stalled-cycles-backend` reports
unsupported, not zero. Separate short capability probes confirm both fixed raw
event sets can run with full coverage.

Four predeclared six-trial blocks alternate `plain, cache, stall, stall, cache,
plain` and `stall, cache, plain, plain, cache, stall`. Each trial measures host
then peer sequentially, using the existing 0.5-second/100,000-packet warm-up and
5-second/2,000,000-packet measurement limits. These are not simultaneous
full-duplex measurements. There are no outcome-dependent retries or exclusions.

`plain` retains boundary and CPU accounting without opening performance events.
Both counted groups retain task-clock, cycles, instructions and reference cycles.
They add three events each, avoiding the need to schedule all six raw events at
once. The existing tested accounting helper is unchanged on disk; a task-local,
disposable wrapper selects these fixed experiment sets in memory. This is not a
new product capability, supported CLI or shipped general raw-PMU interface.

| Group | Event | Raw config | Interpretation |
| --- | --- | --- | --- |
| cache | MEM_LOAD_RETIRED.L1_MISS | 0x08d1 | Retired loads missing L1 |
| cache | MEM_LOAD_RETIRED.L2_MISS | 0x10d1 | Retired loads missing L2 |
| cache | MEM_LOAD_RETIRED.L3_MISS | 0x20d1 | Retired loads missing L3 |
| stall | CYCLE_ACTIVITY.STALLS_TOTAL | 0x040004a3 | Execution stall cycles |
| stall | CYCLE_ACTIVITY.STALLS_L2_MISS | 0x050005a3 | Stalls with an outstanding L2-missing demand load |
| stall | CYCLE_ACTIVITY.STALLS_L3_MISS | 0x060006a3 | Stalls with an outstanding L3-missing demand load |

Encodings and meanings follow the
[Intel Cascade Lake event definitions](https://github.com/intel/perfmon/blob/86f146e15626b0fd3b032cab4538cafaaf2d0635/CLX/events/cascadelakex_core.json),
version 1.25. `cmask` is included in each stall configuration. AnyThread is zero.
All events count only the calling sender thread (`pid=0, cpu=-1`), without
inheritance, sampling, exclusive access, uncore events or CPU-wide attachment.
The scope includes sender user code and its kernel/interrupt context; it is not
an isolated eBPF helper measurement. Descriptors close on exit.

Cache numbers below count retired-load events, not cache-line transactions or a
miss probability: total load instructions were not measured. Stall events overlap
and must not be added. An outstanding L3 miss is not a direct DRAM latency or
bandwidth measurement, nor proof that it alone caused an execution stall. Cache
and stall groups run in different windows and must not be subtracted as if they
were simultaneous. CPU 9 activity comes from read-only `/proc/stat`, not counters
attached to its processes. Small-sample correlations are descriptive, not causal.

All counter readings retain value, enabled time and running time. Only exact
positive enabled/running equality is usable; no multiplexing correction is
applied. Boundaries remain sequential, not atomic, and CPU tick granularity is
10 ms. No cache flushing, forced memory placement or SMT-disable intervention
occurs.

## Complete results

Each direction has eight cache windows, eight stall windows and eight plain
controls. All 48 measurement windows reached five seconds without packet-cap
censoring; all recorded migrations were zero. All 32 counted windows were usable
with exact 100% enabled/running coverage for every event. Independent arithmetic
recomputed and checked all reported event deltas against the raw readings.

| Cache events per packet | Host range | Peer range |
| --- | ---: | ---: |
| L1 miss | 88.807–112.684 | 115.405–134.696 |
| L2 miss | 0.158–0.260 | 0.140–0.299 |
| L3 miss | 0.048–0.088 | 0.045–0.095 |

| Stall cycles divided by thread cycles | Host range | Peer range |
| --- | ---: | ---: |
| Total execution stalls | 25.081–27.503% | 25.563–27.151% |
| Stalls with L2-missing demand load outstanding | 0.366–0.614% | 0.307–0.444% |
| Stalls with L3-missing demand load outstanding | 0.213–0.353% | 0.191–0.267% |

These observations do not support L2/L3-miss-associated execution waiting as the
dominant measured stall component. They do **not** rule out all memory effects:
L1-hit latency, L1-miss/L2-hit waiting, load/store resources and other memory-related
effects are not isolated by this event set. Neither cache misses nor these stall
events identify which user/kernel/eBPF code caused the counts.

Across counted windows, cycles per instruction ranged 0.57564–0.61973 on host
and 0.57815–0.61427 on peer. The cycle-rate proxy remained
2.194674–2.194821 GHz. The largest boundary overhead was 4.301 ms and the largest
boundary-envelope off-CPU upper estimate was 4.241 ms, below 0.085% of a window.
As before, this envelope is not an exact runqueue-wait measurement. Neither a
large clock-rate change nor missing task-context runtime explains these counted
window differences.

An exploratory within-block illustration, host stall block 2, shows why total
stalls and lower-level memory stalls must be separated. Both samples remain in
the complete result; the following pair is not a population effect estimate:

| Metric | First sample | Second sample |
| --- | ---: | ---: |
| PPS | 283,840 | 295,568 |
| Cycles per packet | 7,733.58 | 7,427.21 |
| Total execution stall cycles per packet | 2,126.98 | 1,862.80 |
| L2-miss-associated stall cycles per packet | 28.281 | 27.745 |
| L3-miss-associated stall cycles per packet | 16.461 | 15.826 |
| Sibling CPU 9 busy | 6.640% | 8.669% |

PPS increased 4.132%; cycles per packet fell 306.37 and total stall cycles per
packet fell 264.18. The L2- and L3-associated values changed by less than one
cycle per packet each. The two memory-stall changes must not be summed. This
pair does not support attributing its throughput change mainly to those measured
memory stalls. It also contradicts a simple rule that higher sibling busy time
must always produce lower throughput.

## What the sibling association does and does not establish

Within each eight-window group, descriptive Pearson correlations between CPI
and sibling busy time were 0.592/0.630 for host/peer cache windows and 0.702/0.716
for host/peer stall windows. Total stall cycles per thousand instructions tracked
CPI more closely in the stall groups (0.942/0.975). These are small-sample,
temporally ordered observations with shared normalizations, not independent
causal estimates or evidence that another agent is defective.

Counterexamples matter. In host cache block 2, PPS rose 6.485% while sibling
busy time rose from 10.020% to 10.887% and L1 misses per packet rose slightly.
Average sibling busy time omits what that sibling executes and when it overlaps
the sender. SMT execution contention, cache contention and pipeline behavior
therefore remain candidates, not a proven unique cause.

The largest plain peer decline was 10.983%, from 259,211 to 230,741 PPS, while
sibling busy rose from 8.434% to 41.598%. This control intentionally had **no PMU
events**, so its cache, stall and task-clock decomposition is unavailable. Do not
retroactively assign the counted-window explanation to that worst control.
Preflight CPU 29 busy was 61.785%, unlike the quieter preflight of the previous
run; comparing separate runs as a product speedup would be invalid.

## Instrumentation uncertainty and next diagnostic boundary

| Within-block counted/plain PPS ratio | Host cache | Host stall | Peer cache | Peer stall |
| --- | ---: | ---: | ---: | ---: |
| Block 1 | 1.012530 | 1.012681 | 1.018597 | 1.025991 |
| Block 2 | 0.979175 | 0.999610 | 1.077494 | 1.087928 |
| Block 3 | 1.000695 | 0.971696 | 1.018336 | 1.054505 |
| Block 4 | 1.000337 | 0.981673 | 1.008299 | 0.991894 |

Directional same-mode repeat drift reached 6.485% on host and 10.983% on peer.
The ratios do not establish an instrumentation benefit, negligible overhead or a
stable performance baseline. The slow plain peer sample is retained, not removed
to improve the comparison.

The next useful low-impact diagnostic would align L1D-related stall indicators
with frontend and execution-resource indicators. This can distinguish more of
the currently unclassified stall component. A causal SMT test instead requires
separately arranged dedicated physical-core capacity and an explicit comparison;
do not stop other agents, disable SMT or reserve CPUs on this shared node without
new authorization. Continuing the identical throughput experiment alone is
unlikely to settle the unique cause.

No Map, fingerprint, timestamp or ordinary product code changed. The original
pass-through/observe result remains 940/905 permille against 950/900 thresholds;
pass-through still fails and production readiness is not established.

## Safety verification

All 24 trials reconciled forwarding, hook counters and private observer totals
with zero drops/errors. Before/after measured identities matched, generated-port
LLDP settings were restored, and final global/pre-existing LLDP state matched.
Generated namespace, program, map, pin and product-process counts returned to
zero; final generated residue was zero. No cleanup failure was recorded.

Snapshot coverage is program/map identities, pin roots and interface XDP/TC state,
not an exhaustive inventory of global BPF link IDs. The claim is equality of the
measured state, not proof that every possible aspect of the shared host stayed
unchanged. No physical/business interface or foreign attachment was modified by
the experiment.

## Provenance

Runtime/object/bundle commit: `aab228021e09bbaef61319c4d75d34d6f166e2e9`.
Sender/noise commit: `a4418f4de136749b4271b4ba63e7f8b1b53c7399`.
Unmodified accounting helper: `4e743a32e8c6131fc102bd664e1e83e8c31e6ded`, verified
by [GitHub CI 37107852582](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37107852582).
No source compilation or automated source tests ran locally or on the node.
This turn performs server-side diagnostics and evidence analysis, not a product
implementation change. Raw evidence and disposable controllers remain in the
ignored `.artifacts` directory, as in previous investigations.

Protocol `.artifacts/cache-memory-protocol.json` SHA256:
`b82b9ab3d9bcb59cee993500e10e213ecaf1b4cde569e5766f8cee0ab6226272`.
Controller `.artifacts/ostack7-cache-memory-run.py` SHA256:
`b0d8d6b26659c848a3cc7ec650b28334cb8b58c12efa6df1b14d50d7e6f18221`.
Raw capability `.artifacts/ostack7-cache-raw-capability.json` SHA256:
`6e0c8651179fb17a70eb8be0cc8b49a5538d6e79b39bb5c516e88993ef46b224`.
Raw report `.artifacts/ostack7-cache-memory-1071d2475c4d475592a4dc37be240113.json`
SHA256: `b9f84be85dee1c01f11eb5b59cdc293beb2e0dfdfc4bb77af3fea5ce61871ef3`.
Independent arithmetic: `.artifacts/ostack7-cache-memory-analysis.json`.
Disposable calculation method: `.artifacts/cache-memory-analysis-method.js`.
