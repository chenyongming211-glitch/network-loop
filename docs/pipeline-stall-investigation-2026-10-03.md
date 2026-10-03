# L1 frontend and execution stall investigation

On 2026-10-03, all 24 fixed isolated trials completed with full coverage in all
32 counted directional windows. Load-associated waiting tracked execution cost,
while L1-miss-associated waiting was a much smaller component. Two slow host
windows also showed increased resource stalls and sibling activity. Frontend
undersupply did not explain both directions consistently. The evidence narrows
candidate mechanisms, but neither isolates a product helper nor proves a unique
SMT cause. Product performance and production admission remain unchanged.

## Scope and event meanings

This investigation follows the
[cache and memory experiment](cache-memory-investigation-2026-10-03.md) on ostack7.
The frozen `fp_hash` diagnostic, selected synthetic ARP corpus, timeout sender,
CPU 29 affinity, sequential host/peer directions and existing packet/time limits
are unchanged. CPU 9 remains the sibling thread, not a reserved or controlled
resource. Only our new senders are pinned. Other processes, physical/business
interfaces, foreign BPF, IRQs and global host configuration are not modified.

Four fixed blocks alternate `plain, l1, pipeline, pipeline, l1, plain` and
`pipeline, l1, plain, plain, l1, pipeline`. Each trial retains a
0.5-second/100,000-packet warm-up and 5-second/2,000,000-packet measurement in
each direction. No outcome-driven retry, discarded sample or timing-limit change
is allowed. The controls use the same boundary snapshots without PMU events.

Both counted groups include task-clock, cycles, instructions and reference
cycles. They add three raw events each, selected in a disposable launcher after
checking GenuineIntel family 6, model 85, stepping 7 and PMU type 4. Separate
own-child capability probes confirmed availability before the traffic run.

| Group | Event | Raw config | Unit and condition |
| --- | --- | --- | --- |
| l1 | CYCLE_ACTIVITY.STALLS_TOTAL | 0x040004a3 | Execution stall cycles |
| l1 | CYCLE_ACTIVITY.STALLS_L1D_MISS | 0x0c000ca3 | Stall cycles with an outstanding L1-missing demand load |
| l1 | CYCLE_ACTIVITY.STALLS_MEM_ANY | 0x140014a3 | Stall cycles with an outstanding load |
| pipeline | IDQ_UOPS_NOT_DELIVERED.CORE | 0x019c | Undelivered micro-operations when the backend can accept work |
| pipeline | RESOURCE_STALLS.ANY | 0x01a2 | Resource-related stall cycles |
| pipeline | EXE_ACTIVITY.EXE_BOUND_0_PORTS | 0x01a6 | Cycles with no executed micro-operations and a nonempty reservation station |

Definitions and encodings come from the
[Intel Cascade Lake event catalog](https://github.com/intel/perfmon/blob/86f146e15626b0fd3b032cab4538cafaaf2d0635/CLX/events/cascadelakex_core.json).
The frontend event excludes intervals serving the sibling and intervals where
the allocation stage is stalled. Its count is not elapsed stall cycles. The
zero-execution event can include dependency waits; it does not prove saturated
execution ports or identify SMT contention.

Events are counted in the calling sender's scheduled context, `pid=0, cpu=-1`,
with AnyThread zero, no inheritance, sampling, exclusivity, uncore or CPU-wide
attachment. Shared-core conditions still reflect shared hardware, not isolated
product-helper costs. The frozen accounting helper remains unchanged on disk;
the experiment-only launcher selects the fixed sets in memory. No product or
supported CLI feature is added.

All values retain enabled/running time; incomplete coverage is unusable and never
scaled. CPU and PMU snapshots bracket the packet loop but are sequential, not
atomic. CPU tick granularity is 10 ms. Counts include sender user code and its
kernel/interrupt context. The counter groups are separate windows and cannot be
combined into one simultaneous decomposition. Even within a group, conditions
overlap and are not additive. IDQ micro-operations are normalized per thousand
retired instructions, not mislabeled as a cycle percentage or formal Topdown
frontend-bound score.

## Complete measurements

Each direction has eight `l1`, eight `pipeline` and eight `plain` windows.
All 48 windows completed five seconds without hitting the packet cap; all
recorded migrations were zero. Every event in the 32 counted windows had exact
positive enabled/running equality. Independent arithmetic verified event deltas
against their raw boundary readings; no scaling or sample exclusion was used.

| Indicator and unit | Host range | Peer range |
| --- | ---: | ---: |
| Total stall cycles / cycles, l1 group | 24.951–27.685% | 25.844–27.682% |
| L1-miss-associated stall cycles / cycles | 2.380–3.388% | 2.793–3.311% |
| Outstanding-load-associated stall cycles / cycles | 11.880–14.142% | 12.674–14.055% |
| Resource stall cycles / cycles, pipeline group | 4.042–6.665% | 4.125–4.969% |
| Zero-execution nonempty-station cycles / cycles | 3.560–3.810% | 3.464–3.616% |
| Undelivered micro-operations / 1,000 retired instructions | 783.21–872.42 | 830.04–977.62 |

The larger outstanding-load-associated count shows why loading waits cannot be
reduced to cache misses alone. It is consistent with investigating load-to-use
dependencies and shared execution resources, but it is not a measurement of
pure L1-hit latency. Do not subtract overlapping indicators and label the result
as an independently measured bottleneck. Likewise, resource stalls are not a
direct measurement of execution-port saturation or another agent's interference.

Within the eight `l1` windows per direction, descriptive correlations of CPI
with outstanding-load stall cycles per thousand instructions were 0.985 host and
0.974 peer; corresponding L1-miss-stall correlations were 0.856 and 0.784.
These are small, temporally ordered samples with shared normalizations, not
causal estimates. Both indicators changed; the broader load-associated measure
tracked execution-cost variation more closely in this dataset.

In `pipeline` windows, the CPI correlation with undelivered micro-operations per
thousand instructions was -0.237 host but +0.845 peer. Resource-stall correlations
were +0.875 and +0.447; sibling-busy correlations were +0.982 and +0.480.
The large host associations include two conspicuously slow windows and should
not be generalized as stable population effects. Frontend pressure remains
possible, but is not supported as the single common explanation across directions.

## A captured low throughput window

The two adjacent host pipeline windows in block 3 provide an exploratory
illustration. Both have complete PMU coverage and zero migrations:

| Metric | First sample | Next sample |
| --- | ---: | ---: |
| PPS | 252,042 | 293,498 |
| Instructions per packet | 13,028.99 | 12,983.53 |
| Cycles per instruction | 0.66822 | 0.57608 |
| Cycles per packet | 8,706.23 | 7,479.57 |
| Resource stall cycles per packet | 580.27 | 351.73 |
| Zero-execution nonempty-station cycles per packet | 325.76 | 266.25 |
| Undelivered micro-operations per 1,000 instructions | 814.77 | 783.21 |
| Sibling CPU 9 busy | 38.351% | 10.843% |
| Cycle-rate proxy | 2.194432 GHz | 2.194799 GHz |

The next sample's PPS was 16.448% higher without a product change. This is a
repeatability problem, not an optimization result. The resource-stall change
does not account for the full cycles-per-packet difference, and overlapping
events must not be added into a causal cost allocation. Total/L1/load-associated
stall events were not collected in these pipeline windows; readings from the
other group cannot fill that gap.

Block 4 repeats the slow-host association: 256,903 PPS, CPI 0.66237 and sibling
busy 33.803%, followed later in the block by 292,543 PPS, CPI 0.58061 and sibling
busy 8.249%. Resource stalls fell from 416.62 to 310.62 cycles per packet.
However, normalized undelivered micro-operations **rose** from 835.68 to 851.28
as throughput improved. This counterexample further limits a simple frontend-only
explanation. It does not rule out frontend effects or prove SMT causality.

Across all counted windows the cycle-rate proxy stayed within
2.194432–2.194814 GHz. Maximum boundary overhead was 4.238 ms and the largest
boundary-envelope off-CPU upper estimate was 4.266 ms, below 0.086% of five
seconds. This estimate is not an exact runqueue-wait counter. Large frequency
or runtime losses do not explain the illustrated counted-window differences.

## Observer effects and next step

| Counted/plain PPS ratio within each block | Host l1 | Host pipeline | Peer l1 | Peer pipeline |
| --- | ---: | ---: | ---: | ---: |
| Block 1 | 0.993859 | 0.984645 | 1.001181 | 1.012516 |
| Block 2 | 0.983678 | 0.990702 | 1.004846 | 1.003183 |
| Block 3 | 1.014013 | 0.963802 | 1.019238 | 0.995051 |
| Block 4 | 1.008151 | 0.964884 | 1.031671 | 0.988296 |

Host pipeline/plain is below one in all four blocks, not mixed-sign. Do not
claim negligible instrumentation overhead. At the same time, host same-mode
repeat drift reached 16.448% and peer repeat drift 5.465%, so these controls do
not isolate the observer's causal effect from shared-host variation and order.
All controls and slow counted windows remain in the result. Preflight CPU 29
busy was 17.475%; the core was not dedicated or guaranteed quiet during trials.

The next useful step is **separate user-mode and kernel-mode attribution**, with
matched event sets and counting-on/off controls. This can distinguish sender
user code from its kernel path; kernel counts would still include networking,
interrupts and eBPF, not eBPF alone. Only after locating the expensive domain
should a narrower code-path comparison be designed. Avoid another unstructured
round of throughput-only runs or speculative Map/fingerprint changes.

A causal SMT comparison still needs separately authorized dedicated capacity.
Do not stop other agents, alter their affinity, disable SMT or change IRQ/global
configuration. No product code changed; the original pass-through/observe result
remains 940/905 permille against 950/900 thresholds. Pass-through still fails,
and this diagnostic does not improve the production-admission conclusion.

## Safety verification

All 24 trials reconciled packet/byte forwarding, hook counters and private
observer totals with zero drops/errors. Measured before/after identities matched;
generated-port LLDP and final global/pre-existing LLDP state were restored.
Our namespace, program, map, pin and product-process counts returned to zero,
with zero generated residue and no cleanup failure.

Snapshot coverage includes program/map identities, pin roots and interface
XDP/TC state, not exhaustive global BPF link IDs. Equality is claimed only for
the measured state. The experiment did not modify foreign attachments or physical
interfaces. Its exact-owned generated resources were removed, while raw evidence
was retained locally.

## Provenance

Runtime/object/bundle: `aab228021e09bbaef61319c4d75d34d6f166e2e9`.
Sender/noise: `a4418f4de136749b4271b4ba63e7f8b1b53c7399`.
Accounting helper: `4e743a32e8c6131fc102bd664e1e83e8c31e6ded`, previously verified
by [GitHub CI 37107852582](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37107852582).
Previous documentation commit `43056defc08cc4e07ef6978c8bdcb22c77e2c7f0` also passed
[GitHub CI 37113139079](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37113139079).
No compilation or automated source tests run locally or on the node; this is a
server diagnostic experiment, not a new product implementation. Raw data and
disposable controllers remain in ignored `.artifacts`, following previous runs.

Protocol `.artifacts/pipeline-protocol.json` SHA256:
`83dc6fcfc9a90e11d8bec9b02c59e28880b6ee148bf5c173c8a76489379af5c6`.
Controller `.artifacts/ostack7-pipeline-run.py` SHA256:
`04a1fdd5814aea30b9054cd2b8b6df272cd5430f5ccce27058cfe51c1a8cea0e`.
Capability report `.artifacts/ostack7-pipeline-capability.json` SHA256:
`53566d9109f158cd0240b875e58bf5d23a07dcee5a7d23705d43f35b0d952f89`.
Raw report `.artifacts/ostack7-pipeline-30d5d87358a446f09628ed12a4d5d145.json`
SHA256: `665cff9d48ea79b005749e10acb34bcc08c62e86a154e1ea658bf6985d21c096`.
Independent arithmetic: `.artifacts/ostack7-pipeline-analysis.json`.
Recomputation inputs/method: `.artifacts/pipeline-projection.ps1` and
`.artifacts/pipeline-analysis-method.js`.
