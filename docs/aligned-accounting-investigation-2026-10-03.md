# Aligned sender runtime and execution cost investigation

On 2026-10-03, 20 further isolated trials on ostack7 aligned CPU accounting and
own-thread performance counters to the sender's existing measurement boundaries.
The experiment distinguishes a large interrupt-accounting gap from lost runtime,
and locates an observed slowdown mainly in increased cycles per instruction.
It does not establish a unique cache/SMT cause, a product defect or a product speedup.
The original production-admission result remains unchanged.

## Scope and method

Only newly launched senders are pinned to the previously selected CPU 29. Its
physical-core sibling is CPU 9. No core reselection, exclusive reservation, foreign
process adjustment, IRQ/NUMA/sysctl change or physical-interface operation occurs.
The exact `fp_hash` artifact, selected synthetic ARP corpus and timeout sender are
unchanged. This is not a measurement of the nonblocking sender or full product.

Five alternating ABBA/BAAB blocks compare boundary accounting alone (A, `plain`)
with the same accounting plus four own-thread counters (B, `counted`). All 20
trials retain the existing 0.5-second/100,000-packet warm-up and
5-second/2,000,000-packet measurement bounds, with host then peer measured
sequentially. No sample was removed, no outcome-driven retry occurred, and no
packet/time limit changed. All 40 measurement windows reached their time limit.

`scripts/diagnostic_accounting.py` is a separate acceptance helper, not a product
CLI feature. It reads task-clock, cycles, instructions and reference cycles using
current-thread-only `perf_event_open(pid=0, cpu=-1)`. The event set is fixed; there
is no sampling, inheritance, PMU exclusivity or CPU-wide counting. All descriptors
are closed when the sender exits. Unavailable events remain null with their error
numbers; regressing/malformed readings fail, and multiplexed counts are retained
but marked unusable, never scaled into apparently exact values. The
[performance-counter API](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)
defines the enabled/running fields used to check coverage.

A task-local wrapper collects CPU 29 and CPU 9 counters alongside the existing
own-process CPU snapshot immediately before and after each timed loop, after
corpus preparation. Raw timestamps and readings are preserved. These are bounded
sequential reads, **not an atomic snapshot**. The largest enclosing boundary
overhead was 4.176 ms, under 0.084% of five seconds. CPU ticks use USER_HZ=100;
guest counters are not added a second time to totals. IRQ-plus-softirq differences
have up to about 20 ms of endpoint quantization uncertainty, plus read skew.

The node reports CONFIG_IRQ_TIME_ACCOUNTING and generic virtual CPU accounting
enabled. Scheduler statistics remain disabled; no runqueue-wait value is inferred
from a zero or unavailable counter. A separate short own-child capability probe
confirmed all four counters before any traffic transaction. All 20 counted
directional measurement windows subsequently had exact 100% enabled/running
coverage, zero migrations and CPU 29 at both endpoints.

## CPU time and interrupt accounting

| Counted windows, ten per direction | Host | Peer |
| --- | ---: | ---: |
| Charged process CPU / five-second wall time | 87.707–89.108% | 73.522–74.297% |
| CPU 29 IRQ plus softirq / wall time | 11.000–12.400% | 25.800–26.600% |
| Raw task-clock / wall time | 100.017–100.032% | 100.010–100.032% |
| Largest boundary-envelope off-CPU upper estimate | 2.912 ms | 2.550 ms |
| Cycle rate per task-clock time | 2.194628–2.194819 GHz | 2.194524–2.194823 GHz |

Task-clock slightly exceeds the packet-loop wall duration because its boundary
reads enclose a little extra work. This is not utilization above one CPU. Using
`max(0, wall - task_clock + boundary_overhead)` gives a conservative diagnostic
upper estimate of time off CPU within the recorded boundary envelope, not an
exact runqueue-wait measurement. The largest estimate is below 0.059% of a window.

Across all counted windows, `(task_clock - charged_CPU) - (IRQ + softirq)` ranged
from -9.390 to +10.256 ms, within the tick-quantization/read-skew envelope. The
[Linux 6.6 scheduler accounting code](https://github.com/torvalds/linux/blob/v6.6/kernel/sched/core.c#L658-L702)
subtracts IRQ time from task runtime, while the
[performance task-clock implementation](https://github.com/torvalds/linux/blob/v6.6/kernel/events/core.c#L10508-L10552)
tracks active task-context time. The aligned observations and these distinct
accounting mechanisms explain why charged CPU alone appeared to be missing
roughly 11–26% of wall time. That gap must not be labeled as descheduling.
CPU-wide interrupt totals still include unrelated work; they are not exact
per-packet or eBPF-helper attribution.

This result applies to this run. It does not retroactively prove that the earlier
window with 211 involuntary switches had negligible off-CPU time: that window did
not have aligned task-clock measurements.

## Where the observed execution cost changed

| Counted windows | Host range | Peer range |
| --- | ---: | ---: |
| Instructions per packet | 12,880.95–13,066.65 | 13,935.96–13,998.82 |
| Cycles per packet | 7,389.68–8,674.15 | 8,036.87–8,616.77 |
| Cycles per instruction | 0.57195–0.66384 | 0.57532–0.61682 |

An exploratory decomposition of the largest adjacent counted host decline,
block 5, makes the distinction concrete. Both windows are retained:

| Metric | First window | Second window |
| --- | ---: | ---: |
| PPS | 275,044 | 253,059 |
| Instructions per packet | 12,945.91 | 13,066.65 |
| Cycles per instruction | 0.61650 | 0.66384 |
| Cycles per packet | 7,981.20 | 8,674.15 |
| Cycle rate / task-clock | 2.194807 GHz | 2.194628 GHz |
| Sibling CPU 9 busy fraction | 17.822% | 34.462% |
| Involuntary switches | 8 | 10 |

PPS fell 7.993%, while instructions per packet rose 0.933%, cycles per instruction
rose 7.678%, and cycles per packet rose 8.682%. Runtime stayed within the boundary
envelope of the full window and the cycle rate changed only -0.0082%. Thus this
decline primarily manifests as greater execution cost per instruction, not a
large frequency reduction, migration or loss of execution time.

The simultaneous sibling-load increase is a **correlation**, not a controlled
SMT intervention. Shared execution resources, caches, memory latency, interrupt
work and smaller path changes remain candidates. No cache/stall counters were
collected in this experiment. These are whole-sender-context counts including
kernel/interrupt work, not isolated hash/Map helper costs or a reason to blame
another agent. The evidence narrows the mechanism but does not identify its unique
hardware cause or establish that the product's algorithm needs changing.

## Instrumentation control and limits

Combined counted/plain block ratios were 1.011679, 1.009511, 0.997627, 0.999100
and 0.938355. The combined repeated-control drift envelope was 5.5763%; the
predeclared rule requires every block beyond the same side of that envelope.
Neither combined nor individual-direction comparisons resolved a consistent
instrumentation effect. This is **not proof of zero measurement overhead**; the
last block's lower counted scores remain in the report. Combined PPS sums packets
and elapsed times across sequential directions, not simultaneous full-duplex load.

The next useful step is targeted cache/memory/SMT attribution with bounded,
own-process counters, or separately arranged dedicated test capacity. A causal
SMT experiment would need a separately agreed capacity arrangement; do not evict,
pause or reconfigure existing shared-node tasks. Do not return to speculative
product Map or timestamp changes based on these noisy throughput differences.

## Verification and provenance

GitHub RED commit `2a320f8be06de3f44505a0d3b3fe8976066fd18e`, run `37107770706`,
produced the six expected missing-accounting failures among 26 tests. GREEN commit
`4e743a32e8c6131fc102bd664e1e83e8c31e6ded` passed all five jobs in
[GitHub run 37107852582](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37107852582),
including 26 sender/accounting tests and six paired-analysis tests. Compilation
and automated source tests ran only on GitHub; review remained inline on main.

The experiment intentionally reused the successful frozen runtime/object/bundle
`aab228021e09bbaef61319c4d75d34d6f166e2e9` and unchanged sender/noise sources
`a4418f4de136749b4271b4ba63e7f8b1b53c7399`. Only the new accounting helper came
from the GREEN commit. No ordinary Rust/eBPF code or production command changed.

All trials reconciled forwarding, hook counters and private observer totals with
zero drops/errors. Final measured network/eBPF and cleanup identities equaled the
initial snapshot; generated-port and global/pre-existing LLDP state were restored.
Product-resource counts returned to zero and generated residue was zero. All
senders/runtime processes exited; no foreign attachment or physical interface was
modified. Snapshot coverage is program/map IDs, pin roots and interface XDP/TC
state, not exhaustive global BPF link IDs.

Raw report: `.artifacts/ostack7-aligned-accounting-69c0886550554fff9027a8bc04d8b0fe.json`.
Raw SHA256: `f8ac22e34d35455170216b008766c1faf47bc68bafed1c87e31c9ca235166a31`.
Controller SHA256: `066026372ea63df9158a9e3a689754dbd1a6dd4ba2fcfc80d3dda2c441efa65f`.
Accounting source SHA256: `88ad459a96406a73863516782fd87e7497352836fdacd8b31a22e907b026e49d`.
Protocol: `.artifacts/aligned-accounting-protocol.json`, SHA256
`4e1410c084eaed32b3dd5843aa15762397c37f592d211109f4e56c9e1e64c863`.
Independent arithmetic: `.artifacts/ostack7-aligned-accounting-analysis.json`.
Raw evidence and task-local controllers remain preserved outside version control.

The original pass-through/observe result is still 940/905 permille against
950/900 thresholds. Pass-through still fails; no production-readiness gain is claimed.
