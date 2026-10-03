# Sender CPU affinity investigation

On 2026-10-03, the separately authorized sender-only affinity experiment completed
20 isolated trials on ostack7. Pinning eliminated measured sender migrations but
did **not** establish a stable throughput improvement or lower measurement noise.
The timeout/readiness overhead identified in the preceding investigation remains
proven; the residual jitter does not yet have a complete causal explanation.
No ordinary product code, deployment gate or production-admission conclusion changed.

## Authorization and fixed protocol

The user authorized CPU affinity only for newly launched test senders. A small
task-local launcher calls `os.sched_setaffinity(0, {selected_cpu})` before running
the unchanged sender, verifies the effective mask, and checks it again on exit.
Natural controls use the same launcher without changing affinity. The original
mask must match the read-only preflight mask. Affinity is limited to that child
and its short-lived identity-check children; the controller, diagnostic runtime,
other processes, IRQs, services and global scheduler/NUMA settings are untouched.
The [Python API](https://docs.python.org/3.11/library/os.html#os.sched_setaffinity)
defines PID zero as the caller. This is not a CPU reservation or exclusive access.

A ten-second read-only sample ranked allowed CPUs by the sum of busy fractions
of their physical-core siblings, then their own busy fraction, then CPU number.
It selected CPU 29, package 0, core 12, sharing its core with CPU 9. CPU 29 was
14.329% busy; the two sibling fractions summed to 29.628%. These are selection-time
observations, not guarantees of future availability. No CPU was reselected.

Five blocks alternate natural/pinned/pinned/natural and its reverse: 20 trials,
40 sequential directional measurement windows. Every trial uses the same `fp_hash`
object, selected synthetic ARP corpus, generated namespace/veth and tested timeout
sender. Each direction retains the existing 0.5-second/100,000-packet warm-up and
5-second/2,000,000-packet measurement bounds. Timeout mode was chosen before the
trial to reduce the risk of reaching the packet cap; this experiment does not
measure a combined nonblocking-plus-affinity optimization. Tracing is disabled.

Affinity disagreement, any pinned-window migration, backpressure, censored
measurement, forwarding/counter mismatch or identity change stops the experiment.
All samples are retained. The controller completed its fixed schedule once;
there was no outcome-driven retry or low-score removal.

For each block, divide the mean of its two pinned rates by the mean of its two
natural rates. Compute this separately for each direction and for combined
sequential-direction PPS (sum of packets divided by sum of elapsed times, not
simultaneous bidirectional throughput). The descriptive drift envelope is the
largest absolute within-block same-mode repeat ratio minus one, floored at 1%.
A resolved effect requires all five ratios to exceed the envelope in the same
direction. This is not a confidence interval or a formal performance gate.

## Complete paired results

All 40 measurement windows reached five seconds without packet censoring. All
packets were selected; forwarding, hook counters and private observer totals
matched exactly, with zero packet drops or errors. All 20 pinned directional
measurement windows had zero migrations and endpoint CPU IDs `[29, 29]`; their
warm-ups also had zero migrations. Natural masks remained CPUs 0 through 39.

| Block | Pinned/natural host PPS | Pinned/natural peer PPS | Combined ratio |
| --- | ---: | ---: | ---: |
| 1 | 0.989778 | 1.054166 | 1.019874 |
| 2 | 0.987349 | 0.923847 | 0.957302 |
| 3 | 1.008088 | 1.034263 | 1.020554 |
| 4 | 0.969867 | 1.023522 | 0.995047 |
| 5 | 0.991673 | 1.037177 | 1.013122 |

Combined median paired ratio is 1.013122, but the signs disagree and the
4.5534% drift envelope is not cleared. Host and peer comparisons are also
unresolved under their respective 4.3275% and 8.6520% envelopes. Reporting the
median alone as a 1.31% improvement would be unsupported.

| Descriptive result | Natural | Pinned |
| --- | ---: | ---: |
| Median combined sequential-direction PPS | 275,961 | 277,769 |
| Maximum within-block combined repeat drift | 0.987% | 4.553% |
| Maximum host repeat drift | 3.462% | 4.328% |
| Maximum peer repeat drift | 4.346% | 8.652% |
| Host migrations per measurement | 28–42 | 0 |
| Peer migrations per measurement | 82–92 | 0 |
| Host involuntary switches per measurement | 34–55 | 7–9 |
| Peer involuntary switches per measurement | 85–118 | 6–211 |

These small-sample maxima describe this run, not a general claim that affinity
always worsens measurements. There is no demonstrated noise reduction here.

## What the counterexample establishes

In block 2, the two pinned peer windows fell from 251,896 to 230,102 PPS, an
8.652% repeat decline. Both had zero migrations. Involuntary switches rose from
8 to 211, while charged CPU/wall fraction fell from 74.857% to 72.357%.
This establishes that preventing migration did not prevent preemption or the
observed throughput decline. The switch count does not measure wait duration,
identify another agent, or explain the entire decline. Placement, cache locality,
SMT competition, frequency and interrupt work have not been separately isolated.

Pinned host CPU/wall fractions were 88.113–88.878%; peer fractions were
72.357–74.857%. CPU 29's bracketing softirq fractions were 10.420–11.213% for host
launches and 24.138–25.455% for peer launches. The
[kernel documentation](https://docs.kernel.org/filesystems/proc.html#miscellaneous-kernel-statistics-in-proc-stat)
defines separate process, interrupt and softirq CPU accounting categories.
The observed softirq magnitude is consistent with much of the CPU/wall gap
being accounting for interrupt work, rather than pure scheduling wait. However,
these CPU samples bracket process setup and warm-up as well as measurement and
include unrelated work. They must not be subtracted from the five-second process
window to claim an exact attribution. Runqueue-wait counters remain null because
scheduler statistics are disabled; no global setting was enabled.

The largest boundary-telemetry overhead upper bound was 1.558 ms, under 0.032%
of a five-second window. This instrumentation does not explain the multi-percent
repeat deviations. It also does not measure cycles, frequency or cache misses.

The supported conclusion is narrow: **migration elimination alone is insufficient
to stabilize this shared-host experiment**. Neither migration's independent cost
nor the unique root cause of all residual jitter has been established. The earlier
per-packet readiness syscall remains the proven avoidable sender cost; no evidence
from this run establishes a product Map, hash or timestamp defect.

## Safety and provenance

The final measured network/eBPF snapshot and cleanup identity matched the initial
snapshot. Product-resource counts returned to zero, generated residue was zero,
and the generated-port LLDP status plus global/pre-existing port state were restored.
All diagnostic runtimes and senders exited. Only exact owned generated resources
were removed; no physical interface or foreign BPF attachment was modified.
Snapshot coverage remains program/map IDs, pin roots and interface XDP/TC state,
not exhaustive global BPF link-ID coverage.

The frozen runtime/object/bundle commit is
`aab228021e09bbaef61319c4d75d34d6f166e2e9`, from successful GitHub run `37084538550`.
Sender and noise sources are unchanged from
`a4418f4de136749b4271b4ba63e7f8b1b53c7399`, whose full
[GitHub run 37086100086](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37086100086)
passed. The affinity wrapper is task-local diagnostic orchestration, not a new
tested product API or permanent CLI option. This turn performed no local build
or automated source-code test and changed no tracked executable source.

Run ID: `d3c7456e9c7c4a728c27a3231a69eb7e`.
Raw report: `.artifacts/ostack7-sender-affinity-d3c7456e9c7c4a728c27a3231a69eb7e.json`.
Raw SHA256: `e3af21c4b3cc5fe99ecd70319479c41481f0b4fbf6eefbad2e2c7cdbf7fb1884`.
Controller: `.artifacts/ostack7-sender-affinity-run.py`.
Controller SHA256: `3b1bee6da7f06f11f42cbfec9a0689d64be5bc47261f8cac3ae900912fe16b69`.
Protocol: `.artifacts/sender-affinity-protocol.json`.
Protocol SHA256: `d9c1d6b75f54003bb8faa6963441b1bcd5da7a56229ab3789b532cc5660d5b88`.
Independent arithmetic: `.artifacts/ostack7-sender-affinity-analysis.json`.
These task-local evidence files remain preserved outside version control.

## Next diagnostic step

Do not adopt affinity as a validated noise fix or optimize the product based on
this unresolved stage attribution. Next align own-process runtime and selected-CPU
interrupt accounting to the same measurement boundaries, then assess whether
bounded own-process hardware counters can distinguish per-packet execution cost
from lost execution time. Counter availability and measurement overhead must be
verified first; neither global tracing nor scheduler/IRQ/NUMA changes are implied.
If shared-capacity effects still mask stage cost, use separately arranged dedicated
test capacity instead of stopping other agents or selecting favorable samples.

The original pass-through/observe result remains 940/905 permille against the
950/900 thresholds. Pass-through still fails; this is not production-ready evidence.
