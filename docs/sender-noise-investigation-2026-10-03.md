# Sender-noise investigation: 2026-10-03

## Question and boundaries

The preceding 25 stage trials could not resolve metadata, clock or Map cost above
their 2.425% anchor-drift envelope. This investigation separates avoidable sender
overhead from sender descheduling instead of changing the ordinary eBPF product.
Production admission and the original 950/900-permille gate are unchanged.

Main only, inline review, no local compilation or automated code tests. Only
generated veth/namespace transactions on authorized ostack7 are permitted. No
physical interfaces, foreign programs, affinity, scheduler settings, service
suspension, global tracing or performance-counter configuration are changed.

## Hypotheses and predeclared experiment

1. The sender's positive socket timeout performs an avoidable readiness syscall
   for every successful send. Compare the existing timeout mode with explicit
   nonblocking mode; both use OS-nonblocking sockets, but the latter fails the
   trial immediately on backpressure instead of retrying or waiting.
2. Throughput variation may reflect time not running. Record process CPU time,
   user/system time, context switches, faults and available own-process scheduler
   counters at window boundaries only. Preserve unknown counters as null.
3. Process CPU accounting and wall time are different quantities. Their difference
   may include descheduling and interrupt/softirq work not charged to the process;
   without valid runqueue counters it is not an exact scheduling-wait measurement.
   Neither endpoint CPU IDs nor migration counts identify a particular competing
   agent or distinguish frequency/cache effects by themselves.

The official [CPython 3.11.6 socket implementation](https://github.com/python/cpython/blob/v3.11.6/Modules/socketmodule.c)
routes positive timeouts through a readiness check before the send function.
The [Python socket documentation](https://docs.python.org/3.11/library/socket.html#notes-on-socket-timeouts)
distinguishes timeout and explicit nonblocking behavior. Source evidence predicts
extra calls, but their magnitude on this node still requires measurement.

Two syscall-counting trials use `strace -c` only on the newly launched sender,
one per send mode, with the same `fp_hash` object. They prove call counts only;
tracing perturbs execution and their throughput is excluded from comparison.
Then five blocks alternate timeout/nonblocking/nonblocking/timeout and its reverse:
20 untraced trials, identical corpus/endpoints/object, no removed samples.
Each direction retains the fixed 0.5-second/100,000-packet warm-up and
5-second/2,000,000-packet measurement limits. Censored windows, backpressure,
forwarding mismatches and identity changes stop the transaction.

For each untraced block compare the mean of its two nonblocking rates with the
mean of its two timeout rates. Both modes have repeated same-mode controls.
Use the largest absolute within-block repeat ratio minus one (minimum 1%) as a
descriptive drift envelope; claim a resolved throughput effect only if all five
block ratios exceed it on the same side. This is not a confidence interval.
CPU ns/packet and occupancy are separate descriptive evidence, not a replacement
for wall-clock throughput or deployment gates.

## Read-only host observations

Python is 3.11.6; kernel is `6.6.0-159.4.8.161.oe2403sp4.x86_64`, with 40 allowed
logical CPUs. CPU 0 reports `intel_pstate` / `performance`; the clocksource is
`tsc`. This single policy read does not prove a fixed frequency on every CPU.
The ten-second observation showed load averages around 10 and no aggregate steal
counter increment; neither observation proves an uncontended sender CPU.
An additional read confirmed two CPU packages, 20 physical cores / 40 logical CPUs,
all reporting the performance governor. Root, system.slice and sshd.service CPU
cgroups had unlimited CFS quota and zero recorded throttle events. These are
point-in-time observations, not a claim that CPU frequency or shared demand is fixed.

`kernel.sched_schedstats` is 0 and CPU PSI is unavailable. Per-process runqueue
wait is therefore deliberately null, not zero. No setting was enabled to obtain
missing data. The [kernel scheduler-statistics documentation](https://www.kernel.org/doc/html/v6.12/scheduler/sched-stats.html)
defines the per-process runtime/runqueue-wait/timeslice fields; disabled counters
must not be used to infer absence of contention.

## Implemented instrumentation and verification

`scripts/diagnostic_noise.py` reads only the current process and scheduler-enable
state, with bounded reads. Snapshots bracket the timed loop after corpus/hash
precomputation. The report exposes an upper bound on included boundary overhead;
CPU accounting is not claimed to be cycle-accurate. Existing default timeout
behavior is retained; `--send-mode nonblocking` and `--noise` are explicit
acceptance-sender options, not product CLI or daemon controls.

GitHub RED run `37086014169` had four expected new failures among 20 sender tests.
GREEN implementation commit is `a4418f4de136749b4271b4ba63e7f8b1b53c7399`.
The complete [GitHub run 37086100086](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37086100086)
passed all five jobs, including 20 sender and six paired-analysis tests. New source
is paired with the already verified exact `aab228021e09bbaef61319c4d75d34d6f166e2e9`
diagnostic runtime/object and bundle from run `37084538550`; no ordinary Rust/eBPF
code changed. Artifact digests remain those in the preceding stage report.

## Completed results and established cause

Run `2aeae5b6a83847b48d7150b2bedbe95d` completed exactly two traced and 20 untraced
trials. All 44 directional measurement windows reached their time bound, all packets were
selected, and exact forwarding/counters/observer totals matched with zero drops
or errors. No backpressure failure or censored window occurred.

The traced counts establish **one extra readiness syscall per packet**, rather
than merely suggesting it from a throughput difference:

| Mode / direction | Sent packets including warm-up | `sendto` calls | `poll` calls |
| --- | ---: | ---: | ---: |
| Timeout / host | 113,404 | 113,404 | 113,412 |
| Timeout / peer | 121,299 | 121,299 | 121,307 |
| Nonblocking / host | 226,817 | 226,817 | 8 |
| Nonblocking / peer | 217,555 | 217,555 | 8 |

Both modes have eight fixed control-path polls; only timeout mode adds exactly
one per packet. These are observed syscall counts, not timing estimates from the
tracer. The ordinary eBPF object and all packet semantics stayed unchanged.

For the five untraced blocks, nonblocking/timeout throughput ratios were
**1.285889, 1.334388, 1.277231, 1.309157, 1.301262**. All exceed the predeclared
4.6435% repeated-control envelope; median paired improvement is **30.126%**.
This establishes a material bottleneck in the **test sender's timeout/readiness
path**, not a product hot-path optimization or production throughput claim.

| Descriptive metric, ten untraced trials per mode | Timeout | Nonblocking |
| --- | ---: | ---: |
| Median combined sequential-direction PPS | 274,037 | 357,122 |
| Median charged process CPU ns/packet | 2,969 | 2,160 |
| Median charged system CPU ns/packet | 1,864 | 1,298 |
| Median charged user CPU ns/packet | 1,096 | 860 |

Each metric is independently median-aggregated, so component medians need not sum.
CPU accounting excludes work not charged to this process and includes bounded
snapshot overhead; it is not complete CPU cost for the host or precise helper time.
Maximum observed boundary overhead was 1.474 ms per five-second untraced window
(under 0.030%); it is far below the several-percent repeat variation.

## Remaining noise: evidence and limits

Removing per-packet polling did **not** establish low-noise measurements. Maximum
within-block repeated-mode drift was 4.644% for timeout and 3.429% for nonblocking.
These small-sample descriptive maxima do not prove a stable reduction in noise,
and are not directly comparable to the prior different-run 2.425% envelope.

Across untraced five-second windows, the sender migrated 22–114 times and had
25–160 involuntary context switches. Host-direction CPU/wall ratios remained
88.41–88.71% (timeout) and 85.63–86.19% (nonblocking); peer ratios were
73.69–74.80% and 67.71–69.39%. Consequently CPU/wall accounting alone does not
explain all throughput variation or support attributing it to a particular agent.
Runqueue-wait counters remain unavailable. Aggregate/per-CPU `/proc/stat` snapshots
also include other work and bracket setup/warm-up as well as measurement; they
cannot causally assign shared interrupt work to this sender.

A subsequent ten-second read-only probe found automatic NUMA balancing enabled,
14,245 additional global NUMA hint faults and 24,334 globally migrated pages.
These are **host-wide**, not sender-specific events: they identify another
candidate mechanism, not a proven cause of these samples. No NUMA, scheduler,
IRQ, affinity, frequency or cgroup setting was changed. The [kernel NUMA overview](https://docs.kernel.org/mm/numa.html)
explains why placement/migration can affect locality; this does not prove that
locality caused the remaining measured variation here.

Thus the avoidable timeout/polling overhead is established and an explicit
fail-closed diagnostic alternative is implemented and verified. The full causal
breakdown of the residual jitter is **not yet closed**. Do not claim that metadata,
clock or fingerprint Map behavior is the root cause, or that another agent is at
fault.

## Safety, provenance and next authorization

The final network/eBPF and cleanup identity snapshots matched the initial snapshot,
product-resource counts returned to baseline, LLDP target and global/pre-existing
port state were restored, and generated residue was zero. Snapshot coverage is
program/map IDs, pin roots and interface XDP/TC state, not exhaustive global BPF
link-ID coverage. Only the transaction's own generated resources were removed;
raw local data remain preserved. No server process from this experiment remains.

Controller SHA256: `61de047bca23664b1141f9eb934c230904fbde0e704f8d0a118e9d0285f7a07c`.
Sender SHA256: `6b74aba9eccfd21813a0a2464a047c6ce403e4a22fbf2c6b45ef4170ade41dc2`.
Telemetry module SHA256: `6b82478704aae894c0873b2e90d0830c9ec5a88b87f501d229383e07feb9d110`.
Raw data: ignored `.artifacts/ostack7-sender-noise-2aeae5b6a83847b48d7150b2bedbe95d.json`;
independent paired recomputation: `.artifacts/ostack7-sender-noise-analysis.json`.
Raw report SHA256: `b4e7323e2797ad3da9840398f757d42263f32a5e2f39d91b64331831f7540ab2`.

Use explicit nonblocking mode for a **new diagnostic baseline**, not as a way to
retroactively modify old gate evidence; default timeout mode remains compatible.
Do not spend effort changing product Map or timestamp semantics on the old noisy
attribution. The next causal experiment should compare natural scheduling with
affinity applied **only to the newly launched test sender**, or use separately
arranged dedicated test capacity. Under the established boundary, CPU-affinity
changes require separate explicit authorization. They would not reserve a CPU
or guarantee exclusive access, and would not authorize changing other processes,
IRQs, global scheduler/NUMA settings or services. No such change was performed.
