# User and kernel domain counting investigation

On 2026-10-03, 24 fixed isolated trials on ostack7 completed with full coverage
in all 32 counted directional windows. Kernel-mode cycles formed about 62–67%
of the measured user-plus-kernel sum, but repeat variation affected both domains.
The largest slow peer window had 741 extra user cycles and 1,167 extra kernel
cycles per packet relative to its same-block repeat. This locates the variation
across domains; it neither identifies a unique microarchitectural cause nor
attributes kernel time specifically to eBPF. Product performance and production
admission remain unchanged.

## Method and boundaries

This follows the [pipeline stall investigation](pipeline-stall-investigation-2026-10-03.md).
The frozen fp_hash artifact, selected synthetic ARP corpus, timeout sender,
CPU 29 affinity, CPU 9 sibling observation and sequential host/peer directions
remain unchanged. Each trial has a 0.5-second/100,000-packet warm-up and a
5-second/2,000,000-packet measurement per direction. Four blocks alternate
plain, total, split, split, total, plain and
split, total, plain, plain, total, split. All 24 trials and all 48 directional
windows are retained; none were rerun or discarded based on results.

The three modes retain the same boundary telemetry:

| Mode | Hardware counting | Software counting |
| --- | --- | --- |
| plain | Disabled | No PMU task-clock; existing process and CPU snapshots retained |
| total | Unfiltered cycles, instructions, reference cycles | Unfiltered task-clock |
| split | User cycles, kernel cycles, user instructions, kernel instructions in the same window | Unfiltered task-clock |

An initial own-child capability probe requested total and both domain counters
together. Hardware coverage fell to about 71–86%, so that configuration was
rejected before traffic measurement. The reduced split set achieved 100% in a
second capability probe. Formal traffic windows independently confirmed
enabled_ns == running_ns > 0 for every counted event; there is no scaling.

A disposable launcher changes only the frozen helper's exclusion flags.
User hardware counters set exclude_kernel (bit 5); kernel counters set
exclude_user (bit 4). All other attributes remain unchanged. The syscall is
restricted to the current thread (pid=0, cpu=-1), no inheritance, sampling,
exclusive access or CPU-wide counting. The fixed event set contains no raw
stall events in this run. Definitions follow the
[Linux perf_event_open interface](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)
and [Linux 6.6 attribute layout](https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/perf_event.h).
The tracked helper, sender and product code are unchanged.

Task-clock remains an unfiltered runtime reference, not a user/kernel CPU-time
partition. Process user/system accounting is retained separately and must not
be substituted for PMU domain cycles because interrupt accounting differs.
Kernel counts can include syscalls, networking, interrupts and eBPF while this
sender thread is scheduled. Work deferred to another thread/CPU is outside this
scope. Thus user/kernel is a privilege-domain split, not a complete separation
of sender costs from network costs: the sender also causes kernel work.

Counters are read sequentially at bounded window boundaries, not atomically.
Their raw before/after values and enabled/running durations were independently
recomputed and reconciled with the report. Shares below normalize the two
domain counts from the same window; no independent total counter was collected
in that split window. The separately timed total mode cannot prove an exact
sum identity. Split sum/task-clock was 2.18925–2.19074 cycles/ns, versus
2.19471–2.19482 in total mode; do not reinterpret this small mode difference as
a measured frequency change or add domains from separate trials.

## Domain results

Each direction has eight split windows, all usable.

| Metric | Host range | Peer range |
| --- | --- | --- |
| Kernel share of user-plus-kernel cycles | 62.417–64.435% | 65.028–67.081% |
| User cycles per packet | 2,629.708–3,076.250 | 2,695.707–3,520.349 |
| Kernel cycles per packet | 4,759.425–5,172.598 | 5,378.839–6,545.711 |
| User instructions per packet | 5,743.869–5,806.060 | 5,739.698–5,776.635 |
| Kernel instructions per packet | 7,156.060–7,209.823 | 8,204.296–8,276.301 |
| User cycles per instruction | 0.457829–0.534104 | 0.466727–0.612845 |
| Kernel cycles per instruction | 0.664084–0.717438 | 0.655483–0.790898 |

Average domain weight and the source of variation are different questions.
For every block, the following table compares the second split window with
the first in that direction. Positive cycle deltas mean more cost per packet;
positive PPS change means faster throughput. Blocks 1 and 3 have adjacent
split trials; blocks 2 and 4 have intervening control trials.

| Direction | Block | PPS change | User cycle delta per packet | Kernel cycle delta per packet |
| --- | --- | --- | --- | --- |
| host | 1 | -2.918% | 170.554 | 52.707 |
| host | 2 | 9.902% | -339.736 | -404.084 |
| host | 3 | 4.821% | -191.519 | -168.825 |
| host | 4 | 4.817% | -208.057 | -148.415 |
| peer | 1 | -0.647% | -27.790 | 82.072 |
| peer | 2 | -2.142% | 148.496 | 29.546 |
| peer | 3 | 2.566% | -20.462 | -188.367 |
| peer | 4 | 23.387% | -741.445 | -1166.872 |

Both domains can vary. Host block 1's increase is mostly user-side; peer block 3's
decrease is mostly kernel-side. These counterexamples prevent a universal
single-domain explanation. The deltas are descriptive accounting differences,
not estimates of the causal impact of any one product function.

## Largest slow window

Peer block 4 provides the largest same-mode contrast. No product code changed
between these windows.

| Metric | First split window | Second split window |
| --- | --- | --- |
| PPS | 217,585.715 | 268,471.856 |
| User cycles per packet | 3,520.349 | 2,778.904 |
| Kernel cycles per packet | 6,545.711 | 5,378.839 |
| User instructions per packet | 5,744.277 | 5,744.260 |
| Kernel instructions per packet | 8,276.301 | 8,205.916 |
| User CPI | 0.612845 | 0.483771 |
| Kernel CPI | 0.790898 | 0.655483 |
| Sibling busy | 54.767% | 6.250% |
| Off-CPU upper envelope | 4.212 ms | 1.270 ms |
| Involuntary switches | 15 | 9 |
| Migrations | 0 | 0 |

The extra 1,908.317 cycles per packet split into 741.445 user cycles (38.853%)
and 1,166.872 kernel cycles (61.147%). User instruction volume is essentially
unchanged, while both domain CPIs rise. Off-CPU upper bounds are below 0.085%
of the five-second window, too small to account for this contrast by themselves.
The second window is 23.387% faster, but this is repeat variation, not product
improvement. Increased sibling activity is compatible with shared-core contention;
it is not proof of SMT causality, since no sibling workload was controlled.

## Counting controls and remaining uncertainty

Ratios use pooled packets / pooled elapsed time over both occurrences of each
mode within one block and direction. Host and peer are sequential, never summed
as simultaneous bidirectional throughput.

| Block | Host total/plain | Host split/plain | Peer total/plain | Peer split/plain |
| --- | --- | --- | --- | --- |
| 1 | 1.009966 | 1.018407 | 0.986713 | 0.983621 |
| 2 | 1.018254 | 0.981455 | 1.028270 | 1.013273 |
| 3 | 0.964652 | 0.977296 | 1.010555 | 1.013662 |
| 4 | 1.014661 | 0.999374 | 0.992589 | 0.913892 |

The ratios vary in sign. The peer block 4 split/plain ratio falls to 0.913892
and includes the slow split window; it must not be removed as an outlier.
Largest same-mode repeat changes are 9.902% host and 23.387% peer. These fixed
controls do not distinguish small observer overhead from shared-node drift and
order effects. No negligible-overhead or instrumentation-speedup claim is made.
CPU 29 was already 29.626% busy in preflight; it was not a dedicated core.

The next bounded comparison should quantify the already identified sender
poll path: keep the same artifact and domain counters, compare timeout versus
nonblocking send modes with counting-off controls, and preserve strict
backpressure failure and forwarding reconciliation. This separates an avoidable
sender-induced kernel path before assigning the remaining kernel increment to
the product. It is a measurement-tool comparison, not a product speedup.
A later hooks-only versus fp_hash contrast can then target the product increment.
Do not add another broad raw-event sweep or modify Maps/fingerprints speculatively.

A causal shared-core test still requires separately authorized dedicated capacity.
Do not stop other agents, change their affinity, disable SMT, move IRQs or change
global settings. The original pass-through/observe result remains 940/905
permille against 950/900 thresholds: pass-through still fails.

## Safety verification

All 24 trials reconciled packet/byte forwarding, hook counters and private
observer totals, with zero drops/errors. All 48 measurement windows reached
their five-second duration without packet-cap censoring or migration.
Measured before/after state and cleanup state matched. Generated-port and
global/pre-existing LLDP state were restored. Our namespace, program, map,
pin and product-process counts returned to zero; generated residue was zero.
There was no measurement or cleanup failure.

Snapshot scope includes program/map identities, pin roots and interface XDP/TC
state, not exhaustive global BPF link IDs. Equality is claimed only for the
measured state. No physical interface or foreign attachment was modified.
Only exact-owned generated resources were removed; local raw evidence remains.

## Provenance and verification

Runtime/object/bundle: aab228021e09bbaef61319c4d75d34d6f166e2e9.
Sender/noise: a4418f4de136749b4271b4ba63e7f8b1b53c7399.
Accounting: 4e743a32e8c6131fc102bd664e1e83e8c31e6ded, previously verified by
[GitHub CI 37107852582](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37107852582).
The preceding documentation commit 4bbe8b3eb7c5d2f3d014671dc91dc23620e811a5
passed [GitHub CI 37114358692](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37114358692).

No compilation or automated source regression tests ran locally or on the node.
The disposable launcher was exercised by real server diagnostics, not presented
as a CI-tested new product feature. Controllers and raw evidence remain in
ignored .artifacts, consistent with prior diagnostic runs.

| Evidence | Local path | SHA256 |
| --- | --- | --- |
| Fixed protocol | .artifacts/domain-protocol.json | 59ad183cb8904487659248db69d3736d6005edd1cb9f7b6cbc1a398069d13f97 |
| Controller | .artifacts/ostack7-domain-run.py | b4e9c1f0ae1fed2cfb81bf214d2f7d195db3dbc4e076ce07462e2532018e6886 |
| Rejected counter-set probe | .artifacts/ostack7-domain-capability-overcommitted.json | 7426158316f5170aba8ce710a1fcf1fbb2a5bb8e2e3d54c6b4e29cef84ed330e |
| Reduced counter-set probe | .artifacts/ostack7-domain-capability.json | fcd931df3ea8bd5c5ffe0393324a11057da0b03dd4afa22b6176c04c876f8adb |
| Raw report | .artifacts/ostack7-domain-ecec58c986314e4ca02267fb5fa95aae.json | fac305f13023c75f514733bb507cbb0843ea2c914605a6c67cc738f5724764a0 |

Independent arithmetic is saved in .artifacts/ostack7-domain-analysis.json.
Raw-delta verification and calculation methods are retained in
.artifacts/domain-projection.ps1 and .artifacts/domain-analysis-method.js.
