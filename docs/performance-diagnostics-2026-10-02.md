# Performance diagnostics: 2026-10-02

## Outcome

The bounded persistent traffic sender is implemented and its 16 behavioral tests passed on GitHub. **No product throughput improvement is claimed.** After a separately authorized, reversible generated-port-only LLDP transmit exclusion, all 15 steady-state diagnostic trials completed with exact forwarding, zero drops/errors and cleanup. Relative to the no-attachment baseline, median diagnostic throughput was **92.7% for pass-through and 87.3% for observe**. No daemon-wide LLDP setting, physical interface, or foreign eBPF attachment was changed.

The existing formal gate remains unchanged: five trials, pass-through at least 950 permille and observe at least 900 permille of baseline, with zero observed drops/errors and exact cleanup. Its prior isolated result was 940/905 permille respectively; the pass-through gate remains failed. New diagnostics neither replace that result nor authorize installation or a physical canary.

## Implemented measurement improvements

- One persistent Python process/socket per direction; construction, corpus generation and warm-up are outside the measured interval.
- Separate warm-up (0.5 s / 100,000 packets) and measurement (5 s / 2,000,000 packets) bounds; report which bound ended each window.
- Fixed 64/512/1514-byte ARP corpus using actual generated endpoint MACs and zero protocol addresses.
- Mixed, deterministically selected and unselected fingerprint corpora; report actual selection counts.
- Reject arbitrary interface names, foreign namespace identities, non-veth links, master membership, wrong ifindex, short writes and invalid clocks.
- Task-local controller preserves exact source/artifact digests, raw failure output, endpoint counters, host CPU/softnet observations and exact cleanup evidence. Each of the five observe measurements started after at least 75 seconds, with ready 1/10/60-second windows, a `within_baseline` state, healthy observation and active sampling without failures.

No Rust/eBPF hot-path, Map ABI, fingerprint semantics, sample rate, pass-through definition, or performance threshold changed in this increment. Compilation and behavioral tests ran only on GitHub; the local machine only inspected source and transported authorized remote diagnostics.

## Evidence and attribution

All remote runs used the preserved checksum-verified product bundle from commit `8f4dca293dba0da38cd740b00c14c572944acb6c`. Corrected sender source is `dfb34a445ce651add19f03456ed94200ca81ee9c`. Raw reports remain under ignored `.artifacts/ostack7-diagnostic-<run-id>.json`.

| Run ID | Observation | Meaning |
| --- | --- | --- |
| `187b64d6437d44cc81f943f3db76d65c` | Custom EtherType baseline failed before eBPF attachment | Invalid receiver corpus; not a product comparison |
| `46fb76c589694e4da8bbf38a0ef94934` | 32 custom-type packets caused 32 receive drops with either fixed or actual MACs; 32 actual-MAC ARP packets caused zero drops | Receiver-compatible ARP required |
| `75bfa1e0475e4578b6a3789c8401dede` | Corrected ARP baseline reported one receive drop and failed exact count check | Stop before attaching product eBPF |
| `4c205f9b871a496eb26c5f09148c6bc2` | After bounded receive-counter settling, host TX and peer RX both contained exactly one additional 250-byte frame; peer RX drops increased by one | Background frame, not missing diagnostic traffic |
| `0bae7715b7b84fadb717576c07498ddc` | A 25-second idle, no-eBPF capture on only the generated interface observed one outgoing 250-byte EtherType `0x88cc` frame; `lldpd` was running | Unsolicited LLDP is a demonstrated contamination source |

Every listed transaction completed generated-resource cleanup, reported zero generated residue and restored the measured network/eBPF identity snapshot. Snapshot coverage includes program/map IDs, pin roots and interface XDP/TC state; it is not an exhaustive global BPF-link-ID audit. Idle capture retained only frame length, EtherType and packet type, not packet payload or business-interface traffic.

The apparent one-packet failure must not be silently subtracted, tolerated, or rerun until a passing sample appears. A long-window baseline must first establish a controlled generated-interface traffic environment.

## Verification

- Initial missing-implementation RED: GitHub run `37000652008`, Script safety job `110817344225`, 12 expected failures.
- Receiver regression RED: run `37001503391`, job `110820251984`, one expected corpus assertion failure out of 15 tests.
- Corrected GREEN: [run 37001826503](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37001826503), Script safety job `110821444432`, all 16 tests passed. The complete run succeeded, including Userspace, eBPF, Windows safety and Bundle jobs.

## Authorized LLDP isolation

Only the separately authorized, temporary **per-generated-port** LLDP transmit exclusion is permitted, with exact target validation, original-state capture, restoration and before/after checks. Do not stop/restart `lldpd`, edit its global interface pattern, write persistent configuration, or change any existing/business port. If an installed version cannot support a provably scoped reversible change, stop and choose an uncontaminated test environment.

Upstream documents per-port administrative status and receive-only operation in the [lldpcli manual](https://github.com/lldpd/lldpd/blob/master/src/client/lldpcli.8.in). The user subsequently authorized this narrowly scoped temporary adjustment. Node inspection confirmed lldpd 1.0.18, per-port status support and no permanent-interface pattern. The controller records the original generated-port status, checks exact veth name/ifindex/MAC/peer index, sets only that port to receive-only, verifies the state, restores the original status, then removes generated resources. Before/after global configuration and all pre-existing port statuses must match; no wildcard, global setting, daemon restart or persistent write is used.

Scoped validation run `0d5763979d0f4dbc9ccc969d55b0e864` observed **zero frames in 25 seconds** on the idle generated veth. The report confirms target-status restoration, final LLDP state restoration, measured network/eBPF identity restoration, complete cleanup and zero generated residue. No product eBPF was attached in this validation. Two preceding setup attempts were retained: `1be27276e1304d44b4b258fbfa56246f` stopped on an up/down route-baseline mismatch, and `07a80311af2343f3909b0995aabdbfd6` stopped on an unprivileged command-path failure before LLDP mutation. Both cleaned their generated resources; the first also verified LLDP restoration. Snapshot collection now consistently uses down-link state.

## Completed five-trial diagnostic comparison

Run `b53848788514430cb36320ff8bb44745` retained all five trials per mode in rotating order. Every direction completed the full five-second measurement window without reaching the packet ceiling. Warm-up traffic is excluded from throughput but included in forwarding/counter reconciliation. The same per-direction corpus and endpoints were used across modes; approximately 6.25% of measured frames met deterministic fingerprint selection.

For each trial, combined PPS is `(host packets + peer packets) / (host elapsed seconds + peer elapsed seconds)`. The table reports the median of those five combined rates; this is sequential-direction throughput, not simultaneous bidirectional capacity. Percentages are ratios of mode medians to the baseline median.

| Mode | Median PPS | Five-trial min–max PPS | Relative to baseline |
| --- | ---: | ---: | ---: |
| No attachment | 318,446 | 315,465–322,650 | 100.0% |
| Existing acceptance pass-through | 295,173 | 293,608–301,135 | 92.7% |
| Complete observe, steady-state sampler | 277,976 | 270,903–280,290 | 87.3% |

Directional medians help narrow the next investigation; neither direction is a physical-port benchmark:

| Generated direction / product hook | Baseline PPS | Pass-through PPS | Observe PPS |
| --- | ---: | ---: | ---: |
| Host to peer / TC egress | 321,913 | 309,351 | 293,696 |
| Peer to host / generic XDP ingress | 317,140 | 285,249 | 258,662 |

All 15 trials had zero link drops/errors and exact receive totals. All five observe runs also reconciled XDP/TC Map cumulative counters with actual sends; observation health remained `healthy`. The idle-learned baseline changed to `elevated` during load, as expected. The daemon accumulated 100–110 ms of user-plus-system process CPU between outer before/after reads around each two-direction measurement; this is **not kernel eBPF CPU time**. Peak process RSS was approximately 31.49–32.61 MiB, excluding kernel Map memory. Whole-host CPU/softnet counters were retained but cannot be attributed solely to the product on this shared node.

The run restored the generated port's original LLDP status before deletion, verified final global LLDP configuration and pre-existing port statuses, restored the measured network/eBPF snapshot and reported zero generated residue. The raw report SHA-256 is `f5ccbfee9338866055725b258ce2694dc8af944c1529a6132fd9fa7aa313578e`.

An independent observe/status consistency run, `3fa8e841bacf4f01b3ab68ceba4dca2a`, is **excluded from the five-trial performance statistics**. Both real Unix-socket commands agreed on interface generation and exact ingress/egress packets and bytes before and after traffic; all three status windows were ready before measurement. After traffic, both reported 1,434,633 ingress packets / 999,459,540 bytes and 1,559,062 egress packets / 1,086,145,894 bytes, including warm-up. This run also had zero drops/errors and verified LLDP restoration, measured identity restoration and complete cleanup. Its raw report SHA-256 is `9c5969861e273f69330bd93fc8a715707c0ecff8af80756944961a62a5368f36`.

### Interpretation and next optimization step

These results are **diagnostic measurements of the unchanged product artifact**, not an optimization gain or a new formal gate result. They use a persistent sender, longer windows and a different deterministic corpus from the original formal harness; they must not replace the original 940/905-permille gate evidence. Five repeats on a shared host do not establish production capacity or statistical confidence intervals.

The pass-through path already loses about 7.3% relative to the baseline. Complete observe is about 5.8% below pass-through in this diagnostic. The stronger difference on the ingress direction makes generic-XDP attachment plus its early configuration lookup the first attribution target, followed by classification/counting and sampled fingerprint work. This is an investigation priority, **not proof that any one instruction or Map causes the measured gap**.

The isolated-only layered attribution below completes the next diagnostic step without changing the formal pass-through definition or public command surface. Select a correctness-tested hot-path change only after that evidence. Preserve ownership, exact counter and fingerprint contracts, then rerun the original formal gate on the exact new artifact. This corpus does not cover VLAN/offload behavior, realistic LRU churn, physical/native-XDP, concurrent bidirectional traffic or sustained production load.

## Completed isolated five-layer attribution

The acceptance-only loader and real-object tests are verified at commit `34c152e517b7a77f90655a0f20d343a323f87485`, [GitHub run 37021840057](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37021840057), attempt 2, all five jobs successful. Compilation and automated code tests ran only on GitHub. Attempt 1's Bundle checkout failed TLS certificate verification before compilation; the failed job was retried without weakening TLS checks. The seven privileged runtime cases verify actual profile traffic/counters, bounded exits, byte mismatch refusal, foreign lease refusal and retention of a foreign TC filter during cleanup.

The separate diagnostic runtime artifact is `11232898895`, the four-object artifact is `11233467575`, and the unchanged-inventory ordinary bundle is `11233293502`. The executable SHA-256 is `a328afbe677831428fa0b231be900bdf0546007d4dffef9428c70b76006cb6ea`. The runtime embeds this source commit and the four object digests, checks an immutable object buffer before Aya loading, and accepts only a fixed generated namespace/veth context. Fresh unpinned Maps and an exclusive identity lease are private to each trial; reverse cleanup checks owned identities. See the [loader plan and safety contract](superpowers/plans/2026-10-02-isolated-diagnostic-loader.md) and [runtime usage](development.md#acceptance-only-diagnostic-loader).

### Method and retained evidence

The authorized node was ostack7 (`10.58.146.7`), kernel `6.6.0-159.4.8.161.oe2403sp4.x86_64`, 40 logical CPUs. No installation, systemd action, physical attachment or existing eBPF replacement was performed. A fresh generated namespace/veth and the previously authorized reversible per-generated-port LLDP exclusion were used. The same bounded mixed ARP sender from `dfb34a445ce651add19f03456ed94200ca81ee9c` supplied all layers.

- Smoke run `70b3623c6f254b0da6e91f1863669806`: one trial per layer, excluded from performance statistics. Raw report SHA-256 `36986d91f06e4c3dac848eff2b9d0ec677704846a5c5776d53e347dcee675069`.
- Measurement run `ec9eac972fa34da998a6d01a52910264`: five rotating-order repetitions of baseline and four layers, all 25 trials retained, with no outlier removal. Raw report SHA-256 `700f2f90ad47c1393122fb1371f05143799eb804f814bad692054ec58abc786a`.
- Task-local transport controller `.artifacts/ostack7-layered-run.py` SHA-256 `96cfc27605851621dc0522af3252eebeda7715157d6eaebd34b16699820d4f01`. Raw reports are retained locally as `.artifacts/ostack7-layered-<run-id>.json`; they are not checked into the repository.

Each attached trial initializes the same 16 stats keys and fixed configuration, but **no daemon or background sampler runs**. Host-to-peer TC and peer-to-host generic-XDP traffic run sequentially, with separate warm-up and five-second / two-million-packet measurement bounds. Warm-up is excluded from PPS and included in packet/byte reconciliation. This is not simultaneous duplex capacity or a replacement for the earlier steady-state daemon comparison.

### Results

PPS is calculated from each trial's measured packet total divided by the sum of its two direction durations. Percentages below are ratios of five-trial medians, not a mean of per-trial percentages.

| Layer | Median PPS | Five-trial min–max PPS | Relative to baseline |
| --- | ---: | ---: | ---: |
| No attachment | 317,786 | 317,632–322,106 | 100.0% |
| Hooks only | 298,722 | 289,666–301,914 | 94.0% |
| Configuration lookup | 292,083 | 268,921–293,532 | 91.9% |
| Classification and counters | 291,968 | 288,632–297,281 | 91.9% |
| Complete fingerprint path | 277,777 | 275,438–282,046 | 87.4% |

For comparison, medians of within-round paired ratios to baseline are 93.3%, 92.0%, 91.9% and 87.4% respectively. The complete fingerprint layer is slower than counters in all five rounds; its median paired ratio to counters is 95.1% (ratio of medians: 95.14%). These are descriptive results, not confidence intervals.

All 25 trials have zero observed link drops/errors. Independent reconciliation of the retained records confirms exact transmitted/received packets **and bytes**, including warm-up, in both directions. Counters/full-profile Maps match actual traffic; hooks/config-profile counters remain zero as intended. Both runs completed cleanup and restored the measured network/eBPF identities and LLDP state, with zero generated residue. Snapshot coverage is program/map IDs, pin roots and interface XDP/TC state, **not exhaustive global BPF-link-ID enumeration**. No foreign attachment was removed.

### Decision and limits

Pure hooks account for an approximately 6% difference from the unattached baseline in this environment. This is not all product packet-processing logic; generic-XDP direction is more affected. Configuration and counter medians are almost identical, with overlapping ranges and a low configuration trial, so this does not establish that classification/counting is free or justify a Map redesign.

The next priority is to separate the fingerprint path's per-packet prefix/hash work from selected-only clock and Map operations using selected/unselected corpora. The existing hash implementation is already unrolled, and the selection decision follows hash computation; blindly recommending loop unrolling would not address the current code. Choose an equivalent, correctness-tested optimization only after narrowing that cost, without changing sampling, fingerprint identity, counter or ownership semantics.

**No product hot-path optimization or throughput gain has been delivered by this diagnostic increment.** The original formal gate remains failed and unchanged. Repeated synthetic ARP on a shared host without CPU affinity does not establish physical/native-XDP performance, realistic LRU churn, VLAN/offload behavior or production readiness.
