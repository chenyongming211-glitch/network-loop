# Performance diagnostics: 2026-10-02

## Outcome

The bounded persistent traffic sender is implemented and its 16 behavioral tests passed on GitHub. **No product throughput improvement is claimed.** The three-mode steady-state comparison is blocked by unsolicited LLDP traffic on the generated host-side veth, before product eBPF attachment. No daemon-wide LLDP setting, physical interface, or foreign eBPF attachment was changed.

The existing formal gate remains unchanged: five trials, pass-through at least 950 permille and observe at least 900 permille of baseline, with zero observed drops/errors and exact cleanup. Its prior isolated result was 940/905 permille respectively; the pass-through gate remains failed. New diagnostics neither replace that result nor authorize installation or a physical canary.

## Implemented measurement improvements

- One persistent Python process/socket per direction; construction, corpus generation and warm-up are outside the measured interval.
- Separate warm-up (0.5 s / 100,000 packets) and measurement (5 s / 2,000,000 packets) bounds; report which bound ended each window.
- Fixed 64/512/1514-byte ARP corpus using actual generated endpoint MACs and zero protocol addresses.
- Mixed, deterministically selected and unselected fingerprint corpora; report actual selection counts.
- Reject arbitrary interface names, foreign namespace identities, non-veth links, master membership, wrong ifindex, short writes and invalid clocks.
- Task-local controller preserves exact source/artifact digests, raw failure output, endpoint counters, host CPU/softnet observations and exact cleanup evidence. Its new steady-state comparison requires at least 75 seconds plus ready rate windows and a verified baseline state before observe measurement. This observe path has **not yet executed successfully**.

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

## Next boundary

The recommended next step is an explicitly authorized, temporary **per-generated-port** LLDP transmit exclusion with exact target validation, original-state capture, restoration and before/after checks. Do not stop/restart `lldpd`, edit its global interface pattern, write persistent configuration, or change any existing/business port. If the installed version cannot support a provably scoped reversible change, stop and choose an uncontaminated test environment.

Upstream documents per-port administrative status and receive-only operation in the [lldpcli manual](https://github.com/lldpd/lldpd/blob/master/src/client/lldpcli.8.in). This capability has not been exercised on the node; no LLDP configuration change is included in the current authorization or result.

After this boundary is resolved, complete the unchanged three-mode diagnostic comparison, attribute configuration/counter/fingerprint costs, and only then select a correctness-tested hot-path optimization. Rerun the original formal gate on the exact new artifact. Do not infer physical/native-XDP or production performance from these generic-XDP/veth diagnostics.
