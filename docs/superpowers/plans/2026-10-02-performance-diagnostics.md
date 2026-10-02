# Bounded performance diagnostics implementation plan

> **For agentic workers:** Use executing-plans inline. The user requires main-only development, no worktrees or subagents, and GitHub-only compilation and automated code tests.

**Goal:** Attribute the observed isolated-veth performance gap before changing the packet-processing implementation.

**Architecture:** Keep Delivery G's five-trial 95%/90% gate and its existing failed measurements unchanged. Add a diagnostic-only persistent sender with separate warm-up and timed windows. Diagnostic results cannot authorize installation or a physical canary.

**Tech Stack:** Python 3 standard library for diagnostic traffic, existing Rust/Aya artifacts and generated-veth lifecycle, GitHub Actions for tests.

**Spec:** User-approved performance diagnosis and hotspot optimization proposal in this conversation; existing safety and performance contracts in `docs/superpowers/specs/2026-08-13-production-read-only-deployment-gates-design.md` remain authoritative for formal gates.

## Global constraints

- No changes to production commands, Map ABI, sampling semantics, thresholds, business interfaces, SSH authorization, IRQ affinity, sysctls, or global BPF profiling configuration in the diagnostic increment.
- Only exact generated namespace/veth names with root ownership context, veth kind, expected ifindex, and no master are accepted. No arbitrary interface flag.
- Existing host identity snapshots, empty-hook checks, ownership checks and exact cleanup remain mandatory in the outer controller.
- Python process startup, socket construction, corpus generation and warm-up are outside the measured interval.
- Per direction: warm-up at most 0.5 seconds / 100,000 packets; measurement at most 5 seconds / 2,000,000 packets. Each send has a one-second timeout; a failed/short send or clock rollback yields no successful measurement.
- Selected, unselected and mixed deterministic fingerprint corpora use the same 64/512/1514-byte sizes. Bind Ethernet/ARP addresses to the generated endpoints; keep each direction's corpus identical across modes within a transaction. Report actual selected packet count, not an assumed 1/16 rate.
- A packet-limit result is explicitly censored; it is not equivalent to a full-duration result. Sender CPU time is not daemon or kernel CPU time.
- Original test result: pass-through 940 permille, observe 905 permille; zero observed drops/errors; measured identity restored. Do not overwrite it or rerun to select a passing result.

## Task 1: Persistent bounded traffic engine

**Files:** `scripts/diagnostic_traffic.py`, `scripts/tests/test_diagnostic_traffic.py`, `.github/workflows/ci.yml`.

**Interfaces:** `generated_interface(run_id, side)`, `validate_link(link, run_id, side, ifindex)`, `build_corpus(profile)`, `fingerprint_selected(frame)`, `measure_window(send, frames, clock, duration_ns, packet_limit)`, `run_windows(send, frames, clock)`.

- [x] Add behavioral tests for exact generated targets, foreign/unknown topology rejection, frame corpus selection, separate warm-up accounting, duration/count limits, short writes, failures and clock rollback.
- [x] Commit RED tests and run `python3 -m unittest discover -s scripts/tests -p 'test_diagnostic_traffic.py' -v` on GitHub. Run 37000652008, Script safety job 110817344225: 12 expected missing-implementation assertion failures.
- [x] Implement the standard-library sender. Example engine assertion: three successful 64-byte writes taking 30 ns report `packets=3`, `bytes=192`, and integer `pps=100000000`; no warm-up bytes are included.
- [x] Run the same tests on GitHub to GREEN and wait for existing CI checks. Run `37001826503` completed successfully: all 16 diagnostic tests plus Userspace, eBPF, Windows safety and Bundle jobs. Local work uses static review only.

## Task 2: Diagnostic integration and first attribution measurements

**Files:** task-local controller under ignored `.artifacts/`, raw reports under `.artifacts/`, this plan and README documentation.

- [x] Bind the sender digest and exact green source revision in the report; bind the product artifact separately when product bytes are unchanged.
- [x] Reuse the existing generated-veth transaction and snapshot phases. Do not install or invoke systemd.
- [x] Keep each daemon alive for at least 75 seconds before a measured steady-state observe run. All five observe measurements proved ready windows and baseline state. Independent run `3fa8e841bacf4f01b3ab68ceba4dca2a` recorded and reconciled real observe/status before and after traffic; it is excluded from the five-trial statistics.
- [x] Compare baseline/pass-through/observe using the same mixed corpus and retain all results; run `b53848788514430cb36320ff8bb44745` completed all 15 trials. Selected/unselected comparisons remain separate diagnostics, not substitutes for the formal gate.
- [x] Record forwarding/drop/error deltas, actual sample selection, bounded sender timing, daemon and relevant system CPU observations with their distinct meanings. All 15 trials passed forwarding and zero-drop/error checks; measured identity and LLDP state restored, generated residue zero.

## Task 3: Evidence-directed optimization and regression

**Files selected by evidence:** `ebpf/l2-loop-ebpf/src/programs.rs`, `ebpf/l2-loop-ebpf/src/maps.rs`, shared ABI/readers only if a reviewed Map change is justified.

- [x] Complete stage-level attribution before selecting a code change. The isolated-only hooks/config/count/fingerprint comparison retained all 25 trials; fingerprints are slower than counters in every round. Next narrow per-packet hash versus selected-only work; no individual helper is yet proved responsible. These modes do not replace the formal pass-through definition.
- [ ] For a justified hotspot change, add failing correctness tests on GitHub before implementation; preserve generation, exact counters, fingerprint direction correlation and ownership behavior.
- [ ] Re-run diagnostic comparisons with paired corpora, then run the unchanged formal performance gate on the new exact artifact.
- [ ] Report measured benefit and remaining limits. Physical/native-XDP and installation authorization remain separate gates.

Tasks 2 and 3 are conditional on Task 1 verification and external safety state; no performance improvement is claimed by adding instrumentation alone.

Current checkpoint: Tasks 1 and 2 are complete. The corrected sender's 16 behavioral tests passed in GitHub run `37001826503`; later documentation-only run `37008596976` also passed all CI jobs. The separately authorized generated-port-only LLDP exclusion was validated and restored. All 15 diagnostic trials completed: median pass-through 92.7%, steady-state observe 87.3% of baseline, with no product-code change. Independent observe/status consistency verification passed. No global configuration, service restart, persistent setting or existing-port mutation is allowed. Task 3's subsequent five-layer attribution is also complete; selecting and verifying a hot-path optimization remains outstanding. See [the evidence and authorization boundary](../../performance-diagnostics-2026-10-02.md).

Task 3 foundation checkpoints: the [diagnostic manifest and byte-identity contract](2026-10-02-layered-diagnostic-identity.md) passed GitHub run `37011741122` at `e5b87012dfa4935c7bde0e4fd94aea02ecae6539`. The [four-profile ELF build and inspection increment](2026-10-02-layered-diagnostic-objects.md) added separate objects with actual inventory, helper-stratum, mutation and ordinary-contract rejection tests. The follow-up [isolated loader](2026-10-02-isolated-diagnostic-loader.md) passed full GitHub run `37021840057` at `34c152e517b7a77f90655a0f20d343a323f87485`. Authorized ostack7 run `ec9eac972fa34da998a6d01a52910264` completed all 25 layered trials and precise cleanup: relative medians 94.0% hooks, 91.9% configuration, 91.9% counters, 87.4% fingerprints. No daemon sampler ran in these attribution measurements. Next investigate fingerprint hash versus selected-only operations before an equivalent optimization; Task 3 as a whole is not complete and no throughput improvement is claimed.

## Diagnostic corpus correction

The first diagnostic baseline (run `187b64d6437d44cc81f943f3db76d65c`) stopped before any eBPF attachment because the custom EtherType corpus increased receiver drops. A no-eBPF, 32-packet-per-case probe (`46fb76c589694e4da8bbf38a0ef94934`) measured 32 receive drops for both fixed-MAC and actual-peer-MAC custom EtherType traffic, and zero for actual-peer-MAC ARP traffic. Both transactions restored measured identities and removed their generated resources. These are diagnostic-tool findings, not product performance comparisons.

Use the formal harness's zero-IP ARP structure and actual generated-peer MACs. Preserve both raw reports. The receiver-compatible corpus regression failed as expected on GitHub run `37001503391`, job `110820251984` (one assertion failure out of 15 tests); the corrective implementation must pass GitHub before the next comparison.
