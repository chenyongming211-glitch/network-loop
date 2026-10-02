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
- [ ] Keep each daemon alive for at least 75 seconds before a measured steady-state observe run. Record observe/status before and after to prove windows and baseline state rather than assuming readiness from elapsed time.
- [ ] Compare baseline/pass-through/observe using the same mixed corpus and retain all results; selected/unselected comparisons are separate diagnostics, not substitutes for the formal gate.
- [ ] Record forwarding/drop/error deltas, actual sample selection, bounded sender timing, daemon and relevant system CPU observations with their distinct meanings. Stop on changed foreign identity or failed cleanup.

## Task 3: Evidence-directed optimization and regression

**Files selected by evidence:** `ebpf/l2-loop-ebpf/src/programs.rs`, `ebpf/l2-loop-ebpf/src/maps.rs`, shared ABI/readers only if a reviewed Map change is justified.

- [ ] Identify which stage is responsible before selecting a code change. Pure-pass/config/count/fingerprint diagnostic modes require isolated-only authorization and cannot replace the formal pass-through definition.
- [ ] For a justified hotspot change, add failing correctness tests on GitHub before implementation; preserve generation, exact counters, fingerprint direction correlation and ownership behavior.
- [ ] Re-run diagnostic comparisons with paired corpora, then run the unchanged formal performance gate on the new exact artifact.
- [ ] Report measured benefit and remaining limits. Physical/native-XDP and installation authorization remain separate gates.

Tasks 2 and 3 are conditional on Task 1 verification and external safety state; no performance improvement is claimed by adding instrumentation alone.

Current checkpoint: the corrected sender's 16 behavioral tests passed in GitHub run `37001826503`. Unsolicited LLDP was demonstrated on the generated host veth. The user subsequently authorized a temporary transmit exclusion for only each new test veth, with original-status restoration; no global configuration, service restart, persistent setting or existing-port mutation is allowed. A scoped idle validation succeeded; complete the three-mode diagnostic next. See [the evidence and authorization boundary](../../performance-diagnostics-2026-10-02.md).

## Diagnostic corpus correction

The first diagnostic baseline (run `187b64d6437d44cc81f943f3db76d65c`) stopped before any eBPF attachment because the custom EtherType corpus increased receiver drops. A no-eBPF, 32-packet-per-case probe (`46fb76c589694e4da8bbf38a0ef94934`) measured 32 receive drops for both fixed-MAC and actual-peer-MAC custom EtherType traffic, and zero for actual-peer-MAC ARP traffic. Both transactions restored measured identities and removed their generated resources. These are diagnostic-tool findings, not product performance comparisons.

Use the formal harness's zero-IP ARP structure and actual generated-peer MACs. Preserve both raw reports. The receiver-compatible corpus regression failed as expected on GitHub run `37001503391`, job `110820251984` (one assertion failure out of 15 tests); the corrective implementation must pass GitHub before the next comparison.
