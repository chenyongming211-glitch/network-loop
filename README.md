# 二层环路检测 Agent

L2 Loop Detection Agent is a single-node Rust and eBPF service whose product roadmap covers observing, diagnosing, and temporarily containing Layer 2 loops on an explicitly selected physical interface.

The currently implemented observation slice is deliberately narrow: it provides fail-open XDP ingress and TC egress cumulative observation, bounded rate windows, generation-scoped dynamic baselines, and separate observation-health reporting for one generated, isolated namespace/veth session. It does not classify a storm or loop, collect fingerprints, send probes, apply policies, drop traffic, or attach to production, physical, bond, bridge, OVS, tap, or shared interfaces.

The broader product design remains observe-first. Later deliveries may add NIC/kernel correlation, bounded fingerprints and topology evidence, explicitly authorized one-frame probes, and expiring manual policing only after their own design and safety gates.

## Design documents

- [Product and safety architecture](docs/l2-loop-agent-design.md)
- [Rust foundation specification](docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md)
- [Linux preflight and isolated safe-attach specification](docs/superpowers/specs/2026-08-06-linux-preflight-safe-attach-design.md)
- [Isolated passive-observation specification](docs/superpowers/specs/2026-08-10-isolated-passive-observation-design.md)
- [Bounded daemon sampler and rate-window specification](docs/superpowers/specs/2026-08-11-bounded-daemon-rate-windows-design.md)
- [Dynamic baseline and observation-health specification](docs/superpowers/specs/2026-08-12-dynamic-baseline-observation-health-design.md)
- [Local alert and evidence output specification](docs/superpowers/specs/2026-08-06-local-alert-evidence-output-design.md)
- [Isolated safe-attach implementation plan](docs/superpowers/plans/2026-08-06-isolated-safe-attach.md)
- [Isolated passive-observation implementation plan](docs/superpowers/plans/2026-08-10-isolated-passive-observation.md)

## Build policy

Compilation, tests, Clippy, formatting checks, and eBPF builds run only in GitHub Actions. The local workspace is used for authoring and static inspection.

Repository-controlled build inputs are explicit: the GitHub-generated root `Cargo.lock` is tracked, every dependency-resolving permanent Cargo command uses locked resolution, GitHub Action implementations use reviewed full commit SHAs, and the stable Rust, dated eBPF nightly, and linker versions are fixed. Dependency and tool updates are manual, atomic changes; no updater or write-capable automation is enabled.

Successful CI runs publish a six-file `l2-loop-linux-x86_64-<full-commit-sha>` artifact containing the daemon, CLI, self-contained host acceptance checker, eBPF object, `manifest.json`, and `SHA256SUMS`. All three userspace binaries are static MUSL executables. The full commit SHA in both the artifact name and manifest identifies the exact source revision.

The GitHub-hosted runner image remains outside the repository-controlled boundary, so the project does not claim byte-for-byte reproducible rebuilds. Deployment and acceptance therefore use the artifact and checksum file from the exact successful commit.

## Read-only preflight

The current daemon serves a bounded local Unix control socket at `/run/l2-loop/agent.sock`. Preflight always requires an explicit Linux interface name:

```text
l2-loopctl preflight --interface <IFACE>
l2-loopctl preflight --interface <IFACE> --json
```

The text and JSON forms run the same inspection; `--json` changes rendering only. Exit codes are:

| Code | Meaning |
|---:|---|
| 0 | ready, or ready with warnings |
| 1 | daemon transport, protocol, or internal failure |
| 2 | CLI usage or local interface validation failure |
| 4 | preflight completed and is blocked |

Preflight is read-only. It inspects the explicitly named interface, relevant XDP/TC identities, bpffs/BTF state, and process limits. It does not change interfaces, routes, qdiscs, rlimits, sysctls, pin paths, or loaded programs, and it does not attach eBPF programs.

The socket parent must already exist, be owned by the daemon user (root for the default path), and not be group/world writable. The daemon creates the socket with mode `0600` and removes only the exact socket inode it owns during graceful shutdown.

## Isolated observation, bounded rates, and dynamic baseline

After the daemon has established its one active generated isolated-veth session, these commands read that session without changing kernel state:

```text
l2-loopctl observe --interface <IFACE>
l2-loopctl observe --interface <IFACE> --json
l2-loopctl status [--interface <IFACE>]
l2-loopctl status [--interface <IFACE>] --json
```

Both commands perform a fresh request-time read of generation-scoped cumulative counters. Client reads never insert rate or baseline samples and never recompute the cached baseline. `observe` returns aggregate packets/bytes, six fixed mutually exclusive classes, parse-error counters, VLAN visibility, sampling diagnostics, detailed rates, and the complete fixed-order baseline report for XDP ingress and TC egress. `status` returns zero or one active session with cumulative hook aggregates, summarized hook rates, baseline state, sample counts, and elevated identifiers.

Rate history exists only in daemon memory, belongs to one exact interface generation, and holds at most 64 successful samples. The public windows are fixed at 1, 10, and 60 seconds. Packet rates are packets per second; byte rates are bytes per second and text output labels them `B/s`. A `ready` window contains deltas, exact elapsed nanoseconds, endpoints, and integer rates. `warming_up` and `stale` windows contain `null` endpoints and rates rather than synthetic zeroes. A sample is stale only when its age is strictly greater than three seconds; a paused sampler is also stale.

The baseline learns only the ready 10-second window, at most once per successful one-second background tick. It has exactly 16 hook/subject series; each series stores packet and byte rate as an atomic pair with capacity 300 and minimum 60 samples. Initial readiness therefore takes approximately 69–70 seconds after attach. Upper median and upper MAD produce deterministic integer thresholds: `max(median + 6 * MAD, 4 * median, noise floor)`, with floors of 10 pps and 16,384 B/s. Values must be strictly greater than a threshold to be elevated. The public states are `learning`, `within_baseline`, `elevated`, and `unavailable`. Observation health is independent: trustworthy elevated traffic remains healthy, while stale, paused, or unresolved sampling/baseline integrity is degraded. Observation schema 3 carries this data while the local framing protocol remains version 1.

During learning, trustworthy values are accepted, so a sustained abnormal condition present at startup can be learned; this blind spot is explicit. Once ready, an elevated packet or byte metric rejects the complete pair for that subject, while unaffected sibling subjects continue learning. Transient background failures retain histories and publish unavailable evidence; recovery compares before accepting. Identity, generation, clock, counter, and baseline-integrity failures clear history. Detach and shutdown destroy it. Nothing is persisted.

The parser reads Ethernet plus at most one `802.1Q` or `802.1ad` tag. If a second tag is present, it records that nesting was seen but does not parse through it: broadcast and link-local-control classification remains exact, while other group destinations degrade to other multicast and remaining destinations to unclassified. A real visible outer tag promotes the session-level visibility state to `verified_visible`; this does not prove that every hook can see every VLAN and does not create per-VLAN counters.

Observation refuses absent sessions, interface mismatch, ownership mismatch, unavailable Maps, changed Map identities, or untrustworthy snapshots with stable `OBS_*` errors. It never adopts changed state and never invokes cleanup as an error response.

## Current status

The implementation now contains:

- the multi-crate Rust workspace and GitHub-only CI;
- ABI v1 map keys, values, constants, and layout tests;
- validated domain state, probe, and temporary-policy models;
- a versioned local control protocol;
- the complete safe `l2-loopctl` command grammar and read-only preflight client;
- a bounded Unix control server and preflight dispatcher;
- the real read-only Linux inspector;
- validated Aya object loading and initialization of six fixed public maps;
- atomic no-replace generic XDP attachment and ownership-aware TC attachment;
- an ownership journal schema v2 recording all six owned Map names, exact pins, and kernel Map IDs;
- reverse-order rollback and identity-exact owned-only cleanup;
- four fail-open Aya program entry points with aggregate and classified cumulative packet/byte accounting;
- real ownership-checked Aya observation reads with checked per-CPU aggregation;
- real `observe` and `status` daemon/CLI paths with bounded text and JSON output;
- a cancellation-aware one-second sampler with memory-only, generation-scoped 1/10/60-second rate windows and bounded diagnostics;
- a bounded dynamic-baseline engine with fixed 10-second source, 300/60 bounds, robust integer thresholds, anti-contamination, and orthogonal health;
- a bounded host harness covering eight exact-artifact regression and dynamic-baseline scenarios.

Production and live-interface attachment remain disabled. Loading and attachment are
available only through the generated isolated-veth verification path after the daemon
independently approves preflight. The eBPF entry points always return pass/continue;
this delivery derives rates and baseline-relative evidence from passive counters but never emits storm/loop verdicts, fingerprints packets, sends probes, drops traffic, or applies policies. It has no 100 ms sampler, persistent history, or production-interface enablement.

See [development.md](docs/development.md) for the CI workflow.

