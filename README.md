# 二层环路检测 Agent

L2 Loop Detection Agent is a single-node Rust and eBPF service whose product roadmap covers observing, diagnosing, and temporarily containing Layer 2 loops on an explicitly selected physical interface.

The currently accepted Delivery C slice is deliberately narrower: it provides fail-open XDP ingress and TC egress cumulative observation for one generated, isolated namespace/veth session. It does not yet calculate rates, classify a loop, collect fingerprints, send probes, apply policies, drop traffic, or attach to production, physical, bond, bridge, OVS, tap, or shared interfaces.

The broader product design remains observe-first. Later deliveries may add NIC/kernel correlation, bounded fingerprints and topology evidence, explicitly authorized one-frame probes, and expiring manual policing only after their own design and safety gates.

## Design documents

- [Product and safety architecture](docs/l2-loop-agent-design.md)
- [Rust foundation specification](docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md)
- [Linux preflight and isolated safe-attach specification](docs/superpowers/specs/2026-08-06-linux-preflight-safe-attach-design.md)
- [Isolated passive-observation specification](docs/superpowers/specs/2026-08-10-isolated-passive-observation-design.md)
- [Local alert and evidence output specification](docs/superpowers/specs/2026-08-06-local-alert-evidence-output-design.md)
- [Isolated safe-attach implementation plan](docs/superpowers/plans/2026-08-06-isolated-safe-attach.md)
- [Isolated passive-observation implementation plan](docs/superpowers/plans/2026-08-10-isolated-passive-observation.md)

## Build policy

Compilation, tests, Clippy, formatting checks, and eBPF builds run only in GitHub Actions. The local workspace is used for authoring and static inspection.

Successful CI runs publish a six-file `l2-loop-linux-x86_64-<full-commit-sha>` artifact containing the daemon, CLI, self-contained host acceptance checker, eBPF object, `manifest.json`, and `SHA256SUMS`. All three userspace binaries are static MUSL executables. The full commit SHA in both the artifact name and manifest identifies the exact source revision.

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

## Isolated passive observation

After the daemon has established its one active generated isolated-veth session, these commands read that session without changing kernel state:

```text
l2-loopctl observe --interface <IFACE>
l2-loopctl observe --interface <IFACE> --json
l2-loopctl status [--interface <IFACE>]
l2-loopctl status [--interface <IFACE>] --json
```

`observe` returns the detailed fixed matrix for XDP ingress and TC egress: aggregate packets/bytes, six mutually exclusive traffic classes, parse-error counters, interface generation, capture time, health, and session-level VLAN visibility. `status` returns zero or one summarized active session with only aggregate ingress/egress counters. Both report cumulative counters for the exact interface generation; they do not report PPS/BPS or a sliding time window.

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
- a bounded host harness covering the six attachment/lifecycle scenarios plus passive-observation traffic, Map-read failure, and observation identity change.

Production and live-interface attachment remain disabled. Loading and attachment are
available only through the generated isolated-veth verification path after the daemon
independently approves preflight. The eBPF entry points always return pass/continue;
this delivery observes counters and never calculates rates, emits loop verdicts, fingerprints packets, sends probes, drops traffic, or applies policies.

See [development.md](docs/development.md) for the CI workflow.

