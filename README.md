# 二层环路检测 Agent

L2 Loop Detection Agent is a single-node Rust and eBPF service for observing, diagnosing, and temporarily containing Layer 2 loops on an explicitly selected physical interface.

The first release is observe-first:

- XDP ingress and TC egress observation;
- NIC and kernel resource correlation;
- bounded packet fingerprints and local topology evidence;
- an administrator-triggered one-frame probe;
- optional, expiring manual policing;
- fail-open behavior on missing state or internal errors.

It does not depend on Neutron, communicate across nodes, infer an interface automatically, send periodic probes, or automatically disable ports.

## Design documents

- [Product and safety architecture](docs/l2-loop-agent-design.md)
- [Rust foundation specification](docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md)
- [Local alert and evidence output specification](docs/superpowers/specs/2026-08-06-local-alert-evidence-output-design.md)
- [Implementation plan](docs/superpowers/plans/2026-08-06-l2-loop-rust-foundation.md)

## Build policy

Compilation, tests, Clippy, formatting checks, and eBPF builds run only in GitHub Actions. The local workspace is used for authoring and static inspection.

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

## Current status

The implementation now contains:

- the multi-crate Rust workspace and GitHub-only CI;
- ABI v1 map keys, values, constants, and layout tests;
- validated domain state, probe, and temporary-policy models;
- a versioned local control protocol;
- the complete safe `l2-loopctl` command grammar and read-only preflight client;
- a bounded Unix control server and preflight dispatcher;
- the real read-only Linux inspector;
- user-space adapter traits and transactional hook orchestration;
- four fail-open Aya program entry points and six fixed public maps.

No program is loaded or attached to an interface in this delivery. The eBPF entry points return pass/continue unconditionally.

See [development.md](docs/development.md) for the CI workflow.

