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

## Foundation status

The first implementation slice now contains:

- the multi-crate Rust workspace and GitHub-only CI;
- ABI v1 map keys, values, constants, and layout tests;
- validated domain state, probe, and temporary-policy models;
- a versioned local control protocol;
- the complete safe `l2-loopctl` command grammar;
- user-space adapter traits and transactional hook orchestration;
- four fail-open Aya program entry points and six fixed public maps.

No program is attached to a real interface in this slice. The eBPF entry points return pass/continue unconditionally.

See [development.md](docs/development.md) for the CI workflow.

