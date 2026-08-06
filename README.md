# CSMP Loop Agent

CSMP Loop Agent is a single-node Rust and eBPF service for observing, diagnosing, and temporarily containing Layer 2 loops on an explicitly selected physical interface.

The first release is observe-first:

- XDP ingress and TC egress observation;
- NIC and kernel resource correlation;
- bounded packet fingerprints and local topology evidence;
- an administrator-triggered one-frame probe;
- optional, expiring manual policing;
- fail-open behavior on missing state or internal errors.

It does not depend on Neutron, communicate across nodes, infer an interface automatically, send periodic probes, or automatically disable ports.

## Design documents

- [Product and safety architecture](docs/csmp-physical-loop-agent-design.md)
- [Rust foundation specification](docs/superpowers/specs/2026-08-06-csmp-loop-rust-foundation-design.md)
- [Implementation plan](docs/superpowers/plans/2026-08-06-csmp-loop-rust-foundation.md)

## Build policy

Compilation, tests, Clippy, formatting checks, and eBPF builds run only in GitHub Actions. The local workspace is used for authoring and static inspection.

