# L2 Loop Detection Agent Naming Design

**Date:** 2026-08-06  
**Status:** Approved  
**Repository:** `chenyongming211-glitch/network-loop`

## Goal

The project presents itself only as **二层环路检测 Agent** in Chinese and **L2 Loop Detection Agent** in English. A retired four-letter product identifier must not appear in any tracked path or tracked file, regardless of letter case.

## Canonical names

| Surface | Canonical value |
|---|---|
| Chinese product name | `二层环路检测 Agent` |
| English product name | `L2 Loop Detection Agent` |
| Common ABI crate | `l2-loop-common` |
| Domain crate | `l2-loop-core` |
| Agent crate | `l2-loop-agent` |
| CLI crate | `l2-loop-cli` |
| eBPF crate | `l2-loop-ebpf` |
| Control command | `l2-loopctl` |
| Daemon command | `l2-loopd` |
| Rust import prefix | `l2_loop_` |
| eBPF program prefix | `l2_loop_` |
| System directory stem | `l2-loop` |

## Runtime paths

| Purpose | Path |
|---|---|
| Configuration | `/etc/l2-loop/agent.toml` |
| Runtime socket | `/run/l2-loop/agent.sock` |
| Persistent state | `/var/lib/l2-loop/` |
| Evidence bundles | `/var/lib/l2-loop/evidence/` |
| Pinned maps | `/sys/fs/bpf/l2-loop/v1/<ifindex>/` |

## eBPF public contract

The four initial fail-open programs are:

- `l2_loop_xdp_ingress`
- `l2_loop_tc_egress`
- `l2_loop_tc_path_ingress`
- `l2_loop_tc_path_egress`

Map ABI names and numeric layouts are unchanged because they already describe technical behavior without product branding.

## Repository scope

The rename covers every tracked path and file, including Cargo package names, workspace members, Rust imports, test fixtures, source comments, CLI help, documentation links, system paths, eBPF symbols, and CI documentation. Historical private conversation archives are intentionally untracked and are not part of the GitHub repository.

A repository-level test constructs the retired identifier from byte values and scans `git ls-files`. This prevents the identifier from returning without embedding it in the test itself.

## Branch policy

This is a single-developer repository. Existing development work is fast-forwarded into `main`. Future work is committed and pushed directly to `main`; routine feature branches and pull requests are not part of the default workflow.

All compilation, formatting checks, linting, tests, and eBPF builds continue to run only in GitHub Actions.

