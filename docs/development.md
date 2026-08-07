# Development and CI

All compilation and automated verification for L2 Loop Detection Agent runs in GitHub Actions. Do not run Cargo, rustc, Clippy, rustfmt, `bpf-linker`, or an eBPF compiler from the local authoring workspace.

## Workflow

This single-developer repository commits and pushes directly to `main`. The `CI` workflow runs for pushes to `main` and for pull requests submitted by external contributors.

### Userspace job

The stable Rust job verifies the default workspace members and does not compile the eBPF crate. It runs:

```text
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check
```

This job covers ABI layout, fixed numeric values, domain validation, lifecycle transitions, protocol framing, CLI parsing and rendering, the bounded Unix server, daemon dispatch, Linux snapshot parsing, agent orchestration, and the public eBPF source contract.

### eBPF job

The eBPF job installs stable Rust for `xtask`, nightly Rust with `rust-src`, and `bpf-linker`. It then runs:

```text
cargo xtask build-ebpf
```

The resulting object targets `bpfel-unknown-none`. This job proves that all declared maps and pass-through programs compile; it does not attach them to a runner interface.

## Current safety boundary

- No implementation attaches to a live NIC.
- Preflight reads only the explicitly requested interface and relevant kernel attachment metadata.
- The daemon control socket accepts one bounded request and returns one bounded response per connection.
- No implementation sends a probe frame.
- No implementation returns `XDP_DROP` or `TC_ACT_SHOT`.
- Probe CLI parsing has no count, repeat, interval, or scheduling option.
- Privileged attachment and isolated-host acceptance remain separate future slices.

## Read-only preflight flow

`l2-loopd` constructs the real Linux inspector and serves `/run/l2-loop/agent.sock`. The parent directory must already exist with safe ownership and permissions. The socket itself is created with mode `0600`.

```text
l2-loopctl preflight --interface <IFACE>
l2-loopctl preflight --interface <IFACE> --json
```

The command sends one protocol-v1 request and reads one response. `--json` affects output rendering only. Ready and warning reports exit `0`, transport or internal errors exit `1`, usage and local validation errors exit `2`, and blocked reports exit `4`.

SIGINT and SIGTERM use graceful shutdown. Cleanup verifies the socket device and inode before unlinking it, so a replacement path is preserved.

Do not compile these binaries locally. Until the release bundle workflow is added, GitHub Actions provides verification rather than a deployable artifact.

## Review evidence

Each development handoff must include the GitHub Actions run URL and commit SHA for `main`. A local static inspection is useful for scope review but is never reported as compilation success.
