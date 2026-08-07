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

### Bundle job

After Userspace and eBPF both pass, the Bundle job builds `l2-loopd` and `l2-loopctl` for `x86_64-unknown-linux-musl`, combines them with the exact eBPF object from the same workflow run, and publishes:

```text
l2-loop-linux-x86_64-<full-commit-sha>
├── l2-loopd
├── l2-loopctl
├── l2-loop-ebpf.o
├── manifest.json
└── SHA256SUMS
```

`manifest.json` records the full commit SHA, workspace package version, both target triples, and the three executable/object filenames. `SHA256SUMS` is lexically ordered and covers the other four files. The workflow runs `sha256sum --check SHA256SUMS` before upload.

Download an artifact without compiling locally:

```powershell
$L2LoopCommit = git rev-parse HEAD
$L2LoopRun = gh run list --branch main --commit $L2LoopCommit --limit 1 --json databaseId --jq '.[0].databaseId'
gh run download $L2LoopRun --name "l2-loop-linux-x86_64-$L2LoopCommit" --dir ".artifacts/$L2LoopCommit"
Get-ChildItem ".artifacts/$L2LoopCommit"
```

Keep `.artifacts/` local and ignored. After transfer to Linux, verify `SHA256SUMS` before setting mode `0755` on `l2-loopd` and `l2-loopctl`; GitHub artifact extraction does not preserve executable permission bits.

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

Do not compile these binaries locally. Deploy only the bundle from the exact green GitHub commit being accepted.

## Review evidence

Each development handoff must include the GitHub Actions run URL and commit SHA for `main`. A local static inspection is useful for scope review but is never reported as compilation success.
