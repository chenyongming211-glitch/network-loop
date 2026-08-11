# Development and CI

All compilation and automated verification for L2 Loop Detection Agent runs in GitHub Actions. Do not run Cargo, rustc, Clippy, rustfmt, `bpf-linker`, or an eBPF compiler from the local authoring workspace.

## Workflow

This single-developer repository commits and pushes directly to `main`. The `CI` workflow runs for pushes to `main` and for pull requests submitted by external contributors.

### Userspace job

The stable Rust job verifies the default workspace members and does not compile the eBPF crate. It runs:

```text
cargo metadata --locked --no-deps
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo check --locked
```

Stable Rust is exactly `1.97.1`. `cargo fmt` is the only permanent Cargo command without `--locked`, because rustfmt formats source and does not resolve workspace dependencies; every dependency-resolving path must refuse lock-file changes.

This job covers ABI layout, fixed numeric values, domain validation, lifecycle transitions, protocol framing, CLI parsing and rendering, the bounded Unix server, daemon dispatch, Linux snapshot parsing, agent orchestration, and the public eBPF source contract.

### Script safety jobs

The isolated-host harness has self-contained static safety tests on both Linux
PowerShell 7 and Windows PowerShell. They verify deterministic generated names,
exact SSH argument arrays, bounded cleanup convergence, canonical ownership checks,
and the absence of broad or wildcard cleanup. Both jobs also enforce the build
supply-chain contract: a tracked format-v4 root lock, immutable Action SHAs,
read-only workflow permissions, exact tool versions, and locked build commands.
These jobs never contact a target host.

### eBPF job

The eBPF job installs stable Rust `1.97.1` for `xtask`, nightly Rust `nightly-2026-08-10` with `rust-src`, and `bpf-linker 0.10.4` using `cargo install bpf-linker --version 0.10.4 --locked`. It then runs through the locked workspace alias:

```text
xtask = "run --locked --package xtask --"
cargo xtask build-ebpf
```

The production xtask expands the inner build to the fixed command contract:

```text
cargo +nightly-2026-08-10 build --locked -Z build-std=core --release --target bpfel-unknown-none --package l2-loop-ebpf
```

The resulting object targets `bpfel-unknown-none`. This job proves that all declared maps and pass-through programs compile; it does not attach them to a runner interface.

### Bundle job

After Userspace and eBPF both pass, the Bundle job builds `l2-loopd`, `l2-loopctl`, and `l2-loop-hostcheck` for `x86_64-unknown-linux-musl`, combines them with the exact eBPF object from the same workflow run, and publishes:

```text
cargo build --locked --release --target x86_64-unknown-linux-musl
```

```text
l2-loop-linux-x86_64-<full-commit-sha>
├── l2-loopd
├── l2-loopctl
├── l2-loop-hostcheck
├── l2-loop-ebpf.o
├── manifest.json
└── SHA256SUMS
```

`manifest.json` records the full commit SHA, workspace package version, both target triples, and the four executable/object filenames. `SHA256SUMS` is lexically ordered and covers the other five files. The workflow runs `sha256sum --check SHA256SUMS` before upload.

Download an artifact without compiling locally:

```powershell
$L2LoopCommit = git rev-parse HEAD
$L2LoopRun = gh run list --branch main --commit $L2LoopCommit --limit 1 --json databaseId --jq '.[0].databaseId'
gh run download $L2LoopRun --name "l2-loop-linux-x86_64-$L2LoopCommit" --dir ".artifacts/$L2LoopCommit"
Get-ChildItem ".artifacts/$L2LoopCommit"
```

Keep `.artifacts/` local and ignored. After transfer to Linux, verify `SHA256SUMS` before setting mode `0755` on `l2-loopd`, `l2-loopctl`, and `l2-loop-hostcheck`; GitHub artifact extraction does not preserve executable permission bits.

## Build input update policy

The tracked root `Cargo.lock` is generated only by an explicitly added, temporary GitHub workflow with `contents: read`; the local authoring workspace does not resolve dependencies. Dependency, stable/nightly Rust, `bpf-linker`, and Action-SHA updates are selected manually and committed atomically. The maintainer reviews the lock and workflow diffs, removes the temporary workflow, then requires all five CI jobs and exact-artifact host acceptance again. No dependency updater, bot write, scheduled update, or automatic pull request is enabled.

The repository locks inputs it controls, but the GitHub-hosted runner image is still moving. This is not a byte-for-byte reproducible-build claim: the exact successful artifact, its full commit SHA, manifest, and `SHA256SUMS` remain authoritative for deployment and acceptance.

## Current safety boundary

- Attachment is exposed only through the generated isolated-verification commands. The daemon independently rejects non-veth, active, or shared interfaces.
- XDP uses atomic no-replace attachment. TC uses reserved identities and records whether the transaction created `clsact`; exact cleanup removes that qdisc only when it is still empty and owned by the transaction.
- Preflight reads only the explicitly requested interface and relevant kernel attachment metadata.
- The daemon control socket accepts one bounded request and returns one bounded response per connection.
- `observe` and `status` read only the one active journal-confirmed isolated session; they revalidate hook identities and the exact names, pins, and kernel IDs of required owned Maps before reading counters.
- No implementation sends a probe frame.
- No implementation returns `XDP_DROP` or `TC_ACT_SHOT`.
- Probe CLI parsing has no count, repeat, interval, or scheduling option.
- The authorized host harness creates only one run-derived namespace/veth pair, never configures an address or route, and performs exact owned cleanup.

## Read-only preflight flow

`l2-loopd` constructs the real Linux inspector and serves `/run/l2-loop/agent.sock`. The parent directory must already exist with safe ownership and permissions. The socket itself is created with mode `0600`.

```text
l2-loopctl preflight --interface <IFACE>
l2-loopctl preflight --interface <IFACE> --json
```

The command sends one protocol-v1 request and reads one response. `--json` affects output rendering only. Ready and warning reports exit `0`, transport or internal errors exit `1`, usage and local validation errors exit `2`, and blocked reports exit `4`.

SIGINT and SIGTERM use graceful shutdown. Cleanup verifies the socket device and inode before unlinking it, so a replacement path is preserved.

Do not compile these binaries locally. Deploy only the bundle from the exact green GitHub commit being accepted.

## Passive-observation semantics

```text
l2-loopctl observe --interface <IFACE> [--json]
l2-loopctl status [--interface <IFACE>] [--json]
```

`observe` returns generation-scoped cumulative packets and bytes for XDP ingress and TC egress, split into the six fixed mutually exclusive classes plus aggregate and parse-error counters. `status` returns zero or one active session and summarizes only the two hook aggregates. Capture time states when the Map snapshot was read; it is not a window boundary. Neither command returns PPS/BPS, a baseline, a fingerprint, or a loop verdict.

The Layer 2 parser reads one optional outer VLAN tag. A nested tag is detected but not parsed through; the frame remains fail-open and uses destination-MAC-safe degraded classification. `verified_visible` means that at least one hook in the current session saw a real supported outer tag. It is not per-hook or per-VLAN proof.

Observation failures use stable codes:

| Code | Refusal |
|---|---|
| `OBS_SESSION_NOT_FOUND` | no active isolated session matches |
| `OBS_INTERFACE_MISMATCH` | requested interface differs from the active session |
| `OBS_OWNERSHIP_MISMATCH` | journal, active session, or hook ownership disagrees |
| `OBS_MAP_UNAVAILABLE` | a required owned Map cannot be opened or read |
| `OBS_MAP_IDENTITY_MISMATCH` | a pin no longer resolves to its journal-confirmed Map identity |
| `OBS_SNAPSHOT_FAILED` | checked aggregation, clock, or bounded model construction failed |

These errors do not trigger adoption, repair, detach, or cleanup.

## Authorized isolated-host acceptance

The acceptance harness requires task-scoped environment inputs and never stores the target or key path in the repository:

```powershell
$env:L2_LOOP_TEST_TARGET = '<user>@<authorized-test-target>'
$env:L2_LOOP_TEST_KEY = '<task-scoped-private-key-path>'
$L2LoopCommit = git rev-parse HEAD
pwsh -NoProfile -File scripts/verify-isolated-host.ps1 -Commit $L2LoopCommit
```

The exact commit must already have a successful GitHub Actions bundle. The harness verifies its checksums, uses the bundled `l2-loop-hostcheck` binary to snapshot existing network/eBPF identities without requiring host `tc` or `bpftool` commands, creates a down isolated veth pair, attaches only after daemon preflight, sends a bounded number of raw local Ethernet frames, requires both XDP and TC counters to increase, detaches by exact ownership journal identity, and compares the post-cleanup snapshot with the original. Transaction-internal snapshots omit only the generated host-veth's volatile raw link record while retaining its XDP/TC/`clsact` identities through hostcheck; outer before/after snapshots still cover every host link and route. The loader creates the exact isolated bpffs parent directories only after its transaction preflight succeeds and removes only those empty directories during exact rollback. Missing base prerequisites cause a refusal; the harness does not install packages or change system configuration.

Run all bounded acceptance scenarios against the same exact artifact:

```powershell
$L2LoopScenarios = @(
    'Success',
    'TcAttachFailure',
    'MapInitializeFailure',
    'DaemonTermination',
    'IdentityChange',
    'TrafficInterruption',
    'PassiveObservation',
    'ObservationMapFailure',
    'ObservationIdentityChange'
)
foreach ($L2LoopScenario in $L2LoopScenarios) {
    pwsh -NoProfile -File scripts/verify-isolated-host.ps1 `
        -Commit $L2LoopCommit -Scenario $L2LoopScenario
}
```

Every scenario requires exact rollback of owned state and full restoration of foreign
network/eBPF identities. An intentionally changed ownership identity is refused and
retained for manual review until the original canonical journal is restored.

`PassiveObservation` verifies the exact nine-frame-per-iteration classification matrix in both directions, real tagged visibility, nested-tag degradation, text/JSON Unix-socket round trips, and continued delivery to the peer. The receiver subscribes to all Ethernet protocols and reconstructs an offloaded VLAN header from `PACKET_AUXDATA` only for acceptance comparison. Generated veth endpoints use `addrgenmode none` to suppress unrelated IPv6 DAD traffic; the harness does not change a sysctl or NIC offload setting. `ObservationMapFailure` proves an injected read failure cannot affect forwarding or exact detach. `ObservationIdentityChange` proves observation refuses a changed journal before Map reads, then succeeds in exact cleanup only after the canonical journal is restored.

GitHub runs only the self-contained static/unit safety tests for this harness. CI never reads the task-scoped environment inputs and never contacts a test host.

## Review evidence

Each development handoff must include the GitHub Actions run URL and commit SHA for `main`. A local static inspection is useful for scope review but is never reported as compilation success.

The tracked lock, immutable Action references, fixed Rust/linker versions, and locked Cargo commands make repository-controlled inputs reviewable. They do not freeze the GitHub-hosted runner image or establish byte-for-byte reproducibility, so preserve and verify the checksum file from the exact accepted workflow artifact.
