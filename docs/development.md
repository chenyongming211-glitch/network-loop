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
- The daemon performs one non-overlapping background read per second, skips missed ticks, and keeps at most 64 successful samples in memory for the exact active generation.
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

## Observation, bounded-rate, dynamic-baseline, relationship, and detection semantics

```text
l2-loopctl observe --interface <IFACE> [--json]
l2-loopctl status [--interface <IFACE>] [--json]
```

Each request performs current identity-confirmed cumulative and fingerprint Map reads but never inserts a rate, baseline, fingerprint-window, or detection sample. `observe` returns generation-scoped cumulative packets and bytes for XDP ingress and TC egress, split into the six fixed mutually exclusive classes plus aggregate and parse-error counters, together with detailed rate windows, the complete cached baseline report, a privacy-reduced request-time fingerprint relationship report, and the cached complete detection report. `status` returns zero or one active session and summarizes cumulative/rate data, baseline state, the 16 subject sample counts, at most 32 fixed-order elevated identifiers, relationship evidence, and detection. Observation schema 5 is transported through protocol version 1.

The independent background sampler runs once per second with missed ticks skipped. Its memory-only history contains at most 64 successful samples and is destroyed on successful detach; samples from different generations are never compared. Normal ticks read only counters. When the fixed 10-second analysis deadline is due, exactly one tick also performs a complete identity-confirmed fingerprint-LRU scan; missed analysis intervals are skipped and never replayed. Windows are fixed in the order 1, 10, and 60 seconds. Rates use checked integer arithmetic and monotonic elapsed nanoseconds: packets are rendered as `pps`, and bytes as `B/s`. `ready` includes endpoint evidence, deltas, and rates. `warming_up` means retained endpoints do not cover the requested duration. `stale` means the newest successful sample is strictly more than three seconds old or sampling is paused. Warming and stale windows expose `null` endpoints and rates, not zero or interpolated values.

The baseline consumes only the ready 10-second window and processes at most one advancing endpoint per successful background tick. There are exactly 16 hook/subject series (aggregate, six classes, and parse errors for each hook). Each holds packet and byte rates as an atomic pair, has capacity 300, and becomes ready at 60 samples—approximately 69–70 seconds after attach because the source window itself first needs ten seconds of coverage. Upper median and upper MAD are evaluated with checked integer arithmetic. A metric is elevated only when it is strictly greater than `max(median + 6 * MAD, 4 * median, noise floor)`, using 10 pps and 16,384 B/s floors. `ratio_milli` is clamped integer evidence and may be null when the median is zero.

The four baseline states are `learning`, `within_baseline`, `elevated`, and `unavailable`; aggregate priority is unavailable, elevated, learning, then within-baseline. `within_baseline` is relative evidence, not a safety or loop verdict. During learning every trustworthy sample is accepted, so a sustained startup abnormality can be learned. After readiness, if either packet or byte rate is elevated, the complete pair for that subject is rejected; unaffected siblings still advance. Baseline current/statistical values and `source_end_unix_ms` are cached background evidence, not request-time calculations.

Observation health is orthogonal to traffic deviation. Trustworthy learning, within-baseline, elevated, empty-fingerprint, observed-fingerprint, storm, and passive loop-confidence results are healthy. Paused/stale sampling, unresolved read failure, baseline integrity failure, unavailable fingerprint evidence, or unavailable detection is degraded. Transient background-read failures retain rate/baseline histories and the last trustworthy anomalous detection state separately; unavailable time never advances assertion, clearing, or cooldown. A request-local fingerprint iteration failure leaves cached background detection unchanged. Identity/generation, monotonic-clock, cumulative-counter, source-integrity, or internal invariant failures clear the complete histories. Successful detach and shutdown destroy them. There is no 100 ms sampling, persistent history, caller-selected detection control, confirmed-loop state, probe, drop, policy, or production attachment.

Passive detection evaluates at 1 Hz. The adaptive path requires baseline elevation plus at least 1,000 BUM pps or 1,048,576 B/s in the ready 10-second rate window. The baseline-independent startup path requires at least 100,000 BUM pps or 104,857,600 B/s in the ready 1-second window. Three identical trustworthy candidates confirm ingress, egress, or bidirectional storm. A fresh 10,000–15,000 ms fingerprint delta may upgrade an ingress/bidirectional storm to `external_loop_suspected` at 80% ingress BUM, 16 sampled ingress packets, a repeated relation, and 80% dominant ingress share; egress-first correlation plus at least 4x ingress amplification upgrades it to `external_loop_high_confidence`. A weaker anomaly or clear result requires ten trustworthy ticks. Clear enters a 30-second cooldown that retains the last anomalous state, and at most 16 typed transitions are kept. Passive evidence never confirms a loop.

When multiple anomalies are supported, precedence is `external_loop_high_confidence`, `external_loop_suspected`, bidirectional storm, ingress storm, then egress storm. A stronger currently proven result upgrades immediately after the storm candidate is confirmed; every weaker result uses the ten-tick demotion path.

| Event | Retained | Cleared or reset |
|---|---|---|
| Transient source or analysis read failure | bounded rate/baseline/fingerprint endpoints, transition history, last anomalous state | no assertion, clearing, or cooldown time advances |
| Fingerprint evidence unavailable during a rate-only storm | rate-only storm may remain trustworthy | loop upgrade is disabled |
| Fingerprint evidence unavailable during suspected/high confidence | last anomalous state is retained separately | published detection becomes `unavailable` |
| Identity, generation, clock, counter, or integrity failure | typed error and unavailable transition only | rate, baseline, fingerprint-window, streak, cooldown, and retained anomaly histories |
| Successful detach or shutdown | nothing | complete generation state |
| New generation | nothing from the old identity | new `warming_up`, sequence zero, empty transitions |

Eligible parsed frames of at least 60 bytes use 64-bit FNV-1a over the exact two-byte big-endian frame length plus the first fixed 60 bytes. Shorter frames stay fail-open and remain in cumulative classification but do not enter the fingerprint LRU. The fixed span is the standard minimum Ethernet frame without FCS and permits one verifier-visible packet-bound check on the supported kernel. The fixed `sample_shift=4` selects hashes whose low four bits are zero, approximately one in sixteen, and the 8,192-entry LRU is generation-scoped. Request reads validate the journal-confirmed name, pin path, kernel Map ID, every entry, and the hard capacity before building deterministic direction relationships. Public text/JSON contains only aggregate relationship counts, sampled packet/byte totals, bounded ratios, state, and a stable error code; it never exposes raw fingerprints, MAC addresses, packet bytes, raw keys, or raw timestamps.

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
| `OBS_RATE_CLOCK_REGRESSION` | monotonic rate time did not advance |
| `OBS_RATE_COUNTER_REGRESSION` | a cumulative counter fell below retained same-generation evidence |
| `OBS_RATE_CALCULATION_FAILED` | checked delta, elapsed, or conversion arithmetic failed |
| `OBS_RATE_SAMPLER_PAUSED` | exact detach was attempted and the retained session is paused |

Baseline failures have a separate stable namespace so operators do not confuse traffic evidence with observation transport:

| Code | Baseline meaning |
|---|---|
| `BASELINE_SOURCE_UNAVAILABLE` | a transient background source read failed; histories are retained |
| `BASELINE_IDENTITY_CHANGED` | generation or ownership identity changed; histories are cleared |
| `BASELINE_CLOCK_REGRESSION` | monotonic time regressed; histories are cleared |
| `BASELINE_COUNTER_REGRESSION` | a cumulative counter regressed; histories are cleared |
| `BASELINE_CALCULATION_FAILED` | source shape, arithmetic, or invariant validation failed; histories are cleared |
| `BASELINE_SAMPLER_PAUSED` | sampling paused during exact detach; histories are unavailable/cleared by lifecycle |

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
    'PassiveObservation',
    'RateWindows',
    'RateSamplingFailure',
    'RateGenerationReset',
    'BaselineLifecycle',
    'BaselineSamplingRecovery',
    'BaselineGenerationReset',
    'FingerprintRelationship',
    'FingerprintReadFailure',
    'FingerprintGenerationReset',
    'DetectionAdaptiveLifecycle',
    'DetectionAbsoluteStartup',
    'DetectionRelationshipConfidence',
    'DetectionFailureGenerationReset'
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

`RateWindows` sends the fixed nine-frame matrix in both directions once per second for 65 iterations and validates warming-to-ready transitions, fixed hook/class order, cumulative monotonicity, forwarding, and independent recomputation of every rate from its returned delta and `elapsed_ns`. `RateSamplingFailure` injects only background-read failure and proves request reads and forwarding continue while all windows become stale with null rates and bounded diagnostics. `RateGenerationReset` performs identity-exact detach and reattach with a new run ID, proves the generation changes and all windows restart warming, then independently drives the new 1-second window ready. Every scenario retains full before/after network and eBPF identity equality and exact owned cleanup.

`BaselineLifecycle` proves the bounded `learning -> within_baseline -> elevated -> within_baseline` sequence, fixed schema/cardinality, subject-atomic rejection, sibling learning, and recovery after elevated traffic leaves the 10-second source. `BaselineSamplingRecovery` uses a bounded background-only fault window to prove unavailable output with retained counts, continued request reads/forwarding, and compare-before-accept recovery. `BaselineGenerationReset` proves exact detach/reattach changes generation, clears all 16 histories, returns to learning, and independently advances the new generation.

`FingerprintRelationship` proves deterministic selected/unselected traffic, one unchanged selected frame correlated across ingress and egress, privacy-reduced output, and continued forwarding. `FingerprintReadFailure` injects one request-only iteration failure and proves unavailable/degraded relationship evidence without losing cumulative/rate/baseline output or forwarding, followed by request-local recovery. `FingerprintGenerationReset` proves exact detach/reattach changes generation, begins with an empty relationship report, and independently records only new-generation evidence.

`DetectionAdaptiveLifecycle` proves baseline-ready adaptive assertion, ten-tick clearing, cooldown, and normal recovery. `DetectionAbsoluteStartup` proves the fixed 1-second absolute path can assert during baseline learning. `DetectionRelationshipConfidence` proves a fixed-window egress-first amplified relationship can reach high confidence but never a confirmed-loop value. `DetectionFailureGenerationReset` proves analysis-read failure retention and complete state reset under a new generation. All fifteen required scenarios use one exact GitHub artifact and independently restore existing network/eBPF identity; a changing foreign identity causes refusal rather than being ignored.

GitHub runs only the self-contained static/unit safety tests for this harness. CI never reads the task-scoped environment inputs and never contacts a test host.

## Review evidence

Each development handoff must include the GitHub Actions run URL and commit SHA for `main`. A local static inspection is useful for scope review but is never reported as compilation success.

The tracked lock, immutable Action references, fixed Rust/linker versions, and locked Cargo commands make repository-controlled inputs reviewable. They do not freeze the GitHub-hosted runner image or establish byte-for-byte reproducibility, so preserve and verify the checksum file from the exact accepted workflow artifact.
