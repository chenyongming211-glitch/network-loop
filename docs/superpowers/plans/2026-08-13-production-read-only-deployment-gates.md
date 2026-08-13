# Production Read-Only Deployment Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Delivery G so one exact GitHub artifact can be proven `staging_ready` under a generated root and can produce a fixture-backed, non-executable `canary_candidate` report without installing, starting, attaching to, or mutating a production host.

**Architecture:** Add strict deployment domain contracts to `l2-loop-core`, a pure fail-closed gate service with injected filesystem/platform/clock ports to `l2-loop-agent`, Linux read-only adapters, and a standalone `l2-loop-deploycheck` binary. Extend the deterministic MUSL bundle with the checker, fixed systemd unit, authorization example, and manifest roles. A separate generated-root harness validates packaging and three-mode namespace/veth performance while preserving all existing network/eBPF state.

**Tech Stack:** Rust 2024, serde/serde_json, sha2, tokio, Aya, nix, clap-compatible existing argument parsing style, PowerShell 5.1/7, GitHub Actions, x86_64 MUSL, Linux namespace/veth.

## Global Constraints

- Work directly on `main`; do not create a branch, worktree, or subagent.
- Do not compile, format, lint, or test Rust locally. Every Rust RED/GREEN result comes from the exact pushed SHA in GitHub Actions.
- Local work is limited to read-only inspection, `git diff --check`, tracked-content scans, and the existing PowerShell safety tests.
- Preserve protocol version 1, eBPF object behavior, six-Map ABI, fail-open semantics, and all existing isolated-only attachment restrictions.
- Never add `XDP_DROP`, `TC_ACT_SHOT`, an active probe, packet mutation, production attachment, interface discovery, `force`, `replace`, `adopt`, or a policy override.
- The deployment checker has no install, repair, chmod, chown, enable, start, stop, restart, attach, detach, pin, unpin, or cleanup path.
- The authorized host may touch only `/run/l2-loop/accept/<32-lower-hex>/staging-root` and generated namespace/veth resources. It must not inspect or mutate a physical/business interface or real `/etc`, `/usr`, `/var`, systemd, or journald state.
- The only decisions are `blocked`, `staging_ready`, and `canary_candidate`. No code, document, test, or renderer may introduce `production_ready`.
- `canary_candidate` is exercised through injected physical-interface fixtures only. Every `CanaryPlanV1` has `executable: false`, and no daemon/CLI operation consumes it.
- Reports and errors are deterministic, privacy-reduced, stable-sorted, and bounded to 1 MiB.
- For each RED commit, confirm only the expected job fails. For each GREEN commit, require all five CI jobs to pass before continuing.
- Every final artifact is bound to one 40-character commit SHA and verified using all `SHA256SUMS` entries before host execution.

---

### Task 1: Freeze the Deployment Domain and Strict Schemas

**Files:**
- Create: `crates/l2-loop-core/src/deployment.rs`
- Create: `crates/l2-loop-core/tests/deployment_contract.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`

**Interfaces:**
- Produces the only public decision/finding/gate/report/authorization/performance/plan types used by later tasks.
- Consumes existing `InterfaceKind`, hook state, preflight, and fixed artifact identity value types; does not introduce an execution command.

- [ ] **Step 1: Write RED schema and invariant tests**

Require the wished-for API and exact snake-case values:

```rust
assert_eq!(DeploymentDecisionV1::Blocked.to_string(), "blocked");
assert_eq!(DeploymentDecisionV1::StagingReady.to_string(), "staging_ready");
assert_eq!(DeploymentDecisionV1::CanaryCandidate.to_string(), "canary_candidate");
assert_eq!(DEPLOYMENT_SCHEMA_VERSION, 1);
assert_eq!(CANARY_MAX_OBSERVATION_MS, 15 * 60 * 1_000);
assert_eq!(PERFORMANCE_TRIALS_PER_MODE, 5);
assert_eq!(PERFORMANCE_PASS_THROUGH_MIN_PERMILLE, 950);
assert_eq!(PERFORMANCE_OBSERVE_MIN_PERMILLE, 900);
assert_eq!(PERFORMANCE_MAX_DAEMON_RSS_BYTES, 256 * 1024 * 1024);
assert_eq!(PERFORMANCE_MAX_RSS_GROWTH_BYTES, 16 * 1024 * 1024);
assert_eq!(PERFORMANCE_MAX_DAEMON_CPU_PERMILLE, 1_000);
```

Test strict deserialization of `DeploymentAuthorizationV1` and `PerformanceEvidenceV1`: reject unknown, duplicate, missing and wrong-type fields; non-lowercase/non-32-hex authorization IDs; non-40-hex commit SHAs; non-physical or zero-ifindex targets; any master; non-empty XDP/TC; invalid mode; zero, reversed, over-24-hour, not-yet-valid, or expired authorization; wrong trial count/mode/order; arithmetic overflow; mismatched artifact/host identity; and `passed` evidence with a failed invariant. Assert inclusive issue/expiry boundaries.

Test `CanaryPlanV1` always serializes `executable: false`, fixed 15-minute maximum duration, no action token/command/endpoint, sorted stop and rollback requirements, and no consumer implementation. Test report validation rejects a positive decision with an applicable blocker, a plan in `staging_ready`, a missing plan in `canary_candidate`, or `mutations_performed: true`. Scan all variants and serialized fixtures to prove `production_ready` is absent.

- [ ] **Step 2: Push RED and verify the expected GitHub failure**

Commit and push:

```text
test: specify deployment gate contracts
```

Require Script safety, Windows PowerShell safety, and eBPF to pass. Require Userspace to fail only because `l2_loop_core::deployment` and its schema types do not exist. Record the run URL and exact failing test/build step.

- [ ] **Step 3: Implement the minimal closed domain model**

Use deny-unknown-fields structs and validated constructors. Keep fields private where an invalid combination could otherwise be constructed. The central shape is:

```rust
pub enum DeploymentDecisionV1 {
    Blocked,
    StagingReady,
    CanaryCandidate,
}

pub struct DeploymentGateReportV1 {
    pub schema_version: u16,
    pub decision: DeploymentDecisionV1,
    pub artifact: DeploymentArtifactIdentityV1,
    pub interface: Option<DeploymentInterfaceSummaryV1>,
    pub gates: DeploymentGateSummariesV1,
    pub findings: Vec<DeploymentFindingV1>,
    pub canary_plan: Option<CanaryPlanV1>,
    pub captured_at_unix_ms: u64,
    pub mutations_performed: bool,
}
```

Define the exact stable codes `DG_ARTIFACT_INVENTORY`, `DG_ARTIFACT_MANIFEST`, `DG_ARTIFACT_CHECKSUM`, `DG_STAGING_ROOT`, `DG_LAYOUT_TYPE`, `DG_LAYOUT_MODE`, `DG_LAYOUT_SYMLINK`, `DG_SYSTEMD_CONTRACT`, `DG_AUTH_SCHEMA`, `DG_AUTH_EXPIRED`, `DG_AUTH_ARTIFACT`, `DG_AUTH_IDENTITY`, `DG_INTERFACE_UNSUPPORTED`, `DG_XDP_NOT_EMPTY`, `DG_TC_NOT_EMPTY`, `DG_PLATFORM_BLOCKED`, `DG_EVIDENCE_ROOT`, `DG_PERFORMANCE_UNAVAILABLE`, `DG_PERFORMANCE_REGRESSION`, and `DG_INTERNAL`, plus warnings `DG_REAL_JOURNALD_UNVERIFIED`, `DG_NATIVE_XDP_UNVERIFIED`, and `DG_WORKLOAD_PERFORMANCE_UNVERIFIED`. Add gate states `passed/blocked/unavailable/not_applicable`, exact performance modes `baseline/pass_through/observe`, strict authorization and performance documents, and checked validation helpers. Keep report construction behind one derivation function so adapters cannot choose a positive decision.

- [ ] **Step 4: Push GREEN and require five successful jobs**

Commit and push:

```text
feat: add deployment gate domain contracts
```

Require format, Clippy, tests, default-member check, eBPF, both script jobs, and Bundle to succeed for the exact SHA. Confirm protocol, eBPF, Map ABI, and existing artifact contents remain unchanged at this task.

### Task 2: Implement the Pure Fail-Closed Deployment Gate Service

**Files:**
- Create: `crates/l2-loop-agent/src/deployment.rs`
- Create: `crates/l2-loop-agent/tests/deployment_service.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Modify: `crates/l2-loop-agent/src/ports.rs`

**Interfaces:**
- Consumes injected `DeploymentFilesystem`, `DeploymentPlatformInspector`, and `Clock` ports.
- Produces `DeploymentGateService::{staging, inspect}` and one central decision derivation; performs no direct filesystem, process, socket, netlink, or Aya operation.

- [ ] **Step 1: Write RED orchestration tests**

Create fakes that record calls and prove exact ordering and short-circuit behavior:

```rust
let report = service.staging(&bundle, &generated_root)?;
assert_eq!(report.decision, DeploymentDecisionV1::StagingReady);
assert!(report.canary_plan.is_none());
assert!(!report.mutations_performed);

let report = service.inspect()?;
assert_eq!(report.decision, DeploymentDecisionV1::CanaryCandidate);
assert_eq!(report.canary_plan.unwrap().executable, false);
```

For `staging`, require argument grammar, bundle identity/checksums, staged layout, unit contract, authorization fixture, performance fixture, evidence/runtime prerequisites, then decision. For `inspect`, require fixed installed layout, authorization/performance parse, fresh platform/preflight, exact identity binding, evidence/runtime prerequisites, plan, then decision. Prove a failed identity stage prevents later reads. Prove every error is bounded and stable-sorted.

Assert the unchanged existing `PF_LIVE_INTERFACE` blocker is required and accepted only as evidence that live attachment is still refused; any missing expected blocker or any additional blocker becomes `DG_PLATFORM_BLOCKED`. Independently enforce reserved-port rules. No `PreflightReport` or `CanaryPlanV1` reaches the attachment transaction.

- [ ] **Step 2: Push RED**

Commit `test: specify deployment gate orchestration`. Require Userspace to fail on the missing service/ports and every safety/eBPF job to remain green.

- [ ] **Step 3: Implement orchestration with injected ports**

Add narrow read-only traits:

```rust
pub trait DeploymentFilesystem {
    fn inspect_bundle(&self, bundle: &Path) -> Result<BundleSnapshotV1, DeploymentIoError>;
    fn inspect_staged_layout(&self, root: &Path) -> Result<LayoutSnapshotV1, DeploymentIoError>;
    fn inspect_installed_layout(&self) -> Result<LayoutSnapshotV1, DeploymentIoError>;
}

pub trait DeploymentPlatformInspector {
    fn inspect_authorized_interface(
        &self,
        authorization: &DeploymentAuthorizationV1,
    ) -> Result<DeploymentPlatformSnapshotV1, DeploymentIoError>;
}
```

Do not add a writer trait. Parse/validate each stage before calling the next. Convert adapter failures to the stage's stable finding without exposing raw paths, identities, addresses, topology, or error chains. Derive the plan and decision only after all required identities match.

- [ ] **Step 4: Push GREEN**

Commit `feat: add read-only deployment gate service` and require the exact five-job green run.

### Task 3: Validate Bundle Inventory and the Production-Shaped Staging Layout

**Files:**
- Create: `crates/l2-loop-agent/src/linux/deployment_fs.rs`
- Create: `crates/l2-loop-agent/tests/deployment_layout.rs`
- Create: `crates/l2-loop-agent/tests/fixtures/deployment/manifest-v1.json`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Modify: `crates/l2-loop-agent/src/ports.rs`

**Interfaces:**
- Consumes only explicit `bundle` and exact generated `root` paths for `staging`; fixed paths for `inspect`.
- Produces immutable bundle/layout snapshots containing types, numeric owner/group, modes, digests, canonical containment, and staged runtime occupancy.

- [ ] **Step 1: Write RED filesystem contract tests**

Require bundle inventory to contain exactly eight regular payload files plus `SHA256SUMS`:

```text
l2-loopd
l2-loopctl
l2-loop-deploycheck
l2-loop-hostcheck
l2-loop-ebpf.o
l2-loop.service
deployment-v1.example.json
manifest.json
SHA256SUMS
```

Test extra/missing/nested files, malformed/non-lowercase/duplicate checksums, mismatched digest, wrong commit/role/target/ABI, symlink, hard link, FIFO/socket/device, path traversal, canonical escape, renamed payload, and reads larger than the fixed bound. Require `/run/l2-loop/accept/<32-lower-hex>/staging-root` exactly; reject uppercase, short/long IDs, repeated separators, dot components, trailing paths, and all real/system roots.

Build temporary test trees and require the fixed production-shaped paths, no-follow traversal, root/root production contract metadata, and exact modes: generated roots `0700`; public `/usr` parents `0755`; restricted `/etc/l2-loop` and gates `0700`; executables `0755`; object/manifests/checksums/unit/example `0644`; authorization/performance `0600`; evidence/runtime directories `0700`; empty runtime directory. Any staged `agent.sock` blocks.

When validating installed checksums, resolve each checksum filename through the fixed layout table: the CLI, unit, and example are not siblings of the checksum file. Never join an untrusted checksum filename to an installed directory. Staging tests inject numeric metadata so GitHub does not need privileged chown; the authorized harness creates the generated tree as root and verifies actual uid/gid `0/0`.

- [ ] **Step 2: Push RED**

Commit `test: specify deployment bundle and layout`. Require the focused Userspace failure; do not continue if an existing bundle/security test fails.

- [ ] **Step 3: Implement no-follow bounded readers**

Walk only the finite expected path table; never recursively discover arbitrary content. Use `symlink_metadata`, device/inode/link-count checks, explicit maximum file sizes, exact canonical root-prefix checks, SHA-256 streaming, and constant inventory comparison. Do not create, remove, chmod, chown, rename, or open a path for writing.

Represent fixed installed paths as constants and map them below the generated root only for `staging`. Keep real-layout access unreachable from the staging command. Never accept path aliases through environment variables.

- [ ] **Step 4: Push GREEN**

Commit `feat: validate deployment bundle and layout` and require all five jobs.

### Task 4: Parse and Enforce the Fixed systemd Unit Contract

**Files:**
- Create: `crates/l2-loop-agent/src/linux/deployment_unit.rs`
- Create: `crates/l2-loop-agent/tests/deployment_unit.rs`
- Create: `packaging/l2-loop.service`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`

**Interfaces:**
- Consumes bounded UTF-8 unit bytes from the filesystem snapshot.
- Produces a validated unit summary; never invokes `systemd-analyze`, `systemctl`, a shell, or a service manager.

- [ ] **Step 1: Write RED parser and hardening tests**

Require exact approved values, including:

```ini
ExecStart=/usr/libexec/l2-loop/l2-loopd
User=root
Group=root
RuntimeDirectory=l2-loop
RuntimeDirectoryMode=0700
UMask=0077
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE
RestrictAddressFamilies=AF_UNIX AF_NETLINK
ReadWritePaths=/run/l2-loop /var/lib/l2-loop/evidence/v1
TimeoutStopSec=10s
Restart=no
```

Test every required hardening directive from the design. Reject duplicate/conflicting keys, drop-ins, continuations, shell metacharacters, specifiers, variables, relative commands, `ExecStartPre/Post`, broad writable paths, `CAP_SYS_ADMIN`, capability additions/omissions, automatic restart, installation/evidence creation, sysctl/module/offload actions, and unknown execution-bearing directives.

- [ ] **Step 2: Push RED**

Commit `test: specify hardened service unit`. Require Userspace to fail because the constrained parser/asset is absent.

- [ ] **Step 3: Implement the constrained parser and deterministic asset**

Parse only the approved sections and key/value grammar; normalize horizontal whitespace only where the specification permits it. Compare set-valued fields as exact approved ordered tokens and reject multiple definitions. Return stable `DG_SERVICE_*` findings without echoing input. Keep `l2-loop.service` byte-for-byte deterministic.

- [ ] **Step 4: Push GREEN**

Commit `feat: add hardened service unit contract` and require all five jobs.

### Task 5: Compose the Read-Only Linux Platform Inspector

**Files:**
- Create: `crates/l2-loop-agent/src/linux/deployment_platform.rs`
- Create: `crates/l2-loop-agent/tests/deployment_platform.rs`
- Create: `crates/l2-loop-agent/tests/fixtures/deployment/physical-empty.json`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Modify: `crates/l2-loop-agent/src/linux/inspector.rs`

**Interfaces:**
- Reuses existing read-only collectors and unchanged `PreflightService`.
- Produces one sanitized fresh snapshot bound to the authorization's exact interface name/ifindex; no interface enumeration fallback or mutation.

- [ ] **Step 1: Write RED identity and reserved-port tests**

Use injected facts to cover exact valid physical/empty-hook state and each blocker independently: name/ifindex/admin/oper mismatch; not physical; master/member, bond, bridge, OVS, tap, veth, peer or namespace relation; native/generic XDP occupied/foreign/unknown; clsact/filter occupied/foreign/unknown; L3 address, route, neighbor, interface-bound AF_PACKET service or other visible consumer present; unsupported kernel/BTF/bpffs/memlock; missing expected `PF_LIVE_INTERFACE`; or any additional preflight blocker.

Assert reports expose only consumer-present booleans and sanitized kind/state, never address, route, neighbor, MAC, hostname, machine ID, program/map/pin identity, or raw collector error. Prove platform inspection is never called during `staging`.

- [ ] **Step 2: Push RED**

Commit `test: specify deployment platform inspection`. Require only the wished-for adapter/service tests to fail.

- [ ] **Step 3: Implement strict single-interface composition**

Accept the interface exclusively from the validated authorization. Call the existing collectors with that exact name, compare the returned ifindex before using later facts, run unchanged preflight, require exactly its live-interface refusal plus no other blocker, then apply the stricter reserved-port predicates. Collect address, output-interface route, and neighbour presence through read-only rtnetlink queries and interface-bound packet-socket presence through a bounded `/proc/net/packet` parser; expose booleans/counts only. If any required consumer source is unreadable or ambiguous, return unavailable and block candidacy. Stop on identity change between snapshots. Do not add netlink writes, Aya loads, hook queries with replacement semantics, subprocess inspection, or daemon calls.

- [ ] **Step 4: Push GREEN**

Commit `feat: inspect deployment candidate safely` and require all five jobs.

### Task 6: Validate Isolated Performance Evidence and Derive the Canary Plan

**Files:**
- Modify: `crates/l2-loop-core/src/deployment.rs`
- Create: `crates/l2-loop-core/tests/deployment_performance.rs`
- Modify: `crates/l2-loop-agent/src/deployment.rs`
- Modify: `crates/l2-loop-agent/tests/deployment_service.rs`

**Interfaces:**
- Consumes strict `performance-v1.json`, current artifact identity, and sanitized host compatibility identity.
- Produces checked medians/permille ratios, a performance gate, and the final non-executable plan.

- [ ] **Step 1: Write RED calculation and binding tests**

Fix the trial contract to a warm-up followed by exactly five trials per mode. Each trial sends 65,536 frames at each of 64, 512, and 1,514 bytes (196,608 frames total); thresholds and counts are constants, never CLI options. Mode order rotates:

```text
1: baseline, pass_through, observe
2: pass_through, observe, baseline
3: observe, baseline, pass_through
4: baseline, observe, pass_through
5: pass_through, baseline, observe
```

Test integer median selection, checked PPS/BPS aggregation, exact 950/900 permille boundaries, zero baseline, overflow, wrong frame vectors/order/counts, best-run selection attempts, incomplete/noisy/unavailable evidence, nonzero agent-caused drop/error deltas, daemon CPU above 1,000 permille, peak RSS above 256 MiB, RSS growth above 16 MiB from the first to fifth trial, process/map/program/pin growth, forwarding failure, cleanup/restoration failure, stale over-24-hour evidence, commit/package/arch/kernel/CPU mismatch, and host identity change.

Assert passing isolated evidence still leaves fixed native-driver and representative-workload warnings in `CanaryPlanV1`, includes `DG_REAL_JOURNALD_UNVERIFIED`, and can never yield `production_ready`.

- [ ] **Step 2: Push RED**

Commit `test: specify isolated performance gate`. Require only the new performance behavior to fail.

- [ ] **Step 3: Implement checked validation and plan derivation**

Use `u128` intermediates, lower-median-of-five only, exact fixed arrays, and explicit `passed/failed/unavailable`. Bind evidence to commit, package, architecture, kernel release, logical CPU count, and capture interval. Treat missing or noisy values as unavailable. Construct the plan from already validated snapshots; hard-code `executable: false`, 15 minutes, no-replace/foreign-state requirements, snapshot/stop/rollback requirements, and sorted outstanding warnings.

- [ ] **Step 4: Push GREEN**

Commit `feat: validate deployment performance evidence` and require all five jobs.

### Task 7: Add the Standalone Read-Only Deployment Checker CLI

**Files:**
- Create: `crates/l2-loop-agent/src/bin/deploycheck.rs`
- Create: `crates/l2-loop-agent/src/deployment_cli.rs`
- Create: `crates/l2-loop-agent/tests/deployment_cli.rs`
- Modify: `crates/l2-loop-agent/Cargo.toml`
- Modify: `crates/l2-loop-agent/src/lib.rs`

**Interfaces:**
- Exposes only `staging --bundle <DIR> --root <ROOT> [--json]` and `inspect [--json]`.
- Uses the gate service directly; does not connect to the Unix socket or daemon.

- [ ] **Step 1: Write RED argument/rendering/exit tests**

Assert the complete accepted grammar and reject every other positional/flag/environment override: no interface, install, repair, start, attach, force, policy, output path, evidence root, socket, or fixed-path override. Assert `inspect` has no path arguments. Require `--help` to state read-only/non-executable scope.

Require text and JSON to contain the same decision, exact artifact identity, gate summaries, sorted stable findings, optional sanitized interface, optional plan, capture time, and `mutations_performed: false`. Bound both outputs to 1 MiB and scan for prohibited identities/addresses/raw errors. Define the approved exit codes exactly: `0` for `staging_ready` or `canary_candidate`, `1` when bounded internal/I/O failure prevents a report, `2` for CLI usage or local validation failure, and `4` for a completed `blocked` report.

- [ ] **Step 2: Push RED**

Commit `test: specify deployment checker CLI`. Require the missing binary/parser/rendering tests to fail on Userspace only.

- [ ] **Step 3: Implement minimal parser and calculation-free renderer**

Follow the repository's existing explicit argument parsing style. Route `staging` only to the generated-root adapter and `inspect` only to fixed paths. Serialize domain JSON directly; text rendering only labels existing values. Do not add a daemon command, control protocol variant, socket client, or installer.

- [ ] **Step 4: Push GREEN**

Commit `feat: add read-only deployment checker` and require all five jobs. Confirm `l2-loop-deploycheck --help` is exercised in GitHub, not locally.

### Task 8: Extend the Deterministic GitHub MUSL Bundle

**Files:**
- Create: `packaging/deployment-v1.example.json`
- Modify: `xtask/src/main.rs`
- Modify: `xtask/src/bundle.rs`
- Modify: `xtask/tests/bundle_manifest.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/tests/verify-build-supply-chain.Tests.ps1`

**Interfaces:**
- Consumes three agent binaries, CLI, eBPF object, unit, and example.
- Produces exactly eight payloads plus strict `SHA256SUMS` and an expanded deterministic `manifest.json`.

- [ ] **Step 1: Write RED bundle and workflow policy tests**

Require exact inventory, regular-file types, no nested content, and one lowercase checksum per payload. Require manifest schema version 1, roles for daemon, CLI, deploy checker, host checker, eBPF object, service unit, and authorization example, plus exact commit, package, targets, ABI, service digest, and example digest. Prove the example uses documentation placeholders and is structurally illustrative but never valid real authorization.

Require CI to build `l2-loop-deploycheck` in the pinned MUSL job, pass explicit unit/example paths to `cargo xtask bundle`, verify all eight checksums, retain 14 days, and keep every Action/toolchain pinned. Reject mutable actions, curl-pipe-shell, package installation, unbounded downloads, secret echo, or local artifact identity substitution.

- [ ] **Step 2: Push RED**

Commit `test: specify deployment release bundle`. Expect Userspace and/or script safety to fail on the missing bundle contract while eBPF remains green. Record every expected failing job before implementation.

- [ ] **Step 3: Implement deterministic packaging**

Extend `xtask bundle` with required `--deploy-checker`, `--service-unit`, and `--authorization-example` arguments. Read bounded regular files, hash/copy them deterministically, emit the fixed manifest, sort checksum lines by payload filename, and fail if output inventory differs. Update GitHub-only MUSL build/package arguments without changing artifact naming.

- [ ] **Step 4: Push GREEN and inspect the exact artifact**

Commit `build: package deployment gate assets`. Require five green jobs. Download the exact SHA artifact, verify `sha256sum --check SHA256SUMS` is 8/8, confirm nine total files and no nested/special entries, then delete only the task-scoped local download directory.

### Task 9: Add Acceptance-Only Pass-Through Measurement Support

**Files:**
- Modify: `crates/l2-loop-agent/src/host_acceptance.rs`
- Modify: `crates/l2-loop-agent/src/bin/hostcheck.rs`
- Modify: `crates/l2-loop-agent/src/linux/acceptance_fault.rs`
- Modify: `crates/l2-loop-agent/src/attach.rs`
- Modify: `crates/l2-loop-agent/tests/acceptance_fault.rs`
- Modify: `crates/l2-loop-agent/tests/attach_transaction.rs`
- Modify: `crates/l2-loop-agent/tests/isolated_control.rs`

**Interfaces:**
- Adds no production command. It permits the existing generated veth acceptance path to hold an owned fail-open hook transaction with `IFACE_CONFIG` unpublished, then perform exact owned rollback.
- Consumes only validated acceptance evidence root, generated names, exact artifact, and isolated veth identity.

- [ ] **Step 1: Write RED acceptance-boundary tests**

Require pass-through mode to be unavailable unless all acceptance predicates match: generated run ID, evidence root below the exact acceptance root, generated veth kind/name/ifindex, exact owned object/journal identity, empty hooks, and an explicit acceptance-only mode. Reject physical, business, master/member, arbitrary path, real evidence root, missing identity, foreign/unknown hook, and every production daemon invocation.

Prove the transaction order is load/validate/maps/hook attach, deliberately skip only `IFACE_CONFIG` publication, persist exact ownership identity, pass all traffic, expose no observation session, then rollback TC/XDP/maps/program/pins in exact reverse identity order. Any mismatch fails closed and never broad-cleans.

- [ ] **Step 2: Push RED**

Commit `test: specify isolated pass-through benchmark mode`. Require focused Userspace failures only.

- [ ] **Step 3: Implement the narrow acceptance mode**

Extend the existing acceptance gate rather than general attachment API. Keep the capability unreachable from the normal daemon command dispatcher and deployment checker. Reuse the same Aya object/Map ABI/no-replace/ownership journal/cleanup implementation; the sole difference is withholding observation configuration. Return only bounded readiness and cleanup state needed by the harness.

- [ ] **Step 4: Push GREEN**

Commit `test: support isolated pass-through measurement` and require all five jobs plus unchanged existing isolated attachment tests.

### Task 10: Build the Generated-Root Deployment and Performance Harness

**Files:**
- Create: `scripts/verify-deployment-gates.ps1`
- Create: `scripts/tests/verify-deployment-gates.Tests.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/lib/IsolatedNames.psm1`

**Interfaces:**
- Consumes one checksum-verified exact GitHub artifact and task-scoped SSH variables.
- Produces staging fixtures, a strict `performance-v1.json`, checker reports, restoration evidence, and exact cleanup under generated resources only.

- [ ] **Step 1: Write RED PowerShell safety tests**

Require a cryptographically random 32-lower-hex run ID and exact root `/run/l2-loop/accept/<id>/staging-root`; literal finite path creation; no wildcard/recursive computed deletion; resolved-prefix and identity checks before cleanup; fixed modes/frame sizes/counts/trial order/thresholds; bounded warm-up, polling, process runtime, output size, and SSH timeouts; checksum/commit binding; pre/post network/eBPF snapshots; and failure-path cleanup.

Reject package managers, `systemctl`, `service`, `journalctl`, sysctl/module/offload/OVS mutation, real `/etc`/`/usr`/`/var` writes, address/route changes, physical-interface selection, default-route discovery, arbitrary interface parameters, broad `pkill`, wildcard `ip netns del`, broad bpffs deletion, unbounded loops, and target/key literals.

- [ ] **Step 2: Push RED and require only script jobs to fail**

Commit `test: specify deployment gate host harness`. Require Script safety and Windows PowerShell safety to fail because the harness is absent; Userspace/eBPF/Bundle must remain green.

- [ ] **Step 3: Implement staging-root scenarios**

Create the exact production-shaped tree below the generated root with the approved modes, copy only checksum-verified payloads, generate strict authorization/performance fixtures, leave runtime empty, and invoke:

```text
l2-loop-deploycheck staging --bundle <exact-bundle> --root <generated-root>
l2-loop-deploycheck staging --bundle <exact-bundle> --root <generated-root> --json
```

Exercise positive staging, checksum mismatch, extra file, symlink, wrong mode, occupied runtime, malformed/expired authorization, malformed performance evidence, and hardened-unit failure. Each negative case restores the generated fixture before the next case and expects a stable `DG_*` blocker.

- [ ] **Step 4: Implement the bounded three-mode performance matrix**

Use generated namespace/veth only. Warm up once, then execute the five fixed rotating three-mode trials from Task 6. For each mode send the exact three frame sizes/counts, measure wall time, packet/byte throughput, daemon CPU and peak RSS, link counter/drop/error deltas, process/map/program/pin counts, forwarding, and cleanup/restoration. Never select a best run. Emit a strict evidence document with lower medians and integer permille ratios; noisy/incomplete measurements become `unavailable`.

Add failure scenarios for sub-threshold pass-through, sub-threshold observe, nonzero errors/drops, incomplete trials, identity mismatch, and cleanup/restoration mismatch. Use fixtures for deterministic threshold failures; do not intentionally degrade the host.

- [ ] **Step 5: Push GREEN and require five successful jobs**

Commit `test: verify deployment gates in isolation`. Require both PowerShell versions, Userspace, eBPF, and Bundle green for the exact SHA.

- [ ] **Step 6: Run only the new harness on the authorized node**

Download and verify the exact artifact. Run staging and three-mode measurements on generated resources. Require every positive and negative scenario to pass, exact pre/post network/eBPF identity, and zero generated residue. Do not run `inspect` against real installed paths or a real interface.

### Task 11: Final Safety Audit, Documentation, and Full Regression Acceptance

**Files:**
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`
- Modify: `docs/superpowers/specs/2026-08-13-production-read-only-deployment-gates-design.md` only if implementation evidence proves a real specification defect

**Interfaces:**
- Consumes final code, exact CI artifact, new Delivery G evidence, and all prior isolated host scenarios.
- Produces the final Delivery G audit and an explicit handoff boundary for separately authorized real installation/canary work.

- [ ] **Step 1: Correct documentation to actual behavior**

Document exact bundle inventory/layout/modes, checker commands and exit codes, strict authorization/performance schemas, decision meanings, unit hardening/capabilities, evidence prerequisite, non-executable plan, generated-root acceptance, and fixed performance methodology. State prominently that real installation, real systemd/journald, physical-interface inspection/attachment, driver/workload performance, active probes, drops, and `production_ready` remain unimplemented and unauthorized.

- [ ] **Step 2: Run local non-compiling audits**

Run `git diff --check`, both PowerShell safety suites, and quiet tracked scans proving: retired product keyword zero; target/key material zero; `XDP_DROP`/`TC_ACT_SHOT` zero; `production_ready` zero; mutation verbs/flags absent from checker; public interface/path overrides absent; real-system mutation commands absent from the new harness; unit capabilities/paths exact; Actions pinned; output bounds present; and eBPF/Map ABI unchanged.

- [ ] **Step 3: Commit final docs and require exact five-job green**

Commit and push:

```text
docs: finalize production deployment gates
```

Wait for all five jobs. Download the non-expired exact artifact, verify nine top-level files, all 8/8 checksum lines, manifest commit/roles/targets/ABI, deterministic unit/example digests, and no extra/special files.

- [ ] **Step 4: Run the new Delivery G matrix and all prior 18 isolated scenarios**

Execute the exact artifact only against the authorized generated root and generated namespace/veth resources. Require Delivery G staging/performance scenarios 100%, existing 18/18 scenarios, traffic forwarding, exact owned cleanup, and unchanged pre-existing network/eBPF identity. Never run real `inspect`, systemd, journald, or physical-interface operations.

- [ ] **Step 5: Run independent residue and repository audits**

Prove no generated `l2ns-*`, `l2h*`, `l2n*`, acceptance-root child, `/run/l2-loop` session object, or `/sys/fs/bpf/l2-loop` test object remains. Prove `HEAD == origin/main`, tracked worktree clean, exact CI SHA/status, exact artifact name, and 8/8 checksum verification.

- [ ] **Step 6: Report Delivery G 100% with the correct claim boundary**

Report the final SHA, CI run URL, artifact identity, Delivery G scenario count/results, prior 18/18 regression result, performance medians/ratios, restoration/residue evidence, and remaining blockers. The strongest claim is `staging_ready` plus fixture-proven `canary_candidate`; do not claim installation validation, production safety, production readiness, or authorization to attach a real interface.
