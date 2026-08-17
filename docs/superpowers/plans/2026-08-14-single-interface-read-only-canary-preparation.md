# Real Installation and Single-Interface Read-Only Canary Preparation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Delivery G.1 so one exact GitHub artifact can be transactionally installed and independently verified, its real systemd/journald lifecycle can be accepted using generated veth only, and one reserved physical port can be declared `physical_canary_ready` through a separately authorized read-only inspection without attaching eBPF to it.

**Architecture:** Add focused installation contracts to `l2-loop-core`, a pure planner/transaction service with injected ports to `l2-loop-agent`, a no-follow Linux filesystem adapter with a durable ownership journal, and a separate static `l2-loop-install` binary. Extend `l2-loop-deploycheck` with an interface-free `installed` command, keep physical `inspect` read-only, and sequence real-host gates through bounded PowerShell harnesses whose authorizations never inherit across installation, service, and physical inspection stages.

**Tech Stack:** Rust 2024, serde/serde_json, sha2, nix `openat`/`renameat`/`fsync` primitives, tokio only where the existing agent needs it, PowerShell 5.1/7, systemd, journald, GitHub Actions, x86_64 MUSL, Linux namespace/veth.

## Global Constraints

- Work directly on `main`; do not create a branch, worktree, pull request, or subagent.
- Do not compile, format, lint, check, or test Rust locally. Every Rust RED/GREEN result comes from the exact pushed SHA in GitHub Actions.
- Local work is limited to source inspection, `git diff --check`, tracked-content scans, and PowerShell parser/safety tests that do not connect to a node.
- Follow strict TDD: push a test-only RED commit, observe the expected GitHub failure, then write the minimum GREEN implementation and require all five jobs to pass.
- Tasks 1-8 do not connect to any node. Tasks 9 and 10 require new explicit authorization at execution time and must stop if it is absent.
- Preserve protocol version 1, eBPF behavior, six-Map ABI, fail-open actions, isolated-only daemon control, and all no-replace/owned-cleanup restrictions.
- Never attach to, detach from, replace, adopt, normalize, rename, or mutate an existing physical/business interface or foreign eBPF object in Delivery G.1.
- `l2-loop-deploycheck` remains strictly read-only. `l2-loop-install` never invokes systemd, journald, Aya, netlink mutation, the daemon socket, or an installed executable.
- Production destinations are compile-time constants. No root, prefix, destination, interface, policy, duration, ownership, mode, threshold, `force`, `replace`, `adopt`, or repair override exists.
- Installation accepts only absent objects or exact prior-owned objects confirmed by a completed valid journal. Unknown identity fails closed.
- Reports are deterministic, stable-sorted, privacy-reduced, and bounded to 1 MiB. They never expose raw machine ID, MAC, PCI serial, IP, route, neighbor, packet, arbitrary source path, journal content, or error chain.
- Existing network/eBPF state is captured before every authorized-host stage, remains untouched, and must exactly return to its stable baseline with zero generated residue.
- No code or document may claim production-ready status or make a readiness plan executable.
- The old product keyword remains absent from all tracked content.

---

### Task 1: Freeze Installation Domain Models and Strict Schemas

**Files:**
- Create: `crates/l2-loop-core/src/installation.rs`
- Create: `crates/l2-loop-core/tests/installation_contract.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`

**Interfaces:**
- Consumes: existing `DeploymentArtifactIdentityV1` and serde conventions from `deployment.rs`.
- Produces: `InstallOperationV1`, `InstallCommandV1`, `InstallDecisionV1`, `InstallAuthorizationV1`, `InstallFindingV1`, `InstallReportV1`, constants, and checked validation used by Tasks 2-6.

- [ ] **Step 1: Write the failing strict-contract tests**

Create `installation_contract.rs` with canonical JSON containing schema version 1, two lowercase 128-bit IDs, an exact commit, four lowercase SHA-256 digests, one-hour timestamps, and all three authority flags set to false. Require this public API:

```rust
use l2_loop_core::{
    INSTALL_AUTHORIZATION_MAX_LIFETIME_MS, INSTALLATION_SCHEMA_VERSION,
    GI_AUTH_ARTIFACT, GI_AUTH_EXPIRED, GI_AUTH_HOST, GI_AUTH_SCHEMA,
    InstallAuthorizationV1, InstallCommandV1, InstallDecisionV1,
    InstallFindingV1, InstallOperationV1, InstallReportV1,
};

assert_eq!(INSTALLATION_SCHEMA_VERSION, 1);
assert_eq!(INSTALL_AUTHORIZATION_MAX_LIFETIME_MS, 60 * 60 * 1_000);
assert_eq!(InstallOperationV1::Install.to_string(), "install");
assert_eq!(InstallOperationV1::Upgrade.to_string(), "upgrade");
assert_eq!(InstallOperationV1::Rollback.to_string(), "rollback");
assert_eq!(InstallDecisionV1::Blocked.to_string(), "blocked");
assert_eq!(InstallDecisionV1::InstallPlanReady.to_string(), "install_plan_ready");
assert_eq!(InstallDecisionV1::InstalledVerified.to_string(), "installed_verified");
assert_eq!(InstallDecisionV1::RolledBack.to_string(), "rolled_back");
```

Test `serde_json::from_value::<InstallAuthorizationV1>` rejects every unknown, duplicate, missing, and wrong-type field; uppercase/short/long IDs, commit, and digests; zero/reversed/over-one-hour lifetimes; invalid operation; and any true authority flag. Test `validate_at` accepts exact inclusive issue/expiry boundaries and rejects outside them. Test `validate_for` binds operation, artifact commit, manifest digest, host digest, deployment-authorization digest, and performance-evidence digest.

Require `InstallFindingV1` to accept only the 15 `GI_*` codes and stable severity, reject arbitrary text, sort blocker before warning, and deduplicate equal findings. Require `InstallReportV1::derive` to permit `install_plan_ready` only for `Plan` with no mutations, `installed_verified` only for `Apply` with `mutations_performed: true`, `rolled_back` only for `Rollback`, and `blocked` whenever a blocker exists. Scan serialized values for prohibited execution/service/network fields and the retired product keyword.

- [ ] **Step 2: Push RED and verify the expected GitHub failure**

Commit and push only the new test:

```text
test: specify installation contracts
```

Require Script safety, Windows PowerShell safety, and eBPF to pass. Require Userspace to fail only because the `l2_loop_core` installation exports do not exist. Record the run ID and exact failure; do not implement until this RED is observed.

- [ ] **Step 3: Implement the minimum closed domain model**

Create `installation.rs`, export it from `lib.rs`, and implement these exact shapes with `#[serde(deny_unknown_fields)]` and private fields wherever invalid combinations would otherwise be constructible:

```rust
pub enum InstallOperationV1 { Install, Upgrade, Rollback }
pub enum InstallCommandV1 { Plan, Apply, Status, Rollback }
pub enum InstallDecisionV1 { Blocked, InstallPlanReady, InstalledVerified, RolledBack }

pub struct InstallAuthorizationV1 {
    pub schema_version: u16,
    pub authorization_id: String,
    pub transaction_id: String,
    pub operation: InstallOperationV1,
    pub artifact_commit_sha: String,
    pub bundle_manifest_sha256: String,
    pub host_identity_sha256: String,
    pub deployment_authorization_sha256: String,
    pub performance_evidence_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub service_enable: bool,
    pub service_start: bool,
    pub physical_attach: bool,
}
```

Define exact stable codes `GI_AUTH_SCHEMA`, `GI_AUTH_EXPIRED`, `GI_AUTH_HOST`, `GI_AUTH_ARTIFACT`, `GI_BUNDLE_INVALID`, `GI_DESTINATION_FOREIGN`, `GI_METADATA_UNSAFE`, `GI_TRANSACTION_CONFLICT`, `GI_WRITE_FAILED`, `GI_ROLLBACK_IDENTITY`, `GI_LAYOUT_VERIFY`, `GI_SERVICE_STATE`, `GI_SERVICE_LIFECYCLE`, `GI_PHYSICAL_BLOCKED`, and `GI_INTERNAL`. Use bounded errors without caller text. Centralize report derivation so adapters cannot select a positive decision.

- [ ] **Step 4: Push GREEN and require all five jobs**

Commit and push:

```text
feat: add installation domain contracts
```

Require formatting, Clippy, all tests, default-member check, eBPF, both script jobs, and Bundle to pass for the exact SHA. Confirm the artifact still has nine files/eight checksum entries at this task.

### Task 2: Implement Pure InstallPlanner and InstallService

**Files:**
- Create: `crates/l2-loop-agent/src/installation.rs`
- Create: `crates/l2-loop-agent/tests/installation_service.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Modify: `crates/l2-loop-agent/src/ports.rs`

**Interfaces:**
- Consumes: Task 1 contracts plus injected `InstallSourceReader`, `InstallStateReader`, `InstallTransactionWriter`, `HostIdentityReader`, and `Clock` ports.
- Produces: `InstallPlanner::plan`, `InstallService::{apply,status,rollback}` and ordered `InstallActionV1` values; no direct filesystem, process, network, or Aya call.

- [ ] **Step 1: Write RED orchestration tests**

Use recording fakes to require validate authorization → validate source bundle/documents → hash host identity → inspect fixed destinations → inspect prior journal → build deterministic plan. Assert `plan` never calls the writer; `apply` stops before writes on any identity mismatch; `rollback` enumerates completed actions in exact reverse order; and `status` is read-only. Require actions to be one of `CreateDirectory`, `InstallAbsentFile`, `UpgradeOwnedFile`, `VerifyInstalledObject`, or `RemoveOwnedEmptyDirectory`, with fixed roles rather than caller paths.

- [ ] **Step 2: Push RED**

Commit `test: specify installation orchestration`, push, and require Userspace to fail only on the missing service/ports while all safety/eBPF jobs pass.

- [ ] **Step 3: Implement the injected service**

Add narrow traits whose mutating methods accept validated role/action types instead of raw destination strings. Ensure all reads finish before `begin_transaction`; after begin, every completed write is durably journaled through the writer port. Map adapter failures to one stable `GI_*` finding without raw error content. The service never loops over discovered files and never invokes rollback after identity uncertainty.

- [ ] **Step 4: Push GREEN**

Commit `feat: add installation planner and service` and require the exact five-job green run.

### Task 3: Validate Bundle, Authorization, Host Binding, and Fixed Paths

**Files:**
- Create: `crates/l2-loop-agent/src/installation_layout.rs`
- Create: `crates/l2-loop-agent/tests/installation_layout.rs`
- Create: `crates/l2-loop-agent/tests/fixtures/installation/install-authorization-v1.json`
- Modify: `crates/l2-loop-agent/src/installation.rs`

**Interfaces:**
- Consumes: exact current bundle inventory, strict input documents, stable host-identity bytes, and Task 1 authorization.
- Produces: a finite `InstallLayoutV1` of source roles, fixed absolute destinations, digest, mode, uid/gid, and directory prerequisites.

- [ ] **Step 1: Write RED validation tests**

Require exactly the current nine-file artifact until Task 7, no nested/extra/linked/special objects, matching strict checksums/manifest, no-follow regular mode-`0600` authorization/document inputs, and SHA-256 binding for every source. Require the fixed destination constants from the design and exact modes: executable `0755`; object/manifest/checksums/unit/example `0644`; deployment/performance documents `0600`; restricted `/etc/l2-loop`, `/var/lib/l2-loop/{gates,evidence/v1,install/transactions}` `0700`; public parents `0755`. Reject any public root/prefix/destination environment or argument surface.

- [ ] **Step 2: Push RED**

Commit `test: specify installation layout validation`, push, and observe only the focused Userspace failure.

- [ ] **Step 3: Implement finite validation and layout derivation**

Reuse strict manifest/checksum readers from `linux/deployment_fs.rs` without exposing its staging-root mapping. Read only finite named inputs with size bounds and no-follow metadata. Hash raw stable host identity immediately, retain only its lowercase SHA-256, and zero/drop the raw buffer before producing the plan. Return fixed role enums and static destinations; never join an untrusted destination component.

- [ ] **Step 4: Push GREEN**

Commit `feat: validate installation sources and layout` and require all five jobs.

### Task 4: Implement the Ownership Journal and Crash State Machine

**Files:**
- Create: `crates/l2-loop-core/src/install_journal.rs`
- Create: `crates/l2-loop-core/tests/install_journal.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Modify: `crates/l2-loop-agent/src/installation.rs`

**Interfaces:**
- Consumes: Task 2 deterministic actions and Task 3 fixed roles.
- Produces: strict `InstallJournalV1`, `InstallJournalStateV1`, `InstallJournalEntryV1`, monotonic step transitions, and exact forward/reverse action eligibility.

- [ ] **Step 1: Write RED state-machine tests**

Require only `planned → prepared → applying → installed` and `applying|installed|failed → rolling_back → rolled_back`; any skipped, repeated with different content, decreasing-step, or terminal transition fails. Test strict serialization, exact current/prior identities, absent/prior-owned distinction, created-parent identity, backup identity, first-failure immutability, and deterministic entry order. Test every crash point returns either one exact next forward action or reverse actions for only durably completed steps.

- [ ] **Step 2: Push RED**

Commit `test: specify installation ownership journal`, push, and require the expected missing-contract Userspace failure.

- [ ] **Step 3: Implement checked journal transitions**

Keep all fields private and construct through checked methods. Store role/fixed path, intended digest/mode/uid/gid, sibling/backup basename, prior state, observed inode/device/link identity, created-parent identity, and stable failure code. Reject slashes/dot components in generated basenames. Never represent wildcard, recursive removal, or an unverified rollback action.

- [ ] **Step 4: Push GREEN**

Commit `feat: add durable installation journal model` and require all five jobs.

### Task 5: Implement the Linux No-Follow Transaction Adapter

**Files:**
- Create: `crates/l2-loop-agent/src/linux/installation_fs.rs`
- Create: `crates/l2-loop-agent/tests/installation_fs.rs`
- Create: `crates/l2-loop-agent/tests/installation_faults.rs`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Modify: `crates/l2-loop-agent/src/ports.rs`

**Interfaces:**
- Consumes: only Task 2 validated actions and Task 4 journal transitions.
- Produces: Linux implementations using directory file descriptors, no-follow opens, sibling exclusive files, fsync, atomic rename, fresh identity verification, and exact rollback.

- [ ] **Step 1: Write RED filesystem and fault tests**

Under generated temporary roots through an internal test adapter, cover absent install, exact prior-owned upgrade, foreign/unjournaled refusal, symlink/hardlink/FIFO/socket/device refusal, unexpected uid/gid/mode/inode change, nonempty created directory, and unsupported ACL/xattr/immutable/capability/security-label state. Inject one failure at each create, write, ownership, mode, hash, file sync, backup rename, final rename, directory sync, journal sync/move, verify, and rollback operation; assert the exact durable state and no unrelated path mutation.

- [ ] **Step 2: Push RED**

Commit `test: specify transactional installation filesystem`, push, and require only focused Userspace failures.

- [ ] **Step 3: Implement safe filesystem operations**

Use directory descriptors and `O_NOFOLLOW|O_CLOEXEC`; verify regular type and link count one; create siblings with `O_CREAT|O_EXCL`; set exact root ownership/mode; stream-copy and hash; sync file before rename and directory after each namespace change. Bootstrap the journal only at `/var/lib/.l2-loop-install-<transaction-id>`, then atomically move it to the fixed transaction root. Roll back in reverse only while every current identity matches. Refuse enforcing SELinux or unsupported metadata until a later reviewed adapter exists.

- [ ] **Step 4: Push GREEN**

Commit `feat: add transactional Linux installer filesystem` and require all five jobs.

### Task 6: Add the Separate l2-loop-install CLI

**Files:**
- Create: `crates/l2-loop-agent/src/bin/install.rs`
- Create: `crates/l2-loop-agent/src/installation_cli.rs`
- Create: `crates/l2-loop-agent/tests/installation_cli.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Modify: `crates/l2-loop-agent/Cargo.toml`

**Interfaces:**
- Consumes: Task 2 service and Task 5 Linux adapter.
- Produces: `l2-loop-install plan|apply|status|rollback`, deterministic text/JSON, and exit codes 0/1/2/4.

- [ ] **Step 1: Write RED CLI tests**

Test exact command grammar from the design, required arguments, lowercase transaction ID, `--json` rendering parity, one-megabyte cap, stable finding order, and exit-code mapping. Reject root/prefix/destination/interface/service/network/force/repair flags and environment aliases. Assert `plan/status` cannot construct a writer, `apply/rollback` require effective root plus exact authorization, and help/output contain no arbitrary source path or prohibited private field.

- [ ] **Step 2: Push RED**

Commit `test: specify installation CLI`, push, and require the expected missing-binary/API Userspace failure.

- [ ] **Step 3: Implement bounded argument parsing and rendering**

Follow the existing deploycheck binary style without adding a general shell command builder. Construct production adapters only for `apply/rollback`; keep destination constants internal. Convert usage to 2, trustworthy blocked reports to 4, successful declared terminal states to 0, and bounded internal/I/O failures to 1.

- [ ] **Step 4: Push GREEN**

Commit `feat: add bounded installation CLI` and require all five jobs. The Bundle job may compile the binary but must not package it until Task 7.

### Task 7: Harden Dependencies and Expand the Deterministic MUSL Bundle

**Files:**
- Create: `.cargo/audit.toml`
- Modify: `.github/workflows/ci.yml`
- Modify: `xtask/src/bundle.rs`
- Modify: `xtask/src/main.rs`
- Modify: `xtask/tests/bundle_manifest.rs`
- Modify: `crates/l2-loop-agent/tests/deployment_layout.rs`
- Modify: `scripts/verify-deployment-gates.ps1`
- Modify: `scripts/tests/verify-deployment-gates.Tests.ps1`
- Modify: `docs/development.md`

**Interfaces:**
- Consumes: Task 6 MUSL binary and the exact GitHub SHA.
- Produces: ten top-level artifact files, nine checksum entries, manifest `installer` role, and a mandatory pinned advisory-policy job.

- [ ] **Step 1: Write RED packaging and policy tests**

Require `l2-loop-install` in the manifest/inventory, reject missing/extra/renamed installer roles, and assert exactly ten files/nine checksums. Extend both PowerShell variants to require `cargo install cargo-audit --version 0.22.2 --locked` followed by `cargo audit`; fail closed when the RustSec database is unavailable. Require `.cargo/audit.toml` to set `ignore = []`, `informational_warnings = []`, `severity_threshold = "none"`, database `fetch = true`, database `stale = false`, and yanked checking enabled. Reject `continue-on-error`, unpinned tool installation, `cargo audit fix`, or an ignored advisory. G.1 blocks all RustSec vulnerability advisories without turning unmaintained-crate notices into a new product gate.

- [ ] **Step 2: Push RED**

Commit `test: specify installer bundle and advisory gate`, push, and require Bundle plus both script jobs to fail for only the new expectations while Userspace/eBPF remain green.

- [ ] **Step 3: Implement deterministic packaging and advisory CI**

Pass the exact MUSL installer path to `cargo xtask bundle`, add its static role/digest, update fixed counts, and preserve flat regular-file inventory. Add the pinned `cargo-audit` 0.22.2 GitHub step with locked installation and the checked `.cargo/audit.toml`; record the advisory database revision in the job log and treat fetch/parse/audit failure as a failed job. Do not enable network compilation on test nodes or Dependabot-dependent logic.

- [ ] **Step 4: Push GREEN**

Commit `build: package installer and enforce advisories` and require all five jobs plus exact artifact SHA/inventory/checksums.

### Task 8: Build Generated-Root Install and Recovery Acceptance

**Files:**
- Create: `scripts/verify-installation.ps1`
- Create: `scripts/tests/verify-installation.Tests.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/development.md`

**Interfaces:**
- Consumes: exact Task 7 artifact plus injected/generated root, host identity, and fault selector.
- Produces: deterministic acceptance results for install, exact-owned upgrade, interruption, restart, rollback, foreign refusal, and residue without a public production-root override.

- [ ] **Step 1: Write RED PowerShell safety tests**

Require 32-lower-hex run/transaction IDs, generated roots beneath one exact temporary parent, checksum-first execution, fixed scenario names/counts, no SSH/systemctl/journalctl/ip/tc/bpftool/Aya/physical-interface command, exact path containment checks, registered cleanup before creation, and refusal of recursive deletion, wildcards, unresolved variables, symlinks, or identity disagreement. Include fault cases for every Task 5 boundary.

- [ ] **Step 2: Push RED**

Commit `test: specify generated installation acceptance`, push, and require only Script safety and Windows PowerShell safety to fail on the absent harness.

- [ ] **Step 3: Implement the generated-root harness**

Download/verify one exact artifact, invoke test-only injected-root entry points rather than a public CLI root option, generate strict one-hour authorization/documents, run fixed happy/fault/recovery scenarios, and compare all outside-root sentinel identities before/after. Cleanup only exact generated identities and report residue instead of widening deletion.

- [ ] **Step 4: Push GREEN**

Commit `test: accept transactional installation in generated root` and require all five jobs.

### Task 9: Add Separately Authorized Real Installation and systemd/journald Acceptance

**Files:**
- Create: `scripts/verify-real-install.ps1`
- Create: `scripts/tests/verify-real-install.Tests.ps1`
- Create: `scripts/verify-installed-service.ps1`
- Create: `scripts/tests/verify-installed-service.Tests.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/development.md`

**Interfaces:**
- Consumes: one exact Task 8 artifact, a short-lived real-install authorization, and a separate short-lived service-acceptance authorization.
- Produces: independent `installed_verified` and `service_verified` reports after fixed-path installation and bounded real systemd/journald lifecycle using generated namespace/veth only; the acceptance transaction is exactly rolled back at the end.

- [ ] **Step 1: Write RED static authorization/safety tests**

For `verify-real-install.ps1`, require exact artifact/host/install authorization, checksum verification, `l2-loop-install plan`, `apply`, `l2-loop-deploycheck installed`, and an exact authorized rollback after service acceptance; no installed command may run before `installed_verified`. For `verify-installed-service.ps1`, require a separate exact authorization, prior inactive/disabled unit, fresh network/eBPF baseline, `daemon-reload`, start without enable, root-only socket, generated namespace/veth names, bounded Unix requests, sanitized journal cursor records, injected stderr fallback, fixed two start/stop cycles, ten-second stop bound, exact cleanup, and final state restoration. Both report schemas use fixed fields and decisions; reject physical interface arguments, default-route discovery, enable, restart policy changes, package/sysctl/module/offload commands, broad process killing, and foreign BPF cleanup.

- [ ] **Step 2: Push RED**

Commit `test: specify installed service acceptance`, push, and require both script jobs to fail only because the harness is absent.

- [ ] **Step 3: Implement the bounded harness without running it on a node**

Implement the real-install harness as a fixed transaction wrapper: baseline, plan/apply, independent installed verification, invoke the separately authorized service harness, stop, exact rollback, and final baseline/residue comparison. Sequence service reads and exact commands; pre-register generated identities; use existing isolated daemon authorization; verify journald fields through a captured cursor and prohibited-field scan; stop on any prior service ownership, state, traffic, or BPF uncertainty. GitHub tests exercise only parser/static safety behavior and never invoke SSH or a node.

- [ ] **Step 4: Push GREEN and stop for node authorization**

Commit `test: add installed service acceptance harness` and require all five jobs. Do not connect to a node. Present the exact artifact SHA and requested mutations for explicit approval before real installation/service execution.

### Task 10: Add Installed Verification and Read-Only Physical Readiness

**Files:**
- Modify: `crates/l2-loop-core/src/deployment.rs`
- Modify: `crates/l2-loop-core/tests/deployment_contract.rs`
- Modify: `crates/l2-loop-agent/src/deployment.rs`
- Modify: `crates/l2-loop-agent/src/deployment_cli.rs`
- Modify: `crates/l2-loop-agent/src/bin/deploycheck.rs`
- Modify: `crates/l2-loop-agent/src/linux/deployment_fs.rs`
- Modify: `crates/l2-loop-agent/src/linux/deployment_platform.rs`
- Modify: `crates/l2-loop-agent/tests/deployment_cli.rs`
- Modify: `crates/l2-loop-agent/tests/deployment_platform.rs`
- Modify: `scripts/verify-deployment-gates.ps1`
- Modify: `scripts/tests/verify-deployment-gates.Tests.ps1`

**Interfaces:**
- Consumes: exact completed install journal, installed fixed layout, and separately authorized one-interface read-only collectors.
- Produces: `l2-loop-deploycheck installed` → `installed_verified`; later `inspect` → `physical_canary_ready` plus `executable: false` plan.

- [ ] **Step 1: Write RED command and identity tests**

Require `installed` to accept only `--json`, avoid all interface collectors, verify every journal/file/document identity and no competing transaction, and return `installed_verified` without a canary plan. For `inspect`, test exact name/ifindex/MAC hash/driver/PCI/namespace binding; physical/reserved/no-master/no-consumer state; empty native/generic XDP and TC; BTF/bpffs/memlock/kernel/capability/native-driver/queue/offload facts; stable pre/post identity; current performance evidence; privacy reductions; and every unavailable/occupied/changed blocker independently. Require `physical_canary_ready` only with `executable: false` and 15 minutes.

- [ ] **Step 2: Push RED**

Commit `test: specify installed and physical readiness gates`, push, and require focused Userspace/script failures only.

- [ ] **Step 3: Implement the two read-only gate paths**

Add `DeploymentCommandV1::Installed`, `DeploymentDecisionV1::InstalledVerified`, `DeploymentDecisionV1::PhysicalCanaryReady`, central derivation, exact journal-to-layout verification, and narrowly composed read-only Linux facts. The Task 9 service harness owns its separate strict `ServiceAcceptanceReportV1` JSON decision `service_verified`; deploycheck does not manufacture that evidence. Never enumerate a fallback interface or expose raw identity. Keep plan consumption absent from daemon/CLI/installer types and add static scans against attach/systemctl/netlink-write/Aya calls in deploycheck.

- [ ] **Step 4: Push GREEN and stop for inspection authorization**

Commit `feat: add installed and physical readiness checks` and require all five jobs. Run neither node installation nor physical inspection without new explicit authorization.

### Task 11: Final Security Audit, Documentation, and Canary Handoff

**Files:**
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`
- Modify: `docs/superpowers/specs/2026-08-14-single-interface-read-only-canary-preparation-design.md`
- Modify: `docs/superpowers/plans/2026-08-14-single-interface-read-only-canary-preparation.md`
- Modify: focused tests/scripts only when the audit first adds a reproducing RED test

**Interfaces:**
- Consumes: one final exact SHA, complete GitHub evidence, generated-root evidence, and any separately authorized real install/service/read-only-inspection evidence.
- Produces: an evidence-backed G.1 conclusion and either `physical_canary_ready` or an explicit blocker; never a physical attach.

- [x] **Step 1: Audit fail-closed boundaries and add RED regressions for findings**

Trace CLI → service → journal → Linux adapter and deploycheck → collectors. Search for destination/root/interface overrides, arbitrary shell construction, symlink following, unbounded input/output, recursive cleanup, unsupported metadata loss, service-manager calls from installer, attach capability from deploycheck, raw private fields, non-fail-closed errors, and stale/inherited authorization. Every real defect first receives one focused failing test committed as `test: cover G.1 audit finding` and verified RED in GitHub.

- [x] **Step 2: Fix only proven findings and require GREEN**

Implement the minimum fixes, commit `fix: close G.1 audit findings`, and require all five jobs. If no defect is found, do not create an empty code commit.

- [x] **Step 3: Correct product and operator documentation**

Document exact commands, four independent authorization gates, fixed paths, rollback/manual-review behavior, unsupported SELinux/metadata cases, no-enable/no-start default, evidence limits, and the strongest actually proven state. Explicitly state that G.1 does not execute a physical canary and does not make the product production-ready.

- [x] **Step 4: Complete exact-SHA acceptance and publish the decision**

Require five-job GitHub green, exact ten-file/nine-checksum artifact, generated-root acceptance, clean worktree, `HEAD == origin/main`, old-keyword absence, no active/generated residue, and unchanged existing network/eBPF identity. Count separately authorized node evidence only if it was actually run. Commit documentation as `docs: complete G.1 safety audit`, push, and report the exact evidence plus the next separately designed physical-canary step.

**Task 11 completion record:** Audit RED commit `b4da2f640d2e1a31674469ca7f93052dcf7a1ae5` activated the first privileged raced-destination regression in GitHub run `32003126244`. Variant RED commit `6f96ece2e117678106cf95109cf7fc0bb9efb4be` then proved both upgrade-backup and journal-directory overwrite paths in run `32005460992`. The complete expected-absent no-replace fix passed all five jobs, including exact bundle and generated-root acceptance, at commit `0141e521eabd893b4ca74c614292e387feaa95af` in run `32006013596`. No node, systemd, journald, physical interface, or live eBPF action was executed, so real `installed_verified`, `service_verified`, and `physical_canary_ready` remain unavailable. The final documentation commit must itself pass the same five-job workflow before the handoff is complete.

## Execution Checkpoints

- After every RED: record exact SHA, run ID, failing job/step, and why the failure proves the new test is active.
- After every GREEN: require all five jobs and exact SHA; never stack another code change on a failing run.
- After Tasks 4, 8, 9, and 10: perform an explicit safety-boundary review before continuing.
- Before Task 9 real-node execution and before Task 10 physical inspection: stop and request separate authorization with exact artifact, host, commands, mutations, and rollback scope.
- Physical eBPF attachment is outside this plan and always requires a new design and authorization.
