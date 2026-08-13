# Bond Observation Productization and Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the proven active-backup and 802.3ad implementations into an installable, systemd-managed, locally observable product whose journald, bounded evidence, CLI, rollback, compatibility, security, and exact GitHub artifact contracts are fully accepted.

**Architecture:** Keep detection and collection behavior unchanged while hardening the operational envelope around it. Finalize the one-open-warning publication rule, install only a checksum-bound fixed-layout bundle, validate real systemd/journald and restart recovery, exercise root-only CLI/evidence behavior, and publish a measured support matrix rather than inferring safety for untested hosts.

**Tech Stack:** Rust 2024, systemd, journald native socket, Unix domain control socket, versioned JSON evidence, SHA-256 manifests, GitHub Actions x86_64 MUSL artifacts, PowerShell installation/acceptance harnesses, Linux active-backup and 802.3ad bonds.

## Global Constraints

- Phase A and Phase B must be complete and green before final product acceptance; this plan must not redesign bond collection or detection thresholds.
- The daemon is continuously managed by systemd. CLI requests are read-only queries and never attach, sample, advance state, or create alerts.
- One continuing bond anomaly publishes exactly one warning summary. Revisions caused by escalation, member changes, topology changes, unavailable coverage, or cooldown are evidence-only. Closure may publish one informational lifecycle record.
- Production outputs are limited to journald JSON, `/var/lib/l2-loop/evidence/v1`, and the root-only Unix socket used by `l2-loopctl status/evidence`.
- Do not add Prometheus, Alertmanager, remote webhooks, telemetry export, email, or another monitoring platform.
- Installation may create only the reviewed fixed filesystem layout and systemd unit. It never edits network configuration, bond settings, sysctls, offloads, routes, addresses, firewall, OVS, bridge, or service dependencies.
- Uninstall/rollback removes only exact package-owned files and identity-confirmed collectors. It never recursively deletes an unresolved path or foreign BPF state.
- No real loop/storm generation is allowed on a business network. Destructive traffic scenarios run only in isolated lab topology or separately approved maintenance topology.
- Keep the passive claim boundary and explicitly label `storm` versus suspected/high-confidence external loop.
- Rust compile/test/format/lint and final bundling remain pinned GitHub Actions results for an exact SHA. Real-host runs consume only the checksum-verified artifact for that SHA.

---

## File Structure

- `incident_output.rs` owns the alert-publication policy and output-health truth.
- `alert.rs` owns bounded journald/stderr serialization only.
- `evidence_store.rs` retains atomic versioned storage/recovery/retention.
- `deployment.rs`, `deployment_fs.rs`, and `deployment_unit.rs` own fixed-layout readiness checks.
- `packaging/` contains deterministic service/config/install assets; scripts perform explicit install/rollback acceptance.
- CLI renderers remain calculation-free views of daemon responses.
- Host acceptance scripts are split between isolated destructive traffic tests and real observation-only canaries.

---

### Task 1: Enforce One Open Warning and One Optional Close Record

**Files:**
- Modify: `crates/l2-loop-agent/src/incident_output.rs`
- Modify: `crates/l2-loop-agent/src/alert.rs`
- Modify: `crates/l2-loop-agent/tests/alert_sink.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_incidents.rs`
- Modify: `crates/l2-loop-core/src/evidence.rs`
- Modify: `crates/l2-loop-core/tests/evidence_contract.rs`

**Interfaces:**
- Adds an explicit publication decision to each incident job; persistence still receives every accepted revision.
- `AlertSink::publish` remains unaware of incident history and publishes only jobs already approved by policy.

- [ ] **Step 1: Write RED publication-policy tests**

Require this exact decision model:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertPublication {
    OpenWarning,
    CloseInformation,
    EvidenceOnly,
}
```

For one event, require revision 1 anomaly to be `OpenWarning`; anomalous escalation, topology change, retained unavailable, and cooldown revisions to be `EvidenceOnly`; normal closure to be `CloseInformation`; and a later independent event to receive a new `OpenWarning`. Duplicate/replayed revision IDs publish nothing. Persistence precedes publication in every case.

Require the open JSON summary to contain schema, event ID, code, bond name/ifindex/mode, topology generation, state, aggregate PPS/B/s, member count, and `evidence_status`, with no member array or raw identity. `OpenWarning` always maps to journal priority 4 even when the evidence code itself is `storm_confirmed` or `external_loop_suspected`; `CloseInformation` maps to priority 6. The evidence revision retains its semantic `AlertCode::severity()` independently.

- [ ] **Step 2: Push RED**

Commit `test: specify one bond alert lifecycle`.

- [ ] **Step 3: Implement publication policy**

Set `AlertPublication` when the incident recorder creates the write job. Introduce `SanitizedAlertV2 { publication, bond fields, aggregate rates, evidence_status }`; derive journald priority from `publication`, not from the evidence revision severity. The worker always attempts evidence persistence, then calls the sink only for open/close. On persistence failure, the one open warning still publishes with `evidence_status=unavailable`; evidence-only revisions do not create fallback warning spam.

- [ ] **Step 4: Push GREEN**

Commit `feat: publish one warning per bond incident` and require incident, sink, evidence, and daemon tests green.

### Task 2: Finalize Deterministic Production Bundle and Fixed Configuration

**Files:**
- Create: `packaging/bond-observation-v1.example.json`
- Create: `packaging/install-layout-v1.json`
- Modify: `packaging/l2-loop.service`
- Modify: `xtask/src/bundle.rs`
- Modify: `xtask/tests/bundle_manifest.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/tests/verify-build-supply-chain.Tests.ps1`

**Interfaces:**
- Produces a deterministic bundle whose manifest/checksums bind daemon, CLI, checkers, eBPF object, service unit, example authorization, and install-layout contract.
- The example contains placeholders and cannot authorize a host by itself.

- [ ] **Step 1: Write RED inventory and manifest tests**

Require exact top-level regular-file inventory, lowercase SHA-256 for every payload, no symlink/hard-link/special/nested entry, exact commit/package/target/ABI, and digests for service/config/layout assets. The layout must include only:

```text
/usr/libexec/l2-loop/{l2-loopd,l2-loop-deploycheck,l2-loop-hostcheck,l2-loop-ebpf.o,manifest.json,SHA256SUMS}
/usr/bin/l2-loopctl
/usr/lib/systemd/system/l2-loop.service
/usr/share/doc/l2-loop/{bond-observation-v1.example.json,install-layout-v1.json}
/etc/l2-loop/bond-observation-v1.json
/var/lib/l2-loop/evidence/v1/
/run/l2-loop/{agent.sock,ownership/v1/}
/sys/fs/bpf/l2-loop/production/
```

Require root ownership, public assets `0644`, executables `0755`, config/evidence/runtime/ownership/pin parents `0700`, config and ownership records `0600`, and socket `0600`. Reject mutable Actions, network downloads during bundle construction, package installation, secret output, or an unbound local artifact.

- [ ] **Step 2: Push RED**

Commit `test: specify final bond product bundle`.

- [ ] **Step 3: Extend deterministic bundling and GREEN**

Teach `xtask bundle` the exact additional assets using required explicit arguments and finite inventory comparison. Keep the example invalid until an operator supplies exact name/ifindex/mode/SHA/times. Commit `build: package bond observation product` and require all CI jobs green.

### Task 3: Add Transactional Install, Upgrade, and Rollback Acceptance

**Files:**
- Create: `scripts/install-l2-loop.ps1`
- Create: `scripts/tests/install-l2-loop.Tests.ps1`
- Create: `scripts/verify-installed-l2-loop.ps1`
- Create: `scripts/tests/verify-installed-l2-loop.Tests.ps1`
- Modify: `crates/l2-loop-agent/src/linux/deployment_fs.rs`
- Modify: `crates/l2-loop-agent/tests/deployment_layout.rs`

**Interfaces:**
- Installer consumes one local checksum-verified bundle and one separately prepared valid authorization file.
- Produces only the fixed layout; does not start or enable the service until validation succeeds.

- [ ] **Step 1: Write RED safety and rollback tests**

Require exact absolute targets, no caller-selected destination root in production mode, no wildcard/recursive deletion, no shell-evaluated remote values, preflight checks before writes, same-filesystem temporary staging, fsync, no-replace first install, identity-bound replacement upgrade, and a rollback journal listing each exact path created/replaced.

Reject existing foreign files, symlinks, hard links, wrong owners/modes, occupied socket, unknown ownership/pin objects, invalid authorization, checksum/manifest mismatch, commit mismatch, service already active during upgrade, and downgrade without separate approval. Failure restores the exact previous package files and leaves the service state unchanged.

- [ ] **Step 2: Push RED**

Commit `test: specify transactional bond product installation` and require script safety to fail only for missing implementation.

- [ ] **Step 3: Implement installer and installed verifier**

Use native PowerShell/.NET file APIs and explicit path tables; do not construct `cmd /c`, shell pipelines, or broad delete commands. Create restricted directories before files, copy to exact sibling temporary files, verify digest/mode/owner, rename atomically, then run the read-only installed-layout checker. Service enable/start is a separate explicit operator step after success.

- [ ] **Step 4: Push GREEN**

Commit `build: install bond observation product transactionally` and require both PowerShell versions plus all existing jobs green.

### Task 4: Validate Real systemd and journald Lifecycle

**Files:**
- Create: `scripts/verify-systemd-journald.ps1`
- Create: `scripts/tests/verify-systemd-journald.Tests.ps1`
- Modify: `crates/l2-loop-agent/tests/deployment_unit.rs`
- Modify: `crates/l2-loop-agent/tests/deployment_service.rs`
- Modify: `docs/development.md`

**Interfaces:**
- Runs only on a separately authorized Linux test node with the exact installed artifact and bond authorization.
- Produces bounded evidence for daemon-reload, enable/start/stop/restart/crash/boot behavior and journal output.

- [ ] **Step 1: Write RED service-manager safety contract**

Require the exact unit name, fixed 10-second stop deadline, bounded command timeouts, capture of pre/post enabled/active state, and rollback to the original state. Reject changes to unrelated units, `daemon-reexec`, system-wide journal mutation/vacuum, package manager calls, network changes, and unbounded `journalctl -f`.

- [ ] **Step 2: Push RED**

Commit `test: specify systemd and journald acceptance`.

- [ ] **Step 3: Implement bounded lifecycle scenarios**

Run `systemd-analyze verify`, daemon-reload, explicit start, status query, clean stop, restart, injected process failure, recovery start, and boot-enabled verification where the test node permits reboot. Assert hardening properties and exact capabilities from the unit. Verify the daemon leaves forwarding untouched and exact owned cleanup completes on stop.

Generate alert transitions only in an isolated bond topology on the test node. Query journald by unit, `SYSLOG_IDENTIFIER`, exact event ID, and bounded time interval. Require one warning open record and one information close record, valid JSON fields, correct evidence status, no member array/private fields, and permanent stderr fallback behavior under the existing injected journal-send failure test.

- [ ] **Step 4: Push GREEN and run authorized host test**

Commit `test: verify systemd and journald operation`; require CI safety first, then separately authorize and run the real service lifecycle.

### Task 5: Complete CLI and Evidence Recovery Acceptance

**Files:**
- Modify: `crates/l2-loop-cli/src/render.rs`
- Modify: `crates/l2-loop-cli/tests/render.rs`
- Modify: `crates/l2-loop-cli/tests/evidence_cli.rs`
- Modify: `crates/l2-loop-cli/tests/evidence_render.rs`
- Modify: `crates/l2-loop-agent/tests/unix_transport.rs`
- Modify: `crates/l2-loop-agent/tests/evidence_retention.rs`
- Modify: `crates/l2-loop-agent/tests/evidence_store.rs`
- Create: `scripts/verify-bond-cli-evidence.ps1`
- Create: `scripts/tests/verify-bond-cli-evidence.Tests.ps1`

**Interfaces:**
- Verifies `status`, `evidence list`, and `evidence show` through the real root-only Unix socket and real store.
- Text and JSON are calculation-free renderings of the same versioned response.

- [ ] **Step 1: Write RED command/output tests**

Require:

```text
l2-loopctl status --interface bond0 [--json]
l2-loopctl evidence list --interface bond0 --limit 50 [--json]
l2-loopctl evidence show --id <32-lowercase-hex> [--json]
```

Status must show bond mode, topology generation, stabilization, aggregate 1/10/60-second PPS/B/s, expected/effective/healthy/failed/omitted member counts, member contributions, detection, active event, evidence store, queue, and alert sink health. Evidence list returns one row per bond event. Show returns bounded revisions and member facts. Reject member-name top-level queries, invalid IDs/cursors/limits, non-root socket access, oversized frames, partial frames, and request-time state changes.

- [ ] **Step 2: Push RED**

Commit `test: specify final bond CLI and evidence behavior`.

- [ ] **Step 3: Implement any missing render/protocol compatibility**

Keep protocol version 1 and use tagged evidence detail variants within it. Do not calculate rates/ratios or scan kernel maps from the CLI. Bound member display to 32 and clearly print omitted count and degraded coverage.

- [ ] **Step 4: Exercise store restart and retention**

Create/open/escalate/degrade/recover/close events, restart the daemon, and require byte-identical recovered detail/digest. Exercise 1 GiB, 1,000-event, 16-revision, 1 MiB revision, 16 MiB event, 30-day closed age, and `max(512 MiB, 5%)` reserve rules using injected filesystem accounting. Only complete closed indexed events may be deleted.

- [ ] **Step 5: Push GREEN**

Commit `feat: finalize bond CLI and evidence recovery`; require all socket/evidence/CLI jobs green.

### Task 6: Run the Final Isolation and Real-Canary Matrix

**Files:**
- Create: `scripts/verify-bond-product.ps1`
- Create: `scripts/tests/verify-bond-product.Tests.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/lib/IsolatedNames.psm1`

**Interfaces:**
- Orchestrates existing Phase A/Phase B scenarios without duplicating their implementation.
- Separates destructive isolated traffic tests from observation-only real canaries by an explicit mode and authorization gate.

- [ ] **Step 1: Write RED orchestration safety tests**

Require exact checksum/commit binding, finite scenario list, bounded runtime/output, cryptographic generated names for isolated resources, exact pre/post network/BPF/service snapshots, explicit stop conditions, and exact cleanup. Reject a mode that combines real interface selection with traffic generation, bond reconfiguration, link flap, or namespace cleanup commands.

- [ ] **Step 2: Push RED**

Commit `test: specify final bond product matrix`.

- [ ] **Step 3: Implement isolated destructive matrix**

Require all prior isolated scenarios plus active-backup 1/2/4 members, LACP 1/2/4 members, failover, collecting/distributing transition, aggregator change, member add/remove, rename, collision, partial read, counter reset, daemon restart, journald failure injection, evidence failure injection, BUM storm, cross-member loop relationship, recovery, shutdown, and exact zero residue.

- [ ] **Step 4: Implement observation-only real matrix**

For each approved active-backup/LACP host, verify installed artifact/config, exact bond/member topology, empty/owned hooks, systemd health, continuous status, resource health, stop conditions, bounded duration, clean stop, exact rollback, and pre/post identity. Do not send test traffic or alter the bond.

- [ ] **Step 5: Push GREEN and execute in order**

Commit `test: verify complete bond observation product`. Require exact-SHA CI, then isolated matrix, then separately approved real canaries. Any real-host failure narrows the support matrix; it is never waived by a fixture result.

### Task 7: Security Audit, Compatibility Matrix, and Release Handoff

**Files:**
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`
- Create: `docs/bond-support-matrix.md`
- Modify: `docs/superpowers/specs/2026-08-13-bond-read-only-observation-design.md` only if implementation evidence proves a specification defect

**Interfaces:**
- Produces the reviewed release claim, exact artifact identity, measurable support matrix, and remaining-work boundary.

- [ ] **Step 1: Run final static safety scans**

Require zero new `XDP_DROP`, `TC_ACT_SHOT`, probe-send, policing, force/replace/adopt, network-configuration mutation, remote alert/metrics endpoint, raw packet/MAC/IP/fingerprint output, mutable Action, unpinned build source, caller-selected production root, wildcard cleanup, or shell-evaluated untrusted value. Verify capabilities, writable paths, socket/store/config modes, output bounds, queue bounds, and eBPF/Map ABI.

- [ ] **Step 2: Run independent code/security review**

Review trust boundaries for authorization expiry and SHA binding, namespace/ifindex reuse, TOCTOU during topology reads/attach/detach, foreign-hook collision, ownership journal symlink/hard-link handling, Map identity, counter overflow, partial coverage, incident de-duplication, evidence recovery/retention, journald injection, socket privilege, shutdown deadlines, installer rollback, and secret/privacy exposure.

- [ ] **Step 3: Publish measured compatibility data**

For every supported row record distribution, kernel, architecture, bond mode, member count, NIC, driver/firmware, native/generic XDP mode, TC hook, queues, CPU/IRQ affinity, frame sizes, achieved PPS/B/s, forwarding loss, missed/degraded samples, daemon CPU/RSS, systemd/journald result, evidence/CLI result, cleanup, and artifact SHA. Untested rows are `unsupported`, not assumed compatible.

- [ ] **Step 4: Verify the exact final artifact and residue**

Download the non-expired GitHub artifact, verify every `SHA256SUMS` entry, exact top-level inventory, manifest SHA/targets/ABI/assets, and absence of special/nested files. Prove no generated namespace/veth/bond, acceptance root, ownership record, pin, program, map, filter, socket, temporary install file, or stopped test service state remains.

- [ ] **Step 5: Commit final documentation and require full green**

Commit:

```text
docs: finalize bond observation product
```

Require `HEAD == origin/main`, clean worktree, exact CI SHA/status, exact artifact name/digest, all isolated scenarios, all authorized support-matrix canaries, and independent residue audit.

- [ ] **Step 6: Report the precise completion claim**

The allowed claim is: the product continuously and passively detects BUM storms and can raise suspected/high-confidence external-loop incidents for explicitly supported active-backup and 802.3ad bond combinations, with one bond-level warning, bounded local evidence, and root-only CLI queries. Do not claim active confirmation, prevention, mitigation, bridge/OVS path diagnosis, NIC/softnet root-cause analysis, DDoS protection, monitoring-platform integration, or universal Linux/NIC compatibility.
