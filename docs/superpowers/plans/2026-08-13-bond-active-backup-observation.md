# Bond Active-Backup Observation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a continuously running, explicitly authorized, passive read-only observer for one real Linux active-backup bond, while presenting the bond master as the single status, incident, and alert subject.

**Architecture:** Add a bond domain model and fixed authorization document, discover the complete active-backup topology through bounded Linux readers, and manage one verified collector on the current active member. Aggregate member evidence into one synthetic bond observation identified by bond ifindex plus topology generation; preserve an open incident across failover while rebuilding rate/fingerprint baselines and suppressing new assertions for two successful 1 Hz windows.

**Tech Stack:** Rust 2024, serde/serde_json, tokio, rtnetlink 0.21, netlink-packet-route 0.31, Aya 0.14, Linux bonding, XDP ingress, TC egress, Unix sockets, journald, GitHub Actions, PowerShell acceptance tests.

## Global Constraints

- Implement only active-backup behavior in this plan; the shared types may name 802.3ad, but selecting it returns `BOND_MODE_NOT_IMPLEMENTED` until the LACP plan is complete.
- The operator authorizes and queries exactly one bond master; no default-route, wildcard, first-interface, or unrelated-interface discovery is allowed.
- Member count is dynamic and bounded at input by `BOND_MAX_MEMBERS = 256`; there is no two-member assumption.
- The bond master is never a traffic collector. XDP ingress and TC egress attach only to the currently eligible physical member.
- Keep eBPF fail-open: no `XDP_DROP`, `TC_ACT_SHOT`, probe transmission, packet mutation, policing, link state change, bond configuration change, or sysctl/offload change.
- Do not replace, adopt, chain behind, or detach foreign/unknown XDP or TC programs.
- A topology change creates a new topology generation, clears generation-scoped rate/fingerprint history, and requires exactly two successful 1 Hz stabilization samples before a new assertion.
- An already open bond incident remains open through stabilization or missing coverage and cannot clear until trustworthy post-transition evidence satisfies the existing recovery contract.
- Preserve protocol version 1. Bump only observation/evidence schemas where the plan explicitly requires it and retain backward reading of evidence schema 1.
- Outputs remain JSON journald summaries, bounded local evidence, and root-only `l2-loopctl status/evidence`; do not add monitoring-platform metrics.
- Follow the repository's current release policy: Rust builds, formatting, linting, and tests run in pinned GitHub Actions for the exact pushed SHA; local checks are limited to non-compiling safety scans and `git diff --check`.
- Every RED commit must fail only the intended Userspace/script contract; every GREEN commit requires all configured CI jobs to pass before the next task.

---

## File Structure

- `crates/l2-loop-core/src/bond.rs`: validated bond identity, mode, member eligibility, topology, health, and bounded member-status types.
- `crates/l2-loop-core/src/authorization.rs`: strict fixed-path bond observation authorization schema and expiry rules.
- `crates/l2-loop-agent/src/linux/bond.rs`: strict `/proc/net/bonding` parsing only.
- `crates/l2-loop-agent/src/linux/bond_topology.rs`: rtnetlink/procfs composition and five-second reconciliation snapshots.
- `crates/l2-loop-agent/src/bond_attach.rs`: production collector ownership paths and member attach/detach transactions.
- `crates/l2-loop-agent/src/bond_control.rs`: active-backup desired-state reconciliation and lifecycle state.
- `crates/l2-loop-agent/src/bond_observation.rs`: member reads, checked aggregation, stabilization, and synthetic bond observations.
- `crates/l2-loop-agent/src/bond_authorization.rs`: bounded no-follow loading of the fixed authorization file.
- Existing `daemon.rs`, `main.rs`, `observation.rs`, `incident.rs`, and CLI renderers receive only integration changes; isolated control remains available for regression acceptance.

---

### Task 1: Freeze Bond Identity, Topology, and Authorization Contracts

**Files:**
- Create: `crates/l2-loop-core/src/bond.rs`
- Create: `crates/l2-loop-core/src/authorization.rs`
- Create: `crates/l2-loop-core/tests/bond_contract.rs`
- Create: `crates/l2-loop-core/tests/bond_authorization.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Modify: `crates/l2-loop-core/src/preflight.rs`

**Interfaces:**
- Produces `BondIdentity`, `BondMember`, `BondTopology`, `BondObservationHealth`, `BondMemberStatus`, and `BondObservationAuthorizationV1`.
- `BondTopology::new` is the only constructor allowed to establish a topology generation and validates unique non-zero member ifindexes.

- [ ] **Step 1: Write RED bond contract tests**

Require the following exact constants and public shapes:

```rust
pub const BOND_MAX_MEMBERS: usize = 256;
pub const BOND_PUBLIC_MEMBER_LIMIT: usize = 32;
pub const BOND_STABILIZATION_SAMPLES: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BondXdpMode {
    Native,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BondMode {
    ActiveBackup,
    Ieee8023ad,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondIdentity {
    pub interface: InterfaceRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondMember {
    pub interface: InterfaceRef,
    pub link_up: bool,
    pub ingress_eligible: bool,
    pub egress_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondTopology {
    pub bond: InterfaceRef,
    pub mode: BondMode,
    pub members: Vec<BondMember>,
    pub topology_generation: u64,
}
```

Test zero bond/member ifindex, zero generation, empty or more than 256 members, duplicate names/ifindexes, bond also appearing as member, unsupported mode, active-backup with zero/multiple bidirectionally eligible members, and non-deterministic member order. Require sort-by-ifindex canonicalization and a public view that returns at most 32 members plus exact `omitted_member_count`.

- [ ] **Step 2: Write RED strict authorization tests**

Define `/etc/l2-loop/bond-observation-v1.json` as the only production authorization path and require:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondObservationAuthorizationV1 {
    pub schema_version: u16,
    pub authorization_id: String,
    pub artifact_commit_sha: String,
    pub bond_name: InterfaceName,
    pub bond_ifindex: u32,
    pub expected_mode: BondMode,
    pub xdp_mode: BondXdpMode,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}
```

Require schema 1, 32 lowercase hexadecimal authorization ID, 40 lowercase hexadecimal commit SHA, non-zero bond ifindex, active-backup mode, explicit native/generic XDP mode, inclusive validity interval, maximum 24-hour lifetime, and exact artifact binding. There is no automatic native-to-generic fallback: an unsupported requested mode blocks before mutation. Reject unknown/duplicate/missing fields and 802.3ad with stable `BOND_MODE_NOT_IMPLEMENTED` in this phase.

- [ ] **Step 3: Push RED and verify expected CI failure**

Commit:

```text
test: specify bond observation contracts
```

Require Userspace to fail only because the new module/types are absent. Existing eBPF, script safety, bundle, and isolated observation jobs must remain green.

- [ ] **Step 4: Implement the validated types and exports**

Move the existing `BondMode` declaration from `preflight.rs` into `bond.rs` and re-export it so current imports do not change. Implement `BondTopology::new` with checked bounds and deterministic sorting; implement `BondObservationAuthorizationV1::{validate_at,validate_for}` without filesystem access.

- [ ] **Step 5: Push GREEN**

Commit:

```text
feat: add bond observation domain contracts
```

Require the exact GitHub SHA to pass all jobs.

### Task 2: Generalize Strict Active-Backup Discovery

**Files:**
- Modify: `crates/l2-loop-agent/src/linux/bond.rs`
- Create: `crates/l2-loop-agent/src/linux/bond_topology.rs`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/active-backup-four.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/active-backup-renamed.txt`
- Modify: `crates/l2-loop-agent/tests/linux_fixtures.rs`
- Create: `crates/l2-loop-agent/tests/bond_topology.rs`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Modify: `crates/l2-loop-agent/src/ports.rs`

**Interfaces:**
- Consumes one authorized `BondIdentity` and only its direct member facts.
- Produces `DiscoveredBondTopology { topology: BondTopology, namespace_device: u64, namespace_inode: u64 }`.
- Adds the injected port `BondTopologySource::read(&mut self, bond: &BondIdentity) -> Result<DiscoveredBondTopology, PortError>`.

- [ ] **Step 1: Write RED parser tests for 1, 2, and 4 members**

Require `parse_bond_snapshot` to retain every member, resolve every name to current ifindex, and mark exactly the current active member as ingress/egress eligible. Add cases for `Currently Active Slave: None`, active not listed, disappeared member, duplicate member, malformed name, unsupported mode, more than 256 member stanzas, and member/bond ifindex collision.

Use an expected four-member assertion:

```rust
assert_eq!(topology.members.len(), 4);
assert_eq!(
    topology.members.iter().filter(|m| m.ingress_eligible && m.egress_eligible).count(),
    1
);
assert_eq!(topology.members[2].interface.name.as_str(), "eno3");
```

- [ ] **Step 2: Write RED composition and identity tests**

With injected rtnetlink/procfs data, prove the source checks the bond name/ifindex before and after reading `/proc/net/bonding/<name>`, obtains `/proc/self/ns/net` device/inode without following an alternate namespace, rejects a bridge/OVS master above the bond for this delivery, and never reads an unrelated link's addresses/routes. Rename with stable ifindex must update display name without inventing a new physical identity.

- [ ] **Step 3: Push RED**

Commit `test: specify active-backup topology discovery` and require only the new Userspace tests to fail.

- [ ] **Step 4: Implement bounded topology composition**

Keep pure text parsing in `bond.rs`. Put all Linux I/O in `bond_topology.rs`; use finite rtnetlink link dumps, a maximum 1 MiB bond snapshot, no-follow regular-file validation, and before/after identity comparison. Return stable codes `BOND_IDENTITY_CHANGED`, `BOND_TOPOLOGY_UNAVAILABLE`, `BOND_MEMBER_MISSING`, `BOND_ACTIVE_AMBIGUOUS`, and `BOND_UPPER_MASTER_UNSUPPORTED`.

- [ ] **Step 5: Push GREEN**

Commit `feat: discover active-backup bond topology` and require all jobs green.

### Task 3: Add Production Member Ownership and Exact Attach Transactions

**Files:**
- Create: `crates/l2-loop-agent/src/bond_attach.rs`
- Create: `crates/l2-loop-agent/tests/bond_attach.rs`
- Modify: `crates/l2-loop-agent/src/ownership.rs`
- Modify: `crates/l2-loop-agent/src/attach.rs`
- Modify: `crates/l2-loop-agent/src/ports.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`

**Interfaces:**
- Produces `CollectorKey { bond_ifindex, member_ifindex }`, `MemberAttachmentSession`, and `MemberCollectorDriver`.
- Reuses existing no-replace XDP/TC adapters, ABI validation, Map publication, and exact detach behavior.

- [ ] **Step 1: Write RED production path and transaction tests**

Freeze these paths:

```text
/run/l2-loop/ownership/v1/<bond-ifindex>-<member-ifindex>.json
/sys/fs/bpf/l2-loop/production/<bond-ifindex>/<member-ifindex>/
```

Require decimal non-zero ifindexes with no leading sign/whitespace, root-owned `0700` parents, `0600` no-follow ownership records, and exact namespace-device/inode, bond ifindex, member ifindex, topology generation, program IDs/tags/link IDs, TC identity, and Map IDs in the record. Reject symlink/hard-link/foreign ownership, stale ifindex reuse, and any cleanup identity mismatch.

Require attach order: revalidate topology member, raise memlock, load/validate ABI, initialize dependent Map entries, attach the explicitly authorized native or generic XDP mode with no-replace semantics, verify XDP, attach explicit TC egress no-replace, verify TC, persist ownership, publish `IFACE_CONFIG` last, and reverify everything. Require reverse rollback for every injected failure.

- [ ] **Step 2: Push RED**

Commit `test: specify production member attachment` and require the intended Userspace failures only.

- [ ] **Step 3: Extract shared attach machinery without weakening isolation**

Refactor the existing transaction around a validated scope:

```rust
pub enum AttachmentScope {
    Isolated { run_id: RunId },
    BondMember { key: CollectorKey, namespace_device: u64, namespace_inode: u64 },
}

pub trait MemberCollectorDriver: Send {
    fn attach_member(
        &mut self,
        subject: &BondIdentity,
        member: &BondMember,
        topology_generation: u64,
    ) -> Result<MemberAttachmentSession, AttachmentError>;

    fn detach_member_exact(
        &mut self,
        session: &MemberAttachmentSession,
    ) -> Result<(), AttachmentError>;
}
```

The scope selects fixed roots and validation predicates; it never accepts caller-selected paths. Preserve all existing isolated rejection tests byte-for-byte.

- [ ] **Step 4: Push GREEN**

Commit `feat: attach owned bond member collectors` and require all jobs green, including isolated regressions.

### Task 4: Implement the Active-Backup Reconciler

**Files:**
- Create: `crates/l2-loop-agent/src/bond_control.rs`
- Create: `crates/l2-loop-agent/tests/bond_control.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`

**Interfaces:**
- Consumes `BondTopologySource`, `MemberCollectorDriver`, validated authorization, and monotonic/wall clocks.
- Produces one `ActiveBondSession` and immutable `BondCollectorSnapshot` values for the sampler.

- [ ] **Step 1: Write RED desired-state and failure tests**

Require:

```rust
pub struct ActiveBondSession {
    pub authorization: BondObservationAuthorizationV1,
    pub topology: BondTopology,
    pub collectors: BTreeMap<u32, MemberAttachmentSession>,
    pub stabilization_remaining: u8,
}

pub enum ReconcileOutcome {
    Unchanged,
    TopologyChanged { previous_generation: u64, current_generation: u64 },
    Degraded { code: &'static str },
}
```

Test startup, unchanged snapshots, active-member failover, member add/remove without active change, rename, link-down/no active, authorization expiry, foreign-hook collision, attach failure, detach identity mismatch, and daemon restart recovery. The new active collector must be attached and verified before it is published; the old member stops contributing before exact detach. A failed new attach retains any verified old diagnostics but publishes degraded coverage.

- [ ] **Step 2: Push RED**

Commit `test: specify active-backup reconciliation`.

- [ ] **Step 3: Implement atomic desired-state publication**

Keep reconciliation synchronous behind the existing `spawn_blocking` boundary. A netlink change notification marks topology dirty; additionally, a five-second monotonic deadline forces a full read. Compare semantic topology excluding display-only rename. On an eligibility change, increment generation with checked arithmetic, set `stabilization_remaining = 2`, and publish a complete immutable collector snapshot to sampling.

- [ ] **Step 4: Push GREEN**

Commit `feat: reconcile active-backup collectors` and require all jobs green.

### Task 5: Aggregate Member Counters into One Bond Observation

**Files:**
- Create: `crates/l2-loop-agent/src/bond_observation.rs`
- Create: `crates/l2-loop-agent/tests/bond_observation.rs`
- Modify: `crates/l2-loop-agent/src/observation.rs`
- Modify: `crates/l2-loop-agent/src/ports.rs`
- Modify: `crates/l2-loop-core/src/observation.rs`
- Modify: `crates/l2-loop-core/src/command.rs`

**Interfaces:**
- Produces `BondObservationReader::read_bond(&BondCollectorSnapshot, ObservationReadPurpose) -> Result<RawBondObservation, PortError>`.
- Produces `SamplingService::record_raw(subject, raw, stabilization_remaining)` so reading and rate/detection processing are independently testable.

- [ ] **Step 1: Write RED aggregation and stabilization tests**

Require checked addition of total, all six traffic classes, parse errors, and fingerprint summary for eligible collectors only. For active-backup, standby counters never contribute. Test counter reset/overflow, stale generation, missing active collector, partial read, mismatched roles, and name-only rename.

Require exactly this stabilization sequence after failover:

```text
tick 1 -> warming_up, remaining 1, cannot assert or clear
tick 2 -> warming_up, remaining 0, cannot assert or clear
tick 3 -> eligible for severe fixed-threshold assertion
```

The dynamic baseline starts empty in the new topology generation. An incident that was open before tick 1 remains active and does not receive a false close/generation-ended revision.

- [ ] **Step 2: Push RED**

Commit `test: specify bond aggregation and stabilization`.

- [ ] **Step 3: Extract the raw-recording seam and implement aggregation**

Refactor existing single-session `sample_tick_inner` so the unchanged isolated reader feeds the same `record_raw` path. Build a synthetic `RawObservation` whose ifindex is the bond ifindex and generation is `topology_generation`; never forge a member ownership record for this identity. Preserve the member contribution vector separately for status/evidence and cap public serialization at 32.

- [ ] **Step 4: Push GREEN**

Commit `feat: aggregate active-backup bond observations` and require isolated rate/baseline/detection tests plus new bond tests green.

### Task 6: Add Bond Status and Evidence Schema 2

**Files:**
- Modify: `crates/l2-loop-core/src/command.rs`
- Modify: `crates/l2-loop-core/src/evidence.rs`
- Modify: `crates/l2-loop-core/src/observation.rs`
- Modify: `crates/l2-loop-core/tests/evidence_contract.rs`
- Create: `crates/l2-loop-core/tests/bond_status.rs`
- Modify: `crates/l2-loop-agent/src/incident.rs`
- Modify: `crates/l2-loop-agent/src/evidence_store.rs`
- Modify: `crates/l2-loop-agent/tests/evidence_store.rs`
- Modify: `crates/l2-loop-cli/src/render.rs`
- Modify: `crates/l2-loop-cli/tests/evidence_render.rs`
- Modify: `crates/l2-loop-cli/tests/render.rs`

**Interfaces:**
- Adds optional bounded `bond` details to `InterfaceStatus` and introduces `IncidentRevisionV2`/`EvidenceDetailV2` while preserving schema-1 reads.
- `EvidenceDetail` becomes a tagged enum at the protocol boundary; protocol version remains 1.

- [ ] **Step 1: Write RED schema and rendering tests**

Require `BondStatusV1` to contain mode, topology generation, stabilization remaining, total/effective/healthy/failed/omitted counts, and at most 32 `BondMemberStatus` records. Each member record contains only name, ifindex, role/eligibility, PPS, B/s, health, and contribution permille.

Require evidence schema 2 to bind the bond identity and the member contribution snapshot to every new revision. Test deterministic largest-contribution-then-ifindex truncation, checked contribution calculation, no MAC/IP/payload/fingerprint/Map/path fields, and successful recovery/list/show of existing schema-1 fixtures.

- [ ] **Step 2: Push RED**

Commit `test: specify bond status and evidence schema`.

- [ ] **Step 3: Implement versioned evidence without rewriting history**

Keep the existing on-disk `v1` root and manifest atomicity/retention limits. Dispatch each revision by its embedded schema version, validate it before indexing, and expose a common bounded summary. New bond events write schema 2; isolated sessions may continue writing schema 1 until migrated. Render text and JSON from the same response model.

- [ ] **Step 4: Push GREEN**

Commit `feat: expose bond status and bounded evidence` and require all jobs green.

### Task 7: Wire Fixed Authorization into the Continuous Daemon

**Files:**
- Create: `crates/l2-loop-agent/src/bond_authorization.rs`
- Create: `crates/l2-loop-agent/tests/bond_authorization.rs`
- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_dispatch.rs`
- Create: `crates/l2-loop-agent/tests/daemon_bond.rs`
- Modify: `packaging/l2-loop.service`

**Interfaces:**
- Adds `BondControl` alongside isolated acceptance control; production startup consumes only the fixed authorization file.
- `observe/status` routes by exact active subject identity and never attaches on a CLI request.

- [ ] **Step 1: Write RED loader, daemon, and shutdown tests**

Require no-follow root-owned `0600` authorization loading, bounded 64 KiB JSON, exact artifact SHA from the installed manifest, and fail-closed expiry handling. Prove daemon startup performs preflight/reconciliation before sampling, samples once per second with missed ticks skipped, reconciles immediately on dirty notification and at least every five seconds, and exact-detaches owned collectors on SIGTERM within the existing ten-second systemd timeout.

Prove `l2-loopctl status --interface bond0` and `evidence` only query the socket. A request never attaches, advances sampling, creates an incident, or reloads authorization. A request for a member name returns session-not-found rather than exposing it as a top-level subject.

- [ ] **Step 2: Push RED**

Commit `test: specify continuous bond daemon control`.

- [ ] **Step 3: Implement daemon assembly**

Add an optional `Arc<Mutex<Box<dyn BondControl>>>` to `DaemonDispatcher`, and make the sampling loop call `reconcile_if_due` before `sample_tick`. Keep isolated acceptance control behind its existing explicit commands. When authorization is missing/invalid/expired, start the socket and report a bounded degraded status if a subject can be identified safely; never create or repair the file.

Update the unit only for the fixed authorization read path and production ownership/pin roots. Do not add shell wrappers, network-online dependency, automatic bond mutation, or broad writable paths.

- [ ] **Step 4: Push GREEN**

Commit `feat: run active-backup bond observation continuously` and require all jobs green.

### Task 8: Isolated and Authorized Active-Backup Acceptance

**Files:**
- Create: `scripts/verify-bond-active-backup.ps1`
- Create: `scripts/tests/verify-bond-active-backup.Tests.ps1`
- Modify: `scripts/lib/IsolatedNames.psm1`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`

**Interfaces:**
- Produces reproducible isolated bond scenarios and a separately gated real-host canary procedure.
- Consumes only a checksum-verified GitHub artifact and an explicit authorization document naming one bond master.

- [ ] **Step 1: Write RED script safety contract**

Require cryptographically generated namespace/veth/bond names for isolated tests, exact cleanup identities, bounded loops/timeouts/output, pre/post network and BPF snapshots, and explicit canary parameters for the real host. Reject default-route discovery, wildcard interface selection, physical traffic generation, package installation, sysctl/offload/bond-mode mutation on the real canary, broad process killing, wildcard deletion, and any loop/storm generation outside the isolated namespace.

- [ ] **Step 2: Push RED**

Commit `test: specify active-backup bond acceptance` and require only script-safety jobs to fail.

- [ ] **Step 3: Implement isolated scenarios**

Create generated active-backup bonds covering one, two, and four members; active failover; member add/remove; rename; link loss; counter continuity; collector collision fixture; daemon restart; evidence restart recovery; and exact cleanup. Generate a controlled BUM storm only inside the namespace and prove one bond event, no member event, correct active-member evidence, and no false alert on failover alone.

- [ ] **Step 4: Add the separately authorized real-canary procedure**

The real procedure is read-only except for owned observation attachments and must require a maintenance window, exact bond name/ifindex/mode, empty/owned hooks, verified artifact/config, operator start confirmation, fixed maximum duration, live health stop conditions, and exact rollback. It does not generate a loop or storm on the real network.

- [ ] **Step 5: Push GREEN and run acceptance in order**

Commit `test: verify active-backup bond observation`. Require full CI, then isolated acceptance, then the explicitly approved real canary. Record kernel, bond member count, NIC/driver, attach mode, traffic rates, CPU/RSS, health, cleanup, and pre/post identity.

- [ ] **Step 6: Report Phase A completion boundary**

Report active-backup passive observation as supported only for measured combinations. State that 802.3ad/LACP, cross-member relationship analysis, active confirmation, mitigation, monitoring-platform metrics, and untested kernel/NIC combinations remain unsupported.
