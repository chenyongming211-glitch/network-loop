# Bond 802.3ad/LACP Multi-Member Observation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the proven active-backup bond observer to aggregate every effective collecting/distributing member of an explicitly authorized 802.3ad/LACP bond, including one-, two-, and four-member operation, while retaining one bond-level incident and alert.

**Architecture:** Enrich the shared bond topology with strict LACP aggregator and per-direction eligibility facts, then let the existing reconciler converge the collector set transactionally. Aggregate all eligible member counters without content de-duplication, retain bounded per-member contribution evidence, and add privacy-reduced cross-member return relationships that can strengthen a passive loop conclusion.

**Tech Stack:** Rust 2024, serde, rtnetlink, bounded `/proc/net/bonding` parsing, Aya XDP/TC collectors, existing 1 Hz rate/baseline/detection engine, bounded fingerprint LRU, GitHub Actions, Linux network namespaces and Linux bonding 802.3ad tests.

## Global Constraints

- Phase A must be complete and green before this plan starts; do not duplicate or fork its collector, sampler, incident, or evidence implementations.
- Support a dynamic 1–256 member set. Explicitly test one, two, and four members; never encode `4` as a product limit.
- The bond master remains the only configuration, status, incident, evidence-list, and alert subject.
- XDP/TC attach only to physical members. Never attach a duplicate traffic collector to the bond master.
- Ingress aggregation includes collecting members; egress aggregation includes distributing members. Directional transition is represented explicitly.
- Equal frames on different members are not removed from PPS/B/s totals. They may be the amplification evidence the product exists to observe.
- Missing or failed expected coverage makes the bond degraded; it cannot be substituted with zero or used to clear an event.
- Aggregator/member changes create one topology generation and exactly two successful 1 Hz stabilization samples.
- Retain the passive claim boundary: `storm`, `external_loop_suspected`, and `external_loop_high_confidence`; never add `confirmed_loop` without the separate probe delivery.
- Keep all no-replace, exact-ownership, fail-open, bounded-output, root-only CLI, and no-monitoring-platform constraints from Phase A.
- Rust verification remains exact-SHA GitHub CI; real LACP tests require separate host authorization and must not reconfigure a business bond.

---

## File Structure

- Extend `l2-loop-core/src/bond.rs` with LACP aggregator/member state; do not create a second bond domain model.
- Extend `l2-loop-agent/src/linux/bond.rs` for pure strict LACP parsing.
- Extend `bond_topology.rs` for current-kernel aggregation and directional eligibility.
- Reuse `bond_control.rs` for desired collector set reconciliation.
- Extend `bond_observation.rs` for checked multi-member sums and partial-coverage health.
- Add `bond_fingerprint.rs` for bounded privacy-reduced cross-member relationships, keeping fingerprint identity internal.
- Reuse evidence schema 2 and CLI bond view from Phase A.

---

### Task 1: Freeze LACP Aggregator and Directional Eligibility Contracts

**Files:**
- Modify: `crates/l2-loop-core/src/bond.rs`
- Modify: `crates/l2-loop-core/src/authorization.rs`
- Modify: `crates/l2-loop-core/tests/bond_contract.rs`
- Modify: `crates/l2-loop-core/tests/bond_authorization.rs`

**Interfaces:**
- Adds validated `LacpAggregatorId`, `LacpMemberState`, and directional eligibility to the existing `BondMember`.
- Enables `BondMode::Ieee8023ad` in `BondObservationAuthorizationV1` only after the model tests pass.

- [ ] **Step 1: Write RED domain tests**

Require these exact additions:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LacpAggregatorId(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LacpMemberState {
    pub aggregator_id: LacpAggregatorId,
    pub collecting: bool,
    pub distributing: bool,
    pub synchronized: bool,
}
```

Add `lacp: Option<LacpMemberState>` to `BondMember` and `active_aggregator: Option<LacpAggregatorId>` to `BondTopology`. Validate non-zero aggregator ID, LACP state only in 802.3ad mode, no LACP state in active-backup, eligibility equal to collecting/distributing for the active aggregator, and at least one direction eligible. Reject members from a foreign aggregator being marked effective.

- [ ] **Step 2: Write RED authorization tests**

Require 802.3ad authorization to validate with the same exact bond name/ifindex, artifact SHA, issue/expiry, and 24-hour canary bound. An authorization mode mismatch against discovered active-backup/LACP topology must return `BOND_MODE_MISMATCH` before any attach.

- [ ] **Step 3: Push RED**

Commit `test: specify LACP bond contracts`.

- [ ] **Step 4: Implement and push GREEN**

Commit `feat: add LACP bond domain contracts`; require all existing active-backup and isolated tests green.

### Task 2: Parse and Validate Strict 802.3ad Snapshots

**Files:**
- Modify: `crates/l2-loop-agent/src/linux/bond.rs`
- Modify: `crates/l2-loop-agent/src/linux/bond_topology.rs`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/8023ad-one.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/8023ad-four.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/8023ad-transition.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/8023ad-multiple-aggregators.txt`
- Modify: `crates/l2-loop-agent/tests/linux_fixtures.rs`
- Modify: `crates/l2-loop-agent/tests/bond_topology.rs`

**Interfaces:**
- Extends `parse_bond_snapshot` to map the exact kernel text format into the shared topology.
- Produces per-direction eligibility; no parser output may directly choose an attachment action.

- [ ] **Step 1: Write RED fixture tests**

Cover `Bonding Mode: IEEE 802.3ad Dynamic link aggregation`, active aggregator ID, Slave Interface blocks, MII status, Aggregator ID, and actor/partner churn/state fields. Require one-, two-, and four-member snapshots and a transition where a member is collecting but not distributing.

Reject missing/duplicate fields, zero/overflowing aggregator, no active aggregator, all members in a foreign aggregator, contradictory collecting/distributing facts, duplicate member, more than 256 members, member disappearance, and unbounded lines/file size. Errors use stable codes `BOND_LACP_MALFORMED`, `BOND_LACP_NO_AGGREGATOR`, `BOND_LACP_NO_EFFECTIVE_MEMBER`, and `BOND_LACP_AMBIGUOUS`.

- [ ] **Step 2: Push RED**

Commit `test: specify strict LACP topology parsing`.

- [ ] **Step 3: Implement strict parser state machine**

Parse line-by-line with an explicit current-member block; never use substring guessing across blocks. Compare parsed members with the rtnetlink link set and before/after bond identity. Canonicalize by ifindex only after validation.

- [ ] **Step 4: Push GREEN**

Commit `feat: discover LACP bond topology` and require active-backup regressions green.

### Task 3: Reconcile a Dynamic Directional Collector Set

**Files:**
- Modify: `crates/l2-loop-agent/src/bond_control.rs`
- Modify: `crates/l2-loop-agent/tests/bond_control.rs`
- Modify: `crates/l2-loop-agent/src/bond_attach.rs`
- Modify: `crates/l2-loop-agent/tests/bond_attach.rs`

**Interfaces:**
- Reuses `MemberCollectorDriver` and `ActiveBondSession`.
- Desired collector set is the union of ingress-eligible and egress-eligible member ifindexes; contribution eligibility remains directional.

- [ ] **Step 1: Write RED 1/2/4-member reconciliation tests**

Require initial atomic attach for every desired member, no reattach for unchanged topology, add-before-publish for a joining member, stop-count-before-detach for a leaving member, and one generation change for one semantic topology event. Test collecting-only, distributing-only, aggregator replacement, member flap, partial attach failure, foreign hook, cleanup mismatch, and restart recovery.

For four effective members assert:

```rust
assert_eq!(session.collectors.len(), 4);
assert_eq!(session.topology.topology_generation, 1);
assert_eq!(session.stabilization_remaining, 2);
```

If member 4 attach fails, collectors 1–3 may provide diagnostics but the bond must be degraded and no incomplete sample may advance assertion/recovery.

- [ ] **Step 2: Push RED**

Commit `test: specify LACP collector reconciliation`.

- [ ] **Step 3: Implement union-set transaction and push GREEN**

Use deterministic ifindex order for attach and reverse order for rollback. Publish the new immutable collector snapshot only after every required new collector verifies. Do not detach any session not proven owned by the current authorization and namespace identity.

Commit `feat: reconcile LACP member collectors` and require all jobs green.

### Task 4: Aggregate Directional Multi-Member Rates and Health

**Files:**
- Modify: `crates/l2-loop-agent/src/bond_observation.rs`
- Modify: `crates/l2-loop-agent/tests/bond_observation.rs`
- Modify: `crates/l2-loop-core/src/bond.rs`
- Modify: `crates/l2-loop-core/tests/bond_status.rs`

**Interfaces:**
- Ingress hook totals sum only collecting members; egress hook totals sum only distributing members.
- Produces complete `BondMemberStatus` contributions and an aggregate `ObservationHealth` decision.

- [ ] **Step 1: Write RED checked aggregation tests**

Use distinct counters for four members and require exact sums for totals, all classes, parse errors, packet/byte rates, and contribution permille. Test a collecting-only member contributes only ingress, a distributing-only member only egress, a standby/foreign-aggregator member neither, and all equal frames remain counted.

Test overflow, counter regression on one member, read failure, stale generation, missing expected collector, and member state changing during a read. Any expected-direction failure returns incomplete/degraded, retains bounded diagnostic member facts, substitutes no zero, and cannot clear an incident.

- [ ] **Step 2: Push RED**

Commit `test: specify LACP rate aggregation`.

- [ ] **Step 3: Implement one coherent sample transaction**

Read all member counters against one immutable topology/collector snapshot, then recheck its generation before publishing. On mismatch discard the complete sample. Use `u128` intermediates where sums/ratios can overflow `u64`, then checked-convert. Sort public members by largest byte contribution, then packet contribution, then ifindex.

- [ ] **Step 4: Push GREEN**

Commit `feat: aggregate LACP member rates` and require all rate/baseline/detection regressions green.

### Task 5: Add Bounded Cross-Member Relationship Evidence

**Files:**
- Create: `crates/l2-loop-agent/src/bond_fingerprint.rs`
- Create: `crates/l2-loop-agent/tests/bond_fingerprint.rs`
- Modify: `crates/l2-loop-agent/src/bond_observation.rs`
- Modify: `crates/l2-loop-core/src/fingerprint.rs`
- Modify: `crates/l2-loop-core/src/fingerprint_window.rs`
- Modify: `crates/l2-loop-core/src/detection.rs`
- Modify: `crates/l2-loop-core/tests/fingerprint_relationships.rs`
- Modify: `crates/l2-loop-core/tests/detection_signals.rs`

**Interfaces:**
- Keeps raw fingerprints internal and generation-scoped.
- Produces bounded `BondRelationshipReport` containing aggregate counts/ratios and at most 32 member-pair summaries.

- [ ] **Step 1: Write RED privacy and relationship tests**

Require relation classes `same_member`, `egress_a_to_ingress_b`, and `ingress_repeated_across_members`. Test deterministic selected/unselected frames, one unchanged frame egressing member A then ingressing member B, two-way amplification, empty evidence, LRU eviction, member-pair truncation, and topology-generation reset.

Scan all public JSON/text/evidence to prove no raw fingerprint, packet bytes, MAC/IP, Map key/path, or raw timestamp. A relationship across different bond ifindexes or generations must be impossible.

- [ ] **Step 2: Push RED**

Commit `test: specify cross-member loop relationships`.

- [ ] **Step 3: Implement bounded join and detection input**

Join only the already sampled fixed-size fingerprints from effective members, using a bounded 8,192-entry generation LRU and deterministic member-pair counters. Feed only sanitized counts/ratios into detection. Keep the existing thresholds unless a separate evidence-backed design change is approved; cross-member return strengthens suspected/high-confidence states but never creates `confirmed_loop`.

- [ ] **Step 4: Push GREEN**

Commit `feat: correlate LACP member relationships` and require privacy, detection, and isolated fingerprint tests green.

### Task 6: Preserve One Bond Incident Across LACP Changes

**Files:**
- Modify: `crates/l2-loop-agent/src/incident.rs`
- Modify: `crates/l2-loop-agent/tests/incident_recorder.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_incidents.rs`
- Modify: `crates/l2-loop-core/src/evidence.rs`
- Modify: `crates/l2-loop-core/tests/evidence_contract.rs`
- Modify: `crates/l2-loop-cli/tests/evidence_render.rs`

**Interfaces:**
- Incident identity remains bond name + bond ifindex; topology generation becomes revision evidence, not event identity.
- A topology transition appends at most one bounded revision when semantically useful and never opens per-member events.

- [ ] **Step 1: Write RED lifecycle tests**

Open one event under four-member LACP traffic, remove one member, change aggregator, degrade one collector, recover coverage, escalate confidence, enter cooldown, and close. Require the same `event_id` throughout, contiguous bounded revisions, zero member-level event IDs, no close during unavailable/stabilization, and correct latest member contribution snapshot.

- [ ] **Step 2: Push RED**

Commit `test: preserve incidents across LACP topology changes`.

- [ ] **Step 3: Implement topology-aware revision recording**

Separate stable incident subject generation from `topology_generation`: the bond authorization/ifindex identity owns the recorder, while topology generation is copied into each revision. A topology transition does not call `generation_ended`; only authorization end, exact detach, or daemon shutdown closes with the appropriate lifecycle reason.

- [ ] **Step 4: Push GREEN**

Commit `feat: retain one LACP bond incident` and require all incident/evidence tests green.

### Task 7: LACP Isolation, Four-Member, and Compatibility Acceptance

**Files:**
- Create: `scripts/verify-bond-lacp.ps1`
- Create: `scripts/tests/verify-bond-lacp.Tests.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`

**Interfaces:**
- Produces an isolated 1/2/4-member LACP matrix plus a separately authorized real-host observation-only canary.
- Records the exact kernel/NIC/driver/bond/attach combination; unsupported combinations remain unsupported.

- [ ] **Step 1: Write RED safety tests**

Require generated namespaces/bonds/veths only for creation, mode changes, link flaps, aggregator transitions, traffic generation, and cleanup. For a real host, forbid bond/member reconfiguration, link changes, traffic generation, package installation, sysctl/offload changes, wildcard cleanup, or selecting any interface not named in the signed authorization.

- [ ] **Step 2: Push RED**

Commit `test: specify LACP bond acceptance`.

- [ ] **Step 3: Implement isolated matrix**

Exercise one, two, and four effective members; collecting/distributing transitions; member join/leave; link flap; aggregator replacement; partial hook conflict; daemon restart; counter reset; controlled BUM storm; cross-member return; event recovery; exact cleanup; and pre/post identity. Require one bond warning for a continuing anomaly and zero member warnings.

- [ ] **Step 4: Measure resource scaling**

For 1/2/4 members record achieved PPS/B/s, collector and daemon CPU, RSS, map/program/pin count, sample latency, missed/degraded samples, forwarding loss, and cleanup. Fail the support candidate if forwarding changes, observation loses boundedness, CPU/RSS exceeds the approved Delivery G ceilings, or resource growth is inconsistent with the member count.

- [ ] **Step 5: Run the separately authorized real LACP canary**

Observe existing traffic only for the fixed bounded duration. Verify mode/aggregator/member identities before attach and continuously thereafter. Stop on identity, traffic-health, observation-health, ownership, cleanup, signal, or deadline conditions. Do not generate a loop on a business network.

- [ ] **Step 6: Push final docs and report Phase B boundary**

Commit `test: verify LACP bond observation`, require exact-SHA CI and acceptance evidence, and list the measured compatibility matrix. State explicitly that bridge/OVS path analysis, active confirmation, automatic mitigation, NIC/softnet correlation, and monitoring-platform metrics remain future work.
