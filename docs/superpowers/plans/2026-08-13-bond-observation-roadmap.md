# Bond Observation Delivery Roadmap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sequence the approved bond read-only observation design into three independently reviewable deliveries that culminate in real active-backup and 802.3ad/LACP passive loop detection.

**Architecture:** Phase A establishes the shared bond subject, production member collector, topology-generation, aggregation, evidence, and daemon boundaries using active-backup first. Phase B reuses those boundaries for a dynamic LACP member set and cross-member relationships. Phase C freezes alert de-duplication, packaging, systemd/journald, CLI/evidence, real-host acceptance, security, and the measured compatibility matrix.

**Tech Stack:** Rust 2024, Aya/eBPF, rtnetlink, Linux bonding, systemd/journald, Unix sockets, versioned JSON evidence, PowerShell safety/acceptance harnesses, GitHub Actions MUSL artifacts.

## Global Constraints

- The governing design is `docs/superpowers/specs/2026-08-13-bond-read-only-observation-design.md`.
- Execute phases strictly A → B → C; do not start a later real-host acceptance before its prerequisites are green.
- Complete the remaining Delivery G packaging, generated-root harness, and final audit tasks before Phase C installation acceptance.
- One bond is one operator-visible subject, one active incident, and one warning for a continuing anomaly.
- Member count is dynamic; one, two, and four members are required acceptance cases.
- No probe, mitigation, DDoS feature, bridge/OVS analysis, monitoring-platform metrics, or unsupported compatibility claim is included.

---

### Task 1: Deliver Phase A — active-backup

**Files:**
- Execute: `docs/superpowers/plans/2026-08-13-bond-active-backup-observation.md`

**Interfaces:**
- Produces the shared bond identity, dynamic member collector, topology-generation, aggregation, evidence-schema, and continuous-daemon foundations.
- Produces a measured active-backup observation-only canary result.

- [ ] **Step 1: Complete all eight Phase A tasks in order**

Expected commits and CI evidence are defined in the Phase A plan. Do not mark this roadmap task complete until active-backup 1/2/4-member isolated tests and the separately authorized observation-only real canary pass.

- [ ] **Step 2: Freeze the Phase A review gate**

Require no regression in isolated veth behavior, no master-level collector, no foreign-hook replacement, two-window failover stabilization, one bond event, exact owned cleanup, and a clean exact-SHA artifact result.

### Task 2: Deliver Phase B — 802.3ad/LACP

**Files:**
- Execute: `docs/superpowers/plans/2026-08-13-bond-lacp-multi-member-observation.md`

**Interfaces:**
- Consumes Phase A boundaries unchanged.
- Produces collecting/distributing directional aggregation, four-member operation, cross-member relationships, and a measured LACP support result.

- [ ] **Step 1: Complete all seven Phase B tasks in order**

Do not introduce a second sampler, incident recorder, or evidence store. Require one-, two-, and four-member LACP isolation, partial-coverage degradation, aggregator transitions, and one bond-level incident.

- [ ] **Step 2: Freeze the Phase B review gate**

Require active-backup regression green, no content de-duplication of loop traffic, no raw fingerprint exposure, two-window stabilization, exact cleanup, resource-scaling evidence, and separately authorized observation-only real LACP canary results.

### Task 3: Deliver Phase C — productization and acceptance

**Files:**
- Execute: `docs/superpowers/plans/2026-08-13-bond-productization-acceptance.md`
- Finish remaining applicable tasks in: `docs/superpowers/plans/2026-08-13-production-read-only-deployment-gates.md`

**Interfaces:**
- Consumes green Phase A/Phase B implementations and the checksum-bound Delivery G bundle/checker foundation.
- Produces install/upgrade/rollback, systemd/journald, one-warning alerting, root-only CLI/evidence, final matrices, security review, and release claim.

- [ ] **Step 1: Complete the remaining Delivery G prerequisites**

Finish deterministic bundle extension, generated-root performance/packaging harness, and final Delivery G audit without relaxing its original safety boundary.

- [ ] **Step 2: Complete all seven Phase C tasks in order**

Require transactional install/rollback, bounded real service lifecycle, journald open/close records, schema-1 recovery plus schema-2 bond evidence, complete isolated matrix, observation-only real canaries, security review, compatibility matrix, and exact artifact verification.

- [ ] **Step 3: Freeze the release gate**

Release only measured active-backup and LACP rows. The final product claim must remain passive storm and suspected/high-confidence external-loop detection; active confirmation and mitigation remain separate future deliveries.

## Completion Accounting

- New Phase A tasks: 8.
- New Phase B tasks: 7.
- New Phase C tasks: 7.
- Total newly decomposed bond tasks: 22.
- Existing Delivery G prerequisites still referenced: its remaining bundle/harness/final-audit work, not duplicated here.

The 22 tasks are reviewer-sized delivery units. Every task contains multiple 2–5 minute RED/GREEN/commit checklist steps in its phase plan.
