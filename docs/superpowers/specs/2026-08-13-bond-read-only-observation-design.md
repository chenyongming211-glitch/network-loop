# Bond Read-Only Observation Design

**Date:** 2026-08-13
**Delivery:** H
**Status:** Approved design, implementation not started

## 1. Objective

Delivery H extends the existing isolated passive-observation product to accept a Linux bond master as the operator-visible monitoring subject in an explicitly authorized real-host read-only canary. The daemon discovers and observes the bond's physical member interfaces, aggregates their evidence under one logical bond identity, and emits at most one open alert for one continuing bond incident.

The shortest delivery order is:

1. active-backup bonds on a non-business or maintenance-window canary;
2. 802.3ad/LACP bonds with one or more active members, including four-member acceptance;
3. real systemd, journald, bounded evidence, CLI, compatibility, performance, and security acceptance.

The design supports a dynamic set of one through `N` bond members. Four members are an explicit acceptance case, not a compiled limit. The bond master is the sole configuration, status, incident, and alert subject; its members are internal collection points and evidence contributors.

This delivery remains passive. It does not transmit probes, modify bond or LACP configuration, change forwarding policy, shut a link, drop or police packets, capture packet payloads, or claim a cryptographically or actively confirmed loop. Its highest loop conclusion remains `external_loop_high_confidence`.

## 2. Selected Architecture

Three attachment models were considered:

1. attach only to the bond master;
2. treat the bond as the logical subject and its members as the data-plane collection points;
3. attach to both the master and members and de-duplicate observations afterward.

Delivery H selects model 2. Model 1 cannot be assumed to expose complete ingress and egress behavior across supported kernels, drivers, offloads, and bond modes. Model 3 creates a second observation path for the same traffic and makes rate correctness and incident interpretation unnecessarily ambiguous.

The operator always names the bond master:

```text
l2-loopctl status --interface bond0
l2-loopctl evidence list --interface bond0
```

Internally the daemon maintains:

```text
BondSubject
  bond namespace identity + ifindex + current name
  mode and topology_generation
  dynamic member identities
  per-direction eligibility and collector health
  bond-level rate, baseline, relationship, detection, and incident state
```

Member names are display attributes. Stable runtime identity is network-namespace identity plus ifindex. An interface rename updates presentation without opening another monitoring subject or incident.

## 3. Scope and Safety Boundary

### 3.1 In scope

- one explicitly authorized bond master per initial canary authorization;
- active-backup and 802.3ad/LACP modes;
- dynamic discovery of one through `N` member ports;
- member attachment lifecycle and identity-exact cleanup;
- 1 Hz member sampling and bond-level aggregation;
- bond-level dynamic baseline and passive detection;
- one bond-level incident with bounded member contribution evidence;
- JSON journald alert summaries;
- bounded local evidence and root-only Unix-socket CLI queries;
- systemd-managed continuous daemon operation;
- real-host read-only canary acceptance under separate operator authorization.

### 3.2 Out of scope

- balance-rr, balance-xor, broadcast, balance-tlb, balance-alb, or unknown bond modes;
- bridge or Open vSwitch forwarding-domain analysis;
- internal loop path reconstruction;
- active single-frame probes and a `confirmed_loop` state;
- NIC queue, softnet, IRQ, or driver-resource correlation;
- automatic mitigation, link shutdown, rate limiting, TTL rollback, or bond reconfiguration;
- Prometheus, Alertmanager, or another monitoring-platform integration;
- raw packets, PCAP, MAC/IP identities, or raw fingerprint publication.

Unsupported or ambiguous modes fail closed for observation: the daemon reports a stable degraded/blocking reason and does not guess an attachment matrix.

### 3.3 Meaning of read-only

Read-only means that the product does not change ordinary packet forwarding decisions and does not modify network configuration or transmit traffic. Loading and attaching an observation-only XDP/TC program changes kernel instrumentation state, so it is a controlled host mutation. Every attach therefore requires exact authorization, vacant or explicitly owned hook identity, post-attach verification, ownership journaling, and identity-exact rollback.

The eBPF programs remain fail-open. No XDP path may return `XDP_DROP`, and no TC path may return `TC_ACT_SHOT` or apply mutation/policing actions.

## 4. Bond Topology Model

### 4.1 Source of truth

The daemon uses rtnetlink to discover link identity, master/member relationships, operational state, and topology change events. Mode-specific bond information that rtnetlink does not provide reliably on the supported matrix is read from strict, bounded `/proc/net/bonding/<bond>` and sysfs attributes.

Discovery reads only the explicitly authorized bond and its direct members. It does not select the default-route interface, enumerate unrelated topology for attachment, or silently follow a bond into a bridge/OVS domain. A bridge/OVS master above the bond remains a separately designed future topology-analysis concern and must be surfaced truthfully in preflight.

The daemon also performs a complete reconciliation every five seconds. This repairs a missed notification or a state change that occurred during startup without turning polling into the primary event mechanism.

### 4.2 Canonical model

Each topology snapshot contains:

- bond namespace identity, ifindex, current name, mode, and administrative/operational state;
- ordered member identities and current names;
- member link state;
- active member for active-backup;
- aggregator identity and collecting/distributing eligibility for 802.3ad;
- expected and observed collector ownership per member and direction;
- a monotonically increasing in-memory `topology_generation`.

A topology generation changes when a fact that affects rate membership or relationship interpretation changes: member add/remove, ifindex replacement, active-member change, aggregator change, collecting/distributing change, or collector identity loss. A display-only rename does not change the generation.

### 4.3 Mode eligibility

For active-backup:

- exactly one unambiguous active member is eligible for aggregation;
- collection is attached to the active member;
- a missing, disappearing, or ambiguous active member makes observation degraded;
- backup members remain known but contribute no traffic rate.

For 802.3ad/LACP:

- ingress aggregation includes members eligible to collect;
- egress aggregation includes members eligible to distribute;
- all effective collecting/distributing members have the required observation hooks;
- members in a different aggregator or with ambiguous LACP state do not contribute and degrade health when they were expected to participate;
- a member may be eligible in only one direction during transition, and that directional state is represented explicitly rather than collapsed to a single boolean.

## 5. Collector Lifecycle

### 5.1 Reconciliation transaction

Every topology change is reconciled as a transaction:

1. obtain a stable topology snapshot and calculate the desired per-member hooks;
2. validate authorization, interface identity, mode eligibility, hook vacancy/ownership, kernel capability, and object identity;
3. attach and verify all newly required collectors;
4. publish the new topology generation and aggregation membership atomically to the sampler;
5. stop counting obsolete members;
6. detach only obsolete collectors proven to be owned by this daemon instance.

If step 3 is incomplete, existing verified collection continues where possible, but the bond reports `degraded`; it must not report complete health from partial coverage. The sampler never combines measurements taken under two topology generations.

### 5.2 Foreign programs and collisions

The daemon never replaces, chains behind, adopts, or detaches an unknown XDP/TC program. A foreign, occupied, ambiguous, or unverifiable hook is a stable degraded/blocking condition recorded in status, structured logging, and local evidence. Any future cooperative dispatcher design requires a separate approval.

### 5.3 Restart and shutdown

On restart, the daemon discovers current kernel topology and hook identities. It does not trust a previously persisted member list. Ownership records are evidence to validate, not permission to adopt a mismatched object.

On clean shutdown it detaches only hooks whose namespace, ifindex, attach point, program identity, pin identity, and ownership generation still match. Identity disagreement retains the object and emits a cleanup-health error instead of risking removal of another program.

## 6. Sampling, Aggregation, and De-duplication

### 6.1 One-second sampling

The existing daemon-owned 1 Hz sampler reads cumulative per-hook counters. For every successful member read it calculates checked packet and byte deltas from the previous endpoint in the same topology generation. It then sums eligible member deltas into one bond-level ingress and egress sample.

Rates retain the existing units and windows:

- packets per second (`pps`);
- bytes per second (`B/s`);
- fixed 1, 10, and 60 second windows;
- missed ticks are skipped, not replayed or fabricated.

All arithmetic is checked and bounded. A member counter regression, replacement, or reset invalidates that member's current delta; it never becomes a negative rate or a wrapped spike.

### 6.2 De-duplication rule

There is no master-level traffic collector, so a frame is not counted once at the bond master and again at its member. The product de-duplicates duplicate attachment ownership, duplicate sample endpoints, and repeated state transitions.

It deliberately does not content-de-duplicate equal frames seen on different members. A broadcast frame leaving one member and returning on another is potential loop evidence; removing it from the traffic total would hide the amplification being detected.

### 6.3 Partial reads

When an expected member cannot be read:

- available member data may be retained as diagnostic evidence;
- the bond observation becomes `degraded`;
- missing traffic is not substituted with zero;
- an already open incident cannot clear because of missing coverage;
- an incomplete sample cannot advance a trustworthy assertion or recovery counter.

### 6.4 Transition stabilization

An eligibility-affecting topology change creates a new `topology_generation`, resets rate endpoints and generation-scoped fingerprint relationships, and starts a two-sample stabilization period. The next two successful 1 Hz sampling windows are published as warming/transition evidence but cannot open a new rate incident.

An incident that was already open remains open during stabilization. The product does not treat the transition as recovery. After two complete successful windows, fixed severe-storm detection can operate immediately; the dynamic baseline resumes learning under the new topology and cannot reuse statistical samples from the previous generation.

## 7. Passive Relationship Evidence

Eligible frames retain the existing bounded sampled fingerprint contract. Raw fingerprints, keys, addresses, packet bytes, and timestamps never cross the kernel/user trust boundary into public output.

Bond aggregation adds privacy-reduced member relationships:

- same-member ingress/egress relation;
- egress on member A followed by ingress on member B;
- ingress observations repeated across members;
- bounded sampled packet/byte totals and dominant contribution ratios.

Relations are valid only when both observations belong to the same authorized bond and topology generation. No relation survives an active-member, aggregator, or effective-member-set change.

The public evidence identifies member interface name and ifindex because these are necessary local operational facts, but it does not disclose frame identity. Cross-member return is supporting evidence, not proof by itself; legitimate LACP distribution, mirrored traffic, and upstream behavior remain possible explanations.

## 8. Bond-Level Detection State Machine

Detection consumes only trustworthy bond-level samples and relationships. The semantic states are:

1. `normal` — no current anomaly;
2. `storm` — a BUM/rate storm is established, without a loop claim;
3. `external_loop_suspected` — a storm plus repeated return relationship is present;
4. `external_loop_high_confidence` — stronger cross-direction or cross-member amplification evidence is present;
5. `unavailable` / observation `degraded` — evidence coverage is insufficient for a reliable current conclusion.

The existing adaptive dynamic-baseline path and baseline-independent severe-startup path remain. Threshold constants are not made caller-selectable in this delivery. High PPS or B/s alone can establish `storm` but cannot establish a loop.

State assertion, clearing, and cooldown continue to require consecutive trustworthy observations. Missing member coverage, topology transition, or collector failure pauses those counters. It never clears an incident merely because data became unavailable.

Because no unique active probe is transmitted, Delivery H never emits `confirmed_loop`. Active single-frame probing remains a separately authorized future delivery.

## 9. One Bond, One Incident, One Open Alert

### 9.1 Incident identity

One authorized bond has at most one active incident. A transition from normal to an anomalous state creates one `event_id`. Escalation, topology change, contributor change, degraded retention, cooldown, and closure append immutable revisions to that same event.

The event remains keyed to the stable bond subject, not a member. A member failover or LACP redistribution cannot create one incident per member.

### 9.2 Alert publication

The first open revision publishes exactly one warning alert. Later open revisions are persisted but do not publish additional warning alerts. Closure may publish one informational lifecycle record with the same event ID; it is not a new alert. A later independent anomaly creates a new event and may publish a new warning.

The output worker preserves the current ordering: persist the revision first, then publish its sanitized summary. A full queue or persistence failure degrades output health but never changes forwarding or blocks the sampler. `evidence_status` truthfully reports `stored` or `unavailable`.

Production publication first attempts journald. A journald send failure permanently degrades the process to newline-delimited sanitized JSON on stderr for the remainder of that run. Status reports the configured and observed sink; it does not claim end-to-end journal retention.

### 9.3 Journald JSON

The open warning is a single JSON object containing bounded bond-level fields such as:

```json
{
  "schema": 2,
  "event_id": "0123456789abcdef0123456789abcdef",
  "code": "external_loop_suspected",
  "bond": "bond0",
  "bond_ifindex": 12,
  "bond_mode": "802.3ad",
  "topology_generation": 7,
  "state": "open",
  "pps": 930000,
  "bytes_per_second": 119040000,
  "member_count": 4,
  "evidence_status": "stored"
}
```

The alert contains no raw member array, packet payload, MAC/IP address, fingerprint, filesystem path, Map key, or unbounded string. Detailed member contribution remains in root-only evidence.

## 10. Evidence Schema and Retention

The existing production root remains `/var/lib/l2-loop/evidence/v1`. Its ownership, `0700`/`0600` modes, no-follow validation, same-parent temporary write, fsync, SHA-256 manifest, no-replace rename, recovery, and exact closed-event retention rules remain unchanged.

A new evidence schema version adds:

- bond identity, name, mode, and topology generation;
- aggregate ingress/egress PPS and B/s;
- aggregate BUM classification and passive detection state;
- member count, effective count, omitted count, and collector-health summary;
- bounded member contributions: name, ifindex, role/LACP state, direction eligibility, PPS, B/s, observation health, and contribution ratio;
- bounded privacy-reduced cross-member relationships;
- transition stabilization and degraded reason codes.

At most 32 member details are serialized in one public evidence view. Aggregation still includes every eligible member. If more than 32 exist, deterministic ordering selects the largest contributors with ifindex as a tie-breaker, and `omitted_member_count` makes truncation explicit.

Existing schema-1 evidence remains readable. New incidents use the new version; the daemon does not rewrite historical evidence in place.

## 11. CLI Contract

`l2-loopctl status --interface <bond>` displays:

- logical bond name/ifindex and mode;
- topology generation and stabilization state;
- expected, effective, healthy, failed, and omitted member counts;
- bond-level 1/10/60 second ingress/egress PPS and B/s;
- baseline, relationship, detection, incident, evidence-store, queue, and alert-sink health;
- a bounded member health/contribution table.

`l2-loopctl evidence list --interface <bond>` returns one entry per bond incident, never one per member. `l2-loopctl evidence show --id <event-id>` returns immutable revisions with aggregate evidence and bounded member contributions.

Text and `--json` render from the same sanitized response model. Requests are read-only: they never insert a sample, advance a baseline, rescan history into a new conclusion, create an incident, or publish an alert. The Unix control socket remains root-only `0600`.

## 12. systemd Operation

`l2-loopd` is a continuously running daemon managed by systemd. The existing hardened unit and fixed runtime/evidence paths remain the starting contract. Real-host acceptance must prove install, daemon-reload, start, status, stop, restart, crash recovery, bounded shutdown, and boot-start behavior.

The unit must retain only the capabilities required for the approved observation attach path and must not gain network-configuration or packet-transmission privileges merely for convenience. The daemon must start in a truthful degraded state if its evidence root, authorization, bond topology, or hook prerequisites are absent; it must not repair host permissions or network configuration automatically.

## 13. Delivery Plan

### 13.1 Phase A — active-backup

- generalize the existing strict active-backup parser into the canonical dynamic member model;
- authorize the bond master while binding every attachment to a discovered member identity;
- attach to and aggregate only the current active member;
- implement failover reconciliation, generation reset, and two-window stabilization;
- add fixture, namespace, and authorized real-host canary acceptance.

### 13.2 Phase B — 802.3ad/LACP

- parse and validate aggregator plus collecting/distributing state;
- reconcile all effective directional members;
- aggregate one, two, four, and more members without a fixed compiled count;
- test member add/remove, link flap, aggregator change, asymmetric transition, partial attach failure, and recovery;
- establish the supported kernel/driver/attach-mode matrix from measured behavior.

### 13.3 Phase C — product acceptance

- real systemd and journald lifecycle;
- one-warning alert de-duplication and one informational close record;
- bounded evidence permissions, atomicity, restart recovery, capacity, and retention;
- real Unix-socket status/evidence queries;
- forwarding invariance and foreign-hook collision refusal;
- performance/resource characterization for one, two, and four effective members;
- final security audit, reproducible GitHub artifact verification, and exact cleanup acceptance.

## 14. Verification Matrix

### 14.1 Unit and model tests

- active-backup with 1, 2, and 4 listed members and exactly one active member;
- LACP with 1, 2, and 4 effective members;
- unbounded input rejected safely before allocation or parsing abuse;
- malformed, missing, duplicate, stale, and ambiguous member facts;
- per-direction collecting/distributing eligibility;
- topology-generation changes and rename non-change;
- checked aggregation, counter reset, overflow, partial read, and deterministic 32-member truncation;
- one incident identity across member changes and exactly one open-warning decision.

### 14.2 Isolated Linux integration

- dynamic member add/remove and interface rename;
- active-backup failover with two stabilization windows and no false open/close;
- LACP-equivalent multi-member fixtures plus target-kernel bond tests where available;
- attachment collision, identity replacement, rollback failure, daemon restart, and exact cleanup;
- traffic continues through every observation and output failure path.

### 14.3 Controlled loop/storm acceptance

Only an isolated lab topology or explicitly approved maintenance window may generate a loop or high-rate broadcast traffic. Acceptance proves:

- a BUM storm reaches `storm` without being mislabeled as confirmed loop;
- cross-member return evidence can reach suspected/high-confidence states;
- one continuing bond anomaly emits one warning alert;
- evidence identifies contributing members without exposing raw frame identity;
- stopping the storm closes the same event correctly;
- failover, member loss, or LACP redistribution alone does not create a false alert;
- daemon or output failure does not interrupt ordinary forwarding.

### 14.4 Compatibility and performance record

Every real-host result records kernel, bond mode, member count, NIC, driver/firmware, XDP attach mode, TC attach point, queue count, CPU/IRQ affinity, frame size, achieved PPS, lost samples, collector CPU, daemon RSS, and observed forwarding impact. A combination not in the measured support matrix remains unsupported rather than inferred safe.

## 15. Failure Semantics

- Unsupported bond mode: refuse observation with a stable code.
- No unambiguous active member: degraded, no trustworthy current sample.
- Incomplete LACP eligibility: retain available diagnostics, mark degraded, do not clear an incident.
- Foreign or unknown hook: do not replace or detach it.
- Counter regression or identity change: invalidate the affected generation evidence.
- Missed netlink event: five-second reconciliation repairs desired state and advances topology generation when required.
- Evidence persistence failure: emit sanitized alert with `evidence_status=unavailable`, degrade output health, preserve forwarding.
- Journald failure: use permanent stderr JSON fallback for that process run.
- Output queue full: count the drop and expose health; never block sampling or forwarding.
- Shutdown cleanup identity mismatch: retain the questionable object and report it.

## 16. Decisions Frozen by This Design

1. Both active-backup and 802.3ad/LACP are required, delivered in that order.
2. A bond may have one through `N` members; four-member operation is explicitly tested.
3. The bond master is the only operator-visible monitoring and incident subject.
4. Member interfaces are the internal collection points; master/member double collection is forbidden.
5. Active-backup aggregates the unambiguous active member; LACP aggregates all effective directional members.
6. An eligibility-affecting change creates a new topology generation and two successful 1 Hz stabilization windows.
7. An already open incident is retained across transitions and missing coverage.
8. One continuing bond incident emits one warning summary; member changes only append bounded evidence revisions.
9. journald JSON, bounded local evidence, and root-only `status/evidence` remain the only output surfaces.
10. This is passive high-confidence detection, not active confirmation or automatic mitigation.

## 17. Exit Criteria

Delivery H is complete only when all automated tests pass, the approved active-backup and LACP real-host canaries pass on recorded supported combinations, the one-alert contract is demonstrated through journald and evidence recovery, forwarding invariance is measured, foreign-hook refusal and exact rollback are proven, and the final GitHub artifact is checksum-bound to the reviewed source.

Passing Delivery H means the product can be tested and used for continuous passive bond-level storm and high-confidence external-loop detection on the explicitly supported matrix. It does not authorize active probes, mitigation, or deployment to an untested kernel/NIC/bond combination.
