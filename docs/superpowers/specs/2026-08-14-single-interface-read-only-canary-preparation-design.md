# Real Installation and Single-Interface Read-Only Canary Preparation Design

**Date:** 2026-08-14
**Delivery:** G.1
**Status:** Approved design, implementation started

## 1. Objective

Delivery G.1 closes the gap between the generated-root evidence produced by Delivery G and a future, separately authorized read-only canary on one reserved physical port. It adds a deterministic real-installation transaction, exact ownership and rollback records, real systemd/journald lifecycle acceptance, and a fresh read-only physical-candidate inspection.

The first implementation work does not connect to a test node, write the real host filesystem, start a service, load eBPF, or inspect or attach a physical interface. Each higher-risk acceptance step requires its own explicit authorization after the preceding GitHub artifact and generated-root evidence are complete.

Delivery G.1 prepares a physical canary but does not execute one. The strongest positive conclusions introduced here are:

- `installed_verified`: the exact artifact was installed transactionally at the fixed paths and the installed-layout checker passed;
- `service_verified`: the exact installed service completed bounded start, generated-veth observation, journald, stop, restart, and cleanup acceptance without touching a physical interface;
- `physical_canary_ready`: a fresh, strictly read-only inspection found one explicitly authorized reserved port eligible for a separately authorized canary.

None of these states means production-ready, authorizes attachment, or permits active response.

## 2. Approaches Considered

### 2.1 Selected: separate static transactional installer

Add a small static Rust binary, `l2-loop-install`, with strict schemas, a compile-time destination table, an injected filesystem port, and a durable ownership journal. It validates an exact GitHub bundle and a short-lived host-bound installation authorization before writing. Every file is prepared beside its destination, synced, atomically renamed, and recorded so rollback can restore only exact known prior state.

This keeps mutation out of `l2-loop-deploycheck`, reuses the project's typed fail-closed patterns, permits exhaustive fault injection, and avoids constructing arbitrary shell commands.

### 2.2 Rejected: controller-side PowerShell or SSH installer

A remote script could copy files quickly, but it would split trust across quoting, transport, privilege, and platform-specific filesystem behavior. It would also make crash recovery and exact prior-state ownership harder to prove. SSH may transport a separately approved artifact and invoke the installed tool in acceptance, but it is not the installation transaction.

### 2.3 Rejected: manual copy-and-run runbook

Manual installation cannot reliably prove atomicity, idempotence, rollback identity, or exhaustive failure behavior. A runbook remains useful for operator sequencing, but it must invoke the same bounded installer and checker rather than reproduce their logic.

### 2.4 Deferred: general package manager integration

RPM, DEB, container, image-baking, and configuration-management integrations are outside G.1. They may later wrap the same fixed layout and ownership contract, but no package-manager lifecycle is trusted in this delivery.

## 3. Safety Boundary and Authorization Ladder

The delivery is divided into gates that cannot authorize the next gate implicitly:

1. **GitHub and generated-root development:** build, test, and fault-inject the installer without touching a node.
2. **Real installation acceptance:** after separate authorization, install the exact artifact on one authorized test node, but do not enable or start the service.
3. **Real service lifecycle acceptance:** after separate authorization, start the installed service only for generated namespace/veth sessions; verify systemd and journald, then stop it and restore exact prior state.
4. **Physical-candidate inspection:** after separate authorization, read one named reserved physical port and produce a non-executable readiness report; do not attach.
5. **Physical canary execution:** explicitly outside G.1. It requires a new task-scoped authorization and implementation/acceptance decision.

The following are invariants:

- compilation and Rust verification remain GitHub-only;
- all artifacts are bound to one exact 40-character GitHub commit and strict checksums;
- no wildcard interface selection, route-based selection, discovery default, `force`, `replace`, `adopt`, `repair`, or policy override exists;
- `l2-loop-deploycheck` remains strictly read-only and never gains installation verbs;
- installation never calls `systemctl`, enables or starts the service, loads eBPF, creates a network interface, or opens the daemon control socket;
- real service acceptance uses generated namespace/veth interfaces only;
- physical inspection is read-only and cannot be converted into an attach request;
- foreign, occupied, ambiguous, changed, or unknown eBPF state always blocks and remains untouched;
- no active probe, packet mutation, capture, drop, policing, mitigation, remote notification, bond/LACP support, or business-interface operation is added;
- cleanup and rollback address only exact journal-confirmed objects and stop on identity disagreement.

Existing eBPF programs and network state on an authorized node are baseline inputs. They are never detached, replaced, renamed, moved, or otherwise normalized for testing.

## 4. Component and Trust Boundaries

`l2-loop-core` owns the installation authorization, plan, journal, outcome, and stable finding types. `l2-loop-agent` owns pure planning and transaction services plus narrow filesystem, clock, identity, and hashing ports. Linux adapters implement no-follow metadata inspection, durable sibling-file operations, ownership/mode application, syncing, and atomic rename. The `l2-loop-install` binary owns argument parsing and bounded text/JSON rendering only.

The boundaries are deliberately separate:

- `l2-loop-install` may mutate only the fixed installation table after authorization;
- `l2-loop-deploycheck` reads the installed result and never repairs it;
- `l2-loopd` observes only after its existing isolated-session authorization succeeds;
- the host acceptance harness sequences fixed commands but cannot widen paths, targets, capabilities, durations, or cleanup scope;
- no daemon or CLI command consumes a canary plan as execution authority.

## 5. Deterministic Bundle and Fixed Layout

### 5.1 Bundle inventory

The deterministic Linux x86_64 MUSL artifact expands from nine to ten top-level files by adding `l2-loop-install`. `SHA256SUMS` therefore covers exactly nine payloads:

1. `l2-loopd`;
2. `l2-loopctl`;
3. `l2-loop-deploycheck`;
4. `l2-loop-install`;
5. `l2-loop-hostcheck`;
6. `l2-loop-ebpf.o`;
7. `l2-loop.service`;
8. `deployment-v1.example.json`;
9. `manifest.json`;
10. `SHA256SUMS`.

The manifest adds an `installer` role and remains deterministic. Missing, extra, nested, linked, non-regular, or checksum-mismatched content fails before an installation plan exists.

Before any real installation acceptance, GitHub CI must also run a mandatory pinned Rust dependency-advisory policy. An unavailable or failing advisory check blocks artifact eligibility. This closes the current gap created by repository dependency-alert availability without moving compilation to a node.

### 5.2 Compile-time destination table

Production installation recognizes only these destinations:

```text
/usr/bin/l2-loopctl
/usr/libexec/l2-loop/l2-loopd
/usr/libexec/l2-loop/l2-loop-deploycheck
/usr/libexec/l2-loop/l2-loop-install
/usr/libexec/l2-loop/l2-loop-hostcheck
/usr/libexec/l2-loop/l2-loop-ebpf.o
/usr/libexec/l2-loop/manifest.json
/usr/libexec/l2-loop/SHA256SUMS
/usr/lib/systemd/system/l2-loop.service
/usr/share/doc/l2-loop/deployment-v1.example.json
/etc/l2-loop/deployment-v1.json
/var/lib/l2-loop/gates/performance-v1.json
/var/lib/l2-loop/evidence/v1/
/var/lib/l2-loop/install/transactions/
```

The bundle supplies immutable product payloads. The operator supplies the exact authorization and performance-evidence documents. The installer creates the evidence and persistent transaction parents with the fixed modes required by the deployment contract. It never creates `/run/l2-loop` or the runtime socket; the reviewed systemd `RuntimeDirectory` contract owns that ephemeral lifecycle.

There is no production destination-root option, environment-variable override, prefix, relative path, or configuration alias. Tests use an injected in-memory or generated-root filesystem adapter, not a public root override.

## 6. Installation Authorization

### 6.1 Strict envelope

Every mutating invocation requires a root-owned mode-`0600` `install-authorization-v1.json`. It is strict: missing, duplicate, unknown, incorrectly typed, non-canonical, expired, or out-of-range fields fail closed. It contains:

- `schema_version: 1`;
- random 128-bit lowercase `authorization_id`;
- random 128-bit lowercase `transaction_id`;
- operation: `install`, `upgrade`, or `rollback`;
- exact artifact commit and bundle-manifest digest;
- SHA-256 of a stable host identity, never the raw machine ID;
- exact digests of the deployment authorization and performance evidence to install;
- issue and expiry times with a maximum one-hour lifetime;
- fixed booleans `service_enable: false`, `service_start: false`, and `physical_attach: false`.

The three false fields are assertions checked by schema, not options the caller may change. The envelope grants one operation for one host, transaction, artifact, and document set. It does not grant service or network authority and cannot be renewed or widened by a CLI flag.

### 6.2 Public commands

```text
l2-loop-install plan \
  --bundle <BUNDLE_DIR> \
  --authorization <INSTALL_AUTHORIZATION_FILE> \
  --deployment-authorization <DEPLOYMENT_AUTHORIZATION_FILE> \
  --performance-evidence <PERFORMANCE_EVIDENCE_FILE> \
  [--json]

l2-loop-install apply \
  --bundle <BUNDLE_DIR> \
  --authorization <INSTALL_AUTHORIZATION_FILE> \
  --deployment-authorization <DEPLOYMENT_AUTHORIZATION_FILE> \
  --performance-evidence <PERFORMANCE_EVIDENCE_FILE> \
  [--json]

l2-loop-install status [--json]

l2-loop-install rollback \
  --transaction <32-lower-hex> \
  --authorization <INSTALL_AUTHORIZATION_FILE> \
  [--json]
```

`plan` and `status` are read-only. `apply` and `rollback` require effective root and their exact operation in the envelope. Inputs may be arbitrary readable source paths, but destinations cannot be supplied. Output never echoes source paths or raw host identity.

There is no uninstall, purge, recover-any, force, adopt, chmod, chown, enable, start, stop, attach, detach, or recursive cleanup command in G.1.

## 7. Ownership Journal and Transaction State Machine

### 7.1 Journal schema

Each transaction has one strict root-owned mode-`0600` journal beneath `/var/lib/l2-loop/install/transactions/<transaction-id>/journal-v1.json`. Before that hierarchy exists, the installer exclusively creates `/var/lib/.l2-loop-install-<transaction-id>/` and its journal beneath the already required `/var/lib` parent. The exact transaction ID makes this bootstrap location recoverable without directory discovery or globs. After the persistent hierarchy is journaled and synced, the complete bootstrap transaction directory is atomically moved to its final location and the `/var/lib` parents are synced. A pre-existing bootstrap or final transaction location always blocks ordinary apply and permits only matching exact recovery.

The journal records:

- schema, transaction, authorization, host, artifact, and input-document digests;
- state: `planned`, `prepared`, `applying`, `installed`, `rolling_back`, `rolled_back`, or `failed`;
- a monotonically increasing durable step number;
- for every destination: role, fixed path, intended digest, mode, uid, gid, sibling temporary name, and final observed identity;
- prior state: absent or exact prior-owned file identity plus backup name, digest, mode, uid, and gid;
- every parent directory created by this transaction and its expected identity;
- the first stable failure code and whether precise rollback remains possible.

The journal contains no secret, raw machine ID, arbitrary error chain, or packet/network detail. The bootstrap and final transaction directories are created and validated with no-follow semantics before any product destination mutation.

### 7.2 Existing-state rule

A destination is writable only when it is:

- absent; or
- exactly owned by a previously completed valid installer journal whose artifact, digest, type, mode, uid, gid, inode, regular-file link expectation, and path all match fresh no-follow metadata. A directory's link count is validated as nonzero when observed but is not a persistent identity field because adding or removing a child directory changes it; persistent directory ownership still requires the same device/inode/type/mode/uid/gid, and rollback removes it only when the exact path is empty.

Every foreign, unjournaled, partially matching, linked, special, or unknown object blocks. The installer never adopts it. An incomplete prior transaction blocks a new `apply`; only exact rollback with matching authorization may proceed.

### 7.3 Durable apply sequence

For each fixed destination in deterministic order, the adapter:

1. validates every parent and final component with no-follow metadata;
2. creates missing fixed parent directories one level at a time and journals their exact identities;
3. copies the validated source into a randomly named sibling file using exclusive creation;
4. sets the fixed mode and root ownership, hashes the result, and verifies regular-file and link-count invariants;
5. syncs the sibling file and its parent directory;
6. moves an exact prior-owned destination to its journal backup when upgrading, then syncs the parent;
7. atomically renames the prepared sibling into place and syncs the parent again;
8. records the installed identity and advances the durable journal step.

The final state becomes `installed` only after every object and directory has been freshly revalidated and the journal itself is synced. Installation never invokes installed executables.

### 7.4 Exact rollback

Rollback traverses completed steps in reverse. It removes a newly installed file only when its current identity exactly matches the journal; restores a prior-owned backup only when both backup and destination identities match the recorded transition; and removes a transaction-created directory only when it is still the same directory and empty.

Identity disagreement stops rollback and returns a bounded manual-review finding. There is no wildcard, glob, recursive delete, best-effort detach, or cleanup widening. Backups and transaction records remain until an independently verified terminal state permits a later retention policy; G.1 does not add automatic garbage collection.

The exact `/var/lib/l2-loop`, `/var/lib/l2-loop/install`, and `/var/lib/l2-loop/install/transactions` directory identities are retained when they are required to contain terminal journals. Rollback revalidates their persistent device, inode, type, mode, uid, and gid before marking their retention step complete; it does not misreport their expected child-directory link-count change as an identity disagreement or try to remove a nonempty journal parent. A durable `rolling_back` journal resumes from its exact next reverse action after process restart or after the operator restores a temporarily changed canonical identity.

### 7.5 Metadata limitations

G.1 supports regular files and directories with fixed POSIX mode and root ownership. It refuses installation when a destination or owned predecessor has unsupported ACLs, extended attributes, immutable flags, capabilities, or security labels that cannot be preserved and verified. On an enforcing SELinux host, installation is blocked until a separately reviewed labeling policy and verification adapter exist.

## 8. Real Installed-Layout Verification

After `apply` returns `installed`, the acceptance harness invokes a new read-only command against the fixed paths:

```text
l2-loop-deploycheck installed [--json]
```

`installed` validates installation integrity without selecting, reading, or reporting a physical interface. It accepts no path, root, interface, repair, or mutation argument. The existing `staging` and `inspect` commands retain their meanings; `inspect` remains reserved for the later explicitly authorized physical-candidate gate. The installer does not treat its own write result as verification.

The checker additionally validates:

- exact journal-to-file identity for every installed payload and supplied document;
- no incomplete or competing transaction;
- fixed parent types, ownership, modes, and link counts;
- exact manifest, checksums, unit contract, deployment authorization, performance evidence, and persistent evidence-root prerequisites;
- installed artifact identity equals the authorization and GitHub artifact SHA.

Only this independent pass yields `installed_verified`. A failed check does not trigger automatic repair; the authorized acceptance workflow either performs exact rollback or stops for review.

## 9. Real systemd and journald Lifecycle Acceptance

Installation does not call the service manager. A separately authorized acceptance harness may proceed only after `installed_verified` and a fresh proof that the existing network/eBPF baseline is stable.

The harness performs a bounded lifecycle with the installed deterministic unit:

1. capture unit enablement/activity state, journal cursor, processes, socket, evidence, network, and eBPF identity;
2. run `systemctl daemon-reload` and start the unit without enabling it;
3. verify the root-only Unix socket and daemon identity;
4. create one generated namespace/veth session and exercise the existing isolated observation path only;
5. verify bounded text/JSON requests, sampling, evidence persistence, sanitized structured journald open/close records, and the injected stderr fallback path;
6. stop the service within the fixed deadline and prove exact owned isolated cleanup;
7. repeat one start/stop cycle to validate restart recovery without duplicating evidence revisions;
8. restore the prior unit state, remove only generated resources, and compare the complete network/eBPF baseline.

The harness never enables the unit, attaches to a physical interface, changes sysctl/module/offload state, or removes foreign files, programs, maps, pins, XDP, TC, namespaces, or processes. If the unit was active or enabled before acceptance, the test is blocked rather than taking ownership of that state.

Only the successful exact-artifact lifecycle yields `service_verified`.

## 10. Read-Only Physical-Candidate Inspection

After `service_verified`, a separately authorized command may run `l2-loop-deploycheck inspect` against one exact interface named by the fixed deployment authorization. This stage performs no attach, no traffic generation, no link-state change, and no service start.

Fresh inspection must prove:

- the target is a physical interface with stable name, ifindex, MAC hash, driver, PCI/device identity, and namespace identity matching authorization;
- it is a reserved non-business port with no master/member, bond, bridge, Open vSwitch, tap, veth, peer, or shared topology;
- it has no L3 address, route, neighbor, socket-visible consumer, AF_PACKET consumer, service binding, or other known workload;
- native and generic XDP are explicitly empty;
- TC ingress and egress state are explicitly empty and unambiguous;
- BTF, bpffs, memlock, kernel, capabilities, native-driver support, link state, and required queue/offload facts are supported;
- exact-artifact isolated performance evidence is current, while native-NIC and representative-workload evidence are clearly distinguished;
- the pre/post read-only network/eBPF identity is unchanged.

Privacy-safe public output uses hashed device identity and consumer-present booleans. Root-only authorization may retain exact MAC/PCI fields required for identity binding, but they are never emitted in normal text/JSON or journald output.

A positive report yields `physical_canary_ready` and an `executable: false` plan with a maximum 15-minute duration. It still grants no attach capability.

## 11. Separately Authorized Physical Canary Boundary

The actual physical canary is deferred to a later delivery. Before it can run, a new task-scoped authorization must bind the exact host, artifact, interface name, ifindex, MAC, driver, PCI identity, hook states, observation duration, and operator approval.

Its future design must preserve:

- native XDP/TC no-replace attachment only when both hooks are freshly empty;
- fail-open pass/continue actions only;
- no probes, drops, mutation, rate limiting, or response policy;
- a fixed maximum 15-minute watchdog plus signal-aware exact cleanup;
- pre/post network, traffic-health, XDP, TC, program, map, pin, and journal identity snapshots;
- immediate stop on identity change, observation degradation, traffic-health degradation, ownership uncertainty, signal, or deadline;
- reverse rollback only when exact identities match;
- representative external traffic generation on a reserved non-business link;
- preservation of every pre-existing eBPF object and zero owned residue.

G.1 must not include a general product command that can consume the readiness plan or authorization and perform this operation.

## 12. Decisions, Findings, and Exit Codes

Installation reports use decisions `blocked`, `install_plan_ready`, `installed_verified`, and `rolled_back`. Service acceptance may add `service_verified`; deployment inspection may add `physical_canary_ready`. Decision derivation is centralized and a blocker always wins.

Stable G.1 findings include:

| Code | Meaning |
|---|---|
| `GI_AUTH_SCHEMA` | installation authorization is malformed or non-canonical |
| `GI_AUTH_EXPIRED` | authorization is outside its one-hour lifetime |
| `GI_AUTH_HOST` | host identity does not match |
| `GI_AUTH_ARTIFACT` | artifact, manifest, or supplied-document digest does not match |
| `GI_BUNDLE_INVALID` | inventory, manifest, checksum, or dependency-advisory gate failed |
| `GI_DESTINATION_FOREIGN` | an existing destination is not exact prior-owned state |
| `GI_METADATA_UNSAFE` | type, link, ACL, xattr, flag, capability, label, owner, or mode is unsafe |
| `GI_TRANSACTION_CONFLICT` | a transaction already exists or is incomplete |
| `GI_WRITE_FAILED` | create, copy, ownership, mode, hash, sync, or rename failed |
| `GI_ROLLBACK_IDENTITY` | exact rollback identity no longer matches |
| `GI_LAYOUT_VERIFY` | independent installed-layout verification failed |
| `GI_SERVICE_STATE` | prior systemd state makes acceptance unsafe |
| `GI_SERVICE_LIFECYCLE` | bounded start, request, journal, stop, restart, or cleanup failed |
| `GI_PHYSICAL_BLOCKED` | the read-only target is shared, occupied, unsupported, changed, or unknown |
| `GI_INTERNAL` | a bounded invariant prevented a trustworthy report |

Exit codes remain consistent across text and JSON:

| Code | Meaning |
|---:|---|
| 0 | requested read-only or mutating operation reached its declared positive terminal state |
| 1 | bounded internal or I/O failure prevented a trustworthy terminal result |
| 2 | CLI usage or local validation failed before an operation began |
| 4 | a complete report returned `blocked` |

## 13. Privacy and Output Bounds

Public text/JSON may include only artifact identity, transaction/authorization IDs, stable decisions/findings, fixed destination roles, fixed paths, sanitized timestamps, aggregate service results, kernel compatibility facts, interface name/ifindex/kind/state, hashed device identity, and abstract hook/consumer state.

It excludes raw machine ID, MAC, PCI serial, hostname, IP, VLAN membership, route, neighbor, packet, protocol payload, fingerprint, environment, SSH material, credentials, arbitrary source path, journal content, kernel pointer, verifier log, map data, and raw error chains.

Reports have fixed collection bounds, deterministic ordering, and a one-megabyte serialization ceiling. Serialization overflow fails closed. Root-only transaction and authorization files contain only the exact private identity data required for local validation and are never copied into public evidence.

## 14. Failure and Recovery Semantics

- Validation completes before the first mutation.
- Every mutation has a preceding durable journal state and a following identity verification.
- A crash leaves an incomplete transaction that blocks further apply operations.
- The installer never guesses whether a prior write completed; recovery re-reads exact identities.
- Automatic in-process rollback may run only while all identities match; otherwise it stops and preserves evidence.
- Independent checker or service failure never causes automatic repair, detach, or deletion.
- Missing service-manager or journald capability is unavailable/blocked, not silently skipped.
- Any change in the stable pre-existing network/eBPF baseline invalidates acceptance even if product checks pass.
- Test cleanup removes only exact generated namespace/veth resources and exact installer-owned state.
- Interrupted physical inspection leaves no cleanup work because it is read-only.
- No failure path broadens a path, capability, interface, duration, or ownership boundary.

## 15. Verification Strategy

### 15.1 GitHub RED/GREEN development

Every behavior change follows a RED commit whose expected failure is observed in GitHub, followed by GREEN implementation. No Rust compilation occurs locally.

Coverage includes:

- strict schemas, duplicate/unknown fields, time boundaries, host/artifact/document binding, and privacy scans;
- exact bundle inventory and deterministic ten-file packaging;
- fixed destination table and absence of a public root/prefix override;
- no-follow parents, regular types, link counts, ownership, modes, ACL/xattr/flag/capability/label refusal;
- absent, exact prior-owned, foreign, changed, and incomplete-transaction cases;
- failure injection at every directory create, sibling create, write, chmod/chown, hash, file sync, backup rename, final rename, directory sync, journal update, verification, and rollback step;
- restart from every durable journal state and exact reverse rollback;
- text/JSON parity, exit codes, ordering, size bounds, and prohibited-field scans;
- static proof that installer code has no service-manager, attach, detach, BPF, network, wildcard deletion, or arbitrary command path;
- pinned dependency-advisory policy and existing format, Clippy, test, eBPF, packaging, manifest, and checksum jobs.

### 15.2 Generated-root acceptance

The exact artifact is exercised below one generated root with injected host identity and filesystem failure points. Happy-path install, idempotent plan, exact-owned upgrade, interrupted transaction, every fault boundary, rollback, foreign-object refusal, unsafe metadata refusal, and zero-residue cases must pass. This harness does not expose a production root override through the binary.

### 15.3 Separately authorized node acceptance

Node acceptance is deliberately split:

1. install the exact artifact at fixed real paths without starting or enabling the service;
2. verify installed layout and, if required, exact rollback;
3. with new authorization, exercise real systemd/journald using generated veth only;
4. restore prior service, network, and eBPF identity and prove zero generated residue;
5. with new authorization, perform read-only inspection of one named reserved physical port.

Before and after every stage, the harness snapshots stable network links, addresses/routes counts, namespaces, XDP, TC, programs, maps, pins, service/process state, and G.1-owned paths. A foreign or unexplained difference fails acceptance and stops progression.

## 16. Delivery Plan

Delivery G.1 is implemented as eleven tasks:

1. add installation domain models, strict schemas, decisions, findings, and RED/GREEN tests;
2. implement pure `InstallPlanner` and `InstallService` with injected read-only/mutating ports;
3. implement exact bundle, authorization, host-binding, supplied-document, and fixed-path validation;
4. implement the strict ownership journal and crash-recovery state machine;
5. implement the Linux no-follow transactional filesystem adapter and exact rollback;
6. implement `l2-loop-install` commands, bounded rendering, and exit codes;
7. extend the deterministic MUSL artifact to ten files and add the pinned dependency-advisory gate;
8. build the generated-root install, upgrade, fault, restart, and rollback harness;
9. build the separately authorized real systemd/journald lifecycle harness using generated veth only;
10. add `deploycheck installed`, then extend `deploycheck inspect` for fresh read-only physical identity, native-driver, consumer, and workload-evidence readiness;
11. perform final security audit, documentation correction, exact-artifact acceptance review, and decide whether a separately designed physical-canary delivery may begin.

Tasks 1-11 are implemented. Development and CI remained off-node: Task 9's real install/service harness and Task 10's real physical inspector are implemented and statically/fixture tested, but their real-node execution still requires new explicit authorization at execution time.

## 17. Acceptance Criteria

Delivery G.1 is complete only when one final exact SHA satisfies all applicable authorized gates:

1. GitHub CI and the mandatory dependency-advisory policy are green;
2. the deterministic artifact contains exactly ten top-level files and nine checksum-covered payloads;
3. schemas, bundle binding, fixed paths, no-follow rules, ownership, journal durability, and privacy bounds pass exhaustive tests;
4. every injected filesystem failure either performs exact rollback or leaves a precise recoverable blocked transaction;
5. no foreign or unknown destination can be adopted, overwritten, removed, or restored;
6. generated-root install, exact-owned upgrade, interruption, recovery, rollback, and residue scenarios pass;
7. after separate authorization, real installation does not start/enable a service or change network/eBPF state and the independent installed checker returns `installed_verified`;
8. after separate authorization, systemd/journald acceptance uses only generated veth, returns `service_verified`, restores prior service state, and leaves network/eBPF identity unchanged;
9. after separate authorization, fresh read-only inspection of one reserved physical port either fails closed or returns `physical_canary_ready` without attachment;
10. all exact generated and installer-owned residue is zero after the requested terminal rollback/acceptance state, while retained terminal journals follow the explicit retention contract;
11. no product command can execute the physical readiness plan, attach a production interface, or perform an active response;
12. worktree is clean and `HEAD == origin/main`.

If node or physical inspection authorization is not granted, the corresponding evidence remains explicitly unavailable and Delivery G.1 cannot claim that gate complete.

### 17.1 Final audit conclusion and authorization handoff

The Task 11 audit traced installer CLI → planner/service → ownership journal → Linux filesystem adapter and deploycheck CLI → service → fixed collectors. It also reviewed destination/root/interface override surfaces, shell construction, symlink and metadata handling, I/O bounds, cleanup scope, service-manager and attach capabilities, public privacy fields, error closure, authorization freshness, dependency resolution, Action pinning, RustSec policy, and the deterministic bundle boundary.

One high-confidence defect class was found at three expected-absent publication sites. Final payload, upgrade-backup, and journal-directory renames could replace a foreign destination created after the last absence check. Focused privileged tests first failed in GitHub, then all expected-absent publication and recovery renames were changed to use `renameat2(RENAME_NOREPLACE)`. A raced destination now returns a closed error while the foreign object and unrelated sentinel retain their contents and identity. The complete Userspace, eBPF, script-safety, Windows-safety, MUSL bundle, ten-file/nine-checksum, and generated-root installation acceptance then passed for the fix revision.

No node, systemd, journald, physical-interface, or live eBPF operation was performed as part of this audit. Consequently the exact-artifact generated-root gate is proven, while real-node `installed_verified`, `service_verified`, and `physical_canary_ready` evidence is unavailable. This is the strongest honest G.1 conclusion and is not a production-ready or attachment decision.

The operational handoff remains four separately authorized stages:

1. fixed-path real installation and exact transaction rollback;
2. bounded systemd/journald lifecycle acceptance using generated veth only;
3. fresh read-only inspection of one exact reserved physical port;
4. a newly designed physical Canary, authorized only after the preceding three reports pass for the same artifact and host.

The fourth authorization must bind the exact artifact, host, interface name, ifindex, MAC, driver, device/PCI and namespace identity, freshly empty native/generic XDP and TC states, representative external traffic source, duration no greater than 15 minutes, operator, complete commands and mutations, stop conditions, and exact reverse rollback. Its design must prohibit hook replacement, foreign cleanup, probe traffic, packet drop, policing, persistent enablement, and any broader production claim. G.1 contains no command that can perform it.

### 17.2 G.1.1 controller-boundary correction

The original Task 9 implementation required distinct installation and service authorization documents but consumed both in one outer controller invocation. On 2026-08-17, G.1.1 superseded that operational shape because separate documents alone do not create separate operator execution gates. Gate 1 is now `verify-real-install.ps1` and ends after independent installed verification, exact authorized rollback, stable network/eBPF comparison, and generated transfer cleanup. It has no service parameter or service invocation. Gate 2 is now `verify-real-service-acceptance.ps1`; only after a reviewed Gate 1 report and a new authorization does it create a new installation transaction, require `installed_verified`, invoke the generated-veth-only service harness, exactly roll back, and report cleanup. This correction changes no historical Task 9 evidence and grants no node authorization.

## 18. Explicitly Deferred

- executing any physical-interface canary;
- enabling the service at boot or unattended restart policy;
- RPM/DEB/configuration-management integration;
- SELinux policy, non-root service account, or additional capability reduction;
- automatic backup/journal garbage collection;
- bond/LACP, bridge, Open vSwitch, tap, shared, business, or multi-interface operation;
- active probes, confirmed-loop action, packet drop, policing, mitigation, or remote notification;
- representative production workload approval and any production-ready claim.

## 19. Reference Basis

- `docs/superpowers/specs/2026-08-13-production-read-only-deployment-gates-design.md`
- `docs/superpowers/specs/2026-08-11-github-build-supply-chain-hardening-design.md`
- `docs/superpowers/specs/2026-08-12-bounded-local-incident-output-design.md`
- `docs/superpowers/specs/2026-08-13-bond-read-only-observation-design.md` (future boundary only; not enabled by G.1)
- `docs/l2-loop-agent-design.md`
- current exact-artifact generated-root, isolated host, ownership journal, and performance harness contracts
