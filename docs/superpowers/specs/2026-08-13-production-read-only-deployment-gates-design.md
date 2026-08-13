# Production Read-Only Deployment Gates Design

**Date:** 2026-08-13  
**Delivery:** G  
**Status:** Approved design, implementation not started

## 1. Objective

Delivery G defines and verifies the infrastructure required before the L2 Loop Detection Agent can be considered for a production read-only canary. It adds a checksum-bound deployment bundle contract, a non-mutating deployment checker, a strict single-interface authorization document, a hardened systemd unit contract, an explicitly non-executable canary plan, and isolated performance gates.

Delivery G does not install into the real host filesystem, start or enable a real systemd service, read or mutate the real journal, attach to a production or physical interface, send a probe, drop or police traffic, or claim that the product is production-ready. All authorized-host acceptance uses one generated staging root plus generated network namespace/veth resources.

The strongest positive conclusions are:

- `staging_ready`: the exact GitHub artifact can reproduce a safe production-shaped layout under a generated staging root;
- `canary_candidate`: the fixed installed-layout contract, strict authorization, current read-only host inspection, and isolated performance evidence satisfy the prerequisites for a separately authorized single-interface canary. Delivery G proves this decision path with injected physical-interface fixtures; authorized-host acceptance does not inspect or attach a physical interface.

There is no `production_ready` state in this delivery.

## 2. Approaches Considered

### 2.1 Selected: contract-first generated staging root

Build the complete deployment contract and validate it under `/run/l2-loop/accept/<run-id>/staging-root`. This exercises file layout, ownership and modes, systemd syntax and hardening, manifest binding, authorization validation, preflight integration, plan construction, failure behavior, and exact cleanup without crossing the real `/etc`, `/usr`, `/var`, systemd, or journald trust boundaries.

This approach gives the strongest evidence available before installation authorization and preserves the current isolated-only mutation policy.

### 2.2 Rejected: extend only the existing preflight report

The existing preflight already inspects interfaces, topology, kernel capability, XDP/TC state, bpffs, BTF, and memlock. Extending only that path would not prove the bundle layout, systemd hardening, file identity, evidence-root prerequisites, authorization expiry, installation rollback, or upgrade compatibility.

### 2.3 Deferred: install directly on an authorized test node

A real installation is eventually necessary to validate systemd and journald behavior. It requires separate authorization because it writes persistent host state and operates outside generated namespace/veth resources. Delivery G prepares that test but does not perform it.

## 3. Safety Boundary

The following constraints are invariants, not runtime options:

- compilation remains GitHub-only;
- the target artifact is bound to one exact 40-character commit SHA and verified by `SHA256SUMS`;
- production-shaped filesystem acceptance occurs only below one generated staging root;
- the checker is read-only and has no install, repair, chmod, chown, enable, start, stop, restart, detach, unpin, or cleanup operation;
- only an explicitly named interface is inspected; no default-route, first-interface, wildcard, or discovery-based selection exists;
- the authorization contract names exactly one interface and expires;
- no production attach command or executable canary action is introduced;
- XDP and TC foreign, occupied, ambiguous, or unknown state blocks candidacy;
- bond, bridge, Open vSwitch, tap, veth, master/member, and shared targets block candidacy;
- no `force`, `replace`, `adopt`, `ignore`, or caller-selected policy override exists;
- eBPF and Map ABI remain unchanged and fail-open;
- no eBPF path returns `XDP_DROP` or `TC_ACT_SHOT`;
- no active probe, confirmed-loop state, rate limiting, packet mutation, raw packet capture, or production attachment is added;
- acceptance cleanup operates only on exact generated names and paths and refuses identity disagreement.

An installation-shaped staging root is evidence about packaging and configuration only. It is not evidence that a physical NIC driver supports native XDP or that a workload meets production performance requirements.

## 4. Bundle and Filesystem Contract

### 4.1 GitHub artifact contents

The Linux x86_64 bundle contains exactly these eight payload files plus `SHA256SUMS`:

1. `l2-loopd`;
2. `l2-loopctl`;
3. `l2-loop-deploycheck`;
4. `l2-loop-hostcheck`;
5. `l2-loop-ebpf.o`;
6. `l2-loop.service`;
7. `deployment-v1.example.json`;
8. `manifest.json`.

`SHA256SUMS` contains one strict lowercase SHA-256 line for each payload file. No extra file, nested archive, symlink, hard link, device, FIFO, or socket is accepted.

`manifest.json` remains deterministic and adds explicit roles for the deployment checker, service unit, and authorization example. It binds:

- schema version;
- exact commit SHA;
- package version;
- userspace and eBPF target triples;
- ABI version;
- filenames and roles;
- SHA-256 digest of the service unit and authorization example.

The manifest never contains a host, interface, address, identity path, secret, or environment report.

### 4.2 Production-shaped target layout

The contract describes this fixed layout:

```text
/usr/libexec/l2-loop/l2-loopd
/usr/libexec/l2-loop/l2-loop-deploycheck
/usr/libexec/l2-loop/l2-loop-hostcheck
/usr/libexec/l2-loop/l2-loop-ebpf.o
/usr/libexec/l2-loop/manifest.json
/usr/libexec/l2-loop/SHA256SUMS
/usr/bin/l2-loopctl
/usr/lib/systemd/system/l2-loop.service
/usr/share/doc/l2-loop/deployment-v1.example.json
/etc/l2-loop/deployment-v1.json
/var/lib/l2-loop/gates/performance-v1.json
/var/lib/l2-loop/evidence/v1/
/run/l2-loop/agent.sock
```

Delivery G acceptance mirrors each absolute path below:

```text
/run/l2-loop/accept/<run-id>/staging-root/
```

For example, the staged daemon is at `.../staging-root/usr/libexec/l2-loop/l2-loopd`. Canonicalization must remain below the exact staging root. The root and every parent are checked with no-follow semantics.

Expected types and modes are:

| Object | Type | Mode |
|---|---|---:|
| acceptance root and staging root | directory | `0700` |
| staged `/usr`, `/usr/bin`, `/usr/libexec`, `/usr/lib/systemd/system`, and `/usr/share/doc` parents | directory | `0755` |
| staged `/etc/l2-loop` and `/var/lib/l2-loop/gates` | directory | `0700` |
| `/usr/libexec/l2-loop/*` executable files | regular file | `0755` |
| eBPF object | regular file | `0644` |
| installed manifest and checksum list | regular file | `0644` |
| CLI | regular file | `0755` |
| service unit | regular file | `0644` |
| authorization example | regular file | `0644` |
| authorization document | regular file | `0600` |
| performance evidence | regular file | `0600` |
| evidence root | directory | `0700` |
| runtime directory | directory created by systemd contract | `0700` |
| control socket | Unix socket created by daemon | `0600` |

The production owner/group contract is root/root. Acceptance records the expected numeric identity separately and validates staged types and modes without changing real host ownership. A staged runtime directory must be empty: `agent.sock` is a future daemon-created object and its presence during `staging` is a blocker.

## 5. Deployment Checker

### 5.1 Component boundary

`l2-loop-core` owns deployment report, authorization, canary-plan, finding, and validation types. `l2-loop-agent` owns pure deployment services and injected I/O ports. Linux adapters own filesystem metadata, systemd-unit parsing, clock, artifact hashing, and a new `DeploymentPlatformInspector` composed from the same read-only collectors used by `SystemLinuxInspector`. A small `l2-loop-deploycheck` binary parses arguments, calls the service, and renders text or JSON.

The existing `PreflightService` and its `PF_LIVE_INTERFACE` attachment blocker remain unchanged. Candidate inspection is not an attachment preflight: it verifies that the current agent still refuses a live/physical attach, accepts exactly that one expected blocker as evidence of the existing safety boundary, and independently applies the stricter reserved-port rules in this specification. Every other preflight blocker remains `DG_PLATFORM_BLOCKED`. No attachment transaction consumes a deployment report or plan.

The checker does not call the daemon or require the Unix socket. It must be usable before installation and before service start.

### 5.2 Public commands

The checker exposes two read-only commands:

```text
l2-loop-deploycheck staging \
  --bundle <BUNDLE_DIR> \
  --root <GENERATED_STAGING_ROOT> \
  [--json]

l2-loop-deploycheck inspect [--json]
```

`staging` is acceptance-only. It accepts a root only when it exactly matches `/run/l2-loop/accept/<32-lower-hex>/staging-root`; it validates but never creates or removes that root. The authorized host harness creates and cleans it.

`inspect` reads only the fixed production-shaped paths. It obtains the one target interface from the authorization document; accepting an interface argument would create an override and is forbidden. In Delivery G it is exercised with injected test I/O and static fixtures, not against real `/etc`, `/usr`, `/var`, or `/run` on the authorized host. A later separately authorized installation task may run it against the real layout.

`--json` changes rendering only. Paths cannot be supplied through environment variables, configuration aliases, or daemon requests. The checker accepts no mutation flag.

### 5.3 Processing order

`staging` executes fail-closed gates in this order:

1. validate arguments and generated-root grammar;
2. verify bundle inventory, manifest schema, exact commit, and all checksums;
3. inspect staged filesystem type, ownership contract, modes, symlinks, and canonical containment;
4. parse and validate the service unit contract;
5. parse and structurally validate generated `deployment-v1.json` and `performance-v1.json` fixtures without comparing them to a real interface;
6. validate the staged evidence-root and runtime/socket contracts;
7. derive `staging_ready` only when every staging gate passes.

`inspect` executes fail-closed gates in this order:

1. verify the fixed installed inventory, manifest, checksum list, types, ownership, modes, and unit contract;
2. parse and validate the fixed authorization and performance-evidence files;
3. invoke `DeploymentPlatformInspector` and the unchanged existing preflight for the interface named by authorization;
4. require the existing preflight to contain its physical/live attachment refusal, reject every other blocker, and bind authorization identity to the fresh read-only facts;
5. bind performance evidence to the exact artifact and current host compatibility identity;
6. validate the real evidence-root prerequisite and runtime/socket contract;
7. construct a non-executable canary plan and derive the final decision.

A failure at any stage produces a bounded report. It does not attempt a repair or continue into a stage whose input identity is untrusted.

### 5.4 Report schema

`DeploymentGateReportV1` uses `schema_version: 1` and contains:

- `decision`: `blocked`, `staging_ready`, or `canary_candidate`;
- exact artifact commit and package version;
- optional inspected interface name, ifindex, kind, and administrative/operational state; these are absent for `staging`;
- bundle, layout, service, authorization, platform, evidence, and performance gate summaries;
- stable sorted findings;
- optional `CanaryPlanV1` only when its source inputs are valid;
- capture time in Unix milliseconds;
- `mutations_performed: false`.

Decision derivation is centralized. An adapter cannot return `staging_ready` or `canary_candidate` while a blocker applicable to that command exists. `staging_ready` proves packaging/configuration structure only and cannot contain a plan. `canary_candidate` additionally requires `inspect`, a valid unexpired authorization, a supported empty-hook physical target, all required platform gates, and passing isolated performance evidence for the exact artifact and host compatibility identity.

## 6. Single-Interface Authorization

### 6.1 Strict document

`deployment-v1.json` is a strict JSON document: unknown, duplicate, missing, incorrectly typed, out-of-range, or non-canonical fields are rejected. Its approved shape is:

```json
{
  "schema_version": 1,
  "authorization_id": "00112233445566778899aabbccddeeff",
  "artifact_commit_sha": "0000000000000000000000000000000000000000",
  "mode": "read_only_canary_candidate",
  "interface": {
    "name": "spare0",
    "ifindex": 7,
    "kind": "physical",
    "administrative_state": "up",
    "operational_state": "up",
    "master_ifindex": null,
    "xdp_native": "empty",
    "xdp_generic": "empty",
    "tc_clsact": false,
    "tc_ingress": [],
    "tc_egress": []
  },
  "issued_at_unix_ms": 1786579200000,
  "expires_at_unix_ms": 1786665600000
}
```

The example contains documentation placeholders and is never valid authorization by itself. The real document must use a random 128-bit lowercase authorization ID and the exact artifact commit.

### 6.2 Fixed rules

- exactly one interface is authorized;
- the interface kind must be `physical`;
- ifindex must be non-zero and freshly match the kernel;
- administrative and operational state must both be `up` and freshly match the authorization;
- no master, bond, bridge, Open vSwitch, tap, veth, peer, or namespace relationship is permitted;
- the target must have no L3 address, route, neighbor, service, or other kernel-visible consumer; reports expose only a consumer-present boolean, never the address or route;
- native and generic XDP must both be explicitly `empty`;
- TC state must be known and both ingress and egress filter sets empty;
- authorization lifetime is positive and at most 24 hours;
- capture time must fall within the inclusive issue/expiry interval;
- artifact SHA, interface identity, hook state, and topology must exactly match the fresh inspection;
- an authorization cannot be renewed, widened, or overridden by CLI flags;
- an expired or changed authorization blocks and does not trigger cleanup.

The authorization is a prerequisite for planning only. It does not authorize attachment in Delivery G.

## 7. Non-Executable Canary Plan

`CanaryPlanV1` is a sanitized explanation of a future separately authorized operation. It contains:

- schema version and `executable: false`;
- authorization ID and exact artifact SHA;
- interface name, ifindex, and observed kind;
- planned XDP ingress mode and TC egress hook;
- mandatory no-replace semantics;
- foreign/unknown-state rejection requirements;
- pre/post network, XDP, TC, loaded-program, map, pin, and traffic-health snapshot requirements;
- a fixed maximum observation duration of 15 minutes;
- stop conditions: identity change, observation degradation, traffic-health degradation, ownership mismatch, cleanup uncertainty, signal, or deadline;
- precise owned rollback requirements;
- required native-driver and workload performance evidence still missing;
- sorted blocker and warning codes.

No daemon or CLI command consumes this plan. It has no signature that grants execution authority, no action token, no attach endpoint, and no automatic transition to an observing session.

## 8. systemd Unit Contract

The bundle contains a deterministic `l2-loop.service` file. Delivery G parses the unit as a constrained contract rather than trusting arbitrary systemd syntax.

Required properties include:

- fixed absolute `ExecStart=/usr/libexec/l2-loop/l2-loopd` without a shell or variable expansion;
- `User=root` and `Group=root` for this stage;
- `RuntimeDirectory=l2-loop` and `RuntimeDirectoryMode=0700`;
- `UMask=0077`;
- `NoNewPrivileges=yes`;
- `PrivateTmp=yes`;
- `ProtectSystem=strict`;
- `ProtectHome=yes`;
- `PrivateDevices=yes`;
- `ProtectKernelTunables=yes`;
- `ProtectKernelModules=yes`;
- `ProtectControlGroups=yes`;
- `RestrictSUIDSGID=yes`;
- `RestrictRealtime=yes`;
- `LockPersonality=yes`;
- `MemoryDenyWriteExecute=yes`;
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` exactly;
- `ReadWritePaths=/run/l2-loop /var/lib/l2-loop/evidence/v1`;
- no broad `/etc`, `/usr`, `/var`, `/sys`, or `/proc` write permission;
- `TimeoutStopSec=10s`, which bounds the existing five-second incident-output drain plus exact owned cleanup;
- `Restart=no` and no automatic restart after an attachment, ownership, or cleanup failure.

`CapabilityBoundingSet` is exactly `CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE`, and the checker rejects additions or omissions. `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, and every other capability are forbidden. If an authorized target kernel requires a capability outside the fixed set, candidacy is blocked until a separate capability-risk approval changes this design.

The unit must not run an installer, create the production evidence root, modify sysctl/module/offload settings, invoke a shell, or execute pre/post scripts. Installation tooling, when separately authorized, must create prerequisites before service start.

## 9. Evidence and Alert Prerequisites

The production evidence root remains fixed at `/var/lib/l2-loop/evidence/v1`, root-owned mode `0700`. The daemon never creates, chmods, chowns, follows, replaces, or repairs it. The deployment checker validates it before a positive decision.

Delivery G validates the alert configuration structurally but does not claim real journald delivery. The real-install task must later prove:

- the daemon can send one sanitized structured alert to journald;
- the evidence status accurately reports persistence independently of alert delivery;
- a journald failure permanently falls back to one stderr JSON line;
- no raw packet, MAC, IP, fingerprint, map key/path, topology, hostname, machine ID, or error chain appears;
- service restart and journal behavior do not duplicate evidence revisions.

Until that separately authorized test succeeds, the report includes `DG_REAL_JOURNALD_UNVERIFIED` as a warning and never returns `production_ready`.

## 10. Isolated Performance Gate

### 10.1 Purpose and limits

Delivery G adds a reproducible, bounded performance harness for the exact artifact on generated namespace/veth resources. It detects severe regressions in the agent and test environment; it does not model physical NIC driver, IRQ, queue, offload, or production workload behavior.

### 10.2 Measurement contract

Each run records:

- exact artifact SHA and package version;
- kernel release and architecture;
- logical CPU count;
- veth XDP mode;
- fixed frame sizes and bounded frame count;
- wall-clock duration;
- achieved packets and bytes per second;
- daemon CPU time and peak resident memory;
- receive/transmit counters and errors before/after;
- network and existing eBPF identity before/after.

The three fixed modes are: `baseline` with no agent hooks, `pass_through` with the exact fail-open hooks attached but observation configuration unpublished, and `observe` with the exact hooks plus normal observation configuration. The harness performs a warm-up followed by exactly five bounded three-mode trials, rotating mode order each trial. It reports the median throughput for each mode; no best-run selection is permitted. Fixed gates are:

- pass-through path throughput at least 95% of the no-hook baseline;
- observe path throughput at least 90% of the same-run baseline;
- zero agent-caused packet drops or errors;
- no unbounded CPU, memory, process, namespace, pin, map, or program growth;
- exact cleanup and stable restoration of pre-existing network/eBPF identity.

A noisy or incomplete measurement is `unavailable`, not passing. Thresholds are not CLI options. Physical native-XDP and representative workload performance remain mandatory before any later production-canary authorization.

### 10.3 Performance evidence schema

`performance-v1.json` is a strict, root-owned mode-`0600` document. It contains:

- schema version and random 128-bit lowercase evidence ID;
- exact artifact commit, package version, architecture, kernel release, and logical CPU count;
- issued and expiry times with a maximum 24-hour lifetime;
- exactly five trials for each fixed mode;
- per-mode median packets/bytes per second;
- pass-through/baseline and observe/baseline ratios in integer permille;
- daemon CPU time and peak resident memory;
- packet error/drop deltas;
- booleans proving forwarding, owned cleanup, and restoration of stable network/eBPF identity;
- final result `passed`, `failed`, or `unavailable` plus stable finding codes.

It contains no raw host-identity digest, interface inventory, packet data, or caller-selected threshold. `inspect` accepts it only when artifact, host compatibility identity, lifetime, trial count, ratios, and cleanup proofs validate exactly.

## 11. Stable Findings and Exit Codes

Stable blocker codes include:

| Code | Meaning |
|---|---|
| `DG_ARTIFACT_INVENTORY` | bundle has a missing, extra, or unsafe object |
| `DG_ARTIFACT_MANIFEST` | manifest schema, role, target, ABI, or commit is invalid |
| `DG_ARTIFACT_CHECKSUM` | a payload digest does not match |
| `DG_STAGING_ROOT` | root grammar, canonical containment, or parent identity is unsafe |
| `DG_LAYOUT_TYPE` | a required filesystem object has the wrong type |
| `DG_LAYOUT_MODE` | a required mode or ownership contract is not satisfied |
| `DG_LAYOUT_SYMLINK` | a symlink or unsafe hard-link identity is present |
| `DG_SYSTEMD_CONTRACT` | service unit is missing or violates the fixed contract |
| `DG_AUTH_SCHEMA` | authorization JSON is malformed or contains unknown fields |
| `DG_AUTH_EXPIRED` | authorization is outside its bounded lifetime |
| `DG_AUTH_ARTIFACT` | authorization artifact SHA differs from the inspected bundle |
| `DG_AUTH_IDENTITY` | interface identity/topology differs from authorization |
| `DG_INTERFACE_UNSUPPORTED` | target is not an unshared physical interface |
| `DG_XDP_NOT_EMPTY` | native/generic XDP is occupied or unknown |
| `DG_TC_NOT_EMPTY` | TC state is occupied, ambiguous, or unknown |
| `DG_PLATFORM_BLOCKED` | existing preflight contains a platform blocker |
| `DG_EVIDENCE_ROOT` | evidence prerequisite is missing or unsafe |
| `DG_PERFORMANCE_UNAVAILABLE` | performance evidence is missing, noisy, stale, or mismatched |
| `DG_PERFORMANCE_REGRESSION` | a fixed isolated threshold fails |
| `DG_INTERNAL` | a bounded internal invariant prevents a trustworthy report |

Warnings include `DG_REAL_JOURNALD_UNVERIFIED`, `DG_NATIVE_XDP_UNVERIFIED`, and `DG_WORKLOAD_PERFORMANCE_UNVERIFIED`. Warnings cannot conceal a blocker.

Exit codes are:

| Code | Meaning |
|---:|---|
| 0 | `staging_ready` or `canary_candidate` |
| 1 | bounded internal or I/O failure prevented a report |
| 2 | CLI usage or local validation failure |
| 4 | report completed with decision `blocked` |

## 12. Privacy and Output Bounds

Text and JSON output may include only artifact version/commit, kernel release/architecture/logical CPU count, interface name/ifindex/kind/state, abstract consumer/hook state, capability booleans, fixed paths from this specification, sanitized performance aggregates, authorization ID, timestamps, decision, plan, and stable findings.

It excludes:

- MAC, IP, VLAN membership, routes, neighbor state, packet content, raw fingerprints, protocol payloads, and PCAP;
- hostnames, machine IDs, serial numbers, customer labels, environment variables, SSH information, or credentials;
- arbitrary filesystem paths, journal contents, raw BPF map contents, kernel pointers, verifier logs, or error chains;
- topology beyond the minimal supported/unsupported target relationship;
- caller-selected thresholds, bounds, capability lists, paths, or hardening exceptions.

Reports have fixed cardinality and a one-megabyte serialization ceiling. Findings are deduplicated and sorted by severity then code. A serialization overflow fails closed.

## 13. Failure and Recovery Semantics

- Every operation is read-only; a failed checker leaves no rollback work.
- The acceptance harness registers exact cleanup before creating the staging root or namespace.
- Bundle or path identity disagreement stops before reading deeper content.
- Authorization mismatch never causes detach, cleanup, repair, or renewal.
- Existing foreign XDP, TC, programs, maps, or pins are blockers and remain untouched.
- A preflight inspection failure becomes a stable unavailable/blocker result rather than a guessed state.
- Performance timeout, noise, counter rollback, clock anomaly, process disappearance, or identity change invalidates the measurement.
- Interruption cleans only the exact generated staging root, namespace, veth, journal, and pin paths whose identities still match.
- Unknown or non-canonical objects inside a generated cleanup root stop cleanup and require manual review; the harness never widens deletion.

## 14. Verification Strategy

### 14.1 GitHub RED/GREEN development

Every behavior change follows a RED commit whose expected failure is observed in GitHub, followed by a GREEN implementation. Rust format, Clippy, tests, checks, eBPF build, Linux script safety, Windows PowerShell safety, bundle creation, manifest validation, and checksum verification remain GitHub-only where applicable.

Unit and contract coverage includes:

- strict manifest inventory, roles, commit, target, ABI, and checksums;
- path grammar, containment, type, mode, owner contract, symlink, hard-link, and extra-file refusal;
- strict authorization JSON, duplicate/unknown fields, ID grammar, commit binding, 24-hour maximum, expiry boundaries, interface changes, topology changes, and hook changes;
- systemd required/forbidden directives, exact capabilities, absolute `ExecStart`, address families, write paths, stop timeout, and restart policy;
- centralized report decision and sorted findings;
- `CanaryPlanV1` always non-executable and unavailable on untrusted input;
- text/JSON parity, exit codes, one-megabyte bound, and prohibited-field scans;
- deterministic performance calculations, lower-median selection, exact/plus-one thresholds, noise/unavailable behavior, and resource bounds;
- absence of production attach, force, repair, installer, systemctl, journald mutation, probes, drops, policies, and public threshold/path overrides.

### 14.2 Authorized-host generated-root acceptance

Acceptance uses the exact checksum-verified artifact and performs only these scoped mutations:

1. capture a stable read-only network/eBPF identity baseline;
2. create `/run/l2-loop/accept/<run-id>/staging-root` and one generated namespace/veth pair;
3. reproduce the production-shaped layout under that root using bundle files plus generated authorization/performance fixture files bound to the exact artifact;
4. validate `staging_ready`; validate `canary_candidate` separately in GitHub through an injected unshared-physical-interface fixture, never by inspecting a real physical interface during authorized-host acceptance;
5. verify missing/extra file, checksum corruption, wrong mode, symlink, unsafe path, malformed unit, forbidden capability, expired authorization, commit mismatch, ifindex/topology/hook change, and foreign/unknown hook rejection;
6. run bounded pass-through and observe performance trials on generated veth only;
7. prove packet forwarding remains intact and no drop action exists;
8. stop all generated processes and detach only exact owned isolated hooks;
9. remove only exact generated files, directories, pins, journals, veth, and namespace;
10. require stable restoration of the pre-existing network/eBPF identity and zero generated residue.

The harness must not invoke package managers, `systemctl`, `service`, `journalctl`, sysctl, module loading, offload changes, OVS mutation, host route/address mutation, production evidence paths, or physical/business interfaces.

## 15. Acceptance Criteria

Delivery G is complete only when all of the following are true for one final SHA:

1. the approved bundle contains exactly the required files and every checksum matches;
2. the deployment checker is demonstrably read-only and rejects every unsafe layout/identity case;
3. the authorization model is strict, single-interface, commit-bound, maximum-24-hour, and non-overridable;
4. systemd unit syntax and all fixed hardening/capability rules pass contract tests;
5. the generated staging-root happy path returns `staging_ready`, while a fully satisfied injected physical-interface fixture returns `canary_candidate` without inspecting a real physical interface;
6. every canary plan has `executable: false` and no product command can execute it;
7. isolated performance trials meet 95% disabled and 90% observe thresholds or fail closed as unavailable/blocked;
8. the exact GitHub CI has all required jobs green and the artifact manifest binds the same SHA;
9. authorized-host acceptance touches only generated staging-root and namespace/veth resources;
10. independent residue audit finds no generated runtime root, evidence, authorization, namespace, veth, process, journal, pin, map, program, XDP, or TC object;
11. existing network and eBPF identity returns to the stable pre-run baseline;
12. worktree is clean and `HEAD == origin/main`.

## 16. Explicitly Deferred

The following require separate design or authorization:

- writing real `/usr`, `/etc`, `/var`, or production `/run` paths;
- installing, enabling, starting, stopping, or upgrading the real systemd service;
- creating the real evidence root;
- real journald acceptance;
- non-root user/capability reduction beyond the reviewed unit contract;
- physical-interface, native-driver XDP, bond, failover, bridge, OVS, tap, or shared-interface attachment;
- executing a canary plan;
- representative production workload and NIC performance validation;
- topology attribution, 100 ms burst sampling, active probes, confirmed-loop state, packet drops, policing, mitigation, remote notification, or automatic response.

The next separately approved delivery after G is a single-interface read-only canary on an explicitly reserved non-business physical port. Delivery G itself does not grant that approval.

## 17. Reference Basis

- `docs/superpowers/specs/2026-08-06-linux-preflight-safe-attach-design.md`
- `docs/superpowers/specs/2026-08-11-github-build-supply-chain-hardening-design.md`
- `docs/superpowers/specs/2026-08-12-bounded-local-incident-output-design.md`
- `docs/l2-loop-agent-design.md`
- current exact-artifact isolated host harness and ownership journal contracts
