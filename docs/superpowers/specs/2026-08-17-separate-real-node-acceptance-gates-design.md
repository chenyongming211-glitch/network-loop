# Separate Real-Node Acceptance Gates Design

**Date:** 2026-08-17  
**Status:** Implemented and GitHub-verified; all real-node execution remains pending

**Scope:** Delivery G.1.1 operational gate separation

## 1. Problem

Delivery G.1 defined four independent operational gates:

1. fixed-path real installation and exact rollback;
2. systemd/journald lifecycle acceptance using generated namespace/veth only;
3. read-only inspection of one exact reserved physical interface;
4. a separately designed and authorized physical Canary lasting no more than 15 minutes.

The current `scripts/verify-real-install.ps1` controller accepts both installation and service authorization and invokes `scripts/verify-installed-service.ps1` between installation and rollback. Although the authorization documents are distinct, one controller invocation crosses two operational gates. That does not satisfy the stronger requirement that each gate be requested, approved, executed, and reported independently before the next gate can begin.

No real-node gate has yet been executed. The product remains not production-ready.

## 2. Decision

Split real-node acceptance into two independently invocable, fail-closed controllers.

### 2.1 Gate 1: real installation and exact rollback

`scripts/verify-real-install.ps1` will accept only:

- the exact successful GitHub commit;
- one fresh install authorization;
- one fresh rollback authorization for the same transaction;
- the exact deployment authorization;
- the exact performance evidence;
- the explicitly configured SSH target and task-scoped key.

It will execute this fixed sequence:

1. verify the exact successful GitHub artifact and all checksums;
2. derive and bind the target host identity;
3. capture stable network and eBPF identity snapshots;
4. run installer `plan`;
5. run installer `apply`;
6. run the independent installed-layout checker and require `installed_verified`;
7. run exact authorized rollback for the same transaction;
8. compare stable network and eBPF identities with the pre-install snapshots;
9. remove only controller-owned generated transfer state;
10. report `real_install_verified`.

The script will no longer accept `ServiceAuthorizationPath`, import or invoke the service harness, copy a service authorization, or emit `service_decision`.

Gate 1 writes only the installer’s reviewed fixed `/usr`, `/etc`, and `/var/lib/l2-loop` table plus one controller-owned `/run/l2-loop/accept/<run-id>` transfer root. It never starts, stops, enables, disables, or reloads systemd; creates no network interface; and performs no eBPF attachment or cleanup. Its successful terminal state is the exact pre-install filesystem state restored by the authorized rollback, subject to the installer’s durable journal retention contract.

### 2.2 Gate 2: generated-veth installed-service acceptance

A new outer controller, `scripts/verify-real-service-acceptance.ps1`, will establish and remove the fixed-path installation required by the real systemd unit. It will accept a completely new, short-lived authorization set:

- a fresh install authorization with a new transaction and authorization ID;
- a fresh service-acceptance authorization bound to that new transaction;
- a fresh rollback authorization bound to that new transaction;
- the same exact artifact, deployment authorization, performance evidence, host identity, explicit SSH target, and task-scoped key.

It will execute this fixed sequence:

1. repeat exact artifact, checksum, host, and stable network/eBPF verification;
2. plan, apply, and independently verify a new fixed-path installation;
3. invoke `scripts/verify-installed-service.ps1` only after `installed_verified`;
4. require two bounded start/stop cycles using generated namespace/veth identities only;
5. require `service_verified`, exact generated cleanup, restored prior service state, and sanitized journald/stderr evidence;
6. perform the separately authorized exact rollback for the Gate 2 transaction;
7. compare final network/eBPF and outside-install state with the Gate 2 baseline;
8. remove only controller-owned generated transfer state;
9. report `real_service_acceptance_verified`.

Gate 2 does not inherit Gate 1 authorization, transaction state, installed files, or evidence. Repeating the fixed-path install is an explicit part of Gate 2’s requested mutation scope because the production-shaped unit references fixed installed paths. This avoids leaving an installation active while waiting for another authorization.

The inner `scripts/verify-installed-service.ps1` remains narrowly responsible for generated-veth systemd/journald lifecycle acceptance. It cannot install or roll back files and cannot select a physical interface.

## 3. Authorization and Ordering Contract

Each gate is a separate operator decision. Completion of an earlier gate supplies evidence but never grants permission to execute a later gate.

- Every authorization is bound to the exact 40-character artifact commit, target host identity, input digests, operation, transaction where applicable, issue time, and expiry.
- Install, service, and rollback authorization IDs are unique and cannot be reused between Gate 1 and Gate 2.
- Gate 2 may be requested only after Gate 1 returns a successful, reviewed report.
- Gate 3 may be requested only after Gate 2 returns a successful, reviewed report. It remains pathless and read-only and names exactly one reserved physical interface through the installed deployment document.
- Gate 4 cannot be requested until Gates 1–3 pass for the same artifact and host. It requires a new design and authorization bound to the exact interface identity and a duration no greater than 15 minutes.
- No controller automatically invokes the next gate.

An authorization request must enumerate the exact host, artifact, commands, fixed paths, generated names, mutations, stop conditions, evidence, and rollback scope. Approval of design or source changes is not approval to execute a real-node gate.

## 4. Failure and Recovery Semantics

All controllers fail closed.

- Failure before `apply` removes only the exact controller-owned generated transfer root.
- Failure after a successful `apply` attempts only the already authorized rollback for that exact transaction.
- Identity disagreement, foreign state, expired authorization, missing evidence, occupied generated identity, unstable network/eBPF snapshot, or failed exact rollback stops the gate.
- A failed or identity-disagreeing rollback retains the durable ownership journal and reports manual review; it never adopts, overwrites, recursively removes, or cleans foreign state.
- Network/eBPF comparison is observational. The controllers never detach, replace, or clean pre-existing programs or Maps.
- Gate 2 cleanup targets only its generated namespace, veth pair, runtime/work roots, socket created by the owned service instance, and its exact fixed-path install transaction.
- No failure path advances to Gate 3 or Gate 4.

## 5. Reports

Gate 1 retains Schema 1 and removes the service field:

```text
decision = real_install_verified
install_decision = installed_verified
installed_check_decision = installed_verified
rollback_decision = rolled_back
outside_install_state_unchanged = true
network_identity_before == network_identity_after
ebpf_identity_before == ebpf_identity_after
generated_residue_count = 0
```

Gate 2 returns a distinct Schema 1 report:

```text
decision = real_service_acceptance_verified
install_decision = installed_verified
installed_check_decision = installed_verified
service_decision = service_verified
rollback_decision = rolled_back
outside_install_state_unchanged = true
network_identity_before == network_identity_after
ebpf_identity_before == ebpf_identity_after
owned_cleanup_complete = true
generated_residue_count = 0
```

Neither report claims `physical_canary_ready`, production readiness, physical attachment, or Canary success.

## 6. Verification Strategy

Implementation follows GitHub-only RED/GREEN verification. No Rust compilation or test execution occurs on the workstation.

RED script-safety tests will require:

- Gate 1 has no service parameter, authorization copy, harness import/call, or service report field;
- Gate 1 always performs installed verification and exact rollback;
- Gate 2 requires a new install/service/rollback authorization set and a distinct transaction;
- service execution cannot occur before installed verification;
- both controllers snapshot and compare network/eBPF identity and use bounded, identity-exact cleanup;
- neither controller accepts an interface, enables a service, discovers a default route, replaces a hook, removes foreign BPF state, or uses recursive/wildcard cleanup;
- Gate 3 and Gate 4 remain absent from both execution paths.

After the expected RED failure is recorded, the minimum controller and documentation changes will be implemented and all five GitHub jobs must pass for the exact commit. No node connection or real mutation is part of RED/GREEN development.

## 7. Operational Handoff

After the final exact artifact is green, execution stops again. The first real-node request will name one exact SSH target and request only Gate 1. Gate 2 authorization is requested only after the Gate 1 report is complete and reviewed. Gates 3 and 4 remain separately blocked.
