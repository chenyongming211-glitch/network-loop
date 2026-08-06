# Isolated Safe XDP/TC Attachment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task after the Linux read-only preflight plan is accepted. Work directly on `main`; do not create a branch or worktree. Keep all compilation, formatting, linting, and Rust test execution in GitHub Actions; do not run Cargo or a Rust compiler on the local development host.

**Goal:** Prove that the agent can load its fail-open eBPF object, attach XDP and TC without replacing foreign state, publish configuration last, count bounded traffic on an isolated veth, and clean up only objects it owns.

**Architecture:** Add ownership journals and cleanup-path validation before attachment code. Put XDP and TC behind small collision-safe Linux adapters, use an explicit transaction with reverse rollback, and expose isolated verification as an operator harness that refuses physical, bond, bridge, OVS, tap, or live/shared targets. Keep production attachment disabled; this delivery accepts only a generated test run ID and isolated veth identity.

**Tech Stack:** Rust 2024, Aya 0.14, rtnetlink 0.21, netlink-packet-route 0.31, nix 0.31, Tokio, Serde, existing ABI v1 maps, GitHub Actions, Linux network namespaces and veth for authorized host acceptance.

**Design specification:** `docs/superpowers/specs/2026-08-06-linux-preflight-safe-attach-design.md`

**Prerequisite:** Every acceptance criterion in `docs/superpowers/plans/2026-08-06-linux-read-only-preflight.md` is complete for the same or an ancestor commit.

---

## Global Execution Rules

1. Work only on `main`. Use test-first red and minimal green commits, both pushed to `origin/main` and verified in GitHub Actions.
2. Do not run any Rust compiler, Cargo command, formatter, linter, or Rust test locally.
3. Production/live-interface attachment remains disabled. Delivery B may attach only inside a generated isolated network namespace/veth acceptance run.
4. Never call Aya's default legacy XDP attach path on a shared interface. XDP attach must be atomic no-replace; occupied or unknown state is a blocker.
5. Never choose default TC priority/handle. Use handles `0x4c320001` ingress and `0x4c320002` egress, with the first free priority in `49600..=49699`.
6. Never detach, unpin, rename, or delete an object unless current kernel identity and the ownership journal both match.
7. Never delete a shared clsact qdisc. Delete clsact only when the transaction created it and it remains empty of foreign filters; otherwise leave it.
8. Cleanup validates a 32-character lowercase hexadecimal run ID, rejects symlinks and traversal, resolves under `/sys/fs/bpf/l2-loop/test/`, and operates on the exact test namespace/veth names derived from that run ID.
9. All eBPF paths remain fail-open. This delivery adds only total packet/byte counters; it does not parse, probe, fingerprint, police, drop, or rate-limit.
10. Do not put target identity, SSH credentials, exact host inventory, or foreign pin names in repository files, GitHub secrets, workflow logs, or artifact metadata.

## Task 1: Add Total Packet/Byte Counters Without Changing Verdicts

**Files:**

- Modify: `crates/l2-loop-common/src/abi.rs`
- Modify: `crates/l2-loop-common/tests/layout.rs`
- Modify: `ebpf/l2-loop-ebpf/src/maps.rs`
- Modify: `ebpf/l2-loop-ebpf/src/programs.rs`
- Modify: `xtask/tests/contract.rs`

### Step 1: Write the failing ABI and source-contract tests

Use the existing `HOOK_STATS` map and `CounterValue`. Add tests that all four program bodies invoke the same accounting helper and still return only `XDP_PASS` or `TC_ACT_OK`. Assert the counter key is bounded by ifindex, hook role, traffic class `ALL`, verdict `PASS`, and reason `NONE`.

### Step 2: Push red, then implement minimal accounting

```powershell
git add crates/l2-loop-common ebpf/l2-loop-ebpf xtask
git commit -m "test: define fail-open traffic counters"
git push origin main
```

Expected failure: the eBPF source/object contract cannot find the accounting helper or its call sites.

Implement safe packet length extraction and a per-CPU counter increment. On missing map entries, insertion failure, malformed context, or any other error, immediately return the existing pass/continue verdict. Do not access bytes beyond what total length calculation requires.

### Step 3: Push green

```powershell
git add crates/l2-loop-common ebpf/l2-loop-ebpf xtask
git commit -m "feat: count fail-open hook traffic"
git push origin main
```

Expected: userspace ABI tests and the eBPF build/object inspection pass in GitHub.

## Task 2: Implement Ownership Journals and Safe Test Paths

**Files:**

- Create: `crates/l2-loop-agent/src/ownership.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Create: `crates/l2-loop-agent/tests/ownership.rs`

### Step 1: Write failing journal and cleanup-target tests

Define schema version 1 and test round trips for:

```rust
pub struct OwnershipRecord {
    pub schema_version: u16,
    pub abi_version: u16,
    pub generation: u64,
    pub ifindex: u32,
    pub xdp: Option<OwnedXdp>,
    pub tc: Vec<OwnedTc>,
    pub pin_paths: Vec<PathBuf>,
    pub created_at_unix_seconds: u64,
}
```

Test a generated run ID is exactly 32 lowercase hexadecimal characters. Accept only `/run/l2-loop/tests/<run-id>.json` and `/sys/fs/bpf/l2-loop/test/<run-id>/...`. Reject uppercase, short/long IDs, separators, `..`, absolute suffixes, symlinks, empty paths, the test root itself, production paths, and foreign roots.

Test atomic journal replacement writes a sibling temporary file, fsyncs, renames, and results in mode `0600`. Use a temporary directory and an injected filesystem; never touch `/run`, `/var/lib`, or bpffs in CI.

### Step 2: Push red, then implement

```powershell
git add crates/l2-loop-agent
git commit -m "test: define attachment ownership records"
git push origin main
```

Expected failure: ownership types and validated path constructors are missing.

Implement `RunId`, `TestPinRoot`, `JournalPath`, kernel-identity comparison helpers, and atomic save/load. A missing, malformed, stale, or mismatched journal returns a blocker; it never returns an automatic cleanup target.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent
git commit -m "feat: record exact attachment ownership"
git push origin main
```

Expected: ownership and path-validation tests pass with no privileged filesystem access.

## Task 3: Implement Atomic No-Replace XDP Attachment

**Files:**

- Create: `crates/l2-loop-agent/src/linux/xdp.rs`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Create: `crates/l2-loop-agent/tests/xdp_safety.rs`

### Step 1: Write failing state-machine and netlink tests

Cover XDP states `Empty`, `Owned`, `Foreign`, `Unknown`, and mode-specific native/generic occupancy. Assert only `Empty` reaches attach, `Foreign` produces `PF_XDP_OCCUPIED`, and query errors produce `PF_XDP_STATE_UNKNOWN`.

Inspect the encoded request and require the no-replace flag equivalent to `XDP_FLAGS_UPDATE_IF_NOEXIST`. Simulate `EEXIST` and verify no retry without the flag. Simulate post-attach ID mismatch and require rollback only when the currently attached ID still equals the newly loaded ID. An ownership mismatch must leave the hook untouched and return evidence.

### Step 2: Push red, then implement the focused adapter

```powershell
git add crates/l2-loop-agent
git commit -m "test: define collision-safe XDP attachment"
git push origin main
```

Expected failure: safe XDP query/attach/detach adapter does not exist.

Implement a focused rtnetlink adapter that:

1. dumps XDP state for the exact ifindex and mode;
2. refuses unknown or occupied state;
3. sends one atomic no-replace attach request;
4. re-queries and verifies the program ID/tag;
5. returns `OwnedXdp` for journal persistence;
6. detaches only after current identity matches the record.

Do not call `aya::programs::Xdp::attach()` for this operation because its legacy fallback does not preserve the required shared-interface no-replace guarantee.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent
git commit -m "feat: attach XDP without replacement"
git push origin main
```

Expected: all synthetic netlink/state tests pass; no CI test needs CAP_NET_ADMIN.

## Task 4: Implement Explicit, Ownership-Aware TC Attachment

**Files:**

- Create: `crates/l2-loop-agent/src/linux/tc.rs`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Create: `crates/l2-loop-agent/tests/tc_safety.rs`

### Step 1: Write failing TC selection and detach tests

Test existing/absent clsact, unknown qdisc state, every occupied priority, selection of the first free priority, explicit ingress/egress handles, foreign handle collision, and exact program-ID matching on detach. Required constants are:

```rust
pub const TC_HANDLE_INGRESS: u32 = 0x4c32_0001;
pub const TC_HANDLE_EGRESS: u32 = 0x4c32_0002;
pub const TC_PRIORITY_START: u16 = 49_600;
pub const TC_PRIORITY_END: u16 = 49_699;
```

Prove a pre-existing clsact is never deleted. If this transaction created clsact, cleanup may delete it only after owned filters are gone and a fresh dump proves no foreign filters use it.

### Step 2: Push red, then implement

```powershell
git add crates/l2-loop-agent
git commit -m "test: define collision-safe TC attachment"
git push origin main
```

Expected failure: TC inventory, explicit selection, and owned detach functions do not exist.

Implement netlink qdisc/filter dumps, deterministic priority selection, explicit filter create, post-create program-ID verification, and exact owned deletion. Never invoke `tc`, never use a shell, and never accept kernel-assigned priority/handle values.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent
git commit -m "feat: attach owned TC filters safely"
git push origin main
```

Expected: TC safety tests pass without touching host qdiscs.

## Task 5: Build the Fail-Safe Attachment Transaction

**Files:**

- Modify: `crates/l2-loop-agent/src/ports.rs`
- Modify: `crates/l2-loop-agent/src/service.rs`
- Create: `crates/l2-loop-agent/src/attach.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Create: `crates/l2-loop-agent/tests/attach_transaction.rs`

### Step 1: Write failing transaction tests

With call-recording fakes, require this exact success order:

```text
preflight -> raise_memlock -> load_and_validate_abi -> attach_xdp_no_replace
-> verify_xdp -> attach_tc_explicit -> verify_tc -> initialize_maps
-> save_ephemeral_journal -> publish_iface_config -> observing
```

Inject a failure after every operation. Require reverse rollback of only completed owned operations. `IFACE_CONFIG` must be absent until all hooks, maps, and the ephemeral journal are verified. If journal persistence fails, publish nothing and roll back hooks. Cleanup errors are aggregated as evidence without broad cleanup.

Test that physical, bond, bridge, OVS-internal, tap, unsupported, or `live/shared = true` inputs return `PF_LIVE_INTERFACE` before memlock or BPF work.

### Step 2: Push red, then implement

```powershell
git add crates/l2-loop-agent
git commit -m "test: define isolated attachment transaction"
git push origin main
```

Expected failure: `AttachmentTransaction` and the required ports do not exist.

Implement separate `ResourceLimits`, `BpfObjectLoader`, `SafeXdp`, `SafeTc`, `MapPublisher`, and `OwnershipStore` ports. Raise only the daemon process memlock to infinity before BPF object creation; a failure returns `PF_MEMLOCK_TOO_LOW` before any interface change. Generate a non-zero generation and publish `IFACE_CONFIG` last.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent
git commit -m "feat: add isolated attachment transaction"
git push origin main
```

Expected: success and every partial-failure rollback path pass with deterministic fakes.

## Task 6: Integrate Aya Object Loading, Map Initialization, and Owned Cleanup

**Files:**

- Modify: `crates/l2-loop-agent/Cargo.toml`
- Create: `crates/l2-loop-agent/src/linux/bpf_object.rs`
- Create: `crates/l2-loop-agent/src/linux/maps.rs`
- Create: `crates/l2-loop-agent/src/linux/cleanup.rs`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Create: `crates/l2-loop-agent/tests/bpf_object_contract.rs`
- Create: `crates/l2-loop-agent/tests/cleanup_plan.rs`

### Step 1: Write failing object and cleanup contract tests

Given a fixture object description, require ABI version 1, exact program/map names, expected map key/value sizes, and capacity floors before attach. Test cleanup plans contain only journal-confirmed XDP, TC, map, pin, and ephemeral journal identities, ordered in reverse creation order.

Test that a fresh kernel mismatch removes the operation from the executable cleanup plan and reports it as retained foreign/changed state.

### Step 2: Push red, then implement

```powershell
git add crates/l2-loop-agent
git commit -m "test: define BPF load and cleanup contract"
git push origin main
```

Expected failure: object validation, map publisher, and cleanup planner are absent.

Add Aya to the userspace agent. Load the GitHub-bundled `l2-loop-ebpf.o`, validate every public name and ABI layout before creating pins, initialize dependent entries, then publish `IFACE_CONFIG`. Use test pins only below `/sys/fs/bpf/l2-loop/test/<run-id>/`. Cleanup re-queries each kernel identity immediately before its exact operation.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent
git commit -m "feat: load and clean owned BPF state"
git push origin main
```

Expected: object/cleanup contract tests pass; GitHub still builds the eBPF object and MUSL bundle.

## Task 7: Add an Isolated-Only Daemon Control Path

**Files:**

- Modify: `crates/l2-loop-core/src/command.rs`
- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Modify: `crates/l2-loop-cli/src/args.rs`
- Modify: `crates/l2-loop-cli/src/convert.rs`
- Modify: `crates/l2-loop-cli/src/render.rs`
- Create: `crates/l2-loop-agent/tests/isolated_control.rs`
- Modify: `crates/l2-loop-cli/tests/cli.rs`

### Step 1: Write failing control-boundary tests

Add internal operator commands `IsolatedAttach { interface, run_id }` and `IsolatedDetach { run_id }`. The daemon must independently re-run preflight and validate the interface kind/isolation; a CLI flag cannot bypass safety. Require blocked response code `4` for every non-veth or live/shared target.

The public help text must say these commands are for generated isolated verification only. There is no production `attach`, `force`, `replace`, `adopt`, `cleanup-all`, or interface-discovery flag.

### Step 2: Push red, then implement the boundary

```powershell
git add crates/l2-loop-core crates/l2-loop-agent crates/l2-loop-cli
git commit -m "test: define isolated attachment control boundary"
git push origin main
```

Expected failure: isolated attach/detach commands are missing or not dispatched.

Implement request conversion and dispatch to `AttachmentTransaction`. Detach requires only the validated run ID; the daemon loads the ephemeral journal and refuses mismatches. Do not expose a generic production attach command.

### Step 3: Push green

```powershell
git add crates/l2-loop-core crates/l2-loop-agent crates/l2-loop-cli
git commit -m "feat: expose isolated attachment control"
git push origin main
```

Expected: control tests pass and unsafe verbs remain absent from CLI help.

## Task 8: Add the Authorized Isolated Host Harness

**Files:**

- Create: `scripts/verify-isolated-host.ps1`
- Create: `scripts/lib/IsolatedNames.psm1`
- Create: `scripts/tests/verify-isolated-host.Tests.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/development.md`
- Modify: `.gitignore`

### Step 1: Write failing PowerShell safety tests

Test deterministic names derived from a 128-bit run ID, exact SSH argument arrays, and cleanup guards. The harness must refuse empty/invalid run IDs, non-veth targets, names not generated for the active run, symlinks under the test pin path, or a namespace/veth already present before the run.

Static tests require cleanup registration before the first mutation and require cleanup in `finally`, process-exit, timeout, and interrupt paths. Scan the script to forbid `rm -rf`, wildcards in deletion targets, `eval`, shell interpolation of remote values, package managers, service commands, sysctl, ethtool, physical/OVS/bond operations, and actual target details. Add a GitHub `script-tests` job that invokes `pwsh -NoProfile -File scripts/tests/verify-isolated-host.Tests.ps1`; the test file uses self-contained assertions and installs no PowerShell module.

### Step 2: Push red, then implement the operator harness

```powershell
git add scripts docs/development.md .gitignore .github/workflows/ci.yml
git commit -m "test: define isolated host harness safety"
git push origin main
```

Expected GitHub failure: the `script-tests` job invokes the test file and fails because harness module/functions are missing.

Implement the harness with mandatory task-scoped environment inputs `L2_LOOP_TEST_TARGET` and `L2_LOOP_TEST_KEY`; do not accept them as values committed to a file. It performs this exact bounded sequence:

1. download the exact commit's green GitHub artifact and verify checksums;
2. capture read-only before identities;
3. create one generated namespace and one veth pair with no bridge, bond, OVS, or route membership;
4. start the bundled daemon in an operator temporary directory;
5. run preflight on the isolated endpoint;
6. request isolated attach in generic XDP mode plus TC;
7. send a fixed bounded count of local frames and verify packet/byte counters increase;
8. request exact owned detach;
9. remove the exact generated veth/namespace and test pin/journal paths;
10. compare after identities and require no generated names or owned objects remain.

Use direct argv arrays for `ssh` and remote commands. No real target address, key path, hostname, interface name, or inventory is printed into GitHub logs or stored in the repository.

### Step 3: Push green

```powershell
git add scripts docs/development.md .gitignore .github/workflows/ci.yml
git commit -m "test: add isolated host verification harness"
git push origin main
```

Expected: script safety/unit tests pass in GitHub; the workflow does not contact a target host.

## Task 9: Run Authorized Isolated Acceptance and Fault Injection

**Files:**

- Modify only code/tests required by a reproduced defect
- Do not commit raw host snapshots, target identity, credentials, or foreign object names

### Step 1: Select the exact green artifact

```powershell
$L2LoopCommit = git rev-parse HEAD
$L2LoopRun = gh run list --branch main --commit $L2LoopCommit --limit 1 --json databaseId,conclusion,url
if ($L2LoopRun -notmatch '"conclusion":"success"') { throw "Exact commit is not green" }
```

Set `$env:L2_LOOP_TEST_TARGET` and `$env:L2_LOOP_TEST_KEY` only in the operator session, then run `scripts/verify-isolated-host.ps1 -Commit $L2LoopCommit`.

### Step 2: Exercise success and bounded failures

Run the clean success case, then fault-injection cases for TC attach failure after XDP, map initialization failure after both hooks, daemon termination while observing, identity change before detach, and interruption during traffic. Each case must leave foreign before/after identities unchanged and no generated namespace, veth, program, map, filter, journal, or pin behind. Identity-change cases intentionally retain the changed object and report manual review instead of deleting it.

### Step 3: Acceptance gate

Delivery B passes only when:

- the exact deployed commit is green in all GitHub jobs;
- isolated preflight is ready and live/shared preflight remains blocked for attachment;
- generic XDP and TC are both verified by program ID;
- bounded traffic increments packet/byte counters;
- every verdict remains pass/continue;
- partial failure rolls back only owned state;
- no physical, bond, bridge, OVS, tap, route, sysctl, service, package, offload, or foreign BPF state changes;
- all generated test state is gone after cleanup.

If a defect appears, first add a deterministic reproducing test and observe the expected red GitHub run, then implement the smallest fix and require a green run before repeating host acceptance.

## Task 10: Final Safety and Scope Audit

**Files:**

- Modify: `README.md`
- Modify: `docs/development.md`
- Modify only files required by audit failures

### Step 1: Run non-compiling repository scans

```powershell
git diff --check
rg -n "XDP_DROP|TC_ACT_SHOT|cleanup-all|replace|force-attach|adopt" crates ebpf scripts README.md docs/development.md
rg -n "0x4c32_0001|0x4c32_0002|49_600|49_699|UPDATE_IF_NOEXIST" crates
$L2LoopForbidden = @(("TO" + "DO"), ("T" + "BD"), ("PLACE" + "HOLDER"), ("machine" + "_id"), ("host" + "name"), ("mac" + "_address"), ("ip" + "_address")) -join "|"
rg -n $L2LoopForbidden docs/superpowers/plans crates ebpf scripts .github README.md docs/development.md
```

Expected: no drop action, dangerous CLI, incomplete planning marker, legacy product keyword, credential path, target identity, or prohibited output field exists; all collision-safe constants are present.

### Step 2: Require final GitHub evidence

Push documentation/audit corrections, wait for the exact commit's complete CI, and record only the commit SHA, GitHub Actions URL, artifact name, and acceptance pass/fail summary. Do not claim completion from a different commit's artifact or from local inspection alone.
