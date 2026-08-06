# Linux Read-Only Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task. Work directly on `main`; do not create a branch or worktree. Keep all compilation, formatting, linting, and Rust test execution in GitHub Actions; do not run Cargo or a Rust compiler on the local development host.

**Goal:** Deliver a real `l2-loopd` Unix-socket service and `l2-loopctl preflight` command that inspect an explicitly named Linux interface, derive stable findings, and make no host changes.

**Architecture:** Put all serializable preflight types and decision invariants in `l2-loop-core`, transport-independent orchestration in a dedicated `PreflightService<P>`, and Linux inspection below `l2-loop-agent/src/linux/`. Use rtnetlink/sysfs/procfs and focused syscall adapters, with injected snapshots for tests. Keep the existing protocol at version 1 and make the CLI a one-request/one-response Unix-socket client.

**Tech Stack:** Rust 2024, Tokio 1.40, Serde/serde_json, Clap 4.5, thiserror, rtnetlink 0.21, netlink-packet-route 0.31, nix 0.31, GitHub Actions, `x86_64-unknown-linux-musl`.

**Design specification:** `docs/superpowers/specs/2026-08-06-linux-preflight-safe-attach-design.md`

---

## Global Execution Rules

1. Work only on `main` and push every red and green commit to `origin/main`.
2. Never run `cargo`, `rustc`, `rustup`, rustfmt, Clippy, `bpf-linker`, or another compiler locally. Local checks are limited to `git`, `rg`, file inspection, and `git diff --check`.
3. For each behavior slice, commit the test first, push it, and verify that GitHub Actions fails for the intended missing behavior. Only then add the implementation and require a green run.
4. Never weaken, skip, ignore, or delete a test to make CI green.
5. Delivery A is read-only: do not change rlimits, create directories or sockets outside the daemon socket path, create BPF objects, attach programs, alter qdiscs, install packages, restart services, change sysctls, or change interfaces.
6. Do not commit or log SSH keys, target addresses, hostnames, interface inventory, MAC/IP addresses, machine IDs, routes, customer labels, packet contents, or foreign pin-path names.
7. Use the exact stable blocker codes from the design. Sort findings by severity and then code before serialization or rendering.
8. After every push, identify the run for the exact commit and wait for it:

```powershell
$L2LoopCommit = git rev-parse HEAD
$L2LoopRun = gh run list --branch main --commit $L2LoopCommit --limit 1 --json databaseId --jq '.[0].databaseId'
gh run watch $L2LoopRun --exit-status
```

## Task 1: Add the OS-Neutral Preflight Contract

**Files:**

- Create: `crates/l2-loop-core/src/preflight.rs`
- Modify: `crates/l2-loop-core/src/command.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Create: `crates/l2-loop-core/tests/preflight_report.rs`

### Step 1: Write the failing report-contract tests

Cover snake-case JSON for every enum, a complete report round trip, stable finding order, all eleven blocker codes, and decision derivation. The essential invariant test is:

```rust
let findings = vec![
    PreflightFinding::warning("PF_OVS_DISCOVERY", "optional topology lookup failed"),
    PreflightFinding::blocker(PF_XDP_OCCUPIED, "XDP hook is occupied"),
];
let report = PreflightReport::new(interface(), kernel(), bpf(), findings);
assert_eq!(report.decision, PreflightDecision::Blocked);
assert_eq!(report.findings[0].severity, FindingSeverity::Blocker);
assert_eq!(report.findings[0].code, PF_XDP_OCCUPIED);
```

Assert that `PreflightReport::new` derives `Ready`, `ReadyWithWarnings`, or `Blocked`; callers do not supply the decision. Serialize a report and assert that none of these keys appears: `ip`, `mac`, `hostname`, `machine_id`, `routes`, `packet`, `customer`.

### Step 2: Push the red contract

```powershell
git add crates/l2-loop-core
git commit -m "test: define preflight report contract"
git push origin main
```

Expected GitHub failure: `preflight_report` cannot import `PreflightReport`, `PreflightFinding`, or the blocker constants.

### Step 3: Implement the domain model

Define these public types in `preflight.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightDecision { Ready, ReadyWithWarnings, Blocked }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity { Blocker, Warning, Information }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightFinding { pub code: String, pub severity: FindingSeverity, pub message: String }
```

Also define `InterfaceKind`, `InterfaceInspection`, `AttachmentTarget`, `AttachmentState`, `KernelInspection`, `BpfInspection`, `MemlockInspection`, and `PreflightReport`. Keep fields to names/ifindices, state/kind/master relationships, program/filter IDs, attach modes, capability booleans, and numeric limits:

```rust
pub enum InterfaceKind { Physical, Bond, Veth, Bridge, OvsInternal, Tap, Unsupported }
pub enum BondMode { ActiveBackup, Unsupported }
pub struct InterfaceRef { pub name: InterfaceName, pub ifindex: u32 }
pub struct BondInspection {
    pub mode: BondMode,
    pub slaves: Vec<InterfaceRef>,
    pub active_slave: Option<InterfaceRef>,
}
pub struct AttachmentTarget { pub interface: InterfaceRef, pub role: HookRole }
pub struct InterfaceInspection {
    pub requested: InterfaceRef,
    pub kind: InterfaceKind,
    pub admin_up: bool,
    pub oper_up: bool,
    pub master: Option<InterfaceRef>,
    pub bond: Option<BondInspection>,
    pub proposed_targets: Vec<AttachmentTarget>,
    pub isolated: bool,
    pub live_shared: bool,
}
pub enum AttachmentState {
    Empty,
    Owned { program_id: u32 },
    Occupied { program_id: u32 },
    Unknown,
}
pub enum PinRootState { Absent, Empty, Owned, Foreign }
pub struct TcAttachment {
    pub direction: Direction,
    pub priority: u16,
    pub handle: u32,
    pub program_id: u32,
}
pub struct MemlockInspection {
    pub soft_bytes: Option<u64>,
    pub hard_bytes: Option<u64>,
    pub required_bytes: u64,
    pub can_raise: bool,
}
pub struct KernelInspection {
    pub architecture: String,
    pub release: String,
    pub bpf_syscall: bool,
    pub bpf_jit: bool,
    pub btf_readable: bool,
    pub tc_clsact: bool,
}
pub struct BpfInspection {
    pub bpffs_mounted: bool,
    pub relevant_objects_enumerable: bool,
    pub pin_root: PinRootState,
    pub xdp_native: AttachmentState,
    pub xdp_generic: AttachmentState,
    pub tc_ingress: Vec<TcAttachment>,
    pub tc_egress: Vec<TcAttachment>,
    pub memlock: MemlockInspection,
}
```

Represent unlimited rlimits as `None`; finite values are `Some(bytes)`. `PinRootState` never contains a foreign path. Add exactly these constants:

```rust
pub const PF_INTERFACE_MISSING: &str = "PF_INTERFACE_MISSING";
pub const PF_INTERFACE_UNSUPPORTED: &str = "PF_INTERFACE_UNSUPPORTED";
pub const PF_BOND_NO_ACTIVE_SLAVE: &str = "PF_BOND_NO_ACTIVE_SLAVE";
pub const PF_XDP_STATE_UNKNOWN: &str = "PF_XDP_STATE_UNKNOWN";
pub const PF_XDP_OCCUPIED: &str = "PF_XDP_OCCUPIED";
pub const PF_TC_STATE_UNKNOWN: &str = "PF_TC_STATE_UNKNOWN";
pub const PF_TC_HANDLE_COLLISION: &str = "PF_TC_HANDLE_COLLISION";
pub const PF_PIN_ROOT_FOREIGN: &str = "PF_PIN_ROOT_FOREIGN";
pub const PF_MEMLOCK_TOO_LOW: &str = "PF_MEMLOCK_TOO_LOW";
pub const PF_KERNEL_CAPABILITY: &str = "PF_KERNEL_CAPABILITY";
pub const PF_LIVE_INTERFACE: &str = "PF_LIVE_INTERFACE";
```

Add `AgentCommand::Preflight { interface: InterfaceName }` and `AgentResult::Preflight { report: PreflightReport }` without changing `PROTOCOL_VERSION`.

### Step 4: Push the green implementation

```powershell
git add crates/l2-loop-core
git commit -m "feat: add preflight report model"
git push origin main
```

Expected: all core tests pass in the GitHub `Userspace` job.

## Task 2: Add Preflight Orchestration and Report Invariants

**Files:**

- Modify: `crates/l2-loop-agent/src/ports.rs`
- Create: `crates/l2-loop-agent/src/preflight.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Create: `crates/l2-loop-agent/tests/preflight_service.rs`

### Step 1: Write failing service tests

Create a fake inspector and prove that the service:

- forwards only the explicit `InterfaceName`;
- sorts findings and derives the decision again at the trust boundary;
- rejects an internally inconsistent or structurally invalid report as `PortError`;
- never invokes an attachment or cleanup port;
- preserves all stable finding codes and strips no blocker.

Use the approved boundary:

```rust
pub trait PlatformInspector {
    fn inspect(&mut self, interface: &InterfaceName) -> Result<PreflightReport, PortError>;
}

pub struct PreflightService<P> { inspector: P }
```

### Step 2: Push red, then implement the minimum service

```powershell
git add crates/l2-loop-agent
git commit -m "test: define preflight service behavior"
git push origin main
```

Expected failure: `PlatformInspector` and `PreflightService` do not exist.

Implement `PreflightService::execute(&mut self, &InterfaceName) -> Result<AgentResult, PortError>`. Rebuild the report through `PreflightReport::new` before returning it so a platform adapter cannot force `Ready` in the presence of a blocker.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent
git commit -m "feat: add preflight service"
git push origin main
```

Expected: `preflight_service` passes and existing `AgentService<R, H>` tests remain unchanged.

## Task 3: Implement Strict Snapshot Parsers for Linux State

**Files:**

- Modify: `Cargo.toml`
- Modify: `crates/l2-loop-agent/Cargo.toml`
- Create: `crates/l2-loop-agent/src/linux/mod.rs`
- Create: `crates/l2-loop-agent/src/linux/interface.rs`
- Create: `crates/l2-loop-agent/src/linux/bond.rs`
- Create: `crates/l2-loop-agent/src/linux/topology.rs`
- Create: `crates/l2-loop-agent/src/linux/limits.rs`
- Create: `crates/l2-loop-agent/src/linux/bpf_inventory.rs`
- Create: `crates/l2-loop-agent/tests/linux_fixtures.rs`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/active-backup.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/no-active-slave.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/bond/malformed.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/proc/mounts.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/proc/limits-raisable.txt`
- Create: `crates/l2-loop-agent/tests/fixtures/proc/limits-blocked.txt`

### Step 1: Write failing pure parser tests

Test physical, bond, veth, bridge, tap, OVS-internal, and unsupported classification from injected link records. Bond parsing must accept active-backup, preserve slave order, reject malformed mode, and produce `PF_BOND_NO_ACTIVE_SLAVE` when the active slave is absent or disappears from the link snapshot.

Test mount parsing for bpffs exactly at `/sys/fs/bpf`, memlock soft/hard parsing, BTF readability, architecture mismatch, and pin-root states `Absent`, `Empty`, `Owned`, and `Foreign`. Test that foreign top-level roots are represented only as counts/booleans, never as path names or cleanup targets.

### Step 2: Push red

```powershell
git add Cargo.toml crates/l2-loop-agent
git commit -m "test: define Linux preflight parsers"
git push origin main
```

Expected failure: Linux modules and parser functions are unresolved.

### Step 3: Add dependencies and implement pure parsers

Add centralized dependencies `futures-util = "0.3.31"`, `nix = { version = "0.31.3", features = ["resource", "fs", "user"] }`, `rtnetlink = "0.21.0"`, and `netlink-packet-route = "0.31.0"`. Enable Tokio `fs`, `process`, `sync`, and `time` features for the agent.

Implement parsing as pure functions over bytes or typed link records. `topology.rs` may run only this optional direct command, with a two-second kill deadline and no shell:

```rust
Command::new("ovs-vsctl")
    .args(["--timeout=2", "iface-to-br", interface.as_str()])
    .kill_on_drop(true)
    .output()
```

Treat command absence, timeout, non-zero exit, and invalid UTF-8 as a warning. Do not expose stderr to the protocol response.

### Step 4: Push green

```powershell
git add Cargo.toml crates/l2-loop-agent
git commit -m "feat: parse Linux preflight state"
git push origin main
```

Expected: parser fixture tests pass; no test needs root or host networking.

## Task 4: Assemble the Read-Only Linux Inspector

**Files:**

- Modify: `crates/l2-loop-agent/src/linux/interface.rs`
- Modify: `crates/l2-loop-agent/src/linux/bpf_inventory.rs`
- Modify: `crates/l2-loop-agent/src/linux/limits.rs`
- Modify: `crates/l2-loop-agent/src/linux/topology.rs`
- Create: `crates/l2-loop-agent/src/linux/inspector.rs`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Create: `crates/l2-loop-agent/tests/linux_inspector.rs`

### Step 1: Write failing adapter tests around injected I/O

Define internal traits `LinkSource`, `FileSource`, `BpfQuery`, and `CommandSource`. Use fakes to cover missing interface, ifindex zero, ambiguous master, live/shared interface, unknown and occupied XDP, unknown TC, TC handle collision, foreign pin root, raisable soft memlock warning, hard memlock blocker, missing BPF/JIT/BTF, and a ready isolated veth.

Prove call history contains reads/queries only. Any mutation-shaped method is absent from the Delivery A traits.

### Step 2: Push red, then implement the inspector

```powershell
git add crates/l2-loop-agent
git commit -m "test: define Linux preflight inspection"
git push origin main
```

Expected failure: `LinuxInspector` and injected source traits do not exist.

Implement `LinuxInspector` using rtnetlink link dumps, `/sys/class/net`, `/proc/net/bonding`, `/proc/mounts`, `/proc/self/limits`, `/sys/kernel/btf/vmlinux`, and focused read-only BPF queries. Preserve the approved synchronous `PlatformInspector` boundary by running the async rtnetlink collector on a dedicated current-thread runtime worker; the socket handler calls the service through `spawn_blocking`, so no Tokio runtime is nested. Resolve only the named interface. Do not read addresses or routes. Do not enumerate unrelated map contents. Report native and generic XDP separately.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent
git commit -m "feat: inspect Linux preflight state"
git push origin main
```

Expected: synthetic ready/warning/blocker cases pass without privileges.

## Task 5: Implement the Bounded Unix Control Socket

**Files:**

- Modify: `crates/l2-loop-agent/src/protocol.rs`
- Create: `crates/l2-loop-agent/src/transport.rs`
- Create: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Create: `crates/l2-loop-agent/tests/unix_transport.rs`

### Step 1: Write failing transport tests

Use a temporary socket path and assert:

- one request and one response per connection;
- four-byte big-endian framing and the one-megabyte payload cap;
- malformed JSON, early EOF, oversized frames, and unknown protocol versions return typed errors without panic;
- a semaphore caps active handlers at 16;
- a request exceeding five seconds returns `REQUEST_TIMEOUT`;
- stale non-socket paths are never unlinked;
- the created socket is mode `0600` on Unix.

### Step 2: Push red, then implement bounded I/O

```powershell
git add crates/l2-loop-agent
git commit -m "test: define Unix control transport"
git push origin main
```

Expected failure: transport server/client functions are missing.

Implement `read_frame` so it reads the prefix, rejects lengths above `MAX_PAYLOAD_LEN` before allocation, then reads exactly the declared bytes. Bind `/run/l2-loop/agent.sock` by default, require the parent directory to be root-owned and non-group/world-writable, set socket mode `0600`, and use `tokio::time::timeout(Duration::from_secs(5), ...)` plus a 16-permit semaphore. Convert all client-controlled failures to stable response codes.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent
git commit -m "feat: serve bounded Unix control requests"
git push origin main
```

Expected: Unix transport tests pass on GitHub and no server test accesses `/run`.

## Task 6: Complete the CLI Client, Rendering, and Exit Codes

**Files:**

- Modify: `crates/l2-loop-cli/Cargo.toml`
- Modify: `crates/l2-loop-cli/src/args.rs`
- Modify: `crates/l2-loop-cli/src/convert.rs`
- Create: `crates/l2-loop-cli/src/client.rs`
- Create: `crates/l2-loop-cli/src/render.rs`
- Modify: `crates/l2-loop-cli/src/lib.rs`
- Modify: `crates/l2-loop-cli/src/main.rs`
- Modify: `crates/l2-loop-cli/tests/cli.rs`
- Create: `crates/l2-loop-cli/tests/render.rs`
- Create: `crates/l2-loop-cli/tests/socket_round_trip.rs`

### Step 1: Write failing CLI and rendering tests

Test `l2-loopctl preflight --interface eth0` and the same command with `--json`. Reject missing interfaces and interface names containing whitespace, `/`, NUL, or more than Linux `IFNAMSIZ - 1` bytes. Assert text output has decision/findings and JSON is stable snake-case. Scan both outputs for prohibited identity keys.

Assert exit code `0` for ready/warnings, `4` for blocked, `1` for transport/internal errors, and Clap `2` for usage errors.

### Step 2: Push red, then implement

```powershell
git add crates/l2-loop-cli
git commit -m "test: define preflight CLI behavior"
git push origin main
```

Expected failure: preflight args, socket client, renderers, and exit mapping are missing.

Implement a client that connects to `/run/l2-loop/agent.sock`, sends exactly one request, reads exactly one response, and closes. `--json` is stored outside `AgentCommand` so it affects rendering only. Keep `main` as parse → connect → send → render → exit-code mapping.

### Step 3: Push green

```powershell
git add crates/l2-loop-cli
git commit -m "feat: add preflight CLI client"
git push origin main
```

Expected: parser, renderer, and real temporary-socket round-trip tests pass.

## Task 7: Wire the Daemon Dispatcher End to End

**Files:**

- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Create: `crates/l2-loop-agent/tests/daemon_dispatch.rs`
- Modify: `README.md`
- Modify: `docs/development.md`

### Step 1: Write a failing end-to-end dispatch test

Start the daemon on a temporary socket with a fake `PlatformInspector`, send a framed `Preflight` command through the real client, and assert the returned report. Send a non-preflight command and require the stable `COMMAND_NOT_IMPLEMENTED` error until its service is wired in a later slice. Assert daemon shutdown removes only its own socket.

### Step 2: Push red, then wire production construction

```powershell
git add crates/l2-loop-agent README.md docs/development.md
git commit -m "test: define daemon preflight dispatch"
git push origin main
```

Expected failure: production dispatch does not invoke `PreflightService<LinuxInspector>`.

Construct `LinuxInspector`, `PreflightService`, and the socket server in `main.rs`. Handle SIGINT/SIGTERM with graceful socket cleanup. Update public docs with the CLI syntax, exit codes, read-only guarantee, and the fact that compilation happens only in GitHub.

### Step 3: Push green

```powershell
git add crates/l2-loop-agent README.md docs/development.md
git commit -m "feat: wire daemon preflight dispatch"
git push origin main
```

Expected: a complete fake-inspector Unix-socket round trip is green.

## Task 8: Produce the GitHub-Only MUSL Bundle

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `.gitignore`
- Modify: `xtask/src/main.rs`
- Create: `xtask/src/bundle.rs`
- Create: `xtask/tests/bundle_manifest.rs`
- Modify: `docs/development.md`

### Step 1: Write a failing manifest test

Given fixed file metadata, assert exact `manifest.json` keys for commit SHA, package version, userspace target `x86_64-unknown-linux-musl`, eBPF target `bpfel-unknown-none`, and the three filenames. Assert `SHA256SUMS` is lexically ordered and covers exactly `l2-loopd`, `l2-loopctl`, `l2-loop-ebpf.o`, and `manifest.json`.

### Step 2: Push red, then add the artifact job

```powershell
git add .github/workflows/ci.yml xtask docs/development.md
git commit -m "test: define release bundle contract"
git push origin main
```

Expected failure: bundle manifest support is missing.

Add a `bundle` job depending on `userspace` and `ebpf`. Install the MUSL target, build both userspace binaries with `--release --target x86_64-unknown-linux-musl`, download/pass the eBPF object within the workflow, create the five-file bundle, verify checksums, and upload it with `actions/upload-artifact`. The artifact name is `l2-loop-linux-x86_64-<full-commit-sha>` and contains no environment identity. Add `/.artifacts/` to `.gitignore` before any operator download.

### Step 3: Push green and record the artifact

```powershell
git add .github/workflows/ci.yml .gitignore xtask docs/development.md
git commit -m "build: publish Linux preflight bundle"
git push origin main
```

Expected: `Userspace`, `eBPF`, and `Bundle` all pass for the exact commit; the uploaded archive contains exactly the approved files.

## Task 9: Perform Authorized Read-Only Host Acceptance

**Files:**

- Modify only implementation or tests required by observed failures
- Do not add a host report, SSH command containing a real target, or environment inventory to the repository

### Step 1: Verify the exact CI artifact locally without compiling

Use task-scoped environment variables configured outside the repository:

```powershell
$L2LoopCommit = git rev-parse HEAD
$L2LoopRun = gh run list --branch main --commit $L2LoopCommit --limit 1 --json databaseId --jq '.[0].databaseId'
gh run download $L2LoopRun --name "l2-loop-linux-x86_64-$L2LoopCommit" --dir .artifacts/$L2LoopCommit
Get-ChildItem .artifacts/$L2LoopCommit
```

Expected: the five approved bundle files are present. Keep `.artifacts/` ignored.

### Step 2: Transfer and run only read-only preflight

Supply `$env:L2_LOOP_TEST_TARGET`, `$env:L2_LOOP_TEST_KEY`, and `$env:L2_LOOP_TEST_INTERFACE` outside GitHub and outside tracked files. Transfer to an operator-created temporary directory, verify `SHA256SUMS` on the host, run `l2-loopd` with its socket in an operator-controlled temporary directory, and invoke `l2-loopctl preflight` in text and JSON modes.

Before and after, collect read-only checks sufficient to prove no change to link identities, XDP/TC identities, loaded BPF program IDs, and top-level foreign pin-root identities. Keep the raw comparison only in the operator session; report to the repository or handoff only pass/fail, commit SHA, CI run URL, and stable preflight codes.

### Step 3: Acceptance gate

Delivery A passes only when:

- the deployed binaries came from the exact green GitHub commit;
- the daemon and CLI complete a real Unix-socket request;
- the report contains required fields and no prohibited identifiers;
- the live/shared interface is reported and remains non-attachable;
- before/after identities match;
- no packages, services, sysctls, rlimits, links, qdiscs, BPF objects, or pin trees changed.

If a defect is found, add a reproducing test, push the red test, then the minimal fix, and require green GitHub CI before retesting the host.

## Final Plan Audit

Before declaring Delivery A complete, run these non-compiling local checks:

```powershell
git diff --check
$L2LoopForbidden = @(("TO" + "DO"), ("T" + "BD"), ("PLACE" + "HOLDER"), ("machine" + "_id"), ("host" + "name"), ("mac" + "_address"), ("ip" + "_address")) -join "|"
rg -n $L2LoopForbidden docs/superpowers/plans crates .github README.md docs/development.md
rg -n "PF_INTERFACE_MISSING|PF_INTERFACE_UNSUPPORTED|PF_BOND_NO_ACTIVE_SLAVE|PF_XDP_STATE_UNKNOWN|PF_XDP_OCCUPIED|PF_TC_STATE_UNKNOWN|PF_TC_HANDLE_COLLISION|PF_PIN_ROOT_FOREIGN|PF_MEMLOCK_TOO_LOW|PF_KERNEL_CAPABILITY|PF_LIVE_INTERFACE" crates
```

Expected: no incomplete planning marker, legacy product keyword, credential path, target address, or prohibited output field was introduced; all blocker codes exist. Record the exact successful GitHub run URL and commit SHA in the handoff.
