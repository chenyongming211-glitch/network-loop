# Linux Preflight and Safe Attachment Design

**Date:** 2026-08-06  
**Status:** Approved  
**Parent design:** `docs/l2-loop-agent-design.md`

## 1. Goal

Build the first target-facing vertical slice of the L2 Loop Detection Agent without touching a live business interface. The slice adds a real daemon control path, a read-only Linux preflight, collision-safe XDP and TC attachment primitives, a GitHub-built deployable artifact, and an isolated network-namespace/veth verification flow.

The implementation must coexist with unrelated eBPF programs already running on the host. It must never replace, detach, unpin, rename, or otherwise mutate an object it does not own.

## 2. Delivery slices

This design is implemented in two sequential deliveries.

### Delivery A: read-only preflight

- start `l2-loopd` with a local Unix control socket;
- send `preflight` requests through `l2-loopctl`;
- resolve physical interfaces, bond masters, slaves, and active slaves;
- report Linux bridge or Open vSwitch membership when discoverable;
- inventory XDP, TC, bpffs, BTF, memlock, and relevant kernel capabilities;
- classify findings as informational, warning, or blocker;
- produce text and stable JSON output;
- make no changes to the inspected host.

### Delivery B: isolated safe attachment proof

- load the existing fail-open eBPF object;
- attach XDP and TC only to an isolated veth created for the test;
- publish map configuration after both hooks are verified;
- generate bounded test traffic and observe counters;
- detach only owned hooks and remove only the test namespace and owned pins;
- prove that pre-existing interfaces, hooks, programs, maps, and foreign pin roots are unchanged.

Neither delivery attaches to a physical business interface. Physical-interface observation requires a later design approval after the isolated proof passes.

## 3. Public CLI and protocol

Add the command:

```text
l2-loopctl preflight --interface <IFACE> [--json]
```

The CLI validates the interface name, connects to `/run/l2-loop/agent.sock`, sends one framed request, waits for one framed response, renders it, and exits.

Add this domain command:

```rust
AgentCommand::Preflight {
    interface: InterfaceName,
}
```

Add this result:

```rust
AgentResult::Preflight {
    report: PreflightReport,
}
```

The control protocol remains version 1 because it has not yet been deployed as a compatibility boundary. Unknown commands and malformed reports remain typed protocol errors.

Exit codes are:

| Code | Meaning |
|---:|---|
| 0 | preflight is ready or ready with warnings |
| 1 | daemon transport or internal failure |
| 2 | CLI usage or local argument validation failure |
| 4 | preflight completed and is blocked |

`--json` affects rendering only. It never changes inspection behavior.

## 4. Report model

`l2-loop-core` owns operating-system-neutral report types.

```rust
pub enum PreflightDecision {
    Ready,
    ReadyWithWarnings,
    Blocked,
}

pub enum FindingSeverity {
    Information,
    Warning,
    Blocker,
}

pub struct PreflightFinding {
    pub code: String,
    pub severity: FindingSeverity,
    pub message: String,
}

pub struct PreflightReport {
    pub decision: PreflightDecision,
    pub interface: InterfaceInspection,
    pub kernel: KernelInspection,
    pub bpf: BpfInspection,
    pub findings: Vec<PreflightFinding>,
}
```

The exact serialized field names use `snake_case`. Findings are sorted first by severity and then by code so repeated runs are diffable.

The report includes interface names, ifindex values, program IDs, filter identifiers, attach modes, kernel capability booleans, and size limits. It does not include IP addresses, MAC addresses, hostnames, machine identifiers, routes, customer topology labels, packet contents, or unrelated map contents.

## 5. Component boundaries

### 5.1 Core domain

`l2-loop-core` defines the request, report, decision, finding, interface-kind, attachment-state, and capability types. It contains no filesystem, netlink, Aya, Tokio, or Open vSwitch dependency.

### 5.2 Preflight service

`l2-loop-agent` adds a dedicated `PreflightService<P>` rather than adding another generic parameter to `AgentService<R, H>`. This keeps attachment orchestration and read-only inspection independently testable.

```rust
pub trait PlatformInspector {
    fn inspect(&mut self, interface: &InterfaceName) -> Result<PreflightReport, PortError>;
}
```

`PreflightService` validates the report invariants, derives the final decision from findings, and returns a stable result. A platform adapter cannot mark a report ready while blocker findings exist.

### 5.3 Linux platform adapter

Linux-only code lives below `crates/l2-loop-agent/src/linux/` and is guarded by `cfg(target_os = "linux")`.

Focused modules are:

- `interface.rs`: netlink interface inventory and sysfs identity checks;
- `bond.rs`: strict parsing of `/proc/net/bonding/<name>`;
- `topology.rs`: Linux bridge membership and optional read-only Open vSwitch lookup;
- `bpf_inventory.rs`: loaded-program, XDP, TC, BTF, and bpffs inspection;
- `limits.rs`: rlimit and planned locked-memory checks;
- `xdp.rs`: collision-safe XDP attachment and owned detachment;
- `tc.rs`: collision-safe TC attachment and owned detachment.

The daemon does not require `tc`, `bpftool`, `ip`, or a shell. Netlink and BPF syscalls are invoked through Rust libraries or focused internal adapters.

Open vSwitch bridge-name discovery is optional. If `ovs-vsctl` is present, it may be executed directly with an argument vector, a two-second timeout, and a read-only command. It must never be invoked through a shell. Failure produces a warning while kernel-visible membership remains in the report.

### 5.4 Control transport

`l2-loopd` owns `/run/l2-loop/agent.sock`. The socket directory is root-owned and the initial socket mode is `0600`.

The server:

- accepts only local Unix connections;
- applies the existing one-megabyte frame limit;
- reads one request and writes one response per connection;
- caps concurrent clients at 16;
- applies a five-second request deadline;
- converts every error to a stable protocol error code;
- never panics on client-controlled bytes.

`l2-loopctl` is an unprivileged transport client. Authorization is enforced by socket permissions, not by trusting request fields.

## 6. Interface resolution

Preflight starts with the explicitly requested interface. It never infers a default interface from routes or selects the first physical NIC.

The resolver returns:

- requested logical name and ifindex;
- interface kind: physical, bond, veth, bridge, Open vSwitch internal, tap, or unsupported;
- administrative and operational state;
- kernel master relationship;
- bond mode, slave list, and current active slave when applicable;
- proposed ingress and egress attachment targets;
- whether the target is isolated, inactive physical, or live/shared.

For an active-backup bond, the proposed physical target is the current active slave. Preflight reports the mapping but Delivery A and Delivery B refuse to attach to it. Bond failover monitoring is explicitly deferred until physical attachment is approved.

Missing interfaces, bonds without an active slave, ambiguous master relationships, ifindex zero, and unsupported virtual interface kinds are blockers.

## 7. Existing eBPF coexistence

### 7.1 Foreign ownership

All top-level bpffs trees other than `/sys/fs/bpf/l2-loop` are foreign. The agent may list their presence and query kernel metadata needed for collision checks, but it must not traverse unrelated map contents or mutate those trees.

If `/sys/fs/bpf/l2-loop` already exists and cannot be attributed to the current ABI and ownership record, preflight blocks. The agent never adopts an unknown directory merely because its name matches.

Persistent ownership is recorded in `/var/lib/l2-loop/ownership-v1.json`, owned by root with mode `0600` and replaced atomically after a successful transaction. The record contains only the schema version, ABI version, interface generation, ifindex, program IDs, TC priorities and handles, exact pin paths, and creation timestamp. A pin is owned only when both its kernel metadata and this record agree. Missing, malformed, stale, or mismatched records are blockers; they never trigger automatic deletion.

An isolated verification run uses `/run/l2-loop/tests/<run-id>.json` for its ephemeral ownership journal. Delivery A reads ownership state but creates or repairs neither journal.

Production pin layout remains:

```text
/sys/fs/bpf/l2-loop/v1/<ifindex>/
```

Isolated verification uses:

```text
/sys/fs/bpf/l2-loop/test/<run-id>/
```

`<run-id>` is a freshly generated 128-bit lowercase hexadecimal value. Cleanup resolves the exact path and refuses to operate outside the test root.

### 7.2 XDP collision rule

Aya loads and verifies the XDP program, but shared-interface attachment must not call a legacy attach path that can replace an existing program.

The safe XDP adapter:

1. queries the interface XDP state through rtnetlink;
2. blocks if inspection fails or ownership is unknown;
3. attaches through an atomic no-replace operation equivalent to `XDP_FLAGS_UPDATE_IF_NOEXIST`;
4. records ifindex, mode, program ID, program tag, and owned link state;
5. verifies that the attached program ID is the newly loaded program;
6. detaches only if the current program still matches the ownership record.

If the kernel cannot provide safe compare-and-detach semantics for a legacy link, live-interface attachment is blocked. The isolated veth proof may use the legacy path because the test namespace has a single owner and is deleted as a unit.

XDP multiprogram dispatch is not introduced in this slice. An occupied XDP hook is a blocker rather than a reason to replace, detach, or join an unknown dispatcher.

### 7.3 TC collision rule

TC inspection queries qdiscs, chains, priorities, handles, directions, and BPF program IDs through netlink.

The safe TC adapter:

- reuses an existing clsact qdisc;
- adds clsact only when absent;
- never deletes a shared clsact qdisc;
- uses explicit handles `0x4c320001` for ingress and `0x4c320002` for egress;
- selects the first free priority from `49600..=49699`;
- blocks if an owned handle is occupied by a foreign program;
- records the chosen priority and handle;
- deletes only an exact owned filter whose program ID still matches.

Default or automatically assigned TC priority and handle values are forbidden.

## 8. Resource and compatibility checks

Preflight verifies:

- Linux architecture is x86_64;
- kernel release is parseable and meets each used feature floor;
- BPF syscall and JIT are enabled;
- BTF is readable when required by the loaded object;
- bpffs is mounted at `/sys/fs/bpf`;
- the agent pin root is absent, empty, or owned by the expected ABI;
- the process can enumerate relevant programs and link metadata;
- current soft and hard `RLIMIT_MEMLOCK` values and whether the process has authority to raise them;
- native and generic XDP modes are reported separately;
- TC classifier and clsact support are available;
- the target artifact architecture matches the host.

Delivery A never changes rlimits. A low soft limit is a warning when the process can raise it and a blocker when it cannot. Delivery B raises its own process limit to infinity before creating any BPF object. Failure to raise the limit blocks attachment without changing an interface.

Map capacities remain those in ABI v1. This slice does not tune map sizes from host memory or CPU count.

## 9. Attachment transaction

The isolated attachment transaction is:

```text
preflight Ready
  -> raise process memlock limit
  -> load eBPF object and validate ABI
  -> attach XDP with no-replace semantics
  -> verify XDP program identity
  -> attach TC egress with explicit priority and handle
  -> verify TC filter identity
  -> initialize dependent map entries
  -> publish IFACE_CONFIG last with a new generation
  -> enter Observing
```

Every failure before `IFACE_CONFIG` publication rolls back owned filters and links in reverse order. Cleanup errors are returned as evidence but never trigger broad cleanup of an interface or qdisc.

The eBPF programs remain fail-open. Delivery B may add total packet and byte accounting required to prove traffic traversal, but it does not parse VLANs, fingerprint frames, send probes, police traffic, return `XDP_DROP`, or return `TC_ACT_SHOT`.

## 10. Artifact and deployment

All compilation remains in GitHub Actions.

GitHub produces a versioned x86_64 Linux bundle containing:

- `l2-loopd`;
- `l2-loopctl`;
- `l2-loop-ebpf.o`;
- `manifest.json` with commit SHA, versions, target triples, and filenames;
- `SHA256SUMS`.

Userspace binaries target `x86_64-unknown-linux-musl` so they do not inherit a newer GitHub runner glibc requirement. The eBPF object targets `bpfel-unknown-none`.

The workflow verifies checksums and uploads the bundle as a GitHub Actions artifact. Deployment downloads that artifact and transfers it using the operator's local authenticated SSH session. No SSH private key, target address, target hostname, interface inventory, or environment report is stored in GitHub secrets, repository files, workflow logs, or artifact metadata.

## 11. Isolated host verification

The host verification harness uses names derived from the run ID and performs only these scoped mutations:

1. capture a read-only before-snapshot of active interfaces, their XDP/TC identities, loaded program IDs, and foreign top-level pin roots;
2. create one temporary network namespace and one veth pair;
3. keep both veth endpoints administratively isolated from physical bridges, bonds, Open vSwitch, and routes outside the namespace;
4. run preflight on the test endpoint;
5. attach generic XDP and TC to the test endpoint;
6. generate a bounded number of local Ethernet/IP frames;
7. verify ingress and egress packet/byte counters increase;
8. verify all verdicts remain pass/continue;
9. detach exact owned hooks;
10. remove the exact test pin directory, veth pair, and namespace;
11. capture an after-snapshot and require all pre-existing identities and foreign roots to be unchanged;
12. require no test-named interface, namespace, BPF program, map, filter, or pin to remain.

The harness installs no package, loads no unrelated kernel module, restarts no service, changes no sysctl, changes no offload setting, and touches no physical interface.

Cleanup runs on success, failure, timeout, and interruption. A cleanup target is validated against the generated run ID before deletion.

## 12. Error model

Stable preflight blocker codes include:

| Code | Condition |
|---|---|
| `PF_INTERFACE_MISSING` | requested interface does not exist |
| `PF_INTERFACE_UNSUPPORTED` | interface kind is outside this slice |
| `PF_BOND_NO_ACTIVE_SLAVE` | bond has no unambiguous active slave |
| `PF_XDP_STATE_UNKNOWN` | XDP ownership cannot be determined |
| `PF_XDP_OCCUPIED` | a non-owned XDP program occupies the target |
| `PF_TC_STATE_UNKNOWN` | TC filter ownership cannot be determined |
| `PF_TC_HANDLE_COLLISION` | an owned handle is used by a foreign filter |
| `PF_PIN_ROOT_FOREIGN` | the agent pin root exists without valid ownership |
| `PF_MEMLOCK_TOO_LOW` | memlock is insufficient and the process cannot raise it |
| `PF_KERNEL_CAPABILITY` | a required BPF or netlink capability is unavailable |
| `PF_LIVE_INTERFACE` | this delivery was asked to attach to a live/shared interface |

Warnings never relax a blocker. Internal adapter errors use concise messages and preserve an error source for logs without exposing packet or customer data through the CLI.

## 13. Test contract

### 13.1 Unit and contract tests in GitHub

- CLI parses canonical text and JSON preflight commands;
- protocol round-trips the new command and every report variant;
- malformed or oversized frames remain rejected;
- report decision cannot be ready when a blocker exists;
- bond fixtures cover active-backup, missing active slave, malformed input, and disappearing slave;
- interface fixtures cover physical, bond, veth, bridge, and unsupported kinds;
- XDP state fixtures cover empty, owned, foreign, and unknown states;
- TC fixtures cover existing clsact, free and occupied priorities, handle collision, and exact owned detach;
- foreign pin roots are never returned as cleanup targets;
- cleanup path validation rejects traversal, symlinks, empty run IDs, and paths outside the test root;
- memlock findings distinguish a raisable soft limit from a hard blocker;
- text and JSON output omit prohibited host and link-layer identity fields;
- the repository naming guard continues to pass.

### 13.2 GitHub build tests

- stable Rust format, Clippy, unit tests, and checks pass;
- the eBPF object builds and contains the four required program symbols;
- musl userspace binaries build for x86_64;
- the artifact manifest and checksums match the bundle;
- a Linux job starts the daemon, exercises the Unix socket, and validates preflight against a synthetic or loopback-safe fixture without privileged attachment.

### 13.3 Authorized isolated-host tests

- preflight on a live/shared interface reports it but refuses attachment;
- preflight on the isolated veth is ready;
- XDP and TC attach without modifying a foreign program or pin;
- bounded traffic increments the expected counters;
- partial TC failure rolls back the owned XDP attachment;
- daemon termination leaves traffic fail-open;
- cleanup leaves no owned object behind;
- before/after snapshots prove unrelated eBPF and active network state are unchanged.

## 14. Acceptance criteria

Delivery A is complete when:

1. `l2-loopd` and `l2-loopctl preflight` communicate over the real Unix socket;
2. text and JSON reports contain all required fields and no prohibited identifiers;
3. the target-facing artifact is built only in GitHub and executes on the supported enterprise Linux profile;
4. running preflight on the authorized host produces no mutation;
5. existing or unknown XDP/TC ownership becomes a blocker rather than an overwrite attempt.

Delivery B is complete when:

1. the isolated veth transaction reaches `Observing` and exposes non-zero counters;
2. all packet paths remain pass/continue;
3. forced partial failures roll back only owned state;
4. no physical or shared interface is attached;
5. before/after snapshots prove foreign programs, filters, maps, pins, and active interfaces are unchanged;
6. GitHub CI is green for the exact deployed commit.

## 15. Deferred work

- physical bond attachment and failover reattachment;
- native-driver XDP verification on spare physical ports;
- L2/VLAN/QinQ parsing and traffic classification;
- NIC, queue, softnet, IRQ, and CPU metrics;
- passive fingerprints and loop-state decisions;
- active probes and any drop action;
- policing and token buckets;
- systemd packaging and non-root capability reduction;
- XDP multiprogram dispatcher integration;
- performance benchmarking on a clean host.

## 16. Reference basis

- Parent product design: `docs/l2-loop-agent-design.md`
- Rust/eBPF foundation: `docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md`
- Aya XDP lifecycle and legacy fallback: <https://docs.rs/aya/latest/aya/programs/xdp/struct.Xdp.html>
- Aya TC classifier and ordered attachment: <https://docs.rs/aya/latest/aya/programs/tc/struct.SchedClassifier.html>
- XDP multiprogram compatibility: <https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/README.org>
