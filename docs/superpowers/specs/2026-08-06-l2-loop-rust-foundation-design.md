# L2 Loop Detection Agent Rust Foundation Design

**Date:** 2026-08-06  
**Status:** Approved for implementation  
**Parent design:** `docs/l2-loop-agent-design.md`

## 1. Objective

This phase establishes the executable contract for the L2 Loop Detection Agent before hardware-facing logic is added. It fixes the Rust workspace, eBPF program inventory, map ABI, user-space module boundaries, local daemon protocol, and CLI grammar.

The result is an observe-first foundation whose compilation and automated tests run exclusively in GitHub Actions. The current Windows development host is used only for authoring and non-compiling static checks.

## 2. Scope

This phase includes:

- a Rust workspace with explicit crate ownership;
- C-layout, versioned types shared by eBPF and user space;
- pure Rust domain types and state transitions;
- stable CLI command and argument parsing;
- daemon request and response contracts;
- Aya eBPF crate structure, program entry points, and map declarations;
- GitHub Actions build orchestration that keeps user-space checks independent from the eBPF toolchain;
- unit and ABI-layout tests.

This phase does not include:

- attaching programs to a production NIC;
- live packet parsing or counting;
- netlink or ethtool collection;
- packet transmission;
- policing enforcement;
- systemd packaging;
- Linux VM, lab, or hardware validation.

Those capabilities must build on the contracts fixed here rather than redefining them.

## 3. Chosen Architecture

The project uses an Aya-based, multi-crate Rust workspace:

```text
l2-loop/
├── Cargo.toml
├── rust-toolchain.toml
├── crates/
│   ├── l2-loop-common/
│   ├── l2-loop-core/
│   ├── l2-loop-agent/
│   └── l2-loop-cli/
├── ebpf/
│   └── l2-loop-ebpf/
├── xtask/
└── docs/
```

All crates are workspace members. The root `default-members` list excludes `l2-loop-ebpf`, so user-space and eBPF jobs remain separable in GitHub Actions. The Linux eBPF build is an explicit `cargo xtask build-ebpf` operation that invokes nightly Rust with `rust-src` and `bpf-linker`.

This separation is intentional: shared packet-independent contracts have a fast stable-toolchain CI job, while kernel-specific compilation remains a separately verified Linux CI target. No local compilation command is part of the development workflow.

## 4. Crate Responsibilities

### 4.1 `l2-loop-common`

A `#![no_std]` crate containing only eBPF/user-space ABI types, constants, numeric enums, and conversion validation.

Rules:

- every map key and value is `#[repr(C)]`;
- every field has a fixed-width integer or fixed-size byte-array type;
- no `bool`, `usize`, references, strings, heap containers, or Rust enums cross the ABI;
- reserved bytes are explicit and must be written as zero;
- the optional `user` feature provides the required `aya::Pod` implementations;
- ABI layout tests run in user space and assert exact size and alignment.

### 4.2 `l2-loop-core`

A stable, pure Rust library with no Aya, Tokio, operating-system, or CLI dependencies. It owns:

- validated domain enums corresponding to ABI numeric values;
- interface mode and generation transitions;
- policy validation;
- probe request validation;
- evidence and status view models;
- protocol-neutral agent commands and results.

This is the primary location for deterministic unit tests.

### 4.3 `l2-loop-agent`

A library plus the `l2-loopd` binary. The library owns application orchestration and Linux adapters behind traits:

- `InterfaceResolver` resolves an explicit interface name to ifindex and identity;
- `HookManager` loads, attaches, detaches, and reports Aya links;
- `MetricsReader` reads NIC, kernel, and eBPF observations;
- `ProbeTransport` sends exactly one requested probe frame;
- `EvidenceStore` persists bounded evidence bundles;
- `Clock` provides monotonic and wall-clock time;
- `ControlServer` serves the local daemon protocol.

The binary is a thin composition root. Domain decisions stay in `l2-loop-core`; raw ABI conversions stay at the adapter boundary.

### 4.4 `l2-loop-cli`

A library plus the `l2-loopctl` binary. The library exposes its Clap parser and conversion from CLI arguments to domain commands so parsing can be unit-tested without running a daemon.

The binary connects to the local control socket, sends one request, renders the response, and maps typed failures to stable exit codes.

### 4.5 `l2-loop-ebpf`

A `#![no_std]`, `#![no_main]` Aya eBPF crate. It imports ABI types from `l2-loop-common` without the `user` feature. Program bodies initially return pass/continue after the minimum safe lookup scaffolding; packet parsing and enforcement are later slices.

### 4.6 `xtask`

A stable Rust command runner with these fixed subcommands:

- `cargo xtask build-ebpf` builds the eBPF crate for `bpfel-unknown-none` with nightly Rust;
- `cargo xtask build` builds eBPF first and then user space on Linux;
- `cargo xtask test` is intended for the GitHub Actions Linux runner and runs stable workspace tests plus the eBPF target check;
- `cargo xtask lint` runs formatting and Clippy for stable crates and the available eBPF checks.

The command must fail with an actionable prerequisite message when nightly Rust, `rust-src`, or `bpf-linker` is absent.

## 5. eBPF Program Inventory

The following program names are public attachment contracts:

| Program | Aya type | Intended attachment | Phase-one behavior |
|---|---|---|---|
| `l2_loop_xdp_ingress` | XDP | selected physical NIC ingress | return `XDP_PASS` |
| `l2_loop_tc_egress` | TC classifier | selected physical NIC egress | return `TC_ACT_OK` |
| `l2_loop_tc_path_ingress` | TC classifier | temporary candidate-path ingress | return `TC_ACT_OK` |
| `l2_loop_tc_path_egress` | TC classifier | temporary candidate-path egress | return `TC_ACT_OK` |

Ingress and egress path programs remain separate even when they share internal functions. Attachment direction cannot be inferred reliably from a shared program instance, and the distinction must be unambiguous in evidence.

All error paths are fail-open. Missing configuration, unsupported parsing, and internal observation errors must never drop traffic in observe mode.

## 6. ABI Versioning and Publication Rules

`ABI_VERSION` is `1`.

Every user-space operation that changes interface configuration or policy creates a non-zero, monotonically increasing generation. User space writes dependent map entries first and publishes `IFACE_CONFIG` last. eBPF code ignores entries whose generation differs from the active interface generation.

Map pinning root:

```text
/sys/fs/bpf/l2-loop
```

Pinned map directories are versioned:

```text
/sys/fs/bpf/l2-loop/v1/<ifindex>/
```

An ABI version mismatch prevents map reuse and program attachment. The daemon reports the mismatch rather than attempting an in-place reinterpretation.

## 7. Numeric ABI Values

The following values are fixed for ABI v1.

### `AgentMode`

| Value | Meaning |
|---:|---|
| 0 | disabled |
| 1 | observe |
| 2 | police |

### `Direction`

| Value | Meaning |
|---:|---|
| 1 | ingress |
| 2 | egress |

### `HookRole`

| Value | Meaning |
|---:|---|
| 1 | external XDP ingress |
| 2 | physical TC egress |
| 3 | temporary path ingress |
| 4 | temporary path egress |

### `TrafficClass`

| Value | Meaning |
|---:|---|
| 1 | all frames |
| 2 | L2 broadcast |
| 3 | IPv4 multicast |
| 4 | IPv6 multicast |
| 5 | other L2 multicast |
| 6 | link-local control |
| 7 | unicast or otherwise unclassified |

`TrafficClass::All` is an aggregate counter, not a mutually exclusive classification. The remaining values are mutually exclusive.

### `Verdict`

| Value | Meaning |
|---:|---|
| 1 | pass |
| 2 | would drop |
| 3 | drop |
| 4 | error pass |

### `ObservationReason`

| Value | Meaning |
|---:|---|
| 0 | none |
| 1 | missing configuration |
| 2 | parse error |
| 3 | fingerprint sample selected |
| 4 | probe matched |
| 5 | packet-rate policy exceeded |
| 6 | byte-rate policy exceeded |
| 7 | packet- and byte-rate policies exceeded |

### `VlanVisibility`

| Value | Meaning |
|---:|---|
| 0 | unknown |
| 1 | verified visible at hook |
| 2 | unavailable at hook |

### `ProbeScope`

| Value | Meaning |
|---:|---|
| 1 | external |
| 2 | internal |

## 8. ABI Structs

The listed field order is normative. All sizes are asserted by tests.

### `InterfaceConfig` — 32 bytes, alignment 8

```rust
#[repr(C)]
pub struct InterfaceConfig {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub logical_ifindex: u32,
    pub flags: u32,
    pub mode: u8,
    pub role: u8,
    pub vlan_visibility: u8,
    pub sample_shift: u8,
    pub reserved: [u8; 4],
}
```

`sample_shift` means approximately one sample per `2^sample_shift` eligible packets. `flags` is zero in v1.

### `StatsKey` — 16 bytes, alignment 8

```rust
#[repr(C)]
pub struct StatsKey {
    pub interface_generation: u64,
    pub ifindex: u32,
    pub direction: u8,
    pub traffic_class: u8,
    pub verdict: u8,
    pub reason: u8,
}
```

### `CounterValue` — 16 bytes, alignment 8

```rust
#[repr(C)]
pub struct CounterValue {
    pub packets: u64,
    pub bytes: u64,
}
```

### `FingerprintKey` — 32 bytes, alignment 8

```rust
#[repr(C)]
pub struct FingerprintKey {
    pub interface_generation: u64,
    pub fingerprint: u64,
    pub ifindex: u32,
    pub outer_vlan_id: u16,
    pub ether_type: u16,
    pub frame_len: u16,
    pub direction: u8,
    pub vlan_depth: u8,
    pub protocol: u8,
    pub subtype: u8,
    pub reserved: [u8; 2],
}
```

The fingerprint is a deterministic non-cryptographic hash over selected normalized header fields. Its algorithm is fixed when packet parsing is implemented and is not inferred from this struct alone.

### `FingerprintValue` — 48 bytes, alignment 8

```rust
#[repr(C)]
pub struct FingerprintValue {
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub reserved: [u8; 4],
}
```

### `ProbeKey` — 32 bytes, alignment 8

```rust
#[repr(C)]
pub struct ProbeKey {
    pub nonce: [u8; 16],
    pub interface_generation: u64,
    pub ifindex: u32,
    pub outer_vlan_id: u16,
    pub scope: u8,
    pub reserved: u8,
}
```

VLAN `0xffff` means that no VLAN was requested or observable.

### `ProbeRegistration` — 32 bytes, alignment 8

```rust
#[repr(C)]
pub struct ProbeRegistration {
    pub registered_at_ns: u64,
    pub expires_at_ns: u64,
    pub flags: u32,
    pub reserved: [u8; 12],
}
```

### `PolicyKey` — 16 bytes, alignment 8

```rust
#[repr(C)]
pub struct PolicyKey {
    pub policy_generation: u64,
    pub ifindex: u32,
    pub outer_vlan_id: u16,
    pub direction: u8,
    pub traffic_class: u8,
}
```

### `RatePolicy` — 40 bytes, alignment 8

```rust
#[repr(C)]
pub struct RatePolicy {
    pub pps_limit: u64,
    pub bps_limit: u64,
    pub packet_burst: u64,
    pub byte_burst: u64,
    pub expires_at_ns: u64,
}
```

A zero rate disables that dimension. At least one dimension must be non-zero. Expiry is checked in the packet path and causes fail-open behavior. Mutable token-bucket runtime state is intentionally a separate internal map whose layout will be fixed with the policing implementation; it is not pinned and is not part of ABI v1 persistence.

## 9. Map ABI

All public map names fit the kernel object-name limit and are fixed for ABI v1.

| Map name | Aya map type | Key | Value | Initial capacity | Pinning |
|---|---|---|---|---:|---|
| `IFACE_CONFIG` | hash | `u32` ifindex | `InterfaceConfig` | 64 | pinned |
| `HOOK_STATS` | per-CPU hash | `StatsKey` | `CounterValue` | 4096 | pinned |
| `FINGERPRINTS` | LRU hash | `FingerprintKey` | `FingerprintValue` | 8192 | pinned |
| `PROBE_REGISTRY` | hash | `ProbeKey` | `ProbeRegistration` | 128 | not pinned |
| `PROBE_STATS` | per-CPU hash | `ProbeKey` | `CounterValue` | 128 | not pinned |
| `RATE_POLICY` | hash | `PolicyKey` | `RatePolicy` | 256 | pinned |

`FINGERPRINTS` is evidence-grade sampling data, not an exact accounting source. Races or LRU eviction may reduce observations but must never affect pass/drop decisions.

## 10. Domain State Model

An interface has four user-space lifecycle states:

```text
Detached -> Attaching -> Observing -> Policing
                 |            |           |
                 +----------> Error <------+
```

Valid transitions:

- `Detached -> Attaching` when an explicit interface is resolved;
- `Attaching -> Observing` only after both external hooks are attached and verified;
- `Observing -> Policing` only after a valid, expiring policy is published;
- `Policing -> Observing` on explicit disable, policy expiry, or safety failure;
- any active state may move to `Error`, after which all surviving packet paths remain fail-open;
- `Error -> Detached` requires cleanup followed by an explicit retry.

There is no automatic transition from observation to policing.

## 11. Local Control Protocol

The daemon listens on:

```text
/run/l2-loop/agent.sock
```

Each connection carries one request and one response. Frames use a four-byte unsigned big-endian payload length followed by UTF-8 JSON. The maximum payload length is 1 MiB. Both request and response contain `protocol_version: 1`.

Request and response bodies are serde tagged enums using the `kind` field. Unknown protocol versions, unknown command kinds, oversized frames, invalid UTF-8, and malformed JSON are rejected without changing daemon state.

Read-only operations may be granted to the `l2-loop` operating-system group through socket permissions. Probe and policing operations require an authorized local principal. The daemon runs as root on supported 4.18-era kernels because those kernels predate the finer-grained `CAP_BPF` capability.

## 12. CLI Contract

The executable is `l2-loopctl`.

### Observe

```text
l2-loopctl observe --interface <IFACE>
```

Starts or verifies observe mode for one explicit interface. Interface auto-discovery is not accepted.

### Status

```text
l2-loopctl status [--interface <IFACE>] [--json]
```

Without `--interface`, lists all interfaces managed by this daemon. Human-readable output is the default; `--json` emits the versioned response object.

### Probe

```text
l2-loopctl probe --interface <IFACE> --scope <external|internal> [--vlan <1-4094>] [--timeout <DURATION>]
```

One invocation sends exactly one frame. There is no count, repeat, interval, broadcast loop, or scheduled mode. The default timeout is two seconds and the accepted range is 100 milliseconds through 30 seconds.

### Apply Temporary Policing

```text
l2-loopctl police apply --interface <IFACE> [--vlan <1-4094>] --class <broadcast|ipv4-multicast|ipv6-multicast|other-multicast|link-local-control> [--pps <N>] [--bps <N>] --ttl <DURATION>
```

At least one of `--pps` or `--bps` is required and non-zero. TTL is required and accepted from one second through 24 hours. This command never creates a permanent rule.

### Disable Policing

```text
l2-loopctl police disable --rule <RULE_ID>
```

### Evidence

```text
l2-loopctl evidence list [--interface <IFACE>] [--json]
l2-loopctl evidence show --id <EVIDENCE_ID> [--json]
```

The CLI returns exit code `0` on success, `2` for local argument validation, `3` when the daemon is unavailable, `4` for authorization failure, `5` for a rejected state transition, and `1` for other failures.

## 13. Filesystem Contract

| Purpose | Path |
|---|---|
| Configuration | `/etc/l2-loop/agent.toml` |
| Runtime socket | `/run/l2-loop/agent.sock` |
| Persistent state | `/var/lib/l2-loop/` |
| Evidence bundles | `/var/lib/l2-loop/evidence/` |
| Pinned maps | `/sys/fs/bpf/l2-loop/v1/<ifindex>/` |

The daemon creates runtime and state directories with restrictive ownership. Evidence filenames use daemon-generated identifiers, never raw user input.

## 14. Error and Safety Rules

- Every eBPF error path passes the frame in observe mode.
- Missing, stale, or invalid configuration passes the frame and increments an error-pass counter when possible.
- Program attachment is transactional: a partial attach is detached before an error is returned.
- Mutating daemon requests validate completely before publishing any map entry.
- A manual policy contains a required expiry and reverts to observe behavior without user-space cooperation.
- A probe request creates a registry entry before transmission and removes it after completion or timeout.
- Interface deletion, ifindex reuse, or identity change invalidates the current interface generation.
- No request may infer a target interface from routing tables, default routes, or the first physical NIC.

## 15. Test and CI Contract for This Phase

GitHub Actions stable-toolchain tests must prove:

- every ABI struct has the exact documented size and alignment;
- every numeric ABI value converts to the intended domain enum and unknown values are rejected;
- reserved fields are zero in constructors;
- interface lifecycle accepts all valid transitions and rejects all invalid transitions;
- policies reject missing limits, zero limits, invalid class values, and TTL outside the allowed range;
- probes reject invalid VLANs and timeouts and do not expose repetition controls;
- every CLI command parses its canonical form and rejects unsafe or ambiguous forms;
- protocol framing rejects oversized and malformed messages;
- protocol request/response JSON retains `protocol_version: 1` and stable `kind` tags.

GitHub Actions Linux eBPF verification must prove:

- the four named programs compile for `bpfel-unknown-none`;
- all six public maps have the documented names and key/value layouts;
- phase-one program paths return pass/continue;
- the resulting object can be loaded by Aya on a supported Linux test host.

The repository contains `.github/workflows/ci.yml` with separate `userspace` and `ebpf` jobs. The `userspace` job runs formatting, Clippy, tests, and checks for the default members. The `ebpf` job installs the pinned nightly toolchain, `rust-src`, and `bpf-linker`, then builds the eBPF object through `xtask`. A later privileged integration workflow may perform kernel loading; ordinary hosted runners only compile and inspect the object.

The local development host must not run Cargo, Rust compiler, Clippy, linker, or eBPF build commands. Static inspection may verify paths, manifests, workflow syntax, and exact source text but cannot be reported as compilation success.

## 16. First Implementation Slice Completion Criteria

The foundation slice is complete when:

1. the GitHub Actions `userspace` job passes stable tests, Clippy, formatting, and checks without compiling the eBPF crate;
2. the GitHub Actions `ebpf` job builds the four eBPF programs for `bpfel-unknown-none`;
3. the common, core, agent, CLI, eBPF, and xtask crates exist with the ownership described above;
4. ABI layout, enum conversion, state transition, policy validation, protocol framing, and CLI parser tests pass;
5. the eBPF crate contains the four program entry points and six map declarations with exact public names;
6. the GitHub-only build workflow installs and verifies the required stable and nightly prerequisites;
7. no code sends a frame, attaches to a production interface, or drops traffic.

## 17. Dependency Baseline

The initial Aya dependency versions follow the current official Aya template baseline: `aya 0.14.0`, `aya-build 0.2.0`, `aya-ebpf 0.2.1`, `aya-log 0.3.0`, and `aya-log-ebpf 0.2.0`. Exact dependency versions are centralized in the root workspace manifest. Semver updates require a tested ABI and Linux load check rather than an automatic floating upgrade.

The project uses Rust edition 2024, stable Rust for user space, and nightly Rust only for the eBPF target.

## 18. References

- Aya Book, development environment: <https://aya-rs.dev/book/start/development>
- Official Aya template workspace: <https://github.com/aya-rs/aya-template>
- Parent product and safety design: `docs/l2-loop-agent-design.md`
