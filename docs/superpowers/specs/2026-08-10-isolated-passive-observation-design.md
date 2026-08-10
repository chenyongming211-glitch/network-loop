# Delivery C Isolated Passive Observation Design

**Date:** 2026-08-10  
**Status:** Approved  
**Parent designs:** `docs/l2-loop-agent-design.md`, `docs/superpowers/specs/2026-08-06-linux-preflight-safe-attach-design.md`

## 1. Goal

Turn the isolated safe-attachment proof into a useful passive-observation vertical slice without widening the production safety boundary.

Delivery C parses Ethernet plus at most one VLAN tag, classifies traffic at XDP ingress and TC egress, publishes generation-scoped cumulative packet and byte counters, and implements real read-only `observe` and `status` commands. The exact GitHub artifact is accepted only inside a generated network namespace/veth run on the authorized test node.

Delivery C does not decide whether a loop exists. It creates the trustworthy, bounded observations required by later rate windows, dynamic baselines, fingerprints, and loop-state decisions.

## 2. Scope

Delivery C includes:

- verifier-safe Ethernet parsing;
- parsing of one `802.1Q` or `802.1ad` VLAN header;
- mutually exclusive Layer 2 traffic classification;
- cumulative packet and byte accounting by hook and class;
- session-level VLAN visibility proof from a real tagged frame;
- exact ownership-aware userspace Map snapshots;
- detailed `observe` output and summarized `status` output;
- text and stable JSON rendering;
- GitHub-only compilation and automated tests;
- authorized isolated namespace/veth acceptance.

Delivery C explicitly excludes:

- QinQ or parsing beyond the first VLAN header;
- per-VLAN counters or conclusions;
- packet fingerprints, MAC ranking, packet capture, or raw frame output;
- PPS/BPS, background sampling, sliding windows, or dynamic baselines;
- loop classification or event generation;
- active probes or packet injection by the agent;
- policing, token buckets, drop actions, or policy commands;
- production, physical, bond, bridge, OVS, tap, or shared-interface attachment;
- automatic interface discovery.

## 3. Safety invariants

The following invariants are mandatory:

1. Every XDP path returns pass and every TC path returns continue.
2. Data-plane parsing and accounting failures are fail-open.
3. `observe` and `status` never load, attach, detach, replace, adopt, repair, or clean a kernel object.
4. Observation is available only for the current generated isolated session already established by the existing attachment transaction.
5. Userspace reads only the journal-confirmed interface, generation, pins, Maps, and hook identities.
6. Identity mismatch is an error, never a reason to use or delete the changed object.
7. Existing Map names and ABI v1 structure layouts do not change.
8. Each packet performs bounded header reads and at most two statistics updates.
9. No target identity, credential, raw frame, MAC address, IP address, host identity, or foreign object inventory is committed or emitted by acceptance output.
10. The local authoring host runs no Cargo, compiler, linker, formatter, Clippy, or Rust test command.

## 4. Architecture

The delivery adds four bounded components.

### 4.1 Shared Layer 2 parser

`l2-loop-common` owns a `no_std`, allocation-free parser and traffic classifier that can be exercised by ordinary userspace tests and called from the eBPF crate.

The parser consumes a bounded packet prefix and returns an internal value equivalent to:

```rust
pub struct ParsedL2 {
    pub traffic_class: u8,
    pub outer_vlan_id: Option<u16>,
    pub nested_vlan: bool,
}
```

`outer_vlan_id` and `nested_vlan` are parser facts used by tests and VLAN visibility handling. They are not added to `StatsKey` and are not exposed as per-VLAN counters.

### 4.2 eBPF accounting adapter

Each eBPF entry point:

1. resolves the current `InterfaceConfig` by ifindex;
2. increments the generation-scoped aggregate counter;
3. reads and classifies the bounded Layer 2 prefix;
4. increments exactly one mutually exclusive class counter;
5. records a parse failure as an error-pass observation;
6. returns pass/continue regardless of the result.

The adapter is responsible for verifier-safe bounds checks. The shared parser contains no pointer arithmetic over packet memory.

### 4.3 Ownership-aware observation reader

Userspace adds an injectable observation reader that:

1. loads the canonical ownership journal for the active run;
2. verifies the requested interface and current attachment session;
3. re-queries Map and hook identities;
4. opens only the journal-confirmed `HOOK_STATS` and `IFACE_CONFIG` pins;
5. reads keys for the exact current generation and ifindex;
6. performs checked aggregation of per-CPU counters;
7. returns a bounded domain snapshot.

The reader does not enumerate unrelated bpffs roots and does not accept an arbitrary pin path from a control request.

The current ephemeral ownership journal records pin paths but not kernel Map IDs. Delivery C upgrades the journal to schema version 2 and adds one fixed record per owned Map:

```rust
pub struct OwnedMapPin {
    pub name: String,
    pub path: PathBuf,
    pub map_id: u32,
}
```

The Aya loader captures the name, exact pin path, and non-zero kernel Map ID immediately after pin verification. The attachment transaction persists those values before publishing `IFACE_CONFIG`. Observation reopens each required pin and requires the fresh Map ID to equal the journal value.

Schema version 1 journals are refused. They are ephemeral isolated-test state, so Delivery C does not migrate, adopt, or clean them. This journal change does not change any eBPF Map name, key layout, value layout, or capacity.

### 4.4 Observation service and daemon dispatch

An observation service combines the reader with an injectable clock. The daemon dispatches `Observe` and `Status` through a bounded blocking adapter, just as real Linux preflight isolates synchronous platform I/O from the async socket worker.

The daemon currently owns at most one isolated attachment session. `status` without an interface returns zero or one session; it does not discover host interfaces.

## 5. Packet parsing contract

### 5.1 Bounded reads

The parser reads:

- 14 bytes for an untagged Ethernet header;
- at most 4 additional bytes for one VLAN header;
- no payload and no variable-length Layer 3 header.

The maximum parser input requirement is therefore 18 bytes. The eBPF adapter first proves the 14-byte Ethernet range, then proves the additional 4-byte range only when the outer EtherType is a supported VLAN TPID.

### 5.2 Supported EtherTypes

The parser recognizes:

- `0x8100` as `802.1Q`;
- `0x88a8` as an outer service VLAN tag;
- `0x0800` as IPv4 after optional single-tag decapsulation;
- `0x86dd` as IPv6 after optional single-tag decapsulation.

The VLAN ID is the low 12 bits of the TCI. Priority and drop-eligible bits do not affect traffic classification.

### 5.3 Classification priority

The mutually exclusive classification order is fixed:

1. `L2_BROADCAST` when the destination is `ff:ff:ff:ff:ff:ff`;
2. `LINK_LOCAL_CONTROL` for the IEEE reserved group range `01:80:c2:00:00:00` through `01:80:c2:00:00:0f`;
3. `IPV4_MULTICAST` for IPv4 EtherType with the standard `01:00:5e` multicast prefix;
4. `IPV6_MULTICAST` for IPv6 EtherType with the standard `33:33` multicast prefix;
5. `OTHER_L2_MULTICAST` when the destination group bit is set;
6. `UNICAST_OR_UNCLASSIFIED` otherwise.

`ALL` remains an aggregate counter and is not part of the mutually exclusive selection.

### 5.4 Nested VLAN behavior

If the EtherType after the first VLAN header is another supported VLAN TPID:

- the outer VLAN is valid and proves that one tag was visible;
- `nested_vlan` is true;
- the parser performs no further read;
- broadcast and link-local classifications remain exact from the destination MAC;
- other group destinations become `OTHER_L2_MULTICAST`;
- other destinations become `UNICAST_OR_UNCLASSIFIED`;
- the frame is not counted as malformed and remains pass/continue.

### 5.5 Parse failures

An Ethernet prefix shorter than 14 bytes or a recognized VLAN EtherType without the complete additional 4 bytes is a parse failure.

Every such frame still increments the aggregate pass counter. Its mutually exclusive observation uses:

```text
traffic_class = unicast_or_unclassified
verdict = error_pass
reason = parse_error
```

This verdict describes the observation, not the kernel action. The packet remains pass/continue.

## 6. VLAN visibility semantics

The existing `InterfaceConfig.vlan_visibility` field remains the only visibility state. No Map layout or new visibility Map is introduced.

The state is session-wide because ABI v1 stores one value per ifindex rather than one value per hook:

- a new isolated session starts as `UNKNOWN`;
- when either XDP or TC parses a complete supported outer VLAN header, an idempotent update promotes `UNKNOWN` to `VERIFIED_VISIBLE`;
- the data plane never writes `UNAVAILABLE`;
- the data plane never overwrites `UNAVAILABLE` or another explicit non-unknown state;
- absence of a tagged frame never proves unavailability;
- nested VLAN also proves that the first tag was visible.

`VERIFIED_VISIBLE` means only that at least one attached observation point in the current isolated session saw a real VLAN header. Delivery C does not claim that every hook can see tags and does not make per-VLAN detection claims.

## 7. Counter semantics

`HOOK_STATS` and `StatsKey` retain their ABI v1 layouts. A packet normally updates:

```text
(generation, ifindex, hook_role, all, pass, none)
(generation, ifindex, hook_role, selected_class, pass, none)
```

A parse failure updates:

```text
(generation, ifindex, hook_role, all, pass, none)
(generation, ifindex, hook_role, unclassified, error_pass, parse_error)
```

Counters are cumulative for one exact interface generation:

- they begin with the new isolated attachment session;
- they never merge values from another generation;
- detach removes the owned pinned state through the existing exact cleanup transaction;
- reattach creates a new generation and a logically new counter epoch;
- absent supported keys mean zero traffic, while an absent or mismatched Map is an error.

Counter aggregation uses checked addition. Overflow fails the snapshot instead of returning a truncated value. Data-plane counter increments remain wrapping and fail-open, consistent with ABI v1; userspace detects only aggregation overflow across per-CPU values.

## 8. Domain models

The core domain adds a versioned observation snapshot equivalent to:

```rust
pub struct ObservationSnapshot {
    pub schema_version: u16,
    pub interface: InterfaceName,
    pub generation: u64,
    pub captured_at_unix_ms: u64,
    pub vlan_visibility: VlanVisibility,
    pub health: ObservationHealth,
    pub hooks: Vec<HookObservation>,
}

pub struct HookObservation {
    pub role: HookRole,
    pub total: CounterValue,
    pub classes: Vec<ClassObservation>,
    pub parse_errors: CounterValue,
}

pub struct ClassObservation {
    pub traffic_class: TrafficClass,
    pub counters: CounterValue,
}
```

The concrete implementation should prefer fixed-size arrays where practical. Serialized vectors are accepted only when constructors enforce the exact bounded role and class sets.

`captured_at_unix_ms` is injected by a clock port. Tests never depend on the real wall clock.

`ObservationHealth` is:

- `Healthy` when ownership and all required Maps are verified and readable;
- `Degraded` only for a complete, trustworthy snapshot with an explicitly observed non-fatal limitation;
- not returned when identity or required data is untrustworthy.

Delivery C does not infer degraded health merely because VLAN visibility is unknown, a nested tag was bounded, or a class counter is zero. Unless a concrete limitation has a deterministic signal, a verified complete snapshot is healthy and a failed snapshot returns an error. This prevents status from inventing health conclusions.

The existing `InterfaceStatus` expands to include the current generation, lifecycle state, health, capture time, and ingress/egress aggregate counters. Detailed class counters remain in `ObservationSnapshot`.

## 9. CLI and protocol

### 9.1 Observe

```text
l2-loopctl observe --interface <IFACE> [--json]
```

`observe` is read-only. It requires the exact interface already owned by the active isolated session and returns the detailed `ObservationSnapshot`.

It does not start observe mode, create a session, attach a hook, or change configuration. A caller cannot use `observe` to bypass isolated attachment controls.

### 9.2 Status

```text
l2-loopctl status [--interface <IFACE>] [--json]
```

`status` returns a bounded list containing zero or one current isolated session. With `--interface`, a different or absent interface returns `OBS_SESSION_NOT_FOUND`; it does not inspect that host interface automatically.

The status summary contains:

- interface;
- generation;
- lifecycle state;
- observation health;
- captured time;
- XDP ingress aggregate packets/bytes;
- TC egress aggregate packets/bytes.

### 9.3 Rendering and exit codes

Text and JSON are two renderings of the same domain result. JSON uses stable snake-case fields and enum values.

The control protocol remains version 1. Daemon and CLI are deployed only as one exact commit-bound artifact, and no production compatibility boundary exists yet. A mixed-version daemon/CLI pair is unsupported and fails through the existing protocol checks rather than attempting compatibility inference.

Exit codes remain:

| Code | Meaning |
|---:|---|
| 0 | a complete observation or status result was returned |
| 1 | transport, ownership, identity, Map, aggregation, or internal failure |
| 2 | CLI usage or local interface validation failure |
| 4 | reserved for preflight/attachment safety blockers |

## 10. Error model

Stable control errors are:

| Code | Meaning |
|---|---|
| `OBS_SESSION_NOT_FOUND` | no active isolated session matches the request |
| `OBS_INTERFACE_MISMATCH` | the request differs from the active session interface |
| `OBS_OWNERSHIP_MISMATCH` | canonical journal and active session identity disagree |
| `OBS_MAP_UNAVAILABLE` | a required owned Map cannot be opened or read |
| `OBS_MAP_IDENTITY_MISMATCH` | a pinned Map no longer has the journal-confirmed identity |
| `OBS_SNAPSHOT_FAILED` | checked aggregation, clock, or bounded snapshot construction failed |

Errors expose stable codes and concise messages. They do not expose raw paths, kernel inventories, credentials, or internal error chains.

No observation error invokes cleanup. The existing explicit detach or daemon shutdown transaction remains the only cleanup authority.

## 11. Minimum necessary output boundary

Default observation output includes only information needed to identify and interpret the requested session:

- logical interface name;
- generation;
- lifecycle and health;
- hook role;
- traffic class;
- cumulative packets and bytes;
- capture time;
- session-level VLAN visibility.

It excludes MAC addresses, IP addresses, host identity, raw frames, packet payload, foreign object names, arbitrary pin paths, and test-node identity.

This is an information-minimization rule, not an attempt to hide the host from its administrator. A separate, explicit, root-only diagnostic surface may be designed later if troubleshooting requires additional identities.

## 12. Boundedness and performance

- Packet parsing performs no allocation and no unbounded loop.
- At most 18 packet bytes are required.
- At most two statistics updates occur per packet.
- No fingerprint or payload bytes are copied.
- No data-plane path waits for userspace.
- No observation I/O occurs in the async socket worker.
- A snapshot examines only the fixed current-generation role/class key set.
- No background thread, timer, sampling queue, or database is added.
- Protocol requests and responses remain within the existing one-megabyte frame limit.

Delivery C does not set a final throughput claim. The eBPF build and verifier must remain green, and later performance work compares observation throughput against the pass-through baseline before any production attachment approval.

## 13. Automated verification

### 13.1 Parser tests

Userspace tests cover:

- untagged broadcast;
- untagged IPv4 multicast;
- untagged IPv6 multicast;
- other multicast;
- each IEEE link-local group boundary;
- ordinary unicast;
- one `802.1Q` tag;
- one `802.1ad` tag;
- VLAN ID extraction with priority bits present;
- a nested second VLAN tag and degraded classification;
- truncated Ethernet;
- truncated first VLAN header;
- classification priority;
- exactly one mutually exclusive class for every successful parse.

### 13.2 eBPF contract tests

Contract tests and source scans require:

- all four entry points remain pass/continue;
- no probe, policy, token-bucket, or drop path exists;
- Map names and ABI structure sizes remain unchanged;
- the parser is bounded to one VLAN header;
- accounting is bounded to aggregate plus one class;
- VLAN visibility can only move from unknown to verified;
- GitHub eBPF compilation succeeds.

### 13.3 Userspace service tests

Deterministic fakes cover:

- exact generation filtering;
- checked per-CPU aggregation;
- missing supported keys as zero;
- unexpected current-generation keys as invalid data;
- canonical journal enforcement;
- interface, generation, hook, and Map identity mismatch;
- absent and unreadable Maps;
- injected clock failure;
- detailed observation construction;
- status summary construction;
- zero-session status;
- bounded text and JSON rendering;
- absence of prohibited output fields.

### 13.4 Control tests

Daemon and CLI round trips prove:

- `observe` never invokes attachment;
- `status` never invokes interface discovery;
- a non-session interface is refused before Map I/O;
- an active isolated session returns the expected result;
- protocol errors map to the documented exit codes;
- existing preflight and isolated attach/detach behavior is unchanged.

## 14. Authorized isolated acceptance

Acceptance uses the exact successful GitHub artifact and task-scoped operator credentials. Target details are never stored in the repository.

The harness performs:

1. a complete foreign network/eBPF before snapshot;
2. creation of one generated namespace/veth pair;
3. existing isolated preflight and safe attachment;
4. a baseline `observe` snapshot;
5. namespace-to-host frames that exercise XDP ingress classes;
6. host-to-namespace frames that exercise TC egress classes;
7. fixed untagged frames for all six mutually exclusive classes;
8. fixed one-tag `802.1Q` and `802.1ad` frames;
9. a fixed nested-tag frame proving bounded degraded classification;
10. exact counter-delta checks for packets and bytes;
11. verification that a real tagged frame promotes session VLAN visibility;
12. real text and JSON `observe/status` round trips;
13. proof that bounded frames continue to the peer;
14. exact owned detach and cleanup;
15. a complete after snapshot equal to the before snapshot.

Host acceptance does not require a physically truncated Ethernet frame. Truncation behavior is proved by deterministic parser tests because link-layer padding and raw-socket behavior make a host-level truncated-frame assertion unreliable.

Fault acceptance covers:

- observation before an isolated session exists;
- requested interface mismatch;
- injected Map read failure;
- generation or journal identity change before observation;
- daemon termination;
- operator interruption during bounded traffic;
- exact cleanup after each scenario.

No acceptance scenario mutates a physical or business interface, route, address, service, sysctl, offload setting, package set, or foreign BPF object.

## 15. Delivery sequence

Implementation should be split into test-first tasks in this order:

1. parser and classification domain contracts;
2. eBPF aggregate/class accounting and VLAN visibility promotion;
3. ownership-aware observation reader and per-CPU aggregation;
4. observation/status domain results and service;
5. daemon dispatch, CLI rendering, and exit codes;
6. isolated harness traffic matrix and fault scenarios;
7. final GitHub-only safety, ABI, and authorized-host audit.

Every compiling change follows red/green GitHub Actions evidence. No local Rust compilation is permitted.

## 16. Acceptance criteria

Delivery C is complete only when:

1. one exact `main` commit is green in every GitHub job and publishes its six-file MUSL artifact;
2. the shared parser passes the full untagged and single-tag matrix;
3. XDP ingress and TC egress expose exact aggregate and mutually exclusive class deltas;
4. every data-plane path remains pass/continue;
5. a real tagged isolated frame promotes only the session-level visibility proof;
6. nested VLAN is bounded and fail-open without a false parse-error claim;
7. `observe` and `status` work through the real daemon socket and never attach;
8. identity mismatch refuses observation without cleanup or adoption;
9. output is bounded and contains only the approved fields;
10. authorized isolated success and fault scenarios leave no owned residue;
11. complete before/after snapshots prove foreign network and eBPF state unchanged.

## 17. Next stages

After Delivery C, development proceeds in this order:

1. a bounded daemon sampler and explicit rate windows derived from generation-scoped cumulative counters;
2. dynamic baselines and observation health over those windows;
3. bounded packet fingerprints and ingress/egress relationship analysis;
4. loop-state decisions and event generation;
5. evidence persistence and alert output;
6. separately approved active probes, policing, and production-interface attachment.

The later stages consume Delivery C snapshots; they do not require a Delivery C Map ABI change.
