# Delivery C Isolated Passive Observation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task inline. Work directly on `main`; do not create a branch or worktree and do not dispatch subagents. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded single-VLAN Layer 2 classification, generation-scoped cumulative counters, and real read-only `observe/status` commands while preserving isolated-only attachment and exact owned cleanup.

**Architecture:** A shared `no_std` parser produces one mutually exclusive traffic class from at most 18 bytes. The eBPF programs update a fixed preinitialized key set and promote session-level VLAN visibility, while an ownership-aware Linux reader builds validated snapshots for the daemon and CLI. All mutation remains inside the existing generated namespace/veth attachment transaction.

**Tech Stack:** Rust stable userspace, Rust nightly `bpfel-unknown-none`, Aya/Aya eBPF, Tokio Unix socket, Clap/Serde, PowerShell host harness, GitHub Actions, x86_64 MUSL bundle.

**Design specification:** `docs/superpowers/specs/2026-08-10-isolated-passive-observation-design.md`

## Global Constraints

- Commit and push directly to `main`; this is a single-developer repository.
- Do not create a branch, worktree, pull request, or subagent task.
- Do not run Cargo, rustc, rustfmt, Clippy, `bpf-linker`, or any Rust/eBPF compiler on the local authoring host.
- Every compiling change uses a tests-only RED commit followed by the smallest GREEN implementation commit, both verified in GitHub Actions.
- Keep protocol version 1; daemon and CLI are supported only from one exact commit-bound artifact.
- Keep all six existing public eBPF Map names, key/value layouts, and capacities unchanged.
- Parse at most one `802.1Q` or `802.1ad` header and read at most 18 packet bytes.
- Every packet remains pass/continue and performs at most two `HOOK_STATS` updates.
- `observe/status` are read-only and require the current generated isolated session.
- Do not add PPS/BPS, background sampling, fingerprints, probes, policies, drops, physical attachment, or interface discovery.
- Host acceptance uses only task-scoped `L2_LOOP_TEST_TARGET` and `L2_LOOP_TEST_KEY` environment values and never records them.
- Preserve foreign network and BPF state exactly; unknown or changed identities require refusal and manual review.

## GitHub RED/GREEN checkpoint

Each task repeats this exact remote verification pattern after pushing:

```powershell
$L2LoopCommit = git rev-parse HEAD
$L2LoopRun = gh run list `
    --repo chenyongming211-glitch/network-loop `
    --branch main `
    --commit $L2LoopCommit `
    --limit 1 `
    --json databaseId,headSha,status,conclusion,url |
    ConvertFrom-Json
if (@($L2LoopRun).Count -ne 1 -or $L2LoopRun[0].headSha -cne $L2LoopCommit) {
    throw 'exact GitHub run was not found'
}
gh run watch $L2LoopRun[0].databaseId `
    --repo chenyongming211-glitch/network-loop `
    --interval 5 `
    --exit-status
```

For a RED commit, the exact named job must fail for the asserted missing behavior while unrelated safety jobs remain intact. For a GREEN commit, every job and the six-file MUSL bundle must succeed.

---

### Task 1: Shared Single-VLAN Parser and Statistics-Key Contract

**Files:**

- Create: `crates/l2-loop-common/src/packet.rs`
- Modify: `crates/l2-loop-common/src/lib.rs`
- Modify: `crates/l2-loop-common/src/abi.rs`
- Create: `crates/l2-loop-common/tests/packet_parsing.rs`
- Modify: `crates/l2-loop-common/tests/layout.rs`

**Interfaces:**

- Consumes: ABI v1 numeric constants from `l2-loop-common/src/constants.rs`.
- Produces: `parse_l2(&[u8]) -> Result<ParsedL2, ParseError>`, `ParsedL2`, `ParseError`, `StatsKey::classified`, `StatsKey::parse_error`, and `StatsKey::observation_keys` returning the exact eight keys for one hook.

- [ ] **Step 1: Add failing parser and key tests**

Create table-driven tests with exact frame bytes:

```rust
use l2_loop_common::{
    ParseError, StatsKey, hook_role, parse_l2, traffic_class,
};

fn ethernet(destination: [u8; 6], ether_type: u16) -> Vec<u8> {
    let mut frame = vec![0_u8; 14];
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
    frame
}

fn tagged(destination: [u8; 6], tpid: u16, tci: u16, inner: u16) -> Vec<u8> {
    let mut frame = ethernet(destination, tpid);
    frame.extend_from_slice(&tci.to_be_bytes());
    frame.extend_from_slice(&inner.to_be_bytes());
    frame
}

#[test]
fn classifies_the_complete_untagged_matrix() {
    let cases = [
        ([0xff; 6], 0x0806, traffic_class::L2_BROADCAST),
        ([0x01, 0x80, 0xc2, 0, 0, 0x0e], 0x88cc, traffic_class::LINK_LOCAL_CONTROL),
        ([0x01, 0, 0x5e, 0, 0, 1], 0x0800, traffic_class::IPV4_MULTICAST),
        ([0x33, 0x33, 0, 0, 0, 1], 0x86dd, traffic_class::IPV6_MULTICAST),
        ([0x01, 0, 0x5f, 0, 0, 1], 0x88b5, traffic_class::OTHER_L2_MULTICAST),
        ([0x02, 0, 0, 0, 0, 2], 0x0800, traffic_class::UNICAST_OR_UNCLASSIFIED),
    ];
    for (destination, ether_type, expected) in cases {
        assert_eq!(parse_l2(&ethernet(destination, ether_type)).unwrap().traffic_class, expected);
    }
}

#[test]
fn parses_one_tag_and_bounds_a_second_tag() {
    let one = parse_l2(&tagged([0x33, 0x33, 0, 0, 0, 1], 0x8100, 0xa07b, 0x86dd)).unwrap();
    assert_eq!(one.outer_vlan_id, Some(123));
    assert_eq!(one.traffic_class, traffic_class::IPV6_MULTICAST);
    assert!(!one.nested_vlan);

    let nested = parse_l2(&tagged([0x33, 0x33, 0, 0, 0, 1], 0x88a8, 7, 0x8100)).unwrap();
    assert_eq!(nested.outer_vlan_id, Some(7));
    assert!(nested.nested_vlan);
    assert_eq!(nested.traffic_class, traffic_class::OTHER_L2_MULTICAST);
}

#[test]
fn truncated_headers_are_errors() {
    assert_eq!(parse_l2(&[0_u8; 13]), Err(ParseError::TruncatedEthernet));
    assert_eq!(parse_l2(&ethernet([0xff; 6], 0x8100)), Err(ParseError::TruncatedVlan));
}

#[test]
fn observation_keys_are_fixed_and_generation_scoped() {
    let keys = StatsKey::observation_keys(9, 41, hook_role::EXTERNAL_XDP_INGRESS);
    assert_eq!(keys.len(), 8);
    assert!(keys.iter().all(|key| key.interface_generation == 9 && key.ifindex == 41));
    assert_eq!(keys[0], StatsKey::total(9, 41, hook_role::EXTERNAL_XDP_INGRESS));
    assert_eq!(keys[7], StatsKey::parse_error(9, 41, hook_role::EXTERNAL_XDP_INGRESS));
}
```

- [ ] **Step 2: Push the RED commit**

```powershell
git add crates/l2-loop-common
git commit -m "test: define passive packet classification"
git push origin main
```

Expected GitHub result: Userspace fails because the parser types and key constructors do not exist. Do not run a local Rust command.

- [ ] **Step 3: Implement the bounded parser**

Implement the public contract without allocation:

```rust
pub const ETHERNET_HEADER_LEN: usize = 14;
pub const SINGLE_VLAN_HEADER_LEN: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedL2 {
    pub traffic_class: u8,
    pub outer_vlan_id: Option<u16>,
    pub nested_vlan: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TruncatedEthernet,
    TruncatedVlan,
}

pub fn parse_l2(frame: &[u8]) -> Result<ParsedL2, ParseError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(ParseError::TruncatedEthernet);
    }
    let destination = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];
    let outer = u16::from_be_bytes([frame[12], frame[13]]);
    let (ether_type, outer_vlan_id, nested_vlan) = if is_vlan_tpid(outer) {
        if frame.len() < SINGLE_VLAN_HEADER_LEN {
            return Err(ParseError::TruncatedVlan);
        }
        let tci = u16::from_be_bytes([frame[14], frame[15]]);
        let inner = u16::from_be_bytes([frame[16], frame[17]]);
        (inner, Some(tci & 0x0fff), is_vlan_tpid(inner))
    } else {
        (outer, None, false)
    };
    Ok(ParsedL2 {
        traffic_class: classify(destination, ether_type, nested_vlan),
        outer_vlan_id,
        nested_vlan,
    })
}
```

Implement classification in the approved priority order and export the module from `lib.rs`. Add the three `StatsKey` constructors and return `[StatsKey; 8]` in this order: total, broadcast, IPv4 multicast, IPv6 multicast, other multicast, link-local control, unicast, parse error.

- [ ] **Step 4: Push the GREEN commit and require full CI**

```powershell
git add crates/l2-loop-common
git commit -m "feat: add bounded passive packet parser"
git push origin main
```

Expected GitHub result: every job and the exact bundle succeed; layout tests prove `StatsKey` remains 16 bytes.

---

### Task 2: Journal-Confirmed Owned Map Identity

**Files:**

- Modify: `crates/l2-loop-agent/src/ports.rs`
- Modify: `crates/l2-loop-agent/src/ownership.rs`
- Modify: `crates/l2-loop-agent/src/linux/bpf_object.rs`
- Modify: `crates/l2-loop-agent/src/attach.rs`
- Modify: `crates/l2-loop-agent/src/linux/cleanup.rs`
- Modify: `crates/l2-loop-agent/src/host_acceptance.rs`
- Modify: `crates/l2-loop-agent/tests/ownership.rs`
- Modify: `crates/l2-loop-agent/tests/attach_transaction.rs`
- Modify: `crates/l2-loop-agent/tests/cleanup_plan.rs`
- Create: `crates/l2-loop-agent/tests/owned_map_identity.rs`

**Interfaces:**

- Consumes: verified Map IDs already captured internally by `AyaObjectLoader`.
- Produces: `OwnedMapPin { name, path, map_id }`, `LoadedBpfObject.map_pins`, and ownership journal schema version 2 with exact Map identities.

- [ ] **Step 1: Add failing schema and identity tests**

Require exact name/path/ID persistence and rejection:

```rust
#[test]
fn schema_two_requires_non_zero_unique_owned_map_identities() {
    let record = fixture_record(vec![
        OwnedMapPin::new("HOOK_STATS", pin("HOOK_STATS"), 301).unwrap(),
        OwnedMapPin::new("IFACE_CONFIG", pin("IFACE_CONFIG"), 302).unwrap(),
    ]);
    record.validate_owned_maps().unwrap();

    let duplicate = fixture_record(vec![
        OwnedMapPin::new("HOOK_STATS", pin("HOOK_STATS"), 301).unwrap(),
        OwnedMapPin::new("IFACE_CONFIG", pin("IFACE_CONFIG"), 301).unwrap(),
    ]);
    assert!(matches!(duplicate.validate_owned_maps(), Err(OwnershipError::IdentityMismatch(_))));
}

#[test]
fn old_ephemeral_schema_is_refused_without_migration() {
    let mut record = fixture_record(valid_map_pins());
    record.schema_version = 1;
    assert!(matches!(store_for(record).load_current(), Err(OwnershipError::SchemaMismatch { .. })));
}
```

Add loader/transaction assertions that the journal contains all six fixed names and the exact IDs returned after pin verification.

- [ ] **Step 2: Push the RED commit**

```powershell
git add crates/l2-loop-agent
git commit -m "test: require journal-confirmed map identities"
git push origin main
```

Expected GitHub result: Userspace fails because `OwnedMapPin`, schema 2, and `map_pins` are absent.

- [ ] **Step 3: Implement schema version 2**

Add the exact owned identity:

```rust
pub const OWNED_MAP_NAMES: [&str; 6] = [
    "IFACE_CONFIG",
    "HOOK_STATS",
    "FINGERPRINTS",
    "PROBE_REGISTRY",
    "PROBE_STATS",
    "RATE_POLICY",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedMapPin {
    pub name: String,
    pub path: PathBuf,
    pub map_id: u32,
}

impl OwnedMapPin {
    pub fn new(name: impl Into<String>, path: PathBuf, map_id: u32) -> Result<Self, OwnershipError> {
        let name = name.into();
        if map_id == 0 || !OWNED_MAP_NAMES.contains(&name.as_str()) {
            return Err(OwnershipError::IdentityMismatch("invalid owned map identity".to_owned()));
        }
        Ok(Self { name, path, map_id })
    }
}
```

Set `OWNERSHIP_SCHEMA_VERSION` to `2`. Replace `LoadedBpfObject.pin_paths` with `map_pins: Vec<OwnedMapPin>` and persist the same vector in `OwnershipRecord`. Update cleanup to iterate `record.map_pins` in reverse, compare fresh pin ID to `map_id`, and retain any changed object. Preserve exact empty-directory cleanup.

The loader must attach the fixed Map name to its existing `PinIdentity` immediately after `MapInfo::from_pin` proves the ID. Reject duplicate names, duplicate IDs, non-absolute paths, paths outside the run pin root, and a set different from the six validated public Maps.

- [ ] **Step 4: Push the GREEN commit and require full CI**

```powershell
git add crates/l2-loop-agent
git commit -m "feat: persist exact owned map identities"
git push origin main
```

Expected GitHub result: all tests pass, cleanup tests retain changed pins, and the bundle remains six files.

---

### Task 3: Fixed eBPF Classification Accounting and VLAN Visibility

**Files:**

- Modify: `ebpf/l2-loop-ebpf/src/programs.rs`
- Modify: `crates/l2-loop-agent/src/linux/maps.rs`
- Modify: `xtask/tests/public_ebpf_contract.rs`

**Interfaces:**

- Consumes: `parse_l2`, `StatsKey::observation_keys`, schema-2 loaded object identities.
- Produces: preinitialized aggregate/class/error counters for both hooks, eBPF classification updates, and session-level `UNKNOWN -> VERIFIED_VISIBLE` promotion.

- [ ] **Step 1: Add failing accounting/lifecycle contracts**

Add a `#[cfg(test)]` unit module to `linux/maps.rs` and require sixteen initialized keys in exact rollback order:

```rust
#[test]
fn observation_key_set_is_initialized_and_removed_exactly() {
    let xdp = StatsKey::observation_keys(7, 41, hook_role::EXTERNAL_XDP_INGRESS);
    let tc = StatsKey::observation_keys(7, 41, hook_role::PHYSICAL_TC_EGRESS);
    let expected = xdp.into_iter().chain(tc).collect::<Vec<_>>();
    let actual = stats_keys(41, 7).into_iter().collect::<Vec<_>>();
    assert_eq!(expected.len(), 16);
    assert_eq!(actual, expected);
    assert_eq!(
        stats_keys(41, 7).into_iter().rev().collect::<Vec<_>>(),
        expected.into_iter().rev().collect::<Vec<_>>(),
    );
}
```

Extend the public source contract to require `parse_l2`, `VERIFIED_VISIBLE`, `StatsKey::classified`, `StatsKey::parse_error`, `XDP_PASS`, and `TC_ACT_OK`, and to reject policy/probe/drop symbols in `programs.rs`.

- [ ] **Step 2: Push the RED commit**

```powershell
git add crates/l2-loop-agent xtask
git commit -m "test: define classified eBPF accounting"
git push origin main
```

Expected GitHub result: Userspace contract tests fail because only two total keys are initialized and the programs do not classify.

- [ ] **Step 3: Implement preinitialized fixed keys**

Refactor `AyaMapPublisher::initialize_dependent` to build the sixteen-key array, insert zero per-CPU values one key at a time, remember successfully inserted keys, and remove only those keys in reverse if any insertion fails. `rollback_initialized_exact` re-queries and removes the same fixed keys in reverse.

The eBPF update sequence is:

```rust
fn account(frame: &[u8], ifindex: u32, role: u8, bytes: u64) {
    let Some(config) = IFACE_CONFIG.get_ptr_mut(&ifindex) else { return; };
    let generation = unsafe { (*config).interface_generation };
    increment_existing(StatsKey::total(generation, ifindex, role), bytes);
    match parse_l2(frame) {
        Ok(parsed) => {
            increment_existing(StatsKey::classified(generation, ifindex, role, parsed.traffic_class), bytes);
            if parsed.outer_vlan_id.is_some()
                && unsafe { (*config).vlan_visibility } == vlan_visibility::UNKNOWN
            {
                unsafe { (*config).vlan_visibility = vlan_visibility::VERIFIED_VISIBLE; }
            }
        }
        Err(_) => increment_existing(StatsKey::parse_error(generation, ifindex, role), bytes),
    }
}
```

Use verifier-safe constant-range helpers: prove 14 bytes first, inspect the TPID, and prove 18 bytes only for a recognized tag. Never construct a slice beyond the proven range. Missing counters or failed updates remain pass/continue.

- [ ] **Step 4: Push the GREEN commit and require eBPF build success**

```powershell
git add ebpf crates/l2-loop-agent xtask
git commit -m "feat: classify isolated passive traffic"
git push origin main
```

Expected GitHub result: Userspace, eBPF, and Bundle succeed; public Map layouts and capacities remain unchanged.

---

### Task 4: Observation and Status Domain Results

**Files:**

- Create: `crates/l2-loop-core/src/observation.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Modify: `crates/l2-loop-core/src/command.rs`
- Create: `crates/l2-loop-core/tests/observation_snapshot.rs`
- Modify: `crates/l2-loop-core/tests/interface_lifecycle.rs`

**Interfaces:**

- Consumes: existing `InterfaceName`, `InterfaceState`, `HookRole`, `TrafficClass`, `VlanVisibility`.
- Produces: `ObservationSnapshot`, `HookObservation`, `ClassObservation`, `ObservationCounters`, `ObservationHealth`, expanded `InterfaceStatus`, and `AgentResult::Observation`.

- [ ] **Step 1: Add failing domain-construction and serialization tests**

```rust
#[test]
fn snapshot_requires_exact_roles_classes_and_non_zero_identity() {
    let snapshot = ObservationSnapshot::new(
        InterfaceName::new("l2h0123456789").unwrap(),
        41,
        7,
        1_786_300_000_000,
        VlanVisibility::VerifiedVisible,
        [hook(HookRole::ExternalXdpIngress), hook(HookRole::PhysicalTcEgress)],
    ).unwrap();
    assert_eq!(snapshot.schema_version, 1);
    assert_eq!(snapshot.generation, 7);
    assert_eq!(snapshot.hooks.len(), 2);
}

#[test]
fn json_contains_only_the_approved_observation_fields() {
    let value = serde_json::to_value(fixture_snapshot()).unwrap();
    let text = value.to_string();
    for prohibited in ["mac", "ip_address", "hostname", "machine_id", "pin_path", "map_id"] {
        assert!(!text.contains(prohibited));
    }
}
```

Test checked counter addition, class ordering, duplicate/missing role rejection, zero generation/ifindex rejection, and an empty status list.

- [ ] **Step 2: Push the RED commit**

```powershell
git add crates/l2-loop-core
git commit -m "test: define passive observation results"
git push origin main
```

Expected GitHub result: Userspace fails because observation domain types and result variants are absent.

- [ ] **Step 3: Implement validated bounded models**

Use fixed arrays internally:

```rust
pub const OBSERVATION_SCHEMA_VERSION: u16 = 1;
pub const OBSERVED_HOOK_COUNT: usize = 2;
pub const OBSERVED_CLASS_COUNT: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationCounters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookObservation {
    pub role: HookRole,
    pub total: ObservationCounters,
    pub classes: [ClassObservation; OBSERVED_CLASS_COUNT],
    pub parse_errors: ObservationCounters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationSnapshot {
    pub schema_version: u16,
    pub interface: InterfaceName,
    pub ifindex: u32,
    pub generation: u64,
    pub captured_at_unix_ms: u64,
    pub vlan_visibility: VlanVisibility,
    pub health: ObservationHealth,
    pub hooks: [HookObservation; OBSERVED_HOOK_COUNT],
}
```

`ObservationSnapshot::new` fixes role order as XDP then TC, class order as broadcast, IPv4 multicast, IPv6 multicast, other multicast, link-local, unicast, and returns `DomainError::InvalidObservation` for any mismatch. Extend `InterfaceStatus` with generation, capture time, health, VLAN visibility, and two aggregate counters.

- [ ] **Step 4: Push the GREEN commit and require full CI**

```powershell
git add crates/l2-loop-core
git commit -m "feat: add passive observation domain results"
git push origin main
```

Expected GitHub result: all domain, serialization, and existing protocol tests pass.

---

### Task 5: Observation Reader Port and Service

**Files:**

- Modify: `crates/l2-loop-agent/src/ports.rs`
- Create: `crates/l2-loop-agent/src/observation.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Create: `crates/l2-loop-agent/tests/observation_service.rs`

**Interfaces:**

- Consumes: schema-2 `OwnershipRecord`, `Clock`, Task 4 domain results.
- Produces: `RawObservation`, `ObservationReader::read_exact`, `ObservationService::observe(requested, active_interface, ownership)`, and `ObservationService::status`.

- [ ] **Step 1: Add failing service tests with deterministic fakes**

```rust
#[test]
fn observe_builds_a_generation_scoped_snapshot() {
    let reader = FakeReader::returning(raw_observation(41, 7));
    let clock = FixedClock::unix_ms(1_786_300_000_000);
    let mut service = ObservationService::new(reader, clock);
    let snapshot = service.observe(&interface(), &interface(), &ownership(41, 7)).unwrap();
    assert_eq!(snapshot.ifindex, 41);
    assert_eq!(snapshot.generation, 7);
    assert_eq!(snapshot.captured_at_unix_ms, 1_786_300_000_000);
}

#[test]
fn interface_mismatch_is_rejected_before_reader_io() {
    let reader = FakeReader::panic_on_read();
    let mut service = ObservationService::new(reader, FixedClock::unix_ms(1));
    let error = service.observe(
        &InterfaceName::new("foreign0").unwrap(),
        &interface(),
        &ownership(41, 7),
    ).unwrap_err();
    assert_eq!(error.code(), "OBS_INTERFACE_MISMATCH");
}
```

Cover zero-session status, checked per-CPU totals supplied by the reader, clock before UNIX epoch, reader identity errors, and deterministic error-code preservation.

- [ ] **Step 2: Push the RED commit**

```powershell
git add crates/l2-loop-agent
git commit -m "test: define passive observation service"
git push origin main
```

Expected GitHub result: Userspace fails because the observation port and service do not exist.

- [ ] **Step 3: Implement the narrow port and service**

Define raw data without paths or kernel object names:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawObservation {
    pub ifindex: u32,
    pub generation: u64,
    pub vlan_visibility: VlanVisibility,
    pub hooks: [HookObservation; 2],
}

pub trait ObservationReader: Send {
    fn read_exact(&mut self, ownership: &OwnershipRecord) -> Result<RawObservation, PortError>;
}
```

`ObservationService<R, C>` accepts both the requested interface and the active in-memory session interface, compares them before calling the reader, converts `Clock::wall_time()` to checked UNIX milliseconds, validates raw ifindex/generation against the journal, and constructs the domain result. Map `PortError::stable_code()` through unchanged; use `OBS_SNAPSHOT_FAILED` only for construction or clock failures.

- [ ] **Step 4: Push the GREEN commit and require full CI**

```powershell
git add crates/l2-loop-agent
git commit -m "feat: add passive observation service"
git push origin main
```

Expected GitHub result: service fakes prove no observation error triggers cleanup or attachment.

---

### Task 6: Linux Aya Observation Reader

**Files:**

- Create: `crates/l2-loop-agent/src/linux/observation.rs`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Create: `crates/l2-loop-agent/tests/observation_reader.rs`
- Modify: `crates/l2-loop-agent/Cargo.toml` only if an existing Aya API requires an already-workspace-pinned feature

**Interfaces:**

- Consumes: schema-2 owned Map IDs, fixed observation keys, `ObservationReader`.
- Produces: `LinuxObservationReader<I>`, injectable `ObservationIo`, and production `AyaObservationIo`.

- [ ] **Step 1: Add failing exact-identity and aggregation tests**

```rust
#[test]
fn changed_hook_stats_pin_is_refused_before_counter_reads() {
    let io = FakeIo::with_map_ids([("IFACE_CONFIG", 302), ("HOOK_STATS", 999)]);
    let mut reader = LinuxObservationReader::new(io);
    let error = reader.read_exact(&ownership_with_map_ids(302, 301)).unwrap_err();
    assert_eq!(error.stable_code(), Some("OBS_MAP_IDENTITY_MISMATCH"));
}

#[test]
fn per_cpu_values_are_aggregated_with_checked_addition() {
    let io = FakeIo::complete()
        .counter(total_xdp(), vec![CounterValue { packets: 2, bytes: 120 }, CounterValue { packets: 3, bytes: 180 }]);
    let raw = LinuxObservationReader::new(io).read_exact(&ownership()).unwrap();
    assert_eq!(raw.hooks[0].total.packets, 5);
    assert_eq!(raw.hooks[0].total.bytes, 300);
}
```

Cover missing required Map, unexpected current-generation key, absent fixed key as zero, invalid `IFACE_CONFIG`, non-current generation, aggregation overflow, and `UNKNOWN/VERIFIED_VISIBLE` conversion.

Add a changed-hook test in which the fresh XDP or TC program identity differs from the journal and assert `OBS_OWNERSHIP_MISMATCH` before Map content reads.

- [ ] **Step 2: Push the RED commit**

```powershell
git add crates/l2-loop-agent
git commit -m "test: define exact passive map reader"
git push origin main
```

Expected GitHub result: Userspace fails because the reader and `ObservationIo` do not exist.

- [ ] **Step 3: Implement the injectable Linux reader**

Define the test seam:

```rust
pub trait ObservationIo {
    fn verify_hooks(&mut self, ownership: &OwnershipRecord) -> Result<(), PortError>;
    fn fresh_map_id(&mut self, pin: &OwnedMapPin) -> Result<u32, PortError>;
    fn read_config(&mut self, pin: &OwnedMapPin, ifindex: u32) -> Result<InterfaceConfig, PortError>;
    fn read_counter(&mut self, pin: &OwnedMapPin, key: &StatsKey) -> Result<Option<Vec<CounterValue>>, PortError>;
    fn current_keys(&mut self, pin: &OwnedMapPin) -> Result<Vec<StatsKey>, PortError>;
}
```

`LinuxObservationReader` first re-queries the journal-confirmed XDP and TC identities through `verify_hooks`, then selects `IFACE_CONFIG` and `HOOK_STATS` by exact fixed name, rejects duplicate/missing entries, compares fresh IDs before any content read, validates config generation/ifindex/mode, rejects unsupported current-generation keys, treats absent approved keys as zero, and uses `checked_add` for every per-CPU value.

`AyaObservationIo` uses the same read-only rtnetlink inventory primitives as preflight for hooks, plus `MapInfo::from_pin`, `HashMap<u32, InterfaceConfig>`, and `PerCpuHashMap<StatsKey, CounterValue>` for Maps. It accepts no caller-provided path and emits coded errors without embedding the path.

- [ ] **Step 4: Push the GREEN commit and require full CI**

```powershell
git add crates/l2-loop-agent
git commit -m "feat: read exact passive map snapshots"
git push origin main
```

Expected GitHub result: Userspace tests and MUSL build pass; the reader opens only schema-2 journal-confirmed pins.

---

### Task 7: Daemon Dispatch, CLI Rendering, and Real Socket Round Trip

**Files:**

- Modify: `crates/l2-loop-agent/src/daemon.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Modify: `crates/l2-loop-agent/src/protocol.rs`
- Modify: `crates/l2-loop-agent/tests/daemon_dispatch.rs`
- Modify: `crates/l2-loop-agent/tests/isolated_control.rs`
- Modify: `crates/l2-loop-cli/src/args.rs`
- Modify: `crates/l2-loop-cli/src/convert.rs`
- Modify: `crates/l2-loop-cli/src/render.rs`
- Modify: `crates/l2-loop-cli/tests/cli.rs`
- Modify: `crates/l2-loop-cli/tests/render.rs`
- Modify: `crates/l2-loop-cli/tests/socket_round_trip.rs`

**Interfaces:**

- Consumes: `ObservationService`, `LinuxObservationReader`, active `AttachmentSession`, observation domain results.
- Produces: real `Observe`/`Status` daemon paths, `--json` for observe, text/JSON renderers, stable OBS error mapping.

- [ ] **Step 1: Add failing dispatcher and CLI tests**

```rust
#[tokio::test]
async fn observe_reads_the_active_session_without_invoking_attach() {
    let control = FakeIsolatedControl::active_with_observation(fixture_snapshot());
    let dispatcher = dispatcher_with(control);
    let response = dispatcher.dispatch(request(AgentCommand::Observe { interface: interface() })).await;
    assert_eq!(success_result(response), AgentResult::Observation { snapshot: fixture_snapshot() });
    assert_eq!(events(), vec!["observe"]);
}

#[test]
fn observe_supports_text_and_json_without_rate_options() {
    let parsed = Cli::try_parse_from(["l2-loopctl", "observe", "--interface", "l2h0123456789", "--json"]).unwrap();
    assert!(ParsedCli::try_from(parsed).unwrap().json);
    for forbidden in ["--interval", "--window", "--rate", "--repeat"] {
        assert!(Cli::try_parse_from(["l2-loopctl", "observe", "--interface", "l2h0123456789", forbidden]).is_err());
    }
}
```

Test status with zero/one session, interface mismatch before Map reads, OBS error exit `1`, response field allowlist, one-megabyte framing, and preflight/attach/detach regression behavior.

- [ ] **Step 2: Push the RED commit**

```powershell
git add crates/l2-loop-agent crates/l2-loop-cli
git commit -m "test: define observe and status control paths"
git push origin main
```

Expected GitHub result: Userspace fails because dispatcher/rendering still returns command-not-implemented.

- [ ] **Step 3: Implement active-session observation dispatch**

Extend `IsolatedControl` with read-only methods:

```rust
fn observe(&mut self, interface: &InterfaceName) -> Result<ObservationSnapshot, IsolatedControlError>;
fn status(&mut self, interface: Option<&InterfaceName>) -> Result<Vec<InterfaceStatus>, IsolatedControlError>;
```

`TransactionIsolatedControl` owns `ObservationService<Box<dyn ObservationReader>, SystemClock>` beside the driver and stores active state as `(RunId, InterfaceName, AttachmentSession)`. It reloads the canonical journal, requires equality with `active.session.ownership`, and delegates with both the requested and stored active interface without changing the session. `DaemonDispatcher` runs both calls through `spawn_blocking` under the existing bounded control mutex.

Wire `AyaObservationIo` in `main.rs`. Add `json: bool` to `ObserveArgs`. Render detailed ordered class counters for `AgentResult::Observation`, summarized rows for `AgentResult::Status`, and the same structures in JSON. Do not render raw ownership evidence.

- [ ] **Step 4: Push the GREEN commit and require full CI**

```powershell
git add crates/l2-loop-agent crates/l2-loop-cli
git commit -m "feat: expose isolated passive observations"
git push origin main
```

Expected GitHub result: real socket tests pass, `observe/status` no longer return command-not-implemented, and unsafe commands remain unchanged.

---

### Task 8: Classified Isolated Host Harness and Fault Acceptance

**Files:**

- Modify: `scripts/verify-isolated-host.ps1`
- Modify: `scripts/tests/verify-isolated-host.Tests.ps1`
- Modify: `crates/l2-loop-agent/src/linux/acceptance_fault.rs`
- Modify: `crates/l2-loop-agent/tests/acceptance_fault.rs`
- Modify: `.github/workflows/ci.yml` only if an additional self-contained script test invocation is required

**Interfaces:**

- Consumes: exact GitHub bundle, real observe/status CLI, existing generated naming and snapshot safeguards.
- Produces: `PassiveObservation`, `ObservationMapFailure`, and `ObservationIdentityChange` acceptance scenarios with deterministic frame matrices.

- [ ] **Step 1: Add failing static harness and fault contracts**

Require the new scenarios and bounded frame labels:

```powershell
foreach ($Required in @(
    "'PassiveObservation'",
    "'ObservationMapFailure'",
    "'ObservationIdentityChange'",
    "'l2-broadcast'",
    "'ipv4-multicast'",
    "'ipv6-multicast'",
    "'other-l2-multicast'",
    "'link-local-control'",
    "'unicast-or-unclassified'",
    "'8021q'",
    "'8021ad'",
    "'nested-vlan'",
    "l2-loopctl', 'observe'",
    "l2-loopctl', 'status'"
)) {
    Assert-True ($Harness.Contains($Required)) "harness is missing passive marker: $Required"
}
```

Keep every existing forbidden mutation scan. Add deterministic fault tests requiring `L2_LOOP_ACCEPTANCE_FAULT=observation-map-read` to fail only observation, never traffic or cleanup.

- [ ] **Step 2: Push the RED commit**

```powershell
git add scripts crates/l2-loop-agent .github/workflows/ci.yml
git commit -m "test: define classified isolated acceptance"
git push origin main
```

Expected GitHub result: Script safety and Userspace fail for the missing scenarios/fault adapter; no workflow contacts a host.

- [ ] **Step 3: Implement the bounded traffic matrix**

Use this exact fixed 60-byte frame matrix and send exactly `FrameCount` frames for each label and direction:

```python
source = bytes.fromhex("020000000001")

def untagged(destination, ether_type):
    return bytes.fromhex(destination) + source + bytes.fromhex(ether_type) + bytes(46)

def tagged(destination, tpid, tci, inner_type):
    return (
        bytes.fromhex(destination) + source + bytes.fromhex(tpid)
        + bytes.fromhex(tci) + bytes.fromhex(inner_type) + bytes(42)
    )

frames = {
    "l2-broadcast": untagged("ffffffffffff", "0806"),
    "ipv4-multicast": untagged("01005e000001", "0800"),
    "ipv6-multicast": untagged("333300000001", "86dd"),
    "other-l2-multicast": untagged("01005f000001", "88b5"),
    "link-local-control": untagged("0180c200000e", "88cc"),
    "unicast-or-unclassified": untagged("020000000002", "0800"),
    "8021q": tagged("333300000001", "8100", "007b", "86dd"),
    "8021ad": tagged("01005e000001", "88a8", "0007", "0800"),
    "nested-vlan": (
        bytes.fromhex("01005f000001") + source
        + bytes.fromhex("88a80007810000080800") + bytes(38)
    ),
}
assert all(len(frame) == 60 for frame in frames.values())
```

Namespace-to-host traffic validates XDP ingress; host-to-namespace traffic validates TC egress. Capture baseline and after snapshots through real JSON `observe`, subtract with checked PowerShell arithmetic, and require exact packet deltas and positive byte deltas.

The receiver must prove frames continue to the peer with a bounded timeout. A first valid tagged frame must change session visibility from unknown to verified. Nested VLAN must increment broadcast/link-local/other-multicast/unclassified according to destination MAC without incrementing parse errors.

`ObservationMapFailure` injects a userspace read error and proves traffic still passes and detach remains exact. `ObservationIdentityChange` replaces only the generated journal with a mismatched copy, requires observation refusal, restores the canonical journal, verifies owned hooks, and performs exact detach.

- [ ] **Step 4: Push the GREEN implementation and wait for its exact artifact**

```powershell
git add scripts crates/l2-loop-agent .github/workflows/ci.yml
git commit -m "test: add classified isolated host verification"
git push origin main
```

Expected GitHub result: Linux and Windows script safety, Userspace, eBPF, and Bundle all succeed.

- [ ] **Step 5: Run authorized isolated acceptance**

Do not print environment values. Require them and run the exact artifact:

```powershell
if ([string]::IsNullOrWhiteSpace($env:L2_LOOP_TEST_TARGET)) { throw 'authorized target is unavailable' }
if ([string]::IsNullOrWhiteSpace($env:L2_LOOP_TEST_KEY)) { throw 'authorized key is unavailable' }
$L2LoopCommit = git rev-parse HEAD
foreach ($L2LoopScenario in @(
    'PassiveObservation',
    'ObservationMapFailure',
    'ObservationIdentityChange'
)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File scripts/verify-isolated-host.ps1 `
        -Commit $L2LoopCommit `
        -Scenario $L2LoopScenario `
        -TimeoutSeconds 240
    if ($LASTEXITCODE -ne 0) { throw "isolated scenario failed: $L2LoopScenario" }
}
```

Expected result: all three scenarios pass for the same exact commit and each complete before/after snapshot matches.

---

### Task 9: Documentation, Final Audit, and Exact-Artifact Gate

**Files:**

- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/superpowers/specs/2026-08-10-isolated-passive-observation-design.md` only for implementation-confirmed corrections
- Modify only source/tests required by a reproduced audit failure

**Interfaces:**

- Consumes: completed Delivery C behavior and host evidence.
- Produces: accurate operator documentation and one final exact green/accepted `main` commit.

- [ ] **Step 1: Correct current-status and operator documentation**

Document:

- single-VLAN parsing and nested-tag degradation;
- generation-scoped cumulative counter semantics;
- detailed observe versus summarized status;
- session-level VLAN visibility meaning;
- OBS error codes;
- isolated-only boundary;
- exact GitHub artifact and acceptance commands;
- explicit absence of rates, fingerprints, loop verdicts, probes, drops, policies, and production attachment.

- [ ] **Step 2: Run non-compiling local audits**

```powershell
git diff --check
$Tracked = git ls-files
$RetiredIdentifier = ("cs" + "mp")
if (git grep -n -i -E $RetiredIdentifier -- $Tracked) { throw 'retired identifier remains' }
if (rg -n 'XDP_DROP|TC_ACT_SHOT' ebpf) { throw 'drop action remains in eBPF source' }
if (rg -n '"(replace|adopt|cleanup-all|force-attach)"' crates/l2-loop-cli/src crates/l2-loop-core/src) {
    throw 'dangerous public command remains'
}
$Markers = @(("TO"+"DO"),("T"+"BD"),("PLACE"+"HOLDER")) -join '|'
if (rg -n $Markers crates ebpf scripts .github README.md docs/development.md docs/superpowers) {
    throw 'incomplete marker remains'
}
if (git grep -n -E '([0-9]{1,3}\.){3}[0-9]{1,3}|root@|\.ssh[\\/]|BEGIN (OPENSSH|RSA|EC) PRIVATE KEY' -- $Tracked) {
    throw 'target identity or credential material remains'
}
rg -n '0x4c32_0001|0x4c32_0002|49_600|49_699|UPDATE_IF_NOEXIST' crates
rg -n 'parse_l2|SINGLE_VLAN_HEADER_LEN|observation_keys|VERIFIED_VISIBLE|OBS_MAP_IDENTITY_MISMATCH' crates ebpf
```

Expected result: no prohibited output; collision-safe constants and Delivery C safety markers are present.

- [ ] **Step 3: Push the final documentation/audit commit**

```powershell
git add README.md docs/development.md docs/superpowers
git commit -m "docs: record passive observation delivery"
git push origin main
```

If an audit finds a real code defect, first add a deterministic tests-only RED commit, observe the exact GitHub failure, then push the smallest GREEN fix before this documentation commit.

- [ ] **Step 4: Require final exact GitHub evidence**

Use the global checkpoint and require all five jobs to succeed. Then verify the artifact name:

```powershell
$L2LoopCommit = git rev-parse HEAD
$L2LoopRun = gh run list --repo chenyongming211-glitch/network-loop --branch main --commit $L2LoopCommit --limit 1 --json databaseId,conclusion,url | ConvertFrom-Json
if (@($L2LoopRun).Count -ne 1 -or $L2LoopRun[0].conclusion -cne 'success') { throw 'final exact run is not green' }
$Artifacts = gh api "repos/chenyongming211-glitch/network-loop/actions/runs/$($L2LoopRun[0].databaseId)/artifacts" | ConvertFrom-Json
$ExpectedArtifact = "l2-loop-linux-x86_64-$L2LoopCommit"
if (@($Artifacts.artifacts | Where-Object name -ceq $ExpectedArtifact).Count -ne 1) { throw 'final exact bundle is missing' }
```

- [ ] **Step 5: Re-run all Delivery B and C scenarios against the final artifact**

```powershell
$L2LoopCommit = git rev-parse HEAD
foreach ($L2LoopScenario in @(
    'Success',
    'TcAttachFailure',
    'MapInitializeFailure',
    'DaemonTermination',
    'IdentityChange',
    'TrafficInterruption',
    'PassiveObservation',
    'ObservationMapFailure',
    'ObservationIdentityChange'
)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File scripts/verify-isolated-host.ps1 `
        -Commit $L2LoopCommit `
        -Scenario $L2LoopScenario `
        -TimeoutSeconds 240
    if ($LASTEXITCODE -ne 0) { throw "final isolated scenario failed: $L2LoopScenario" }
}
```

Expected result: all nine scenarios pass for one exact artifact, all generated state is gone, and every complete foreign-state snapshot is unchanged.

- [ ] **Step 6: Verify repository synchronization**

```powershell
$Status = git status --porcelain=v1
if ($Status) { throw 'worktree is not clean' }
$Head = git rev-parse HEAD
$Remote = git rev-parse origin/main
if ($Head -cne $Remote) { throw 'main is not synchronized with origin/main' }
```

Record only the final commit SHA, GitHub Actions URL, artifact name, and nine-scenario pass/fail summary. Do not record target or foreign host identities.
