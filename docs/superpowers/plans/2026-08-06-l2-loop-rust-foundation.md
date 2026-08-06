# L2 Loop Rust Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task. Keep all compilation and test execution in GitHub Actions; do not run Cargo or a Rust compiler on the local development host.

**Goal:** Establish the versioned Rust, Aya eBPF, map ABI, daemon-module, control-protocol, and CLI foundation described in the approved phase-one design.

**Architecture:** Use a Cargo workspace with a no-std ABI crate, a pure domain crate, separate daemon and CLI crates, a Linux-only Aya eBPF crate, and an xtask build orchestrator. GitHub Actions is the only compilation environment. Each behavior slice is introduced by a test commit that is observed failing in GitHub before its minimal implementation is added.

**Tech Stack:** Rust 2024, Aya 0.14.0, aya-ebpf 0.2.1, Clap 4.5, Serde/serde_json, Tokio, thiserror, GitHub Actions, nightly `bpfel-unknown-none`, and `bpf-linker`.

**Design specification:** `docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md`

---

## Global Execution Rules

1. Do not run `cargo`, `rustc`, `rustup`, Clippy, rustfmt, `bpf-linker`, or another compiler locally.
2. For every behavior task, add the test first, push it, and confirm that the targeted GitHub Actions assertion fails for the expected missing behavior.
3. Only after the red run may the minimal implementation be added and pushed for a green run.
4. Do not weaken, skip, ignore, or delete a failing test to obtain green CI.
5. Keep eBPF programs fail-open and do not add live attachment, packet transmission, or drop behavior in this phase.
6. When the repository has no GitHub remote, stop after preparing the workflow and first failing test. Obtain the repository location or authorization to create one before implementation code.

## Task 1: Bootstrap the Workspace and GitHub CI Contract

**Files:**

- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `.gitignore`
- Create: `.github/workflows/ci.yml`
- Create: `crates/l2-loop-common/Cargo.toml`
- Create: `crates/l2-loop-core/Cargo.toml`
- Create: `crates/l2-loop-agent/Cargo.toml`
- Create: `crates/l2-loop-cli/Cargo.toml`
- Create: `ebpf/l2-loop-ebpf/Cargo.toml`
- Create: `xtask/Cargo.toml`
- Create minimal crate roots: `crates/*/src/lib.rs`, `crates/l2-loop-agent/src/main.rs`, `crates/l2-loop-cli/src/main.rs`, `ebpf/l2-loop-ebpf/src/main.rs`, `xtask/src/main.rs`

### Step 1: Create manifests with centralized exact direct dependency versions

Set workspace resolver `2`, edition `2024`, all six members, and default members excluding `l2-loop-ebpf`. Keep `l2-loop-common` dependency-free unless its `user` feature is enabled. User-space crates inherit dependency versions from `[workspace.dependencies]`.

### Step 2: Add two independent CI jobs

The `userspace` job must run on `ubuntu-latest` and execute:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check
```

The `ebpf` job must run on `ubuntu-latest`, install nightly plus `rust-src`, install `bpf-linker`, and execute:

```bash
cargo xtask build-ebpf
```

Use minimal workflow permission `contents: read` and cancel superseded runs for the same branch.

### Step 3: Perform local non-compiling inspection

Use text and path checks only:

```powershell
rg --files Cargo.toml rust-toolchain.toml .github crates ebpf xtask
rg -n "userspace|ebpf|cargo test|cargo xtask build-ebpf" .github/workflows/ci.yml
```

Expected: all planned files and both CI jobs are present. Do not claim that manifests compile.

### Step 4: Commit bootstrap

```bash
git add Cargo.toml rust-toolchain.toml .gitignore .github crates ebpf xtask
git commit -m "build: bootstrap Rust and eBPF workspace"
git push
```

Expected: GitHub Actions may fail because behavioral tests and implementations are not complete; infrastructure or syntax errors must be fixed before Task 2.

## Task 2: Lock the Shared Map ABI With Layout Tests

**Files:**

- Create: `crates/l2-loop-common/src/abi.rs`
- Create: `crates/l2-loop-common/src/constants.rs`
- Modify: `crates/l2-loop-common/src/lib.rs`
- Create: `crates/l2-loop-common/tests/layout.rs`
- Create: `crates/l2-loop-common/tests/numeric_values.rs`

### Step 1: Write failing ABI layout tests

Add assertions for all documented types:

```rust
assert_eq!(size_of::<InterfaceConfig>(), 32);
assert_eq!(align_of::<InterfaceConfig>(), 8);
assert_eq!(size_of::<StatsKey>(), 16);
assert_eq!(size_of::<CounterValue>(), 16);
assert_eq!(size_of::<FingerprintKey>(), 32);
assert_eq!(size_of::<FingerprintValue>(), 48);
assert_eq!(size_of::<ProbeKey>(), 32);
assert_eq!(size_of::<ProbeRegistration>(), 32);
assert_eq!(size_of::<PolicyKey>(), 16);
assert_eq!(size_of::<RatePolicy>(), 40);
```

Add tests for `ABI_VERSION == 1`, VLAN sentinel `0xffff`, every fixed numeric value, and zeroed reserved bytes from constructors.

### Step 2: Push and observe red CI

```bash
git add crates/l2-loop-common
git commit -m "test: define shared ABI contract"
git push
```

Expected failure: imports or types in `layout.rs` and `numeric_values.rs` are unresolved. If CI fails for workflow or dependency reasons instead, fix infrastructure and rerun until the test fails for missing ABI behavior.

### Step 3: Implement the minimal ABI

Add the exact `#[repr(C)]` structs and constants from the design specification. Use numeric newtypes or constants across the shared boundary rather than Rust data-carrying enums. Add compile-time-safe constructors that explicitly zero reserved fields. Under the `user` feature, provide `unsafe impl aya::Pod` only for plain ABI types.

### Step 4: Push and observe green CI

```bash
git add crates/l2-loop-common
git commit -m "feat: add versioned eBPF map ABI"
git push
```

Expected: common layout and numeric tests pass in `userspace`.

## Task 3: Implement Pure Domain Validation and Lifecycle

**Files:**

- Create: `crates/l2-loop-core/src/error.rs`
- Create: `crates/l2-loop-core/src/interface.rs`
- Create: `crates/l2-loop-core/src/policy.rs`
- Create: `crates/l2-loop-core/src/probe.rs`
- Create: `crates/l2-loop-core/src/command.rs`
- Modify: `crates/l2-loop-core/src/lib.rs`
- Create: `crates/l2-loop-core/tests/interface_lifecycle.rs`
- Create: `crates/l2-loop-core/tests/policy_validation.rs`
- Create: `crates/l2-loop-core/tests/probe_validation.rs`

### Step 1: Write failing state and validation tests

Cover every valid lifecycle transition and a table of invalid transitions. Assert that:

- generation zero is rejected;
- policy requires at least one non-zero rate;
- policy class cannot be aggregate or unicast;
- policy TTL accepts one second through 24 hours only;
- probe VLAN accepts 1 through 4094 or absence;
- probe timeout accepts 100 milliseconds through 30 seconds;
- no domain command contains a count, repeat, interval, or schedule field.

### Step 2: Push and observe red CI

Expected failure: missing lifecycle and validated request types.

### Step 3: Add the minimal domain types

Implement typed enums with fallible conversion from ABI numeric values, `InterfaceState::transition`, `PolicyRequest::new`, `ProbeRequest::new`, and protocol-neutral `AgentCommand`/`AgentResult` enums. Return typed errors; do not panic on user input.

### Step 4: Push and observe green CI

Expected: all core tests pass with no Aya, Tokio, or operating-system dependency in `l2-loop-core`.

## Task 4: Define and Test the Local Control Protocol

**Files:**

- Create: `crates/l2-loop-agent/src/protocol.rs`
- Create: `crates/l2-loop-agent/tests/protocol_framing.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`

### Step 1: Write failing protocol tests

Test a four-byte big-endian size prefix, 1 MiB maximum payload, protocol version `1`, stable serde `kind` tags, round trips for every request/response variant, and rejection of malformed JSON, invalid UTF-8, unknown versions, and oversized frames.

### Step 2: Push and observe red CI

Expected failure: framing functions and wire types do not exist.

### Step 3: Implement the minimal protocol

Implement pure encode/decode functions first. Keep socket I/O outside these functions. Translate wire requests to `l2-loop-core` commands through fallible conversions.

### Step 4: Push and observe green CI

Expected: protocol tests pass without binding a Unix socket.

## Task 5: Freeze the CLI Grammar

**Files:**

- Create: `crates/l2-loop-cli/src/args.rs`
- Create: `crates/l2-loop-cli/src/convert.rs`
- Modify: `crates/l2-loop-cli/src/lib.rs`
- Modify: `crates/l2-loop-cli/src/main.rs`
- Create: `crates/l2-loop-cli/tests/cli.rs`

### Step 1: Write failing parser tests

Cover canonical forms for `observe`, `status`, `probe`, `police apply`, `police disable`, `evidence list`, and `evidence show`. Reject missing explicit interfaces, VLAN 0/4095, missing policy rate, invalid TTL/timeout, unsupported policing classes, and all repetition flags such as `--count`, `--repeat`, and `--interval`.

### Step 2: Push and observe red CI

Expected failure: `Cli` and command argument types do not exist.

### Step 3: Implement minimal Clap parsing and conversion

Expose `Cli::try_parse_from` through the library. Convert parsed values to validated core commands. Keep `main.rs` limited to parse, connect, send, render, and stable exit-code mapping; socket transport may return a clearly typed unavailable error until its implementation slice.

### Step 4: Push and observe green CI

Expected: parser and conversion tests pass, and unsafe repetition arguments remain rejected.

## Task 6: Establish Agent Ports and Fail-Open Orchestration

**Files:**

- Create: `crates/l2-loop-agent/src/ports.rs`
- Create: `crates/l2-loop-agent/src/service.rs`
- Create: `crates/l2-loop-agent/src/error.rs`
- Modify: `crates/l2-loop-agent/src/lib.rs`
- Modify: `crates/l2-loop-agent/src/main.rs`
- Create: `crates/l2-loop-agent/tests/service.rs`

### Step 1: Write failing mock-driven service tests

Define fake ports in tests and assert:

- observe requires an explicit resolved interface;
- a second hook attach failure detaches the first hook;
- config publication occurs only after both hooks verify;
- policing cannot begin outside observing state;
- policy expiry returns to observing behavior;
- every adapter error returns a typed error and requests fail-open cleanup.

### Step 2: Push and observe red CI

Expected failure: port traits and `AgentService` do not exist.

### Step 3: Implement traits and the minimal service

Add `InterfaceResolver`, `HookManager`, `MetricsReader`, `ProbeTransport`, `EvidenceStore`, and `Clock`. Implement only orchestration against those traits; do not implement real Linux attachment, metrics, storage, or transmission in this task.

### Step 4: Push and observe green CI

Expected: service tests pass with deterministic fakes and no privileged operations.

## Task 7: Declare the Aya Programs and Public Maps

**Files:**

- Create: `ebpf/l2-loop-ebpf/src/maps.rs`
- Create: `ebpf/l2-loop-ebpf/src/programs.rs`
- Modify: `ebpf/l2-loop-ebpf/src/main.rs`
- Create: `xtask/src/inspect.rs`
- Create: `xtask/tests/contract.rs`

### Step 1: Write failing source/object contract tests

The stable source-level contract test must assert the exact six map names and four program names. The eBPF CI job must also inspect the built object and fail if any named symbol is absent.

### Step 2: Push and observe red CI

Expected failure: public maps and program entry points are absent.

### Step 3: Add minimal fail-open Aya declarations

Declare:

- `IFACE_CONFIG`
- `HOOK_STATS`
- `FINGERPRINTS`
- `PROBE_REGISTRY`
- `PROBE_STATS`
- `RATE_POLICY`

Add `l2_loop_xdp_ingress`, `l2_loop_tc_egress`, `l2_loop_tc_path_ingress`, and `l2_loop_tc_path_egress`. Each program calls a shared inner function and converts every success or error path to `XDP_PASS` or `TC_ACT_OK`. Do not parse packets or mutate counters yet.

### Step 4: Push and observe green CI

Expected: the eBPF job compiles the object and verifies all ten public names.

## Task 8: Complete `xtask` and Developer Documentation

**Files:**

- Modify: `xtask/src/main.rs`
- Create: `xtask/src/build.rs`
- Create: `xtask/src/prerequisites.rs`
- Create: `docs/development.md`
- Modify: `README.md`
- Create: `xtask/tests/cli.rs`

### Step 1: Write failing xtask CLI tests

Test `build-ebpf`, `build`, `test`, and `lint` parsing, plus actionable error messages for missing nightly, `rust-src`, and `bpf-linker`. Model process execution behind an injectable command-runner trait so unit tests never invoke a compiler.

### Step 2: Push and observe red CI

Expected failure: xtask parser and prerequisite validation are absent.

### Step 3: Implement minimal orchestration and documentation

Implement explicit subprocess argument lists with no shell interpolation. Document that compilation is GitHub-only, explain both CI jobs, list required repository settings, and describe how to download CI artifacts. Do not document local Cargo commands as supported development steps.

### Step 4: Push and observe green CI

Expected: xtask unit tests pass and the eBPF job continues to build through `cargo xtask build-ebpf`.

## Task 9: Final CI Verification and Contract Audit

**Files:**

- Modify only files required by observed CI failures
- Update: `docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md` only if an approved contract correction is necessary

### Step 1: Run the complete GitHub workflow from a clean commit

Push the final branch and require fresh, non-cached successful runs for both jobs.

Expected:

- `userspace`: format, Clippy, test, and check all pass;
- `ebpf`: eBPF compile and public-name inspection pass.

### Step 2: Audit scope and safety

Use repository search to confirm:

```powershell
rg -n "XDP_DROP|TC_ACT_SHOT|--count|--repeat|--interval" crates ebpf xtask
rg -n "l2_loop_xdp_ingress|l2_loop_tc_egress|l2_loop_tc_path_ingress|l2_loop_tc_path_egress" ebpf xtask
rg -n "IFACE_CONFIG|HOOK_STATS|FINGERPRINTS|PROBE_REGISTRY|PROBE_STATS|RATE_POLICY" ebpf xtask
```

Expected: no drop action or probe repetition option exists; all required public names exist.

### Step 3: Record verification evidence

Record the GitHub Actions run URL and commit SHA in the handoff. Do not report the foundation complete without both green jobs.

