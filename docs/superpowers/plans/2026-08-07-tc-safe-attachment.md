# TC Safe Attachment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a collision-safe, ownership-aware TC attachment state machine that never replaces or broadly deletes an existing filter.

**Architecture:** Add a focused `linux::tc` module beside the XDP adapter. Pure classification and orchestration depend on an injected `TcIo` boundary; the production adapter uses rtnetlink messages with `NLM_F_CREATE | NLM_F_EXCL`, explicit handles and priorities, and fresh identity queries before any detach.

**Tech Stack:** Rust 2024, rtnetlink 0.21, netlink-packet-route types re-exported by rtnetlink, Linux clsact and BPF classifier netlink APIs, GitHub Actions.

## Global Constraints

- Work directly on `main`; do not create branches, worktrees, or subagents.
- Do not compile, test, run Clippy, or run rustfmt locally; all Rust and eBPF verification runs in GitHub Actions.
- Do not connect to the test host or mutate any interface during this task.
- Existing clsact qdiscs and unrelated filters are foreign state and must remain unchanged.
- Ingress uses handle `0x4c320001`; egress uses handle `0x4c320002`.
- Select the first free priority in `49600..=49699`; default or automatic priority and handle assignment is forbidden.
- `RTM_NEWTFILTER` must use `NLM_F_CREATE | NLM_F_EXCL`; replace/change operations are forbidden.
- A filter may be detached only after a fresh query exactly matches ifindex, hook, priority, handle, and program ID.
- Task 4 does not remove clsact qdiscs; this prevents broad cleanup of a potentially shared hook.

---

### Task 1: Define the TC safety contract

**Files:**
- Create: `crates/l2-loop-agent/tests/tc_safety.rs`
- Consume: `crates/l2-loop-agent/src/ownership.rs`

**Interfaces:**
- Consumes: `OwnedTc`, `TcHook`, and `TcKernelIdentity`.
- Produces: the required public API for `TcInventory`, `TcState`, `TcIo`, `SafeTc`, `TcAttachOutcome`, `TcDetachOutcome`, and `TcError`.

- [ ] **Step 1: Add classification tests**

  Cover absent/present clsact, first-free priority selection, reserved-handle collision, exact owned identity, stale ownership, unknown filters, and exhausted priority range.

- [ ] **Step 2: Add orchestration tests**

  Use a recording `TcIo` test double to prove that only an empty reserved slot reaches `attach_exclusive`, an `Exists` result is not retried, verification mismatch detaches only the just-attached exact identity, a changed identity is retained, and explicit detach refuses mismatches.

- [ ] **Step 3: Add netlink encoding tests**

  Assert that attach messages contain explicit ifindex, clsact parent for the selected hook, exact handle, exact priority, `ETH_P_ALL`, BPF program FD, and direct-action flags. Assert that the request flags are `REQUEST | ACK | CREATE | EXCL` and never include `REPLACE`.

- [ ] **Step 4: Commit and verify red in GitHub**

  Commit only the contract test, push `main`, and run the repository CI workflow. The expected failure is an unresolved `l2_loop_agent::linux::tc` module after formatting is clean.

### Task 2: Implement the pure state machine

**Files:**
- Create: `crates/l2-loop-agent/src/linux/tc.rs`
- Modify: `crates/l2-loop-agent/src/linux/mod.rs`
- Test: `crates/l2-loop-agent/tests/tc_safety.rs`

**Interfaces:**
- `classify_inventory(inventory: &TcInventory, hook: TcHook, owned: Option<&OwnedTc>) -> TcState`
- `SafeTc::attach(&mut self, ifindex: u32, hook: TcHook, loaded: LoadedTc) -> Result<TcAttachOutcome, TcError>`
- `SafeTc::detach(&mut self, owned: &OwnedTc) -> Result<TcDetachOutcome, TcError>`
- `TcIo::query`, `TcIo::ensure_clsact_exclusive`, `TcIo::attach_exclusive`, and `TcIo::detach_exact`.

- [ ] **Step 1: Implement classification**

  Treat an uninspectable clsact/filter as `Unknown`, an exact journal match as `Owned`, a reserved-handle mismatch or exhausted priority range as `Foreign`, and otherwise return `Empty` with the first free priority.

- [ ] **Step 2: Implement attach**

  Query before mutation, create clsact only when absent, attach exactly once with exclusive-create semantics, re-query, and return ownership only after the kernel identity matches the loaded program and selected slot.

- [ ] **Step 3: Implement rollback and detach**

  On post-attach verification failure, detach only if a fresh query still reports the exact newly attached identity. On explicit detach, return retained evidence for every mismatch and never perform a broad delete.

### Task 3: Implement the focused rtnetlink adapter

**Files:**
- Modify: `crates/l2-loop-agent/src/linux/tc.rs`
- Test: `crates/l2-loop-agent/tests/tc_safety.rs`

**Interfaces:**
- Produces: `RtnetlinkTcIo`, `encode_clsact_request`, `encode_attach_request`, and `encode_detach_request`.

- [ ] **Step 1: Query exact kernel state**

  Dump qdiscs and both clsact directions for one ifindex. Parse BPF IDs and preserve non-BPF occupants as known foreign slots; fail closed on malformed or incomplete BPF identity.

- [ ] **Step 2: Encode exclusive creation**

  Build clsact and BPF filter messages directly. Use explicit parent, protocol, priority, handle, program FD, name, and direct-action flag with create-and-exclusive netlink flags.

- [ ] **Step 3: Encode exact deletion**

  Re-query inside the adapter, require the complete identity tuple, then send a delete message containing exact ifindex, parent, priority, protocol, handle, and BPF kind. Never send a zero handle or zero priority.

- [ ] **Step 4: Verify green in GitHub**

  Push implementation-only commits as needed until formatting, Clippy, userspace tests, workspace checks, eBPF build, and MUSL bundle jobs all succeed for the exact `main` commit.

### Task 4: Final repository verification

**Files:**
- Inspect: all changed files and Git state.

- [ ] **Step 1: Confirm exact CI evidence**

  Verify the successful workflow head SHA equals `origin/main` and all required jobs concluded successfully.

- [ ] **Step 2: Confirm repository state**

  Verify the current branch is `main`, local HEAD equals `origin/main`, and `git status --short` is empty.

