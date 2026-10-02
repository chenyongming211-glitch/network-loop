# Isolated diagnostic loader implementation plan

> Execute inline with executing-plans and test-driven-development. The user requires main only, no worktrees/subagents, and GitHub-only compilation/tests.

**Goal:** Load the four approved diagnostic profiles only onto a generated isolated veth, roll back by exact identity, then collect bounded layered measurements.

**Architecture:** A separate required-feature `l2-loop-diagnostic` binary in xtask reuses offline validators and existing safe XDP/TC adapters, never the ordinary daemon loader. CI embeds the commit and four object digests into this binary. Each process owns fresh unpinned Maps and records kernel identities in an exclusive local lease before attachment. No Map pin paths, ordinary ownership journals, production options or bundle inventory change.

**Tech Stack:** Existing pinned Rust, Aya, rtnetlink, SHA256 and serde; GitHub MUSL build; generated namespace/veth host harness.

**Spec:** The approved next step in `2026-10-02-layered-diagnostic-objects.md` and the user's current request.

## Safety contract

- Request schema rejects unknown/duplicate fields. Run ID is 32 lowercase hex; host/peer/namespace/root are derived, never arbitrary CLI targets. Bind both ifindices, MACs and namespace device/inode. Deadline is 1–120 seconds.
- Require root-owned private generated root, regular single-link bounded inputs, no symlink components, dedicated namespace containing only loopback and the peer, reciprocal veth indices, no masters or addresses. Both veth ends must be down before load/attach. The harness alone controls their up/down state.
- Read the payload once; verify manifest, compiled commit/digest and offline ELF against those same bytes before any BPF creation. CI provenance is established through the trusted Actions run/download and digest-bound loader, not a self-declared manifest.
- Require empty native/generic XDP, absent clsact and no TC filters. Generic XDP uses atomic no-replace. TC uses exclusive create with explicit priority/handle. Existing safe detach checks exact program identities; TC query/delete is not an atomic kernel compare-and-delete and exclusive generated-interface control remains necessary.
- Initialize the ordinary 16 stats keys and fixed config in private Maps for all profiles. No daemon sampler runs in these attribution trials. This differs from end-to-end daemon measurements and must be labeled.
- Record loaded program and Map IDs before attach; retain lease on incomplete cleanup or process crash. Normal stop, EOF, malformed input, deadline and termination signals run reverse cleanup. SIGKILL/power loss cannot promise automatic cleanup; do not automatically replay a stale lease.
- Never unload by global ID/name, clear shared pins, delete foreign filters or remove a nonempty clsact. Only close our own Map/program FDs after precise hook cleanup attempts. Record failures, stop further trials, retain evidence.
- Report is diagnostic only, never deployment-gate evidence. Formal performance thresholds remain unchanged.

## Task 1: Request and rollback orchestration

Files: `xtask/src/diagnostic_session.rs`, `xtask/tests/diagnostic_session.rs`, `xtask/src/lib.rs`, CI.

- [ ] RED on GitHub: strict schema and identity cases; success sequence; fault at every forward step; reverse cleanup continues after an error; final lease closure only after all cleanup succeeds.
- [ ] GREEN: `validate_request(bytes) -> Result<DiagnosticRequest, DiagnosticSessionError>` and `run_session(&mut impl DiagnosticBackend)`. Backend methods receive explicit `SessionStep`; state belongs to the runtime adapter, not to caller-supplied cleanup IDs.
- [ ] Full CI verification and inline review.

## Task 2: Separate runtime and artifact

Files: `xtask/src/diagnostic_runtime.rs`, `xtask/src/bin/diagnostic.rs`, Cargo manifests/lock, CI, real-object integration tests.

- [ ] Implement validated-byte identity API; runtime validates fixed generated context and exclusive lease, loads exact bytes and records identities before hook mutation.
- [ ] Implement XDP/TC attach, private Map initialization, ready/control deadline and precise reverse cleanup. Check each current interface/namespace identity before mutation and cleanup.
- [ ] Build a separate MUSL diagnostic executable with compiled four-profile SHA256 allowlist. Upload separately; do not change the ordinary ten-file bundle.
- [ ] GitHub tests cover real-object rejection before kernel load; privileged generated-veth tests cover all profiles, stop/EOF/deadline and retained foreign state.

## Task 3: Authorized node measurements

Files: isolated diagnostic host harness and `docs/performance-diagnostics-2026-10-02.md`.

- [ ] Download exact full-green artifacts and verify GitHub commit/digests. Recheck ostack7 current state and coexistence prerequisites.
- [ ] Run correctness/cleanup smoke before performance. If any check fails, stop and retain evidence.
- [ ] Measure baseline plus four layers, five rotating-order repetitions, same bounded sender/corpus and per-generated-port LLDP guard. Record raw directions, packet/byte accounting, drops/errors, profile and loaded IDs.
- [ ] Compare before/after network and enumerable BPF identities, exact cleanup and LLDP restoration; report scope limitations and paired ratios, not production readiness.
