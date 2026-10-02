# Isolated diagnostic loader implementation plan

> Execute inline with executing-plans and test-driven-development. The user requires main only, no worktrees/subagents, and GitHub-only compilation/tests.

**Goal:** Load the four approved diagnostic profiles only onto a generated isolated veth, roll back by exact identity, then collect bounded layered measurements.

**Architecture:** A separate required-feature `l2-loop-diagnostic` binary in xtask reuses offline validators and existing safe XDP/TC adapters, never the ordinary daemon loader. CI embeds the commit and four object digests into this binary. Each process owns fresh unpinned Maps and records kernel identities in an exclusive local lease before attachment. No Map pin paths, ordinary ownership journals, production options or bundle inventory change.

**Tech Stack:** Existing pinned Rust, Aya, rtnetlink, SHA256 and serde; GitHub MUSL build; generated namespace/veth host harness.

**Spec:** The approved next step in `2026-10-02-layered-diagnostic-objects.md` and the user's current request.

## Safety contract

- Request schema rejects unknown/duplicate fields. Run ID is 32 lowercase hex; host/peer/namespace/root are derived, never arbitrary CLI targets. Bind both ifindices, MACs and namespace device/inode. Deadline is 1–120 seconds after ready.
- Require root-owned private generated root, regular single-link bounded inputs, no symlink components, dedicated namespace containing only loopback and the peer, reciprocal veth indices, no masters or addresses. Both veth ends must be down before load/attach. The harness alone controls their up/down state.
- Read a bounded payload buffer and verify its compiled digest and offline ELF before any BPF creation. Reuse the existing separate manifest verifier; pass the same verified buffer directly to Aya rather than reopening a path for loading. CI provenance is established through the trusted Actions run/download and digest-bound loader, not a self-declared manifest.
- Require empty native/generic XDP, absent clsact and no TC filters. Generic XDP uses atomic no-replace. TC uses exclusive create with explicit priority/handle. Existing safe detach checks exact program identities; TC query/delete is not an atomic kernel compare-and-delete and exclusive generated-interface control remains necessary.
- Initialize the ordinary 16 stats keys and fixed config in private Maps for all profiles. No daemon sampler runs in these attribution trials. This differs from end-to-end daemon measurements and must be labeled.
- Record loaded program and Map IDs before attach; retain lease on incomplete cleanup or process crash. Normal stop, EOF, malformed input, deadline and termination signals run reverse cleanup. SIGKILL/power loss cannot promise automatic cleanup; do not automatically replay a stale lease.
- Never unload by global ID/name, clear shared pins, delete foreign filters or remove a nonempty clsact. Only close our own Map/program FDs after precise hook cleanup attempts. Record failures, stop further trials, retain evidence.
- Report is diagnostic only, never deployment-gate evidence. Formal performance thresholds remain unchanged.

## Task 1: Request and rollback orchestration

Files: `xtask/src/diagnostic_session.rs`, `xtask/tests/diagnostic_session.rs`, `xtask/src/lib.rs`, CI.

- [x] RED: run `37018726946`, Userspace job `110876307193`: four expected lifecycle/request failures. Additional namespace-binding RED in run `37021519560`, job `110885999444`: wrong peer namespace accepted before the new guard.
- [x] GREEN: `validate_request(bytes) -> Result<DiagnosticRequest, DiagnosticSessionError>` and `run_session(&mut impl DiagnosticBackend)`. Five tests cover strict inputs, namespace binding, every forward fault, reverse cleanup continuation and retained leases.
- [x] Full CI and inline review: code `34c152e517b7a77f90655a0f20d343a323f87485`, run `37021840057`, attempt 2, all five jobs succeeded. Attempt 1's Bundle checkout failed certificate verification before compilation; retry retained TLS verification. No ordinary runtime, eBPF hot-path or ABI changes. Only three dependency edges to already locked packages were added.

## Task 2: Separate runtime and artifact

Files: `xtask/src/diagnostic_runtime.rs`, `xtask/src/bin/diagnostic.rs`, Cargo manifests/lock, CI, real-object integration tests.

- [x] Reused the manifest verifier and checked the immutable load buffer against the compiled digest/ELF contract; no second load-by-path operation. Fixed generated context and exclusive lease precede hook mutation.
- [x] XDP/TC attach, private Map initialization, ready/control deadline and precise reverse cleanup. Fresh interface/namespace identity checks precede mutation and cleanup; the namespace-ID binding discovered during review is required, not inferred from peer ifindices.
- [x] Separate MUSL executable with compiled four-profile SHA256 allowlist, artifact ID `11232898895`; executable SHA256 `a328afbe677831428fa0b231be900bdf0546007d4dffef9428c70b76006cb6ea`. Four-profile artifact ID `11233467575`; ordinary bundle ID `11233293502`, unchanged inventory.
- [x] Runtime RED: run `37019303206`, eBPF job `110877946617`, six expected not-implemented failures. GREEN: run `37021840057`, eBPF attempt-1 job `110887009781`: seven tests passed, including four actual profiles with bidirectional packet/byte counts, stop/EOF/deadline/signal, changed bytes, foreign lease and foreign TC retention. Feature-enabled Clippy also passed. The signal fixture keeps stdin open so EOF cannot race the signal being tested.

## Task 3: Authorized node measurements

Files: isolated diagnostic host harness and `docs/performance-diagnostics-2026-10-02.md`.

- [x] Exact full-green artifacts downloaded and identities checked. Current ostack7 prechecks passed without changes to existing attachments.
- [x] Five-layer smoke run `70b3623c6f254b0da6e91f1863669806`: exact forwarding and counter semantics, zero drops/errors, complete cleanup and LLDP restoration. Report SHA256 `36986d91f06e4c3dac848eff2b9d0ec677704846a5c5776d53e347dcee675069`. Excluded from repeated measurement statistics.
- [x] Run `ec9eac972fa34da998a6d01a52910264`: baseline plus four layers, five rotating-order repetitions, same bounded sender/corpus and per-generated-port LLDP guard. All 25 trials retained; raw directions, packet/byte accounting, drops/errors, profile and loaded IDs recorded. Report SHA256 `700f2f90ad47c1393122fb1371f05143799eb804f814bad692054ec58abc786a`.
- [x] Before/after measured network and enumerable BPF identities match, exact cleanup and LLDP restoration complete, generated residue zero. All trials have exact packets/bytes and zero observed drops/errors. Relative median throughput: hooks 94.0%, config 91.9%, counters 91.9%, fingerprints 87.4%. [Evidence and limitations](../../performance-diagnostics-2026-10-02.md#completed-isolated-five-layer-attribution) include paired ratios and non-exhaustive global BPF-link coverage. This completes the diagnostic increment, not hot-path optimization or production readiness.
