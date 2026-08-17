# 二层环路检测 Agent

L2 Loop Detection Agent is a single-node Rust and eBPF service whose product roadmap covers observing, diagnosing, and temporarily containing Layer 2 loops on an explicitly selected physical interface.

The currently implemented slice is deliberately narrow: it provides fail-open XDP ingress and TC egress cumulative observation, bounded rate windows, generation-scoped dynamic baselines, bounded passive frame fingerprints, privacy-reduced ingress/egress relationship evidence, separate observation-health reporting, an in-memory passive detection state machine, and bounded local incident output for one generated, isolated namespace/veth session. It can classify rate storms, publish passive external-loop suspicion or high confidence, persist immutable sanitized incident revisions, emit local alerts, and serve root-only evidence queries. It never confirms a loop, sends probes, applies policies, drops traffic, or attaches to production, physical, bond, bridge, OVS, tap, or shared interfaces.

The broader product design remains observe-first. Later deliveries may add NIC/kernel and topology correlation, explicitly authorized one-frame probes, and expiring manual policing only after their own design and safety gates.

## Design documents

- [Product and safety architecture](docs/l2-loop-agent-design.md)
- [Rust foundation specification](docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md)
- [Linux preflight and isolated safe-attach specification](docs/superpowers/specs/2026-08-06-linux-preflight-safe-attach-design.md)
- [Isolated passive-observation specification](docs/superpowers/specs/2026-08-10-isolated-passive-observation-design.md)
- [Bounded daemon sampler and rate-window specification](docs/superpowers/specs/2026-08-11-bounded-daemon-rate-windows-design.md)
- [Dynamic baseline and observation-health specification](docs/superpowers/specs/2026-08-12-dynamic-baseline-observation-health-design.md)
- [Bounded fingerprint relationships specification](docs/superpowers/specs/2026-08-12-bounded-fingerprint-relationships-design.md)
- [Passive detection state-machine specification](docs/superpowers/specs/2026-08-12-passive-detection-state-machine-design.md)
- [Bounded local incident output specification](docs/superpowers/specs/2026-08-12-bounded-local-incident-output-design.md)
- [Production read-only deployment-gate specification](docs/superpowers/specs/2026-08-13-production-read-only-deployment-gates-design.md)
- [Superseded alert/evidence draft](docs/superpowers/specs/2026-08-06-local-alert-evidence-output-design.md)
- [Isolated safe-attach implementation plan](docs/superpowers/plans/2026-08-06-isolated-safe-attach.md)
- [Isolated passive-observation implementation plan](docs/superpowers/plans/2026-08-10-isolated-passive-observation.md)

## Build policy

Compilation, tests, Clippy, formatting checks, and eBPF builds run only in GitHub Actions. The local workspace is used for authoring and static inspection.

Repository-controlled build inputs are explicit: the GitHub-generated root `Cargo.lock` is tracked, every dependency-resolving permanent Cargo command uses locked resolution, GitHub Action implementations use reviewed full commit SHAs, and the stable Rust, dated eBPF nightly, and linker versions are fixed. Dependency and tool updates are manual, atomic changes; no updater or write-capable automation is enabled.

Successful CI runs publish a ten-file `l2-loop-linux-x86_64-<full-commit-sha>` artifact. Its nine checksum-covered payloads are `l2-loopd`, `l2-loopctl`, `l2-loop-deploycheck`, `l2-loop-install`, `l2-loop-hostcheck`, `l2-loop-ebpf.o`, `l2-loop.service`, `deployment-v1.example.json`, and `manifest.json`; `SHA256SUMS` is the tenth file. All five userspace binaries are static MUSL executables. The full commit SHA in both the artifact name and manifest identifies the exact source revision, and the manifest binds every payload role, both build targets, the public ABI, and the deterministic unit/example digests. The same workflow installs the exact pinned `cargo-audit` version, requires a fresh RustSec database with no ignored vulnerability advisories, and records the database revision before the artifact is eligible.

The GitHub-hosted runner image remains outside the repository-controlled boundary, so the project does not claim byte-for-byte reproducible rebuilds. Deployment and acceptance therefore use the artifact and checksum file from the exact successful commit.

## Production-shaped deployment gate

`l2-loop-deploycheck` is an independent, fail-closed, read-only checker. It does not connect to the daemon and exposes only:

```text
l2-loop-deploycheck staging --bundle <DIR> --root /run/l2-loop/accept/<32-lower-hex>/staging-root [--json]
l2-loop-deploycheck inspect [--json]
```

`staging` accepts only the exact generated-root grammar and validates the checksum-bound bundle plus a production-shaped mirror containing the fixed daemon/CLI/checker/object/unit/example paths, root ownership, exact `0755`/`0644`/`0600`/`0700` modes, an empty runtime directory, the strict authorization document, and strict performance evidence. It never reads real `/etc`, `/usr`, `/var`, systemd, journald, or a physical interface.

`inspect` is intentionally pathless. It reads only the fixed installed layout and derives the authorized interface exclusively from `/etc/l2-loop/deployment-v1.json`. A positive fixture-backed result requires one physical, up, unshared interface with the exact authorized name/ifindex, no L3 or visible service consumer, empty native/generic XDP and TC state, the expected live-interface preflight refusal with no other blocker, a safe evidence root, and passing evidence for the exact artifact and current host compatibility identity. Delivery G does not run `inspect` on the authorized test host.

The authorization schema is version 1, binds one random 128-bit lowercase ID and one exact 40-character artifact commit, and is valid for at most 24 hours. It grants planning input only and cannot be widened by CLI flags. Performance schema 1 records one warm-up followed by exactly five rotating trials in each of `baseline`, `pass_through`, and `observe`; every trial uses fixed 64/512/1514-byte frames. Lower medians must retain at least 950 permille for pass-through and 900 permille for observe, with zero agent-caused drops/errors, bounded CPU/RSS, forwarding intact, exact owned cleanup, and restored pre-existing network/eBPF identity. No best-run selection or caller-supplied threshold exists.

Decisions are limited to `blocked`, `staging_ready`, and `canary_candidate`. `staging_ready` proves the generated packaging/layout contract. `canary_candidate` is proven only by injected physical-interface fixtures and contains a `CanaryPlanV1` with `executable: false`; no product command consumes that plan. Exit codes are `0` for either positive decision, `1` when bounded I/O/internal failure prevents a report, `2` for usage/local validation failure, and `4` for a completed blocked report. Real installation, service-manager and journald validation, physical-interface inspection or attachment, native-driver and representative-workload performance, active probes, packet drops/policing, and any production-ready claim remain outside this delivery and require separate authorization.

## Read-only preflight

The current daemon serves a bounded local Unix control socket at `/run/l2-loop/agent.sock`. Preflight always requires an explicit Linux interface name:

```text
l2-loopctl preflight --interface <IFACE>
l2-loopctl preflight --interface <IFACE> --json
```

The text and JSON forms run the same inspection; `--json` changes rendering only. Exit codes are:

| Code | Meaning |
|---:|---|
| 0 | ready, or ready with warnings |
| 1 | daemon transport, protocol, or internal failure |
| 2 | CLI usage or local interface validation failure |
| 4 | preflight completed and is blocked |

Preflight is read-only. It inspects the explicitly named interface, relevant XDP/TC identities, bpffs/BTF state, and process limits. It does not change interfaces, routes, qdiscs, rlimits, sysctls, pin paths, or loaded programs, and it does not attach eBPF programs.

The socket parent must already exist, be owned by the daemon user (root for the default path), and not be group/world writable. The daemon creates the socket with mode `0600` and removes only the exact socket inode it owns during graceful shutdown.

## Isolated observation, bounded rates, dynamic baseline, relationships, and detection

After the daemon has established its one active generated isolated-veth session, these commands read that session without changing kernel state:

```text
l2-loopctl observe --interface <IFACE>
l2-loopctl observe --interface <IFACE> --json
l2-loopctl status [--interface <IFACE>]
l2-loopctl status [--interface <IFACE>] --json
```

Both commands perform a fresh request-time read of generation-scoped cumulative counters and the bounded fingerprint LRU. Client reads never insert rate, baseline, fingerprint-window, or detection samples and never recompute cached background state. The one-second background sampler reads counters on every tick and performs one complete identity-confirmed fingerprint scan only when the fixed 10-second analysis deadline is due; missed intervals are skipped rather than replayed. `observe` returns aggregate packets/bytes, six fixed mutually exclusive classes, parse-error counters, VLAN visibility, sampling diagnostics, detailed rates, the complete fixed-order baseline report, a request-time privacy-reduced fingerprint relationship report, and the cached complete detection report. `status` returns zero or one active session with cumulative hook aggregates, summarized hook rates, baseline state, sample counts, elevated identifiers, relationship evidence, and a compact detection summary.

Rate history exists only in daemon memory, belongs to one exact interface generation, and holds at most 64 successful samples. The public windows are fixed at 1, 10, and 60 seconds. Packet rates are packets per second; byte rates are bytes per second and text output labels them `B/s`. A `ready` window contains deltas, exact elapsed nanoseconds, endpoints, and integer rates. `warming_up` and `stale` windows contain `null` endpoints and rates rather than synthetic zeroes. A sample is stale only when its age is strictly greater than three seconds; a paused sampler is also stale.

The baseline learns only the ready 10-second window, at most once per successful one-second background tick. It has exactly 16 hook/subject series; each series stores packet and byte rate as an atomic pair with capacity 300 and minimum 60 samples. Initial readiness therefore takes approximately 69–70 seconds after attach. Upper median and upper MAD produce deterministic integer thresholds: `max(median + 6 * MAD, 4 * median, noise floor)`, with floors of 10 pps and 16,384 B/s. Values must be strictly greater than a threshold to be elevated. The public baseline states are `learning`, `within_baseline`, `elevated`, and `unavailable`. Observation health is independent: trustworthy elevated traffic remains healthy, while stale, paused, or unresolved sampling/baseline/fingerprint integrity is degraded. Observation schema 5 carries this data while the local framing protocol remains version 1.

During learning, trustworthy values are accepted, so a sustained abnormal condition present at startup can be learned; this blind spot is explicit. Once ready, an elevated packet or byte metric rejects the complete pair for that subject, while unaffected sibling subjects continue learning. Transient background failures retain histories and publish unavailable evidence; recovery compares before accepting. Identity, generation, clock, counter, and baseline-integrity failures clear history. Detach and shutdown destroy it. Nothing is persisted.

The parser reads Ethernet plus at most one `802.1Q` or `802.1ad` tag. If a second tag is present, it records that nesting was seen but does not parse through it: broadcast and link-local-control classification remains exact, while other group destinations degrade to other multicast and remaining destinations to unclassified. A real visible outer tag promotes the session-level visibility state to `verified_visible`; this does not prove that every hook can see every VLAN and does not create per-VLAN counters.

Observation refuses absent sessions, interface mismatch, ownership mismatch, unavailable Maps, changed Map identities, or untrustworthy snapshots with stable `OBS_*` errors. It never adopts changed state and never invokes cleanup as an error response.

Eligible parsed frames of at least 60 bytes use a fixed allocation-free 64-bit FNV-1a hash over the two-byte big-endian exact frame length and the first 60 bytes. Shorter frames remain fail-open and counted by the cumulative classifier but are not fingerprinted. This fixed span matches the standard minimum Ethernet frame as observed without the FCS and avoids verifier-fragile dynamic packet reads on the supported kernel. A fixed shift of four deterministically selects approximately one in sixteen eligible frames, identically at ingress and egress because direction is excluded from the hash. The LRU holds at most 8,192 entries and is destroyed with its generation. Public output contains only bounded counts, direction relationships, ratios, state, and a stable error code; it never exposes raw fingerprints, MAC addresses, packet bytes, raw keys, or raw timestamps. This evidence remains a lower-bound passive signal and never becomes a loop verdict by itself.

The passive detector evaluates rates at 1 Hz. Its adaptive path requires baseline elevation plus at least 1,000 BUM pps or 1,048,576 B/s in the ready 10-second window. Its startup path is baseline-independent and requires at least 100,000 BUM pps or 104,857,600 B/s in the ready 1-second window. BUM is broadcast plus IPv4, IPv6, and other L2 multicast; link-local control and unicast/unclassified traffic are excluded. The same non-empty candidate must persist for three trustworthy ticks. External-loop suspicion additionally requires an ingress or bidirectional storm, at least 80% ingress BUM, at least 16 sampled ingress packets, and one repeated fingerprint relation with at least 80% dominance. High confidence also requires an egress-first correlated relation and at least 4x ingress amplification. Fingerprint deltas are accepted only for 10,000–15,000 ms coverage.

Public detection states are `warming_up`, `normal`, the three confirmed storm directions, `external_loop_suspected`, `external_loop_high_confidence`, `cooldown`, and `unavailable`. Strongest currently proven evidence wins. A weaker anomaly or clear result needs ten consecutive trustworthy ticks; clear enters a 30-second cooldown retaining the last anomaly before returning to normal. Missing or invalid evidence never advances assertion, clearing, or cooldown. Transient failures retain bounded histories and the last trustworthy anomaly separately; identity, generation, counter, clock, or integrity failures clear histories. Detach, shutdown, and generation change destroy all live detection state. At most 16 typed transitions are retained in memory; only privacy-reduced incident revisions derived from transitions are persisted by the separate output worker.

## Local incident output

Background detection transitions open at most one incident per interface generation. Every output job is queued without blocking sampling or packet forwarding; the queue has a fixed capacity of 32 and one serialized worker. A committed revision contains only Schema 5-derived aggregates and bounded summaries—never raw fingerprints, MAC/IP addresses, packet bytes, raw Map keys, topology, or PCAP. Exact detach or shutdown closes an active incident with a `generation_ended` revision when persistence remains available.

The production evidence root is `/var/lib/l2-loop/evidence/v1` and must already exist as a root-owned mode-`0700` directory. The daemon neither creates nor repairs it. Event and revision directories are `0700`; `evidence.json` and `manifest.json` are `0600`. Revisions are written in a same-parent private directory, fsynced, and published with no-replace rename. Startup validates complete revisions and preserves but counts corrupt, incomplete, or unknown objects. Fixed limits are 1 GiB, 1,000 events, 16 revisions per event, 1 MiB per revision, 16 MiB per event, 30 days for closed events, and a free-space reserve of max(512 MiB, 5%). Retention removes only complete closed events; active or untrusted objects are never selected.

Alerts are emitted after the persistence attempt and explicitly report `stored` or `unavailable`. Production first attempts a sanitized structured journald datagram and permanently falls back to one JSON object per stderr line after failure. Output failure degrades `status` but never changes detection, forwarding, attachment, or cleanup. The root-only control socket is the only supported query path:

```text
l2-loopctl evidence list [--interface <IFACE>] [--limit <1-200>] [--cursor <OPAQUE>] [--json]
l2-loopctl evidence show --id <32-lowercase-hex> [--json]
```

List order and cursors are stable and bounded. The daemon never returns filesystem paths or adapter error chains. A failed revision is not retried; the preceding complete revision remains authoritative and output health stays degraded for that incident.

## Current status

The implementation now contains:

- the multi-crate Rust workspace and GitHub-only CI;
- ABI v1 map keys, values, constants, and layout tests;
- validated domain state, probe, and temporary-policy models;
- a versioned local control protocol;
- the complete safe `l2-loopctl` command grammar and read-only preflight client;
- a bounded Unix control server and preflight dispatcher;
- the real read-only Linux inspector;
- validated Aya object loading and initialization of six fixed public maps;
- atomic no-replace generic XDP attachment and ownership-aware TC attachment;
- an ownership journal schema v2 recording all six owned Map names, exact pins, and kernel Map IDs;
- reverse-order rollback and identity-exact owned-only cleanup;
- four fail-open Aya program entry points with aggregate and classified cumulative packet/byte accounting;
- real ownership-checked Aya observation reads with checked per-CPU aggregation;
- real `observe` and `status` daemon/CLI paths with bounded text and JSON output;
- a cancellation-aware one-second sampler with memory-only, generation-scoped 1/10/60-second rate windows and bounded diagnostics;
- a bounded dynamic-baseline engine with fixed 10-second source, 300/60 bounds, robust integer thresholds, anti-contamination, and orthogonal health;
- a fixed shift-4, 8,192-entry fail-open fingerprint LRU with request-only, identity-confirmed reads;
- deterministic, privacy-reduced ingress/egress relationship reports and cached passive detection in observation schema 5;
- a generation-scoped passive state machine with fixed adaptive/absolute storm paths, hysteresis, cooldown, and at most 16 transitions;
- a 32-job serialized incident-output queue, atomic Schema 1 filesystem evidence store, fixed retention, startup recovery, truthful journald/stderr alerts, output health, and root-only bounded evidence CLI;
- a standalone read-only deployment checker with strict bundle, installed-layout, authorization, platform, systemd-unit, evidence, and performance gates;
- a deterministic ten-file GitHub MUSL bundle containing the installer, checkers, hardened unit, and authorization example;
- a generated-root deployment/performance harness covering ten staging cases, six deterministic performance-failure fixtures, and fifteen fixed real traffic trials without touching a physical interface;
- a bounded host harness covering eighteen exact-artifact regression, observation, detection, and incident-output scenarios.

Production and live-interface attachment remain disabled. Delivery G's strongest result is
`staging_ready` plus fixture-proven `canary_candidate`; neither is permission to install, start,
inspect, or attach on a real interface. Loading and attachment are
available only through the generated isolated-veth verification path after the daemon
independently approves preflight. The eBPF entry points always return pass/continue;
this delivery derives rates, baseline-relative evidence, sampled ingress/egress relationships, storm states, passive external-loop confidence, and durable privacy-reduced local incident output, but never emits a confirmed-loop state, sends probes, drops traffic, or applies policies. It has no 100 ms sampler, raw fingerprint output, topology attribution, remote notification, or production-interface enablement. Production-root creation and real journald acceptance remain separately authorized installation work.

See [development.md](docs/development.md) for the CI workflow.

