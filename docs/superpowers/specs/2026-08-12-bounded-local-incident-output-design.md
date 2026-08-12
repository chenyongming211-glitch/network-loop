# Bounded Local Incident Output Design

**Date:** 2026-08-12

**Status:** Approved by the standing recommendation authority

**Scope:** Durable, privacy-reduced incident evidence, local alert summaries, and root-only CLI queries for Schema 5 passive detection

**Supersedes:** `2026-08-06-local-alert-evidence-output-design.md` where that document refers to the pre-implementation `LoopState`, raw evidence, PCAP, read-only group access, or interfaces not present in Delivery E

## 1. Decision

Delivery F consumes the typed, generation-scoped `DetectionTransition` stream already produced by `SamplingService`. It adds three output layers:

1. an authoritative bounded filesystem store of immutable, privacy-reduced incident revisions;
2. one sanitized best-effort local alert per persisted transition, with newline-delimited JSON fallback when journald is unavailable;
3. root-only `status`, `evidence list`, and `evidence show` control paths.

No output operation runs in eBPF, changes detection state, blocks packet forwarding, or widens attachment. The delivery adds no raw packet capture, MAC/IP address, raw fingerprint/key/timestamp, topology, probe, policy, drop, remote notification, database, or production-interface support.

## 2. Incident Lifecycle

An anomalous detection state is one of the three storm states, `external_loop_suspected`, or `external_loop_high_confidence`.

- entering an anomalous state with no active incident opens one incident with a new random 16-byte `EventId`;
- anomaly upgrades/demotions, `unavailable` with a retained anomaly, and `cooldown` add immutable revisions to that incident;
- returning to `normal` from cooldown adds the closing revision and closes the incident;
- exact detach or shutdown while an incident is active adds a `generation_ended` closing revision before in-memory state is destroyed when the store remains available;
- a new generation never reuses an incident ID or sequence;
- warming/normal transitions with no active incident do not create evidence;
- output-health changes may emit a sanitized alert but never recursively create evidence incidents.

One interface generation has at most one active incident. `transition_sequence` is the detection transition sequence; `revision` starts at one per event and increments only for committed incident revisions.

## 3. Domain Contracts

All serialized names use `snake_case`; evidence schema is version 1.

`EventId` contains exactly 16 bytes and renders as 32 lowercase hexadecimal characters. Parsing rejects all non-canonical text before any filesystem access. The Linux generator reads exactly 16 bytes from the kernel random source; collisions never overwrite and retry at most three times.

`IncidentRevisionV1` contains only bounded, already privacy-reduced evidence:

- event ID, revision, interface, ifindex, generation, transition sequence, previous/current detection state and transition reason;
- opened, occurred, and optional closed Unix-millisecond timestamps;
- alert code/severity and evidence status;
- cumulative XDP ingress and TC egress aggregate counters;
- fixed 1/10/60-second status rate windows;
- `BaselineSummary`, `FingerprintWindowReport`, `DetectionReport`, observation health, and VLAN visibility;
- output completeness and a stable sanitized error code.

It never contains `FingerprintEvidence`, raw LRU entries, MAC/IP addresses, frame bytes, raw paths, hostnames, packet captures, topology, probe data, or adapter error chains.

`EvidenceSummaryV1` is the indexed/list representation. `EvidenceDetailV1` is the latest validated revision plus the bounded transition timeline already present in `DetectionReport`. `OutputHealth` reports `healthy` or `degraded`, store availability, corrupt/incomplete/unknown object counts, alert sink mode (`journald` or `stderr_json`), and one stable last error code.

Severity is fixed: storm or suspicion is `notice`; high confidence and output degradation are `warning`; cooldown/normal closure and generation-ended closure are `information`. Passive evidence has no `error` severity because it cannot confirm a loop.

## 4. Store Layout and Atomicity

The fixed production root is `/var/lib/l2-loop/evidence/v1`. Tests inject a temporary root. Root, event, temporary, and revision directories are mode `0700`; files are `0600`. Unsafe ownership/mode, symlinks, non-directories, or a missing production root make the store unavailable; the daemon does not repair them.

```text
v1/<event-id>/0000000000000001/{evidence.json,manifest.json}
v1/<event-id>/0000000000000002/{evidence.json,manifest.json}
```

Each commit writes a same-parent private temporary revision, fsyncs `evidence.json`, writes and fsyncs `manifest.json` last, fsyncs the directory, publishes with Linux no-replace rename, then fsyncs the event directory. Existing targets are never overwritten. The manifest records exact length and SHA-256 for `evidence.json`, total bytes, schema, event ID, revision, state, and package version.

Startup scans at most 1,000 canonical event directories and at most 16 revisions per event. It validates names, modes, manifest shape, lengths, hashes, and identity. Highest valid revisions form the in-memory index. Corrupt, incomplete, linked, non-canonical, or unknown objects are preserved and counted, never adopted or broadly deleted. Only exact daemon-owned temporary names older than one hour may be removed.

## 5. Fixed Bounds and Retention

- maximum store: 1 GiB;
- maximum events: 1,000;
- maximum revisions per event: 16;
- maximum structured revision: 1 MiB;
- maximum event: 16 MiB;
- maximum age for closed events: 30 days;
- minimum free reserve: max(512 MiB, 5% of the filesystem);
- list limit: default 50, range 1 through 200;
- response frame: below the existing 1 MiB protocol cap;
- filesystem writes: one serialized bounded worker, queue capacity 32, no retry queue.

Before commit, retention removes only complete closed canonical events, oldest close time then event ID. Active incidents, unknown objects, corrupt objects, and individual revisions are never deleted by retention. If bounds still prevent structured evidence, detection continues, output health becomes degraded, and the alert reports `evidence_status=unavailable`.

## 6. Alert and Query Contract

Alerts are emitted after the persistence attempt. Their fixed fields are event ID, evidence status, revision, transition sequence, code, severity, previous/current state, interface, ifindex, generation, and a short fixed-template message. Prohibited raw fields are scanned in tests. Journald submission is best effort; failure switches to one sanitized JSON object per line on stderr and does not retry.

`status` adds output health and optional active event ID/revision to each active interface. It never claims journald end-to-end delivery.

```text
l2-loopctl evidence list [--interface <IFACE>] [--limit <1-200>] [--cursor <OPAQUE>] [--json]
l2-loopctl evidence show --id <32-lower-hex> [--json]
```

List order is last-transition time descending, then event ID descending. The opaque cursor encodes version, filter hash, last timestamp, and event ID and is validated before lookup. Show returns sanitized detail only. Stable errors distinguish invalid request, not found, corrupt, permission denied, response too large, and store unavailable.

## 7. Failure and Lifecycle Semantics

- output failure never changes a detection state, hook return, attachment, or cleanup identity;
- a full queue drops only the output job, increments a bounded suppression/drop counter, degrades output health, and emits one deduplicated fallback warning;
- persistence succeeds before `stored` is emitted; failure can only emit `unavailable`;
- failed revision commit leaves the preceding valid revision authoritative;
- restart reconstructs the index only from complete validated revisions;
- exact detach remains allowed when output is unavailable and records the failure in output health;
- successful detach destroys only active in-memory incident state, not committed evidence;
- no caller controls paths, limits above fixed maxima, detection thresholds, or alert text.

## 8. Delivery Decomposition

Delivery F is implemented as one plan with independently green tasks: domain/query contracts; pure incident recorder; atomic filesystem store and recovery; retention; daemon lifecycle and bounded worker; alert sink/fallback; protocol/CLI; isolated host acceptance; final audit/documentation. GitHub performs every Rust compile/test. Host acceptance uses only the exact checksum-verified artifact and generated namespace/veth resources; evidence uses a generated temporary root under the acceptance run and is removed by exact identity after verification, so `/var/lib` and host journald are not mutated in the first host gate.

Actual production-root and journald acceptance is deferred until production installation/authorization is separately approved. Active probes, confirmed-loop state, raw evidence, packet drops, policing, and production attachment remain separate trust-boundary approvals.
