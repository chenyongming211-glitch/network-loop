# Delivery D Bounded Fingerprint Relationships Design

**Status:** approved by the operator's standing instruction to use the recommended safe design

## 1. Goal

Delivery D adds bounded passive packet fingerprints and generation-scoped ingress/egress relationship evidence to the isolated L2 Loop Detection Agent. It consumes the existing `FINGERPRINTS` LRU Map and the already frozen ABI structs, keeps every data-plane return path fail-open, and exposes only privacy-reduced aggregate relationship evidence through `observe` and `status`.

This delivery does not produce a loop or storm verdict. It creates trustworthy relationship evidence for the next loop-state delivery.

## 2. Safety Boundary

The existing attachment boundary does not widen:

- only the generated isolated namespace/veth acceptance path may attach;
- XDP always returns `XDP_PASS` and TC always returns `TC_ACT_OK`;
- no probe is transmitted and no probe Map is activated;
- no policy, drop, policing, rate limiting, packet mutation, PCAP, or production attachment is added;
- no physical, bond, bridge, OVS, tap, shared, or business interface may be selected;
- journal-confirmed hook and Map identity remains mandatory;
- a foreign network or eBPF identity change remains a hard refusal;
- cleanup continues to remove only exact journal-owned identities.

The existing six-Map ownership schema remains version 2. `FingerprintKey` and `FingerprintValue` are already part of ABI version 1, so this delivery activates their frozen semantics without changing their layout, names, capacities, pin paths, or kernel Map IDs.

## 3. Fixed Sampling Contract

Only successfully parsed Ethernet frames with a length representable by `u16` and at least 60 bytes are eligible. The data plane computes 64-bit FNV-1a over:

1. the exact frame length encoded as two big-endian bytes; and
2. the first fixed 60 bytes of the frame.

The direction is intentionally excluded so an unchanged frame has the same fingerprint at ingress and egress. The exact length is included so equal prefixes with different lengths do not alias by construction. Frames below 60 bytes remain fail-open and continue cumulative classification but are not fingerprinted. The fixed span matches the standard minimum Ethernet frame as observed without FCS and lets the supported older kernel prove one packet-bound check without dynamic packet offsets. The algorithm is allocation-free and uses exactly 60 statically bounded, verifier-visible byte steps.

`sample_shift` is fixed to `4` for this delivery. An eligible frame is selected when the low four fingerprint bits are zero, which is deterministic across hooks and approximately one sample per sixteen eligible frames. Values above `16` are invalid; callers cannot configure the value. The zero value used by older code is no longer published.

Fingerprint collisions remain possible because this is a non-cryptographic bounded signal. A fingerprint is therefore evidence, never an identity or verdict.

## 4. Normalized Key Semantics

The existing `FingerprintKey` fields are populated as follows:

- `interface_generation`: exact active journal generation;
- `fingerprint`: the fixed hash above;
- `ifindex`: exact active journal ifindex;
- `outer_vlan_id`: visible outer VID or `NO_VLAN`;
- `ether_type`: post-single-tag EtherType;
- `frame_len`: exact representable frame length;
- `direction`: `INGRESS` for external XDP and `EGRESS` for physical TC egress;
- `vlan_depth`: `0`, `1`, or `2`, where `2` means a second tag was observed but not parsed;
- `protocol`: IPv4 protocol, IPv6 next-header, or zero when unavailable/not applicable;
- `subtype`: ICMP/ICMPv6 type or low ARP opcode when safely visible, otherwise zero;
- `reserved`: all zero.

The source and destination MAC are copied into the kernel value only as root-owned internal evidence. Packet payload bytes are never copied into a Map or userspace report.

## 5. Bounded Map Updates

`FINGERPRINTS` remains an 8,192-entry LRU hash. A key represents one direction of one normalized fingerprint relation. On first selection the program inserts a value containing first/last boot-monotonic timestamps, packet/byte counts of one, and the two MAC addresses. Later selections update last-seen and saturating counters. Insert/update failure is ignored after ordinary cumulative accounting, preserving fail-open forwarding.

The Map is recreated for each isolated object load. Generation is also present in every key. No cross-generation adoption, migration, or cleanup scan is allowed.

## 6. Userspace Identity and Read Contract

Background 1 Hz rate/baseline sampling does not enumerate the fingerprint LRU. Only request-purpose reads obtain relationship evidence.

Before reading, the Linux adapter validates:

- exact ownership schema and ABI;
- exact journal-confirmed `FINGERPRINTS` name, pin path, and current kernel Map ID;
- exact LRU key/value types through Aya;
- a maximum of 8,192 returned entries;
- exact current generation and ifindex on every entry;
- approved direction, VLAN depth/range, reserved bytes, non-zero counts, ordered timestamps, and representable byte evidence;
- absence of duplicate keys.

Hook or Map identity failure refuses the whole observation. A bounded iteration/read failure after identity validation publishes fingerprint state `unavailable`, records a stable error code, and degrades observation health while preserving cumulative counters, rate windows, baseline state, and forwarding.

## 7. Pure Relationship Analysis

The core relation builder is a pure domain component. It groups entries by every key field except direction and never groups across generation or interface. For each group it records whether ingress and/or egress evidence exists, which direction was first, whether either side repeated, and the directional packet/byte counts.

The builder enforces these fixed bounds:

- no more than 8,192 raw entries;
- no more than 8,192 relation groups;
- checked `u64` aggregate arithmetic;
- `u128` intermediate arithmetic for ratio-per-thousand values, clamped to `u64`;
- deterministic ordering independent of kernel iteration order.

This delivery does not infer causality from timestamp order and does not label any relation as a loop. LRU eviction and deterministic sampling make all counts lower bounds.

## 8. Public Schema 4

`ObservationSnapshot.schema_version` becomes `4`; the control protocol remains version `1` because daemon and CLI are distributed only as one exact commit-bound artifact.

`observe` adds a complete `fingerprints` report:

- `state`: `empty`, `observed`, or `unavailable`;
- fixed `capacity=8192` and `sample_shift=4`;
- `captured_entry_count` and `relation_count`;
- ingress-only, egress-only, and correlated relation counts;
- ingress-first, egress-first, and simultaneous correlated counts;
- repeated relation count;
- aggregate sampled packets/bytes by direction;
- maximum directional packet and byte ratio-per-thousand;
- stable `last_error_code` only when unavailable.

`status` contains the same privacy-reduced summary. Neither output contains fingerprints, MAC addresses, packet bytes, raw keys, raw timestamps, or a caller-selectable sampling control. Text rendering performs no calculations; JSON serializes the validated domain model directly.

Observation health is degraded when fingerprint evidence is unavailable. Empty or observed fingerprint evidence is healthy when the existing sampling/baseline health is healthy.

## 9. Failure and Lifecycle Semantics

- Attach publishes the fixed sample shift only after dependent stats initialization and hook verification.
- Detach and shutdown unload the object and therefore destroy the complete fingerprint LRU.
- Reattach creates a new generation and an empty fingerprint report.
- Identity change refuses observation and never adopts or removes foreign state.
- Iteration failure is request-local; a later successful request recovers without daemon restart.
- Fingerprint evidence never changes rate or baseline learning and never causes data-plane blocking.

## 10. Verification

Unit tests cover the fixed hash, length separation, deterministic selection, protocol/subtype normalization, relation grouping, ordering, limits, overflow handling, privacy-reduced summaries, Schema 4, and failure composition.

GitHub CI remains the only Rust compiler and must pass all five jobs. The exact checksum-verified MUSL artifact is then exercised on the authorized node with the existing eight scenarios plus:

9. `FingerprintRelationship`: selected and unselected frames prove deterministic sampling, an unchanged selected frame observed on both hooks produces one correlated relation with the expected first direction, and forwarding remains unchanged.
10. `FingerprintReadFailure`: an injected request-only LRU iteration failure produces unavailable/degraded fingerprint evidence while cumulative/rate/baseline output and forwarding remain available, then a later request recovers.
11. `FingerprintGenerationReset`: detach/reattach changes generation, starts with an empty relation report, and independently records new-generation evidence.

Every scenario must preserve the complete before/after foreign network and eBPF identity snapshot and leave zero owned runtime, socket, journal, pin, namespace, veth, process, or artifact residue.

## 11. Delivery Boundary

Delivery D completes bounded passive fingerprint collection and ingress/egress relationship summaries. The next delivery may consume this evidence together with Schema 4 baselines to implement an explicit observation-only loop-state machine and bounded event transitions. Active probes, packet drops, policing, evidence persistence, alert sinks, and production attachment remain separately gated.
