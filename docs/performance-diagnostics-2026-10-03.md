# Selected-packet stage diagnostics: 2026-10-03

## Scope and current status

Four acceptance-only cumulative stages distinguish hash/selection, metadata,
kernel-clock and fingerprint Map work. The ordinary product hot path, Map ABI,
selection predicate and production admission decision are unchanged. **No product
performance improvement is claimed.** All 25 scheduled node trials completed with
exact forwarding, zero drops/errors and precise cleanup. All three adjacent-stage
contrasts remain **unresolved** under the predeclared 2.425% observed noise envelope.
No product optimization was selected or implemented from this inconclusive evidence.

The original formal isolated gate remains 940/905 permille for pass-through/observe,
against minimums of 950/900. Diagnostics do not replace this failed pass-through
gate or authorize installation, physical attachment or production rollout.

## Observable stages

| Profile | Cumulative work after common counters | Observer |
| --- | --- | --- |
| `fp_hash` | Original FNV hash and selected-packet predicate | Hash and selected count |
| `fp_metadata` | Add original fixed fingerprint metadata | Add packed L2/MAC/protocol fields |
| `fp_clock` | Add `bpf_ktime_get_ns` | Add kernel timestamp |
| `fp_map` | Add original lookup/update/insert semantics | Same shape as clock stage |

Every stage writes the same eight scalar u64 fields into a private, unpinned,
per-CPU `DIAG_RESULTS` Map. This makes calculations observable and prevents
dead-code elimination. It is measurement overhead common to these profiles,
not a production ABI change. Original profiles retain six Maps; new stages have
seven. New stages also share an extra configuration lookup and parser call.
Therefore differences include compiler/code-layout and observer interactions;
they are not exact helper nanoseconds or directly subtractable product costs.

## Noise-aware protocol

Five blocks alternate `hash, metadata, clock, map, hash` and
`hash, map, clock, metadata, hash`: exactly 25 trials. Each uses identical generated
endpoints and selected ARP corpus, with a 0.5-second/100,000-packet warm-up and
5-second/2,000,000-packet measurement bound per direction. Directions run sequentially.
All windows must end by duration, not packet ceiling, and forwarding/counters
must reconcile exactly with zero drops/errors. Warm-up is excluded from throughput
but included in packet and byte reconciliation.

Each contrast retains all five within-block ratios. Metadata uses its adjacent hash
anchor; clock/metadata and map/clock use the same block. The noise envelope is the
maximum absolute first/last hash-anchor ratio deviation from 1, floored at 1%.
A contrast is resolved only if all five ratios lie strictly beyond that envelope
on the same side. Otherwise it is unresolved. This conservative descriptive rule
is not a confidence interval; no outliers are removed or trials rerun until passing.

No CPU/IRQ affinity, global profiling, sysctl or shared-agent settings are changed.
Only the separately authorized generated-port LLDP transmit exclusion is permitted,
with exact restoration. No physical/business interface or foreign hook is touched.

## Development verification

- Identity and paired-analysis RED: run `37083898518`; unsupported-profile failure
  and expected missing schedule/summary assertion failures, not a compile failure.
- Real-artifact RED: run `37083975412`; new profile objects were not yet implemented.
- Run `37084147966` passed paired-analysis tests but exposed formatting and strict
  linked-function rejection. Run `37084374349` recorded an eight-instruction extra
  reachable memory routine after the 101-instruction shared parser.
- Whole-record assignment was replaced by eight fixed volatile scalar stores,
  rather than expanding the allowed support-function contract. GitHub run
  `37084538550` passed all four actual-ELF test methods, the ordinary-object rejection
  and instruction-identity regression, and all ten real-kernel loader test methods.
- Kernel fixtures independently check FNV selection, packed metadata, 192 selected
  observations per hook, exact 192 fingerprint keys/values across both hooks, no
  writes for unselected traffic, foreign TC retention and bounded cleanup paths.

Full GREEN: [run 37084538550](https://github.com/chenyongming211-glitch/network-loop/actions/runs/37084538550),
commit `aab228021e09bbaef61319c4d75d34d6f166e2e9`; Script safety, Windows safety,
Userspace, eBPF and Bundle all succeeded.

Compilation and automated code tests run only on GitHub. The inline review follows
the user's no-subagent/no-branch constraint. Node use requires complete CI success,
including the ordinary ten-file bundle and separate MUSL diagnostic runtime.

## Exact node artifact identity

All three downloads come from the complete GREEN run above; archive SHA256 values
are the GitHub artifact metadata digests, distinct from extracted file digests.

| Artifact | ID | Archive SHA256 |
| --- | ---: | --- |
| Eight diagnostic objects | 11259601674 | `9dba71fed18764dd54d7601b2e0c23914cf66e28f2d33be0f3e608f7cf103859` |
| MUSL diagnostic runtime | 11260056677 | `810beb30105e6c50f39c8049c9cee77e6c38cd38a4cc40b7d9ff2c49d0f20c6b` |
| Ordinary ten-file bundle | 11259762945 | `360c8b75a13601af802d8d7474b567434f27c78ea8e045ff62b18114d2f8b3c3` |

The extracted runtime SHA256 is `a18ea757e1bfcb3c0c77eba33942d5fdb66fe6b986b5828df8ebc1ca6a73add5`.
The controller verifies the bundle's nine checksums and manifest commit, and each
profile's exact two-file inventory, manifest commit and object digest. The runtime
independently binds the compiled commit and object digests before loading.

## Retained setup failure and recovery

Run `4a0ed0cdfe6d4cc49e1ef2016ae9162b` stopped after its first hash-stage trial:
an observer-loop variable shadowed the controller's link-record function, causing
its final identity/file cleanup to fail. This was a control-script failure, not
a valid throughput sample or evidence of a forwarding regression. The failure
output is retained; no result from this run enters the 25-trial analysis.

Read-only recovery checks confirmed no diagnostic lease, XDP hook or clsact remained,
and exact down-state veth/namespace identities matched the recorded context.
Only this run's request and object files were removed after exact content, ownership,
single-link and inode checks; then the existing generated-tree cleanup completed.
Recovery verified measured network/eBPF identity equality, restored LLDP state,
and zero generated residue. The original failure fields remain in the raw report.
The loop variable was renamed before starting a fresh fixed 25-trial experiment;
there was no outcome-based sample selection or repeat-until-pass performance gate.

## Interpretation limits

The selected-only synthetic ARP corpus deliberately amplifies selected-packet work;
it is not the production mix. Repeated keys predominantly measure a warm fingerprint
Map, not LRU churn or insert-heavy operation. The shared node, Python sender,
sequential directions and generic XDP/veth path remain limitations. Anchor controls
quantify observed drift but do not prove it was eliminated.

## Completed paired measurements

Run `5f31ff5d190d47a0a05f5b75b0bf6f8a` used authorized ostack7 (`10.58.146.7`),
kernel `6.6.0-159.4.8.161.oe2403sp4.x86_64`, 40 logical CPUs. All 50 directional
measurement windows ended by duration and all warm-up/measurement packets were
selected. No trials were dropped from this run. Ratios use combined actual packets
divided by combined elapsed time, not rounded sender PPS.

| Contrast | Block 1 | Block 2 | Block 3 | Block 4 | Block 5 | Median | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| metadata/hash | 99.213% | 98.079% | 102.225% | 96.136% | 97.980% | 98.079% | Unresolved |
| clock/metadata | 99.664% | 99.344% | 95.195% | 104.184% | 97.286% | 99.344% | Unresolved |
| map/clock | 96.876% | 93.624% | 98.878% | 99.022% | 101.766% | 98.878% | Unresolved |

First/last same-stage anchor ratios were 99.652%, 100.721%, 100.722%, 97.575%,
100.931%. The exact retained values are
`[0.9965212785654202, 1.0072112534070552, 1.0072206673485444,
0.9757503924044263, 1.0093109218923555]`; the envelope is
`0.024249607595573708`. The unrounded records, not displayed rounding, determine
classification. Every contrast includes at least one reversal and therefore fails
the consistency requirement as well as the all-block noise-bound requirement.

Absolute combined medians were 275,977 PPS for hash (10 anchors), 271,407 for
metadata, 269,628 for clock and 265,336 for map (five trials each). These descriptive
medians must not be substituted for the paired decision or described as product
gain/loss. A lower aggregate median alone is insufficient attribution evidence.

The controller verified forwarding packets/bytes including warm-up, per-hook
counters, selected observer totals, stage output shape, exact object identity and
cleaned state on every trial. An independent final recomputation reproduced all
15 contrast ratios and the noise envelope from raw counts/times. Final before/after
and cleanup snapshots matched; product-resource counts returned to baseline; LLDP
target/global/pre-existing-port state was restored and generated residue was zero.
Snapshot coverage includes program/map IDs, pin roots and interface XDP/TC state;
it is not an exhaustive global BPF-link-ID audit. Only this run's generated files,
veth and namespace were removed; raw local reports remain preserved.

Controller SHA256: `99ce5b6fdd3366a1183d36271d4eea71fa7d8d5766e7f95bbc1b0851006c02cf`.
Sender source remained frozen at commit `dfb34a445ce651add19f03456ed94200ca81ee9c`,
SHA256 `3f85925177b70e381aaa6c55fbd0eae0f14c240ad9a67ba8bfe3adf88e488b19`.
The local analysis source was checked against the tested commit (allowing CRLF);
its recorded SHA256 is `09e84c297a217c4eed160e71bb85c1ff6b9b0e63d0941fed0d9906623a9e014b`.
Raw reports and task-local transport remain under ignored `.artifacts/`.
Completed report SHA256: `746b8414b009b4541524f2133817feb34e6fe57942c83f8b6c977552434534e8`;
recovered setup-failure report SHA256:
`e33c94644877d51b552a65aa4eac0d52145babd215ccc8f666c01489be4430e1`.

## Next decision

Do not optimize metadata, clock or Map semantics on these results. The next useful
step is to bound sender/scheduling variability in a separately arranged quiet test
window or dedicated isolated test capacity, retaining same-stage controls and
fixed predeclared comparisons. Longer runs alone are not proof of reduced noise.
Any CPU/IRQ affinity, service suspension or shared-host-wide profiling requires
separate scope/authorization and was not performed here. Only after a stable
contrast should one choose a semantics-preserving candidate and repeat paired A/B
and the original formal gate. Production admission remains unchanged.
