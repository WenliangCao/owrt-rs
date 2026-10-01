# Shared-entry singleton name-index screen, version 1

This freezes one new private mechanism before implementation or measurement:
V1 shared entries plus a `One(usize) / Many(Vec<usize>)` name-index value.
It is independent of inline RDATA: `Record.data` remains `Vec<u8>`, wire
`Name` is unchanged, and canonical HashMap keys remain `Vec<u8>`. Neither
the inline16 p95 failure nor earlier V1/chunk32 failures are retried, waived
or used to select a parameter. No product representation is adopted.

The source and cost audit is
[TCP_SNAPSHOT_INDEX_OWNERSHIP_REVIEW.md](TCP_SNAPSHOT_INDEX_OWNERSHIP_REVIEW.md).
Use exact `e77d966d0bf92e5296f73ee3e54fdaf960ed7781`, cache SHA-256
`8c73672d4ebe3959d8172cecf5b951afef61f23ec568c52b27f6b00ae081e9a5`,
in private copied trees. The two representations are `deep` and
`shared_one_index`; the control and shared-entry/LRU transformations retain
the original V1 mechanisms. Current product changes and private TCP features
remain outside this frozen primitive source.

## Representation and compatibility boundary

The private name-index value has two variants. Default empty state is
`Many(Vec::new())` with no allocation. Pushing into an empty value produces
`One(slot)`. Pushing a second slot promotes through ordinary Vec pushes,
preserving standard growth and order. `retain` keeps the existing Vec for
nonempty Many states; removing the One element produces an empty value.
Many may legitimately contain one element after retention. A later push
into an emptied Many state may discard that buffer and become One.

Provide only a small private adapter: default/clone/debug, immutable slice
view, push, retain, ordered insertion before an index, collection from an
iterator, and conversion to an owned Vec for existing mutation-sensitive
iteration. Do not add a new general collection API. The ordinary lookup,
conflict scan and victim scan retain their current temporary owned copies.
Round-robin keeps the existing retain/splice ordering algorithm, with ordered
insertion delegated to Vec in the Many case. DHCP publication's ordered
collection must preserve every index and its order. No mutable alias to a
snapshot's map or vector is permitted.

Cache Slot/Entry/Record fields, EntryId generations, CNAME relationships,
pending visibility, counters, capacities, TTLs and local-name precedence are
unchanged. The table is independently cloned at snapshot time; first lookup
does not trigger whole-table copy-on-write. There is no new same-name chain,
shared-name/wire API, persistent library, unsafe code or dependency.

Expected native aarch64 sizes are Cache 168, shared Slot 32, Entry 120,
Record 56 and index value 24 bytes. The control remains 168 / 160 / 120 /
56 / 24. Verify those actual layouts before costs. If the enum differs from
24 bytes, stop; do not force it using unsafe code, packed layouts or clever
encodings. Stop if the source change expands beyond this private adapter and
its narrow caller substitutions, or if correctness/allocation gates fail.

## Correctness before allocation

Reuse the exact C corpus unchanged: 21 scenarios / 22,571 operations, with
its original source and input/output hash checks. Each variant retains a
snapshot over every operation and compares its complete state before/after.
The sole existing cross-type Generic RR ordering allowance remains unchanged;
within-type order, data, TTL, expiry, negative and stale fields stay exact.
Changed-TTL and missing-observation calibration must fail.

Supplement that oracle with bounded index adapter checks against ordinary
Vec behavior: empty → One (including slot zero), One → Many, Many retention
with preserved order, insertion before both ends/interior, removal to empty,
empty-buffer reuse, ordered collection, and retained clones across mutations.
Include both parent/retained-clone drop orders with balanced allocation
accounting. These validate storage operations, not a replacement DNS oracle.

Use the same four fixed profiles: capacity 150 empty, and full capacities
150, 1,000 and 10,000. Occupied profiles contain 75% A / 25% AAAA, 10% long
names, one record per name, TTL 3,600 and clock 100, with TTL clamps and
stale cache disabled. Commit each populated record in its own transaction.
Prepared inputs and measurement buffers stay outside population/live-heap
deltas, using identical logical data in both representations. Payload lookup
validation compares byte slices identically on both sides.

Separate instrumented allocation binaries run one untimed group of 20
simultaneous snapshots and their first real lookup, followed by drops. Two
representations times four profiles means eight allocation runs. Require
all 160 completions, zero errors, full row identities, balanced drops and
population allocation/reallocation counts no greater than deep in these
address profiles. Instrumented CPU/wall values are diagnostic only.

Predicted requested parent bytes for the candidate are 4,800 empty and
47,738 / 334,792 / 3,146,856 full. Predicted live bytes for 20 images after
lookup are 96,000 empty and 436,140 / 3,241,200 / 28,396,480 full. Full
population allocation counts should equal deep's 909 / 6,012 / 60,015;
clone allocations should fall to 3,040 / 20,040 / 200,040. These are
pre-measurement predictions. Mixed-RR names retain Many Vec storage and do
not necessarily save the population allocation, so no broader claim follows.

## Timing requires a separate quiet window

Only passing correctness, layout and deterministic allocation gates can
qualify a timing run. Root must separately coordinate a quiet build-host
window and fixed CPU. Use native aarch64 Rust 1.98.1, O3/LTO, one codegen
unit, and separately compiled uninstrumented timing binaries. The three
fixed pair orders are `deep, shared_one_index`; `shared_one_index, deep`;
`deep, shared_one_index`. Each profile/run has five warm groups, followed by
25 measured groups of 20 retained snapshot/lookups. This is 24 runs and
12,000 measured completions. No extra round or new fast window is allowed
after seeing results.

Keep the original thresholds: at least 20% combined snapshot/first-lookup
CPU and snapshot-live-heap reduction at 1,000 and 10,000, with CPU gain
exceeding paired-ratio spread; no more than 5% worst-pair population CPU or
steady requested-heap regression at any profile; and no more than 5%
worst-pair combined p95 regression at capacity 150. Report all absolute
costs, allocation counts, complete/error counts, per-run samples, windows
and separate snapshot-group drop CPU. Do not pool runs or report p99.

All artifacts use new private paths beneath
`private/dnsmasq-rewrite/resume-single-index-20261001/`. Archive every source,
tool, compiler, binary, input, invocation, failure and result without changing
prior screens. Requested heap is not RSS/PSS or exclusive physical memory.
A passing primitive screen would not establish mixed-RR population, C
fork/COW speedup, service/resource qualification, production adoption or any
router deployment.
