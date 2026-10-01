# Shared-entry snapshot with inline RDATA: frozen mechanism screen

This is a new, single-candidate private screen. The earlier shared-entry V1
and chunk32 rejections remain unchanged. No candidate implementation,
correctness test, allocation measurement or timing result exists at this
freeze. The mechanism below is feasible to implement without product edits,
unsafe code or an additional dependency; its costs are estimates until the
declared gates run.

## Source and mechanism

Use exact source `e77d966d0bf92e5296f73ee3e54fdaf960ed7781`, cache SHA-256
`8c73672d4ebe3959d8172cecf5b951afef61f23ec568c52b27f6b00ae081e9a5`,
for direct comparison with the original V1 screen. Keep `wire.rs`, `Name`
storage and lease trait declarations unchanged. Current typed transfer,
ordinary-CD caller changes and the private TCP reference are outside this
frozen primitive source; a passing screen would not integrate with them
automatically.

There are exactly two representations:

1. `deep`: the existing complete-clone control from the same frozen source.
2. `shared_inline16`: the V1 shared-entry mechanism, including its compact
   optional LRU links and `Arc<Entry>` detachment, plus inline RDATA up to and
   including 16 bytes.

The candidate replaces only the private copy's `Record.data: Vec<u8>` with a
small read-only RDATA wrapper. Its private storage enum has
`Inline { len: u8, bytes: [u8; 16] }` and `Heap(Box<[u8]>)` variants. The
wrapper provides `from_slice`, `as_slice`, immutable `Deref<Target = [u8]>`,
and ordinary clone/equality/debug support. The constructor alone creates
inline lengths, so callers cannot construct an invalid slice boundary.
There is no mutable slice API, custom allocator, packed pointer or encoded
payload length. Long CNAME/SOA/opaque data remains an owned heap slice.

Construction must use the source slice directly. Allocating a `Vec` and only
then converting it to inline storage would retain the population allocation
being removed. The prepared benchmark records and generated primitive driver
must create the candidate's inline values directly; the deep control retains
its original bytes and `Vec` representation. Candidate population clones
those prepared inline values without allocating their payload. The primitive
API change is limited to the private copied `Record` field and its generated
driver constructors/readers; product source and public APIs remain unchanged.

## Estimated absolute requested heap

The expected aarch64 Rust 1.98.1 layout is RDATA 24 bytes, `Record` 56,
`Entry` 120 and shared `Slot` 32. An entry's Arc allocation requests 136 bytes
including its two counters. These are predictions, not measured layout
guarantees. Stop before costs if the actual layout differs; do not tune enum
representation or add another candidate after seeing it.

For the fixed V1 address workload, the candidate removes one 4/16-byte payload
allocation per entry while retaining the single Arc allocation. The table
subtracts those payload bytes from V1's measured shared-entry parent heap.
The 150-entry case has 113 A and 37 AAAA records, totaling 1,044 payload bytes;
the larger profiles average seven payload bytes per record.

| Capacity / occupancy | Deep parent bytes | Estimated candidate parent bytes | Estimated change | Estimated 20-snapshot live bytes after lookup |
| --- | ---: | ---: | ---: | ---: |
| 150 / empty | 24,000 | 4,800 | -19,200 | 96,000 |
| 150 / full | 51,338 | 51,494 | +156 / +0.30% | 460,140 |
| 1,000 / full | 358,792 | 359,792 | +1,000 / +0.28% | 3,401,200 |
| 10,000 / full | 3,386,856 | 3,396,856 | +10,000 / +0.30% | 29,996,480 |

The expected full-profile population allocation counts return to the deep
control's 909 / 6,012 / 60,015; reallocations remain 330 / 2,200 / 22,000.
The empty profile still allocates its slot vector once. Snapshot extra heap
is expected to match V1 shared-entry because those snapshots share the
already allocated entry and only clone the same slots/indexes. All these
numbers exclude prepared inputs and measurement buffers in the same way as
V1. They describe allocator-requested bytes, not allocator size classes,
RSS/PSS or exclusive physical memory.

Nonempty payloads up to 16 bytes remove one payload allocation. Empty
negative payloads originally allocate nothing, so the entry Arc remains an
additional allocation for them. Payloads over 16 bytes retain both a payload
heap allocation and the entry Arc allocation. Their population allocation
count can also exceed deep by one per record. This screen makes no general
mixed-RR population claim.
Atomic Arc initialization, detachment checks and pointer indirection also
remain: removing a call to the allocator does not establish a CPU benefit.

## Frozen gates and run order

Correctness precedes allocation, which precedes timing. New tools and output
paths must be distinct from V1 and chunk32. Archive every source, compiler,
binary, input/output, invocation, failure and result; never overwrite old
evidence or rerun a failed candidate with revised thresholds.

Reuse the exact calibrated C corpus: 21 scenarios / 22,571 operations with a
snapshot retained across each operation. Verify the original input/source
hashes and reuse unchanged C expected output. The existing only-Generic
cross-type ordering allowance and changed-TTL/missing-row checks remain;
record data, within-type order, TTL, expiry, negative and stale state stay
exact. Add bounded storage-invariant checks for lengths 0, 1, 4, 15, 16, 17
and a longer opaque payload, including retained-clone independence and drops.
These are byte-storage checks, not a replacement protocol oracle.

Measure allocation separately with the same four profiles, 75% A / 25% AAAA,
10% long names, clock 100, TTL 3,600, disabled TTL clamps/stale cache, and one
committed record per population transaction. Each allocation run has one
group of 20 retained snapshots followed by their real first lookups. This
gives eight allocation runs. Require correct results, balanced drops, the
predicted fixed layouts and no extra population allocations versus deep in
these address profiles. Stop if those mechanism checks or the unchanged
deterministic heap gates fail. Instrumented CPU/wall fields are diagnostic
only and must never be used as timing evidence.

Timing requires a separately coordinated quiet window from the root agent,
with fixed CPU and no competing tests/builds. No timing is authorized by the
feasibility estimate alone. Pin native aarch64 Rust 1.98.1, release O3/LTO,
one codegen unit and separate uninstrumented binaries. Keep five warm groups,
25 measured groups and 20 retained snapshot/lookups per group. The three
fixed paired orders are `deep, shared_inline16`; `shared_inline16, deep`;
`deep, shared_inline16`. Across four profiles this is 24 runs and 12,000
completed measured operations. Do not add rounds, retry to select a better
window, pool samples or change the order after inspecting results.

Acceptance thresholds are unchanged: at least 20% combined snapshot plus
first-lookup CPU and snapshot-live-heap reduction at capacities 1,000 and
10,000, with gains exceeding paired-ratio spread; no more than 5% worst-pair
population CPU or steady requested-heap regression in any profile; and no
more than 5% worst-pair combined p95 regression at capacity 150. Report every
absolute cost and allocation count, combined wall samples, separate drop CPU,
errors and completion counts. No p99, C fork/COW speedup, full TCP service,
resource acceptance, production representation or router claim is allowed.

The isolated tooling worktree is
`private/dnsmasq-rewrite/resume-inline-rdata-20261001`, based on `0c8f362`.
Frozen candidate sources will be private copies of `e77d966`, not that
worktree's current product files. A result can qualify only this new bounded
mechanism; any later integration requires a separate source and behavior gate.
