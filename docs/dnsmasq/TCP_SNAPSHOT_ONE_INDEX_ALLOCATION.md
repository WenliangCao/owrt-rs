# Singleton name-index: correctness and allocation pass

The later unchanged [24-run timing screen](TCP_SNAPSHOT_ONE_INDEX_RESULT.md)
rejects this candidate on the population CPU guard. Pending-timing statements
below describe this earlier allocation phase.

The single private `shared_one_index` candidate passes correctness, actual
layout and all deterministic allocation gates. Its name-index value removes
the separate singleton index allocation while RDATA remains `Vec<u8>`.
**Timing has not run and the representation is not accepted or adopted.**
All previous shared-entry, chunk32 and inline16 rejections remain unchanged.

The independent [frozen plan](TCP_SNAPSHOT_ONE_INDEX_V1.md) uses exact
`e77d966d0bf92e5296f73ee3e54fdaf960ed7781`, native aarch64 Rust 1.98.1,
O3/LTO and one codegen unit. Product source, wire Name, canonical index keys,
RDATA, C input/output and prior screen artifacts are unchanged. Only private
copied sources receive the existing shared-entry/LRU transformation and the
new `One(usize) / Many(Vec<usize>)` value adapter. No new unsafe code or
dependency is introduced by that representation.

## Correctness and layout

Deep and candidate each match all **22,571 exact-C operations in 21
scenarios**, including the same 138 permitted cross-type Generic RR order
variations. Every operation retains a snapshot and verifies its entire state
after the mutation. Pending insertion, commit/abort, expiry, replacement,
eviction, CNAME generations and rotation remain covered. The exact C outputs
were reused unchanged after checking their inputs and source hashes.

The adapter checks cover empty and slot-zero values, One-to-Many growth,
stable Many retention including length one, insertion at both ends and in
the middle, empty insertion, emptied-buffer reuse, duplicate/filtered ordered
collection and retained-clone independence. Both parent/clone drop orders
balance live-byte accounting. The changed-TTL negative control detects one
mismatch among 13 rows and exits 1; missing observations are rejected.

Measured native structure sizes match the predictions:

| Representation | Cache | Slot | Entry | Record | Index value |
| --- | ---: | ---: | ---: | ---: | ---: |
| deep | 168 | 160 | 120 | 56 | 24 |
| shared_one_index | 168 | 32 | 120 | 56 | 24 |

The enum does not enlarge HashMap buckets. No same-name chain or new slot
links were introduced. Each snapshot owns its index table, so lookup does
not detach a shared whole table. The three existing mutation-sensitive scans
still take explicit owned Vec copies, preserving their ordinary lookup and
removal boundaries.

## Requested heap and allocation work

All eight allocation invocations complete 20 snapshot/lookups each: **160
completions, zero errors**, with balanced snapshot and parent drops. Snapshot
columns include twenty simultaneous images and their first mutable lookup.
Prepared input records and measurement buffers remain outside the deltas.
All figures are allocator-requested bytes, not RSS/PSS or exclusive memory.

| Capacity / occupied | Representation | Parent live bytes | 20 snapshots after lookup | Snapshot peak extra |
| --- | --- | ---: | ---: | ---: |
| 150 / 0 | deep | 24,000 | 480,000 | 480,020 |
| 150 / 0 | shared_one_index | 4,800 | 96,000 | 96,020 |
| 150 / 150 | deep | 51,338 | 954,120 | 954,249 |
| 150 / 150 | shared_one_index | 47,738 | 436,140 | 436,269 |
| 1,000 / 1,000 | deep | 358,792 | 6,695,200 | 6,695,329 |
| 1,000 / 1,000 | shared_one_index | 334,792 | 3,241,200 | 3,241,329 |
| 10,000 / 10,000 | deep | 3,386,856 | 62,936,480 | 62,936,609 |
| 10,000 / 10,000 | shared_one_index | 3,146,856 | 28,396,480 | 28,396,609 |

Full parent live heap falls **7.01% / 6.69% / 7.09%** relative to deep.
Snapshot live heap falls **51.59% / 54.88%** at capacities 1,000 and 10,000.
These exactly reproduce the source-derived prediction in the
[ownership audit](TCP_SNAPSHOT_INDEX_OWNERSHIP_REVIEW.md).

| Capacity / occupied | Population allocations, both | Reallocations, both | Deep clone allocations | Candidate clone allocations | First lookup allocations, both |
| --- | ---: | ---: | ---: | ---: | ---: |
| 150 / 0 | 1 | 0 | 20 | 20 | 20 |
| 150 / 150 | 909 | 330 | 12,040 | 3,040 | 80 |
| 1,000 / 1,000 | 6,012 | 2,200 | 80,040 | 20,040 | 80 |
| 10,000 / 10,000 | 60,015 | 22,000 | 800,040 | 200,040 | 80 |

The single index avoids a 32-byte parent allocation per name and an
eight-byte payload allocation per cloned name in this workload. That saved
parent allocation offsets the shared entry's Arc allocation. Canonical key
buffers still clone independently; ordinary first-lookup temporary allocation
counts are unchanged. Names containing multiple records retain Many Vec
storage and may not save the population allocation, so these measurements
do not qualify arbitrary mixed-RR or reused-cache workloads.

## Evidence and pending decision

The tools are `tcp_snapshot_one_index_screen.py`, its Rust measurement
driver, private index adapter, adapter checks and instrumented check driver.
Their generated sources, compiler/binary identities, raw C and Rust outputs,
all invocation logs and checksum manifest remain under ignored
`private/dnsmasq-rewrite/resume-single-index-20261001/private/` in
`one-index-evidence/one-index-01/` and `one-index-preparation/`.
No preparation, build, correctness or allocation failure occurred.

[The JSON report](TCP_SNAPSHOT_ONE_INDEX_ALLOCATION.json) records the derived
results and source/artifact hashes. The remote root is
`/home/ubuntu/dnsmasq-tcp-one-index-20261001/work01`, with passing `gate.json`
and `allocation-result.json` in `private/one-index-01/`. There is no timing
result; instrumented CPU/wall values are diagnostic only.

Only a separately root-coordinated quiet window can execute the frozen
24-run timing schedule. The unchanged population CPU, combined CPU and
capacity-150 p95 guards remain unmeasured. No production representation,
full TCP/service/resource acceptance or router action follows from these
allocation results.
