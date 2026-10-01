# Chunk32 snapshot screen: correctness and allocation pass

The independent `chunk32` candidate passes the frozen deterministic gates in
[`TCP_SNAPSHOT_CHUNK_V1.md`](TCP_SNAPSHOT_CHUNK_V1.md). Timing has not run and
no candidate is adopted. This does not revise the earlier representation
screen or its rejections.

Both `deep` and `chunk32` match all 22,571 operations in the existing exact-C
21-scenario corpus. Each retains a snapshot across every operation and checks
that its complete derived state remains unchanged. There are zero failures
and the same 138 permitted cross-type Generic RR ordering variations per
variant. The one-TTL-mismatch control detects exactly one failure among 13
rows and exits 1. C expectations were reused unchanged.

The source remains `e77d966d0bf92e5296f73ee3e54fdaf960ed7781`; compilation is
native Linux aarch64 Rust 1.98.1 with release optimization, LTO and one codegen
unit. This primitive boundary excludes the later TCP writeback journal.

## Requested heap

Snapshot values include 20 simultaneous snapshots and their first mutable
lookups. These are allocator-requested bytes, not RSS/PSS or exclusive memory.

| Capacity / occupied | Representation | Parent live | Snapshot live after lookup | Snapshot peak extra |
| --- | --- | ---: | ---: | ---: |
| 150 / 0 | deep | 24,000 | 480,000 | 480,020 |
| 150 / 0 | chunk32 | 24,160 | 1,600 | 1,620 |
| 150 / 150 | deep | 51,338 | 954,120 | 954,249 |
| 150 / 150 | chunk32 | 51,498 | 597,438 | 597,510 |
| 1,000 / 1,000 | deep | 358,792 | 6,695,200 | 6,695,329 |
| 1,000 / 1,000 | chunk32 | 359,816 | 3,025,286 | 3,025,415 |
| 10,000 / 10,000 | deep | 3,386,856 | 62,936,480 | 62,936,609 |
| 10,000 / 10,000 | chunk32 | 3,396,872 | 23,958,313 | 23,958,442 |

At 1,000 and 10,000 entries, snapshot live heap falls 54.81% and 61.93%, while
parent heap increases 0.285% and 0.296%. All eight allocation runs complete
20 operations each: 160 completions, zero errors, balanced snapshot and parent
drops. The empty 150-slot parent increases 0.667%, also within the 5% guard.

## Allocation work and remaining decision

The chunk table keeps the existing 160-byte slots and 120-byte inline entries.
The cache/image header grows from 168 to 176 bytes. Each chunk contains at most
32 slots; the final slice contains only the remaining slots. Name-index and
LRU snapshot semantics remain unchanged.

| Capacity / occupied | Representation | Population allocations | Population reallocations | Clone allocations | Lookup allocations |
| --- | --- | ---: | ---: | ---: | ---: |
| 150 / 0 | deep | 1 | 0 | 20 | 20 |
| 150 / 0 | chunk32 | 11 | 0 | 20 | 20 |
| 150 / 150 | deep | 909 | 330 | 12,040 | 80 |
| 150 / 150 | chunk32 | 919 | 330 | 6,040 | 2,470 |
| 1,000 / 1,000 | deep | 6,012 | 2,200 | 80,040 | 80 |
| 1,000 / 1,000 | chunk32 | 6,076 | 2,200 | 40,040 | 2,697 |
| 10,000 / 10,000 | deep | 60,015 | 22,000 | 800,040 | 80 |
| 10,000 / 10,000 | chunk32 | 60,641 | 22,000 | 400,040 | 2,778 |

Population adds two allocation calls per chunk: its temporary construction
buffer and final shared slice. It adds no allocation per entry. First lookup
detaches touched chunks and therefore performs more allocations than deep;
those costs remain included in both the memory and pending CPU gates.
Instrumented CPU/wall fields are diagnostic, not timing evidence. Parent
mutation uniqueness checks may still fail the unchanged 5% population CPU
guard. The combined CPU and capacity-150 p95 guards remain unmeasured.

[`TCP_SNAPSHOT_CHUNK_ALLOCATION.json`](TCP_SNAPSHOT_CHUNK_ALLOCATION.json)
contains derived rows, identities and evidence hashes. Raw evidence is under
the isolated worktree's ignored
`private/chunk-preparation/allocation-evidence-01/private/chunk-01/`, archived
as `private/chunk-preparation/allocation-evidence-01.tar.gz`. The remote copy
is `/home/ubuntu/dnsmasq-tcp-chunk-20261001/work01/private/chunk-01/`. Tools are
`tcp_snapshot_chunk_screen.py`, its Rust driver and its `.slots.rs` fragment.
Product sources, earlier V1 evidence and routers were not changed.
