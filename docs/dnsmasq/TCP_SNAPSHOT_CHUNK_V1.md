# TCP snapshot chunk storage screen, version 1

This is a new private mechanism screen. It does not revise or rerun the
rejected candidates in `TCP_SNAPSHOT_SCREEN_V1.md`. Product code is unchanged.
The frozen input is source `e77d966d0bf92e5296f73ee3e54fdaf960ed7781`, whose
cache SHA-256 is
`8c73672d4ebe3959d8172cecf5b951afef61f23ec568c52b27f6b00ae081e9a5`.

There are exactly two representations:

- `deep`: the previous explicit deep-clone reference, newly measured in this
  independent screen with the same source, compiler and workload.
- `chunk32`: replace only `Vec<Slot>` storage with a private indexed table of
  `Arc<[Slot]>` chunks containing at most 32 slots. The last chunk is short.
  Slots still contain owned inline entries and ordinary optional LRU indices.
  Names, pending inserts, header state and each snapshot's LRU state retain
  their existing semantics. Mutable access uses `Arc::make_mut` on its chunk;
  snapshots copy chunk handles and the existing name index. There is no
  per-entry shared allocation and no top-level whole-cache detachment.

The short final chunk avoids padding 150 slots to 160, which alone would
exceed the existing five-percent empty-parent heap allowance. Chunk creation
may use transient per-chunk buffers; all such allocation work is measured.
The expected tradeoff is copying only the few chunks touched by a lookup's
LRU updates, at the cost of an extra indexed load and uniqueness check during
parent mutations. No alternate chunk size or representation will be selected
after seeing results. A failed candidate remains rejected.

Correctness precedes allocation, which precedes any timing. Reuse the exact
C 21-scenario, 22,571-operation corpus from
`cache-expiry-eps1/counted-3277404/legacy-b0-01`, verifying its source hashes,
inputs and answers. Keep a clone alive across every operation, as in the
previous screen, and preserve its exact normalization: only cross-type
Generic RR grouping may vary; within-type order, data, TTL, expiry, negative
status and stale flags remain exact. Retain the one-TTL-mismatch negative
control and its failing command exit. Also verify retained snapshot content
and lookup isolation: serialize the held image's complete derived `Debug`
state before and after each operation and require identical bytes. This
covers slots, entries, generations, links, name-index ordering, pending state
and header fields without mutating the held image. Both representations add
only the `Debug` derivations needed for this untimed check. The active image
still compares against C; no C oracle or expected output is changed.

Allocation and timing workloads stay identical to the previous screen:
empty capacity 150 and full capacities 150, 1,000 and 10,000; 75% A and 25%
AAAA; one record per name; 10% long names; TTL 3,600; clock 100; no TTL
clamps or stale policy. Prefill commits one record per transaction. Each
group keeps 20 snapshots alive through their first real mutable lookup.
Record selection is deterministic, distributed and advanced per group.
Instrumented allocation mode has one group and is never timing evidence.

Native Linux aarch64 Rust 1.98.1 is pinned, with release optimization, LTO
and one codegen unit. Timing requires a root-coordinated quiet host window
and fixed CPU. There are five warm groups and 25 measured groups, yielding
500 completions per run. Three fixed orders are:

```
deep, chunk32
chunk32, deep
deep, chunk32
```

Thus allocation has eight runs, and timing has 24. Keep every invocation,
raw sample, source/binary hash, error and unexpected exit. Do not add rounds,
retry completed measurement runs, discard outliers or change thresholds
after viewing results. Preparation/compiler errors may be fixed before
measurements in new evidence paths; preserve every failed attempt.

The decision gates remain unchanged: exact correctness, balanced drops, at
least 20% combined snapshot-plus-first-lookup CPU and snapshot-live-heap
reduction at both 1,000 and 10,000, with CPU gain exceeding paired ratio
spread; no greater than 5% worst-pair population CPU or steady requested
heap regression at any profile; no greater than 5% worst-pair capacity-150
p95 regression. Report all allocation counts and absolute costs. Stop before
timing if a deterministic correctness or allocation gate fails.

Report population, clone, lookup and drop CPU separately, combined wall
p50/p95 and active completions per second, completed/errors, layouts,
allocation/reallocation counts, live/peak requested heap and balanced drops.
Requested heap is not RSS/PSS or exclusive physical memory. This screen
cannot establish C fork/COW costs, complete TCP service correctness or
latency, target resource acceptance, router behavior or product adoption.
The later TCP writeback journal is outside this frozen source boundary.
