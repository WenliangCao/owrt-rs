# TCP cache snapshot candidate screen, version 1

This is a frozen host-side mechanism screen, not component/router performance
acceptance. The C normal-mode 32-observation gate establishes the required
snapshot/clock/writeback semantics. C uses fork/COW; this screen compares Rust
representations and makes no C-versus-Rust speedup claim.

Candidates remain in private copied source trees:

1. `deep`: explicit complete clone of the current cache layout and owned data.
2. `compact`: the same clone with nonzero-encoded optional LRU indices; zero
   represents no link, while a stored value is the slot index plus one.
3. `shared`: compact private layout/index plus immutable `Arc<Entry>` records;
   entry mutation detaches through `Arc::make_mut`. This may reduce snapshot
   payload copies but adds a normal-insertion allocation that must be counted.
4. `top`: top-level `Arc<Cache>` using the deep representation. Its first
   mutable lookup can copy the entire cache; creation cost alone is misleading.

Before measurement, every representation must retain the exact C cache
primitive results while a clone is kept alive across each operation. This
exercises pending commits, aborts, expiry, reuse, CNAME targets and rotation.
The existing C primitive corpus and its normalizations are unchanged.

The four fixed workloads are empty capacity 150, full capacities 150, 1,000
and 10,000. Full cases contain 75% A and 25% AAAA, one record per name, and
10% names exceeding C's small-name boundary. TTL is 3,600 seconds, explicit
clock is 100, min/max clamps and stale cache are disabled. Prefill commits one
record per transaction so the pending vector does not grow artificially with
the whole cache. The same prepared records feed every representation.

Each timing run has five warm groups followed by 25 measured groups. A group
creates 20 snapshots, performs one real cache lookup in each, then drops them.
All 20 remain alive across the lookup phase. Record choices are deterministic,
distributed across the cache and advanced each group. Each measured run has
500 completed snapshots/lookups. Three rounds use these orders:

```
deep, compact, shared, top
top, shared, compact, deep
compact, top, deep, shared
```

Compile with pinned Rust 1.98.1, release optimization and LTO. Run timing only
in an agreed quiet host window with a fixed CPU. Allocation builds are separate
and never used for timing. Save every invocation, source/binary hash, raw
sample, error, unexpected exit and result; do not add rounds or choose a fast
window after seeing output.

Report population CPU and requested heap, snapshot and first-lookup CPU per
completion, p50/p95 wall samples, snapshot throughput, completed/error counts,
fixed structure sizes, allocation/reallocation counts, live/peak requested
heap and drop balance. Do not label requested heap or RSS exclusive memory.
First-lookup and population costs remain visible even if a candidate improves
snapshot creation. With 500 samples per run, no p99 claim is planned.
Combined wall samples pair each snapshot creation with its first lookup;
throughput divides completions by their summed active wall duration. Waiting
between creation and lookup is outside this primitive boundary. Drops have a
separate CPU total. The capacity-150 p95 guard uses the combined wall samples.
Allocation mode uses one untimed group of 20 and reports CPU/wall fields only
as diagnostics; those instrumented values never establish a performance gain.

The candidate screen requires correctness and balanced drops. Relative to
`deep`, a candidate needs at least 20% combined snapshot-plus-first-lookup CPU
and snapshot live-heap reduction for the 1,000/10,000 cases; gains must exceed
paired ratio spread. Capacity-150 p95 may not regress by more than 5%, and
population CPU or steady requested cache heap may not regress by more than 5%.
Allocation counts and absolute costs are reported even when these gates pass.
A failed candidate is not silently accepted as an optimization. The deep
clone remains only a correctness/cost reference, not a presumed final design.

Real C/Rust TCP service latency, full cache ownership costs, allocator/RSS/PSS
behavior, failure isolation, target limits and router validation are separate
gates. These results cannot by themselves close resource acceptance.
