# EPS1 current-source freeze and measurement boundaries

This records the current-source EPS1 screening inputs before timing. The
thresholds in `CACHE_EXPIRY_SCREEN_V1.md` remain unchanged. The old `bb0a923`
result is historical evidence; no result is transferred to the newer source.
Default product cache code is not modified by this experiment.

B0 is Git `816b955e607b591025409b56a924da1e3257de57`, including the retained
local CNAME targets and DHCP publication semantics. Frozen source SHA-256:

| Input | SHA-256 |
|---|---|
| B0 `cache.rs` | `f1892002ae9ea5c825f1d94249ffd4d723a9ce1d910576fe4a331722ebbfabc5` |
| `wire.rs` | `43bdcbfdb760623504ac696902800343e1be060e05bcd0350d9d91a78ad4f283` |
| `lease_names.rs` | `cb05a82f1d5f8e90e37dfee942b0464366eedac92b6dfcc35ecb50c86fe2b0b3` |
| EPS1 `cache.rs` | `3520602fae4d1568639b846157fb337532990061ca693af4acdd2feec07c45cd` |
| Candidate-only patch | `917edac9266d844d96ac0c1c2b3e1e87548ffecf074d861f4b7bc44e178d2c1e` |

The candidate adds exactly one conservative `i64` bound, initializes/resets it
to `i64::MAX`, lowers it for successfully committed entries and uses the same
expiry predicate at the existing pressure point. A necessary scan still walks
all slots in the original order and recomputes the committed survivor minimum.
Ordinary deletion does not repair the bound; an old deleted minimum can cost an
extra scan. This is not an ordered expiry index or a better worst-case bound.
A separate read-only invariant review found no missed-expiry path, including
publication deletion, local CNAME identity changes, clear, finite/forever stale
policy and backward time. That review is not a mathematical bug-free claim.

## Fixed workload details

All four vectors have 100,000 measured operations, capacity 1000 and exactly one
100,000-operation warm pass on each fresh cache. Inputs are parsed and names
prepared before warmup/timing. An operation performs a lookup; on miss it creates
and commits the known record, including its real owned name and RDATA copies.
IPv4/IPv6 RDATA uses four/sixteen-byte vectors; NXDOMAIN carries no RDATA. The
source oracle returns record type/value, negative bit, expiry, remaining TTL,
stale bit, hit/miss, insert/commit status and answer count for every operation.
The C outputs supply expected counts and digests. Rust never supplies an answer
oracle. This models cache-aside primitive work, not full DNS request processing.

| Vector | Frozen selection and clock | Input SHA-256 |
|---|---|---|
| Hot | 800 prefilled records: 560 A / 240 AAAA; seeded repeated lookups; TTL120; `now=100` throughout | `efd5540c42048b0fa8d3a3a39b4ad3c12067cf234d0ac2059e8eb098c3bb07bd` |
| Unexpired churn | 100,000 distinct names, 70/30 A/AAAA; TTL120; `now=100` throughout | `29437f153a3936d9bcbe535667dc66436fb897904d3b96b6dcba7f6862ebdf23` |
| Mixed | Same prefill; exactly 70,000 hot / 20,000 unique / 10,000 negative operations, shuffled by the frozen seed. Sixteen repeated negative names; positive120/negative30; `now=100` | `19c80f41711bb2371f61851371f155347d441da731d41eeceb2f9e36e3976f06` |
| Expiry | Distinct names; equally distributed TTL1/2/30/120. Advance one logical second per 1000 operations: warm100–199, measured200–299 | `f5012e17a830053d3e7549f8c0fa5ddf047369bd0ac4823c00b7982131c93913` |

The generator uses one `random.Random(0x293001)` stream in the listed vector
order. Warm/timed expiry timestamps advance continuously; warmup does not
manufacture a backward clock jump in the cost vector. Backward clocks remain
in the separate correctness corpus. Actual hits and evictions are retained:
mixed “hot” selection is not an assumption that every selected name still hits.

One separate untimed allocation run repeats 2,000 source-defined bookkeeping
cycles: commit earliest, selectively remove it through publication, commit a
later record, fail/abort a pending batch at zero TTL, clear, recommit and clear.
It asserts 8,000 required absences and 2,000 exact new expiries and checks drop
balance. No timing claim is derived from this instrumentation.

## Build, cost and acceptance boundaries

Formal binaries use the project-pinned native Linux Rust **1.98.1**, identical
`opt-level=3`, LTO, one codegen unit and `panic=abort` for B0/EPS1. The initial
`screen-02` functional build discovered that the host's default rustup selection
was 1.98.0; its successful traces remain a diagnostic, not the formal build.
The corrected preparation pins the exact compiler path, full version and SHA.
Sources, inputs and binary identities are checked again before use.

Timing uses process CPU nanoseconds and monotonic wall time around only the
100,000 operations, excluding parse/prefill/warmup, startup and output. The
correctness digest/count work is identical in both binaries. Each process is
pinned to CPU0. Vector order is hot, unexpired, mixed, expiry in each of the
three pairs; within each vector the pair orders are B0/EPS1, EPS1/B0, B0/EPS1.
Every window is retained. No allocation atomics are present in timed binaries.
Any changed result stops remaining windows; a speed cannot compensate for it.

A separate global-allocator build measures requested allocation/reallocation
counts, requested bytes, live bytes and peak live bytes. Input allocations are
outside the cache baseline; drop must return to that baseline. These numbers
are Rust allocation-layout requests, not malloc usable-size, RSS or process
USS. Cache/Entry layouts are measured separately. The extra fixed Cache field
can also add bytes when the enclosing object is heap-allocated in a service;
the primitive screen does not waive that later service memory comparison.

Retention still requires median paired CPU improvement at least 15% for both
unexpired and mixed, each hot/expiry pair at most 5% slower, zero extra heap
requests/per-entry bytes, complete drop recovery and fixed Cache growth at most
16 bytes. For each primary vector, its median improvement must exceed the
max-minus-min spread of its three EPS1/B0 ratios. There are no automatic extra
rounds after noise or a failing result.

The private sources and early gates are in
`private/dnsmasq-rewrite/cache-expiry-eps1/current-816b955/`. Native full-object
and screen artifacts are staged independently on the build host. Before any
product adoption, a retained candidate must be rebased onto then-current code
(including later metric instrumentation), pass the corresponding service and
target gates, and demonstrate the shared performance/resource goals. This
primitive screen cannot establish a C-to-Rust component gain or router gain.
