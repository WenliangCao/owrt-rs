# EPS1: conservative expiry bound — frozen host screening plan

2026-10-01. This plan precedes any EPS1 timing result. It freezes a small
cache-primitive screening decision, not the shared C/Rust service acceptance
protocol. No default cache implementation, cache capacity, memory limit,
TTL, stale policy or physical device changes are authorized by this plan.
Functional work retains priority. A current-source candidate must be rebased
over the separate DHCP-publication/shared-cache work before any integration.

## Baseline and reason for this candidate

The baseline cache source is Git `bb0a923`, SHA256
`ce40fbf1bb34e01f5d760e46fa7ad377af5e6daf5368c3b49dded5fe850faf75`.
The matching patched C `cache.c` SHA256 is
`51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`.
Sources, compiler flags and every generated vector must be retained and
hashed in the private screening directory. Working-tree changes must not
silently replace a frozen input. This source baseline is a comparison input,
not a declaration that its remaining functional gaps are accepted.

Exact C `cache_scan_free` (`cache.c:518–635`) scans a name bucket for forward
conflicts. When a forward insertion finds an occupied LRU tail,
`really_insert` (`737–781`) first scans every bucket for expired records,
then evicts the conflicting RRset if no free entry resulted. The global
expiry pass is O(records + buckets), including when no record has expired.
C's expiry check (`468–490`) is separate from outdated-CNAME detection.
In particular, the global `flags == 0` pass removes expired records, not
every dangling CNAME; name lookup/conflict paths retain their own checks.

Rust's existing pressure branch (`Cache::insert`) also visits all capacity
slots before spilling a live RRset. It removes committed expired records
in increasing slot order. Therefore its global check is O(capacity), even
with all records unexpired. [C_COST_RESULT.md](C_COST_RESULT.md) records
11.07%/21.54% sampled self cycles in C `cache_scan_free` for host mixed/TCP
traffic. The host glibc expiry-arithmetic cost is not a target musl cost.
That evidence identifies work worth avoiding; it predicts no Rust speedup.

## EPS1: skip only a provably empty expiry pass

Start with one `i64` conservative lower bound on committed record `expires`,
initialized to `i64::MAX`. There is no new collection or per-record field.
The invariant is `bound <= min(expires of every committed record)`; equality
is unnecessary. Empty state may use `i64::MAX`: a needless scan at the maximum
timestamp is safe. Reuse the existing `Policy::expired(bound, now)` predicate,
including its i128 subtraction for finite stale allowances; do not add the
allowance in i64 or replace equality with a strict comparison.

At the **existing occupied-tail pressure trigger**, skip the existing global
pass only if that predicate is false. Otherwise run the **same slot-order
pass**, with the same expiry predicate and calls to `remove`; recompute the
minimum of surviving committed expiries during that pass. Do not free records
eagerly, pop in deadline order, remove only enough records for one insertion,
or change the subsequent LRU/RRset spilling sequence.

| Mutation/boundary | Bound maintenance | Required behavior preserved |
| --- | --- | --- |
| Constructor / `clear` | Reset to `i64::MAX` | Clear retains generation history and policy; no records remain |
| Successful commit of a valid pending entry | `bound = min(bound, entry.expires)` | Pending entries enter the bound only when they become visible |
| Pending insert, including a preserved CNAME target slot | No update until commit | Pending entries remain outside committed lookup/index state |
| Conflict removal, lookup expiry, RRset spill, DHCP selective invalidation | Leave the bound unchanged | A deleted minimum may cause an extra scan, never a missed expiry |
| Failed insertion/failed commit | No new pending expiry added | Old-record removals remain effective; rollback is not invented |
| `start_insert` abort cleanup / discarded outdated CNAME at commit | No removal bookkeeping needed for uncommitted entries | Failed/pending cleanup cannot grow stale index state |
| Full pressure scan | Reset/recompute from committed survivors in the original loop | Removal order and free-tail effects remain unchanged |
| CNAME target reassignment / ordinary lookup promotion | No deadline change | UID/generation preservation and LRU order remain unchanged |

`Forever` makes the predicate false, so no committed record can expire in
this primitive; pressure can still evict the live LRU RRset. `Seconds(0)`
retains constructor normalization to Disabled. Backward wall-clock movement
needs no invalidation: monotonicity is with respect to expiry at the supplied
`now`, not a claim that time only moves forward. An earlier subsequently
committed deadline lowers the bound. No operation may mutate an entry's
expiry or stale policy through a new API without revisiting this invariant.

The proof obligation is narrow: if the minimum possible expiry cannot be
expired, no committed slot passes the original predicate, so the skipped loop
has no side effect. If the bound is stale or expiry is possible, the original
loop executes. This preserves the old Rust trace; it does **not** by itself
establish equivalence to C.

## Cost and space model; full indexes are deferred

| Mechanism | No-expiry pressure check | Insert/delete upkeep | Expiry removal order | Added retained state |
| --- | --- | --- | --- | --- |
| Original C / current Rust | O(N + buckets) / O(capacity) | Existing name/LRU costs | C hash traversal / Rust slot traversal | Baseline |
| EPS1 bound | O(1) when bound proves no expiry | One min per committed entry; no delete index update | Existing Rust scan unchanged when needed | One i64 payload, actual Cache layout delta must be measured |
| Ordered set of `(expiry, slot)` | O(1) minimum | O(log N), node allocation/free | Deadline order differs; restoring scan order adds work | O(N) keys/nodes plus allocator overhead |
| Indexed binary heap | O(1) minimum | O(log N), inverse-position updates | Deadline order differs; restoring scan order adds work | O(N) heap plus inverse positions |

EPS1 worst-case pressure work remains O(capacity), with an extra bound check
and minimum update. An expiry-heavy or adversarial workload can make it
slower. It eliminates repeated scans during a known-unexpired interval; it
does not promise an O(log N) expiry algorithm. No monotonic-time assumption,
lazy heap tombstones or unbounded stale-entry history is introduced.

For an explicit 64-bit heap design using a `(i64, usize)` array plus a
`usize` inverse-position array, payload alone is 24*N bytes: 24,000 bytes at
capacity 1000, excluding Vec headers/alignment. A BTreeSet has 16*N key bytes
before tree links, unused node capacity and allocation overhead; its actual
allocation cost must be measured, not guessed from `size_of::<BTreeSet>()`.
Neither candidate is queued for implementation or budget increases now.

EPS1's planned payload is 8 bytes per Cache. Measure actual `size_of::<Cache>`
before/after on the same compiler/target, total owned allocation bytes and
allocation count. **No extra heap allocation, per-slot bytes, record capacity,
resource limit or cache memory reservation is allowed.** The local screen
permits at most 16 bytes of additional fixed Cache layout after alignment,
explicitly reported in bytes; that is a screening tradeoff, not a waiver of
the shared protocol's total-memory gate. A larger delta requires redesign.
Repetitions must retain no growing metadata; dropping the cache must restore
the allocation balance. RSS cannot establish these allocation properties.

## Correctness gate before timing

1. Build the existing exact-source C primitive oracle with its source hashes
   and ASan/UBSan checks. Snapshot baseline Rust source before building its
   driver. Calibrate known insert/hit/expiry/failed-transaction outputs and
   make one changed expected result fail the comparator. This oracle is a
   cache primitive, not the complete C daemon or target dependency build.
2. Add fixed pressure sequences at capacities 8, 64 and 1000: no-expiry
   eviction, simultaneous expiry, mixed expiry/live RRsets, a repeatedly
   deleted earliest record, shorter-deadline replacement, CNAME target reuse,
   zero TTL, failed/aborted pending batches, finite/forever stale caching,
   backward time, and the exact expiry/stale boundary. Compare all output rows,
   hit/miss, record values, TTL, expiry, negative/stale bits and order.
3. Run each C sequence in three fresh processes before comparing Rust.
   `hash_bucket` mixes bytes from `typestr`, including relocation-dependent
   data; internal bucket/free-slot order is not a portable physical-slot
   contract. Do not normalize observable differences because of that fact.
   If C/C outputs differ, retain the differing traces and stop that case for
   contract analysis; normalization requires separate independent calibration.
4. Candidate must exactly match baseline Rust's externally visible trace
   **and** exact C on these supported cases. The old Rust trace protects the
   optimization against new regressions; it never supplies the C expectation.
   The old primitive corpus deliberately avoids random full-cache pressure,
   so its existing success does not substitute for this new pressure gate.
5. Before product integration, exercise the exact full-object C
   `extract_addresses`/`answer_request` pressure sequences, then affected
   UDP/TCP cache/reload/publication tests on the rebased source. Include
   SOA-backed/no-SOA negatives, TTL clamps, bounded packet/truncation behavior,
   round-robin, CNAME and DNS publication invalidation. The standalone oracle
   cannot validate TCP cache IPC, reverse/local records or service lifetime.

Any baseline C/Rust mismatch is a functional blocker for that case, not
evidence that EPS1 is acceptable. Preserve the failure and fix correctness
before collecting candidate performance for the affected path.

## Small host screen frozen before results

Only after the applicable correctness gate: same local compiler, optimization
flags, source dependencies and capacity 1000; serial execution, no competing
build/fuzz workload. Keep diagnostic counters and allocation tracking out of
timed binaries. Prepare names/inputs outside timing; time the cache operations,
including their real name/RDATA ownership costs, not a replacement toy loop.

Four fixed vectors, seed `0x293001`, 100,000 completed operations each:
hot lookups (800 records, 70/30 A/AAAA), full unexpired churn (TTL120, synthetic
time fixed), 70% hot/20% unique/10% negative mixed operations (positive120 /
negative30), and expiry bursts (one logical second per 1000 operations,
TTL pattern 1/2/30/120 equally represented). Preserve actual cache-hit and
eviction results; do not adjust workload composition after observing timings.
One separate untimed vector stresses delete/abort/clear/recommit bookkeeping.

Use three predeclared B0/EPS1 pairs, orders B0/EPS1, EPS1/B0, B0/EPS1; all
rounds retained. Warm each fresh cache using the fixed vector once before
timing. Collect process CPU/completed operation and wall time, correctness
digest/count, and a separate allocation-instrumented run over the same vector.
Digest expectations come from the C gate, not candidate output. This is a
primitive throughput/cost screen; no network RTT percentile or service CPU
claim is produced. Do not mix these times with the earlier C host windows.

Retain EPS1 for a later service comparison only if all functional gates pass,
full-unexpired and mixed CPU/operation each improve by at least **15% at the
median of paired ratios**, every hot/expiry-burst pair regresses by at most
**5%**, completed counts are unchanged, and the explicit storage limits above
hold. Improvement must exceed observed round spread; otherwise label it
unproven, with no automatic extra rounds. A failing or unhelpful candidate is
withdrawn from adoption; retain data and revisit the source-cost evidence.
Passing this small screen still does not establish the shared 15%/10%
CPU/private-memory goals, target-build acceptance or router performance.
