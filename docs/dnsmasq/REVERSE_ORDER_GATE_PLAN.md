# Frozen C-only multi-PTR order, transfer and pressure study

This executable freeze is independent of the original 21-case/12-order-row
transfer comparator. It changes neither that comparator nor candidate `0eaaef8`.
Exactly **7 profiles × native/SDK × 3 invocations = 42 top-level oracle runs**
are scheduled; each forks one real child. No extra rounds or run-until loop.

After `cache_init` and before any insertion, enumerate **mp000.test through
mp256.test**, once, using unchanged C `hash_bucket`. Record every mapping,
actual `hash_size` (required 64), and all 64 mixing bytes in private evidence.
Choose D's first three pool names having distinct buckets. For C, choose the
lowest numbered bucket containing at least three pool names, then its first
three pool names. M uses that bucket's first two names and the first pool name
in another bucket; I uses its first two names as A/B/A. E/S use pool entry zero.
Insufficient coverage is a fixture failure. No selection depends on returned
answers, LRU results, counters or a later run.

| Profile | PTR insertion order and TTL | Capacity |
| --- | --- | ---: |
| D | Three distinct names in distinct buckets; 120 each | 5 |
| C | Three distinct names in one bucket; 120 each | 5 |
| M | Two names in one bucket, third in another; 120 each | 5 |
| E | Same canonical name; 30, 60, 90 | 5 |
| I | Same-bucket A/B/A; 30, 60, 90 | 5 |
| S1 | Same name; 10, 60; forever stale | 4 |
| S2 | Same name; 60, 10; forever stale | 4 |

Different TTLs and repeated target names are deliberate primitive observations,
not a claim about a normal well-formed upstream RRset. This executable plan
uses time 120 for **all** address lookups and pressure, a concrete refinement
of the source-only proposal; all E/I entries remain fresh then.

Parent seeds forward S at 100 and forks. Child commits the profile's PTRs at
100 through the actual cache pipe, observes LRU/hash chains, queries the address
twice, and records the resulting LRU/hash chains each time. Parent inserts
forward P at 101, then invokes unchanged `cache_recv_insert` at 103. It observes
its pre-lookup state, two queries and their states, hits P then S, captures the
actual full-cache tail, inserts and commits forward New at 120, and probes the
removed address and all three surviving forward records. Ordinary capacity is
exactly S + three PTRs + P; stale capacity is S + two PTRs + P.

Each snapshot retains original target bytes, family/direction, address, absolute
deadline, complete ordered `hash_next` chains, dynamic LRU, actual tail and both
real counters. Pool/mixing bytes and raw records stay private. Native and SDK
traces are not required to have the same salt or returned permutation.

Required relations are frozen before execution:

- Child and parent pre-lookup LRUs show the existing export/commit reversal.
- `cache_hash` skips only the leading consecutive identical-name run at the
  insertion point. The independent checker uses actual C buckets and this
  rule; profile I must retain the two separated A records around B.
- Each address answer equals the reverse of the actual matching hash walk;
  its order equals the resulting LRU head prefix. The hash chain is unchanged
  by these retained/fresh lookups, so the repeated answer stays exact.
- D's distinct-bucket child/parent answers agree. The single-bucket profiles
  reverse; M reverses its collision subsequence while retaining bucket order.
  These are scoped relations, not an assertion that all transfers preserve or
  reverse every PTR answer.
- After P/S promotion, the selected tail belongs to the address group. Pressure
  removes the entire group and retains S/P/New. `live_freed` increments exactly
  when C's `difftime(now, tail->ttd) < 0`, based on that actual tail, not on any
  fresh member elsewhere in the group. S1 predicts zero and S2 one; a contrary
  C result is retained as failure. Equality is source-defined but not a new
  separately measured profile here.
- All scheduled insertion/commit/import outcomes, clocks and counter totals
  are checked. Changed ordered answers and counters must be rejected; missing
  observation boundaries must fail. Negative calibrations mutate saved traces
  only and start no additional oracle.

Build native and matching-source SDK-musl executables from hash-verified exact
source/headers and the existing pinned non-cache objects. The SDK oracle uses
verified image loader/libraries but is not the stock dnsmasq ELF. Run all 42
inside Linux isolation, retaining failures and complete traces. No Rust/model
representation is adopted, no old mismatch becomes a pass, and no router,
performance, allocation or production acceptance is implied.
