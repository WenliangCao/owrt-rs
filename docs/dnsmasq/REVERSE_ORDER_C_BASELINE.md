# Multi-PTR C hash-chain, transfer and pressure baseline

The independently frozen seven-profile study completes **42/42 oracle
invocations and 3,666/3,666 ordered source-relation checks**, with zero failures.
Each profile runs three native and three matching-source SDK-musl invocations;
each invocation also forks one child. These counts are not total OS process
counts or stock-image daemon passes. No extra oracle round was added.

The unchanged exact `cache.c` supplies insertion, commit, child pipe transfer,
parent import, address lookup and eviction. Before insertion, each invocation
enumerates the same bounded 257-name pool through the real C hash and applies
the [frozen selection algorithm](REVERSE_ORDER_GATE_PLAN.md). All pool mappings,
mixing bytes, complete hash chains, LRU states, actual tails and counters are
retained. The schedule observes 21 distinct native mixing fingerprints and one
SDK fingerprint; it does not require cross-process permutations to agree.

The table uses input-record positions as roles. Different deadlines keep two
records of the same canonical target distinct. It preserves observed order;
it is not a sorted response comparison.

| Profile | Observed child address order | Observed parent address order | Pressure `live_freed` delta |
| --- | --- | --- | ---: |
| D: three distinct buckets | `2,1,3`, `2,3,1`, or `3,2,1` | Exactly the child's order within each invocation | 1 |
| C: three distinct names, one bucket | `3,2,1` | `1,2,3` | 1 |
| M: two colliding names, third elsewhere | `3,2,1` | `3,1,2` | 1 |
| E: same target, three deadlines | `1,2,3` | `3,2,1` | 1 |
| I: same-bucket A/B/A | `3,2,1` | `1,2,3` | 1 |
| S1: same target, TTL 10/60, forever stale | `1,2` | `2,1` | 0 |
| S2: same target, TTL 60/10, forever stale | `1,2` | `2,1` | 1 |

These are the concrete permutations of this frozen schedule, not all possible
orders for each topology. The D relation requires distinct buckets; a global
claim that child and parent PTR answers always preserve order is false.
Likewise, the other rows do not justify universally reversing every PTR set.

Every returned address sequence equals the reverse of that invocation's actual
matching hash walk and exactly matches the resulting dynamic LRU prefix. A
second lookup retains the sequence and leaves the hash chain unchanged. Before
the first lookup, child and parent LRUs retain the existing export/commit double
reversal. The independent checker applies the insertion-point rule to observed
C buckets, preserving every record's identity and deadline.

Profile I establishes the previously unresolved non-contiguous-name boundary.
The child's reverse bucket chain is roles `1,2,3` (A/B/A), and the parent's is
`3,2,1` (A/B/A with A's deadlines reversed). `cache_hash` skips only the leading
consecutive equal-name run at its insertion point. It does **not** globally
gather all records for target A together. A per-target grouping or target-name
sort would erase B's position and cannot represent this observed chain.

Pressure runs only after the full parent cache contains S, P and the entire
PTR set. Hitting P then S leaves the PTR group oldest. A new forward insertion
removes the whole address RRset while retaining S/P/New. The metric uses the
actual selected tail: `difftime(now, tail->ttd) < 0`. At pressure time 120, S1's
tail expires at 110 and increments zero even though another member expires at
160; S2's tail expires at 160 and increments once. The source's strict equality
boundary is not separately measured by these two cases. Repeated target names
with different TTLs are primitive/adversarial fixtures, not a normal upstream
RRset qualification.

The frozen comparator rejects a changed ordered answer, changed eviction counter
and missing observation boundary. An additional offline audit strengthened
completeness after the run: the original parser's missing-row negative removed
a TAIL row, but a missing final HASH row needed a separate check. The audit
verifies hash-chain membership against LRU membership at **462/462 snapshots**
and rejects a removed HASH row in **42/42 saved-trace negatives**. It also
rechecks all original 3,666 ordered relations. This adds no C execution, changes
no original trace or comparator, and uses membership only as an additional
completeness invariant; ordered comparisons remain exact.

Freeze commit `9e8caf9` and offline-auditor commit `20b92df` remain distinct.
The [derived JSON](REVERSE_ORDER_C_BASELINE.json) records every run's stdout,
stderr, relation and pool/mixing fingerprints, original artifacts, ordered role
projections and completeness evidence. Raw data and executables are ignored
under the detached gate worktree's `private/reverse-order-evidence/`, mirrored
from `/home/ubuntu/dnsmasq-reverse-order-20261001/work01/`. The downloaded archive
is verified against its complete file-hash manifest.

The SDK executable is newly linked exact source with verified image loader and
libraries, not the image's existing dnsmasq ELF. All oracle executions use Linux
isolation. This study covers small 64-bucket dynamic IPv4 primitives; it does
not qualify arbitrary collisions, local prefixes, rehash lifecycle, full DNS
service, Rust representation, OOM, allocation or performance. No router was
accessed. Candidate `0eaaef8`, the original 21-case fixture and its 12 unresolved
ordering observations remain unchanged; that original full comparator still
exits 1.
