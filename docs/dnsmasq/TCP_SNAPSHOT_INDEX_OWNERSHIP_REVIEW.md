# Snapshot index ownership: source and allocation audit

The next bounded mechanism is a private `One(usize) / Many(Vec<usize>)`
name-index value combined with the original V1 shared-entry representation.
RDATA remains `Vec<u8>`. This targets a different allocation path from the
rejected inline16 candidate and is not a parameter adjustment based on its
failed timing window. This audit runs no new candidate, allocation or timing
experiment and makes no performance acceptance claim.

## The two name owners are separate

Exact `e77d966` has `Record.name: wire::Name`, whose wire buffer is a `Vec<u8>`,
and `Cache.names: HashMap<Vec<u8>, Vec<usize>>`. The latter key is another
owned buffer made by `Name::canonical_wire`; it is not a borrowed view of the
record name. Canonicalization lowercases ASCII while preserving wire labels,
including binary labels. The value is the ordered list of committed slot
indices for that name. CNAME links separately use slot/generation `EntryId`s.

The V1 shared-entry candidate shares each `Entry`, including its record name
and RDATA, through an Arc. It still clones the entire owned `names` map for
each image: the table, each canonical key buffer and each slot-index vector.
With one record per name, a snapshot allocates its slots and map table once
each, plus two allocations per name. Twenty snapshots therefore allocate
40,040 / 400,040 times at 1,000 / 10,000 occupied entries. Inline16 retains
those same snapshot allocation counts because it changes entry payloads.

The table clone dominates index bytes, while keys and small index vectors
dominate allocation calls. Source-derived accounting exactly balances the
existing V1 measured totals at all three full profiles:

| Parent component | 150 full | 1,000 full | 10,000 full |
| --- | ---: | ---: | ---: |
| Shared slot vector, 32 bytes/slot | 4,800 | 32,000 | 320,000 |
| Entry Arc allocations, 136 bytes/entry | 20,400 | 136,000 | 1,360,000 |
| Entry wire-name payloads | 4,455 | 29,700 | 297,000 |
| Entry RDATA payloads | 1,044 | 7,000 | 70,000 |
| Name HashMap table allocation | 12,552 | 100,360 | 802,824 |
| Canonical HashMap key payloads | 4,455 | 29,700 | 297,000 |
| Singleton index Vec payloads | 4,800 | 32,000 | 320,000 |
| Pending insertion vector | 32 | 32 | 32 |
| Total, matching V1 shared | 52,538 | 366,792 | 3,466,856 |

These are a decomposition of retained allocator-requested totals, not a new
field-tagged allocation measurement. Initial one-element `Vec<usize>` values
retain 32-byte capacity in this frozen workload/compiler; their clones copy
only the one live index and allocate eight bytes. For one shared snapshot,
32 × capacity plus table bytes plus canonical-key bytes plus 8 × occupied
entries exactly reproduces the recorded live bytes. Twenty images total
460,140 / 3,401,200 / 29,996,480 bytes. First-lookup temporary allocations
return to zero live-byte delta; their peaks and calls remain separately visible.

## Why not a new name chain or shared whole table

A per-slot `next_name` and name-to-head map can preserve public APIs and
CNAME IDs, but it is not a local storage substitution. Directly preserving
the current ordered tail insertion needs either a tail pointer or a linear
walk; repeated head-only tail insertion would be quadratic for a large RRset.
An inverse physical chain can instead prepend and reverse at the logical
boundary, but then all readers/rebuilders must maintain that extra ordering
invariant.

Either chain scheme changes commit, conflict removal, expiry removal,
round-robin rewriting, DHCP publication ordering, reset and slot reuse. It
must prove acyclicity, complete membership and uncommitted-slot exclusion
alongside the existing LRU and generation invariants. Round-robin currently
uses stable Vec retain/splice; DHCP publication rebuilds the value from an
ordered mixed local/dynamic list. Rewriting those algorithms merely to try a
representation is not justified here. This direction is not selected.

Sharing the entire map through `Arc<HashMap<...>>` can avoid copying on a
fresh singleton lookup, but lookup is not generally read-only: expiry,
outdated CNAME removal and multi-answer rotation mutate the name index.
Those first mutations would copy the whole table. That failure boundary
cannot be hidden by measuring only fresh singleton records. Sharing each
canonical key internally is possible without changing the public wire Name
API, but adds Arc metadata and does not by itself remove V1 shared-entry's
extra population allocation. Neither direction is selected for this screen.

## Selected local mechanism and predictions

Keep the canonical key and table owned by each cache image. Change only the
private map value to an enum with `One(usize)` and `Many(Vec<usize>)`. An empty
value is `Many(Vec::new())`, which allocates nothing. The first push stores
one index inline; the second promotes through ordinary Vec pushes. Many-value
retains and ordered insertion continue to use the existing Vec algorithms.
Do not compact a nonempty Many value during retain. An emptied value can
become One on a subsequent push. Preserve the current owned temporary Vec
copies at mutation-sensitive scans and lookups, so no new iterator borrows
interfere with record removal.

This requires no new record, wire-name or public cache API. It changes the
private index field plus its small push/retain/ordered-insert/from-iterator
adapter and three existing clone-for-iteration sites. Slot layout, EntryId,
CNAME targets, capacity, TTL and counters remain unchanged. No whole-table
copy is triggered by a first lookup: the table was already independently
cloned when the snapshot was made.

If the enum remains 24 bytes on the pinned aarch64 compiler, it replaces the
24-byte Vec descriptor without enlarging map buckets. Cache/Slot/Entry/Record
sizes remain 168 / 32 / 120 / 56. These layouts are predictions requiring a
separate pre-cost gate; no enum representation tricks or unsafe code will
be used to force them.

| Capacity / occupied | Deep parent bytes | Predicted new parent bytes | Predicted 20 snapshots after lookup | Predicted clone allocations |
| --- | ---: | ---: | ---: | ---: |
| 150 / 0 | 24,000 | 4,800 | 96,000 | 20 |
| 150 / 150 | 51,338 | 47,738 | 436,140 | 3,040 |
| 1,000 / 1,000 | 358,792 | 334,792 | 3,241,200 | 20,040 |
| 10,000 / 10,000 | 3,386,856 | 3,146,856 | 28,396,480 | 200,040 |

The predicted address-profile population allocations return to deep's
909 / 6,012 / 60,015 because eliminating one index allocation per name
offsets the entry Arc allocation. Full parent heap falls approximately
7.01% / 6.69% / 7.09% relative to deep; primary snapshot heap reductions
would be 51.59% / 54.88%. These are requested-heap predictions, not RSS/PSS
or CPU measurements. Names with multiple records retain Vec storage and
sharing entries still allocates per record, so mixed-RR costs need separate
qualification.

Stop before costs if the actual enum grows beyond the predicted 24 bytes,
source edits spread beyond the private index adapter, or exact-C/retained
state checks fail. Do not weaken ordering, generation, counter or allocation
guards to proceed. Any later private screen must freeze its own plan and
retain the original four profiles and performance thresholds; timing still
requires a root-coordinated quiet window. Product adoption and full service
resource acceptance remain separate decisions.
