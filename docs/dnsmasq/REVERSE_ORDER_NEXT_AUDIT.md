# Next reverse-order qualification: source audit and proposed gate

The next step is a **separate seven-profile C study**, before another Rust
representation change. The retained exact ordering comparison remains failed.
This audit reads the matching source and saved traces; it runs no C/Rust oracle,
performance workload or router operation and leaves candidate `0eaaef8` intact.
The executable gate owner must freeze its driver, selector and row counts
before execution; this document is a proposal, not a measured gate result.

## What the retained evidence actually proves

The six saved C traces from
[the earlier source review](REVERSE_ORDER_SOURCE_REVIEW.md) were independently
hash-checked against `REVERSE_TRANSFER_C_BASELINE.json`. All six selected three
distinct target-name buckets. Child/parent lookup orders agree within each
invocation: input positions `2,1,3` for native, `1,2,3` for SDK-musl. Before
lookup, child LRU is `1,2,3` and parent LRU is `3,2,1` in all six.
The [derived trace table](REVERSE_ORDER_NEXT_AUDIT.json) retains those ordered
roles and their source hashes. No output is sorted to manufacture a pass.

These observations establish the distinct-bucket case. They do not establish
collision behavior, repeated-lookup behavior or a universal rule that child
and parent answers must have the same order. The old 12-row gate still has
four native and two SDK differences and its complete comparator still exits 1.

## Order is part of several different interfaces

| Boundary | Matching source | Required relation |
| --- | --- | --- |
| Name placement | `cache.c:295`, `hash_bucket` | Case-insensitive target name; bucket depends on the process's `typestr` bytes |
| Bucket insertion | `cache.c:312`, `cache_hash` | Reverse prefix; insertion preserves only the consecutive same-name/same-flags group at the current insertion point |
| Address lookup | `cache.c:1261`, `cache_find_by_addr` | Ascending buckets and chain order; promote each dynamic match, then return the resulting LRU prefix |
| Repeated lookup | Same function | Without insertion/removal/rehash, hash chains stay unchanged, so the returned order stays unchanged |
| Transfer | `cache.c:844,954` | Child sends reverse pending order; parent builds its own reversed pending chain; absolute expiry and real insertion effects remain separate from lookup order |
| Pressure | `cache.c:753-780`, `cache_scan_free` | Spill the actual tail's address RRset; `live_freed` increments only if that selected tail has `ttd > now` |
| Local prefix | `cache.c:1286`, `rfc1035.c:1939` | Local address entries precede dynamic entries; that first entry also determines RD/DO admission of the following chain |

Let `I` denote three entries' input order and `rev(I)` its reversal. With no
pre-existing reverse entry in their buckets, the following are **source-derived
predictions for calibration**, not new observed passes:

| Input topology | Child first address result | Parent first address result |
| --- | --- | --- |
| Three names in distinct buckets | Descending actual bucket order | Same descending actual bucket order |
| Three distinct names in one bucket | `rev(I)` | `I` |
| Three entries with one identical name | `I` | `rev(I)` |
| Same-bucket names `A, B, A`, with distinct deadlines | `rev(I)` | `I` |

The final row matters. `cache_hash` does not seek out every occurrence of a
name in a bucket. Inserting `A`, then `B`, then another `A` can leave two
separate `A` groups around `B`. The current per-name vectors do not represent
that cross-name chain. Globally grouping equal names would lose this relation.

LRU is a separate mutable view. Using its current order as the next scan order
would risk flipping the answer on every lookup; using physical slot order is
stable but already fails the retained child/parent relation. An order chosen
only when formatting the response would leave pressure selection inconsistent
with the answer-producing lookup.

Mixed expiry exposes more than presentation order. With stale retention, one
member of an address RRset can be stale while another is fresh. C removes the
whole RRset when either is selected, but counts a live eviction according to
the actual selected member. Both membership and the tail-to-counter relation
must survive. Counting one eviction merely because some member is fresh would
change the source contract.

## DNS validity is a narrower question than implementation equivalence

DNS permits multiple PTR values, and PTR RDATA carries a domain name without a
preference field. A permutation of a complete positive PTR answer can therefore
be protocol-valid; this is a protocol-level inference, not permission to
discard the measured C order/state relationship. [RFC 2181 section 10.2](https://www.rfc-editor.org/rfc/rfc2181.html#section-10.2),
[RFC 1035 section 3.3.12](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.12).

Equal-target duplicates and different TTLs in one RRset are deliberately
adversarial primitive inputs here: the standard calls for duplicate suppression
and uniform RRset TTLs. Their purpose is to distinguish stored entries and
expose C's actual lifecycle behavior. They must not be silently deduplicated or
TTL-normalized during this compatibility study. [RFC 2181 sections 5–5.2](https://www.rfc-editor.org/rfc/rfc2181.html#section-5).

Protocol validity does not authorize changing returned membership, original
target bytes, expiry, flags, local-source precedence, transfer order, repeated
lookup stability, the selected LRU victim or actual counters. In particular,
the old exact comparator cannot become a set comparator because a different
serialization could also form a valid DNS packet.

## Proposed bounded C-first matrix

Use the real insertion, lookup, fork/pipe and import entrypoints. The proposed
budget is **7 profiles × 2 runtimes × 3 invocations = 42 top-level oracle
invocations**, with their child processes counted separately. No added rounds
or run-until-coverage loop. The original 21-case transfer gate remains unchanged.

Select names before any cache insert, using read-only `hash_bucket` calls on a
fixed pool of 257 short names. Freeze pool spelling/order and a lexicographic
selection rule over pool indices. Choose the first tuple satisfying each
profile's bucket relation; do not select by eventual answer order. At these
small capacities the C table starts at 64 buckets. Record the actual size and
every selected name's bucket; missing required coverage is a fixture failure,
not a reason to rerun the process or modify its hash.

| Profile | PTR entries in input order | Capacity | Purpose |
| --- | --- | ---: | --- |
| D | Three distinct names, three buckets, TTL 120 each | 5 | Name-based placement independent of physical child/parent slots |
| C | Three distinct names, one bucket, TTL 120 each | 5 | Opposite commit direction within one collision chain |
| M | Two distinct names sharing a bucket, a third in another bucket; TTL 120 | 5 | Bucket order combined with within-bucket order |
| E | One identical canonical name, TTL 30/60/90 | 5 | Same-name contiguous-group preservation; deadlines distinguish entries |
| I | Same-bucket `A/B/A`, TTL 30/60/90 | 5 | Non-contiguous identical-name groups must remain distinct |
| S1 | One identical name, TTL 10/60, forever-stale policy | 4 | Actual tail stale at pressure time |
| S2 | One identical name, TTL 60/10, forever-stale policy | 4 | Actual tail fresh at pressure time |

Common schedule:

1. Parent seeds a forward sentinel `S` at time 100. Fork a child.
2. Child inserts the profile's PTR records as one transaction at time 100;
   commit through the real pipe. Capture LRU, address lookup, LRU, repeat the
   same lookup, and LRU again. Record bucket chains without changing them.
3. Parent inserts another forward sentinel `P` at 101 before import, ensuring
   child and parent need not use the same physical slots. Import at 103.
4. Capture parent LRU and two address lookups with their resulting LRUs. Use
   time 103 for D/C/M/E/I and time 120 for S1/S2.
5. Hit `P`, then `S`, making the PTR address group oldest. Capture the actual
   LRU tail with its deadline. Insert a new forward record, commit, then inspect
   LRU and probe the old address and all forward sentinels.

Keep forward sentinels fresh through time 120. For S1/S2, import occurs before
the short record expires; pressure occurs after expiry while stale retention
keeps it present. This avoids conflating ordering with past-deadline import
saturation. For every profile, retain direction, target bytes, address, deadline,
complete `hash_next` chains, LRU and both counters at every boundary. Hash bucket
numbers alone cannot reveal the two `A` groups in profile I.

Calibration must check actual query order against the resulting dynamic LRU
prefix, repeated-lookup stability without chain changes, pre-lookup transfer
reversals, full address-RRset removal and the tail deadline's exact counter
effect. Detect a changed ordered row/counter and reject a missing row. Keep
every complete trace even if a prediction above fails. Raw native/SDK outputs
remain separate; topology classification explains differences rather than
erasing them. Local-prefix behavior stays covered by its existing separate
evidence and must not be inferred from these dynamic-only profiles.

## A representation direction worth testing after the C study

The simplest structural direction is **one ordered bucket directory in place
of the existing per-name directory**, still referring to the current slots.
A bucket's vector would preserve the reverse/ordinary grouping and the exact
insertion point rule; forward lookup filters name and direction inside that
bucket. Reverse lookup walks buckets in order and performs the actual LRU
promotions. Lookup would never reorder the directory merely to format an answer.
The existing transaction, generation, shared capacity and counters remain.

This replaces one index field rather than adding a global insertion serial,
an address cache or another per-record ordering field. It can represent the
`A/B/A` chain that the current per-name vectors cannot. It is a feasibility
direction, not a selected production implementation or a resource win.

Three decisions remain before implementation:

- **Hash placement is still unresolved.** Do not copy `typestr` pointer bytes,
  choose a canonical target sort, or use HashMap iteration order as an accepted
  substitute. A portable hash may change collision classes and forward expiry
  side effects as well as PTR order. Structural similarity alone cannot make
  its same-input trace equal to the exact C trace.
- **The future comparator's scope must be explicit.** The new C study can
  establish ordered relations within declared topologies. If a later
  topology-controlled Rust probe is considered, its input selection/role map
  must be frozen independently and its limited structural claim kept separate
  from literal same-input service equivalence. It cannot retroactively pass
  the old 12 observations or accept any convenient permutation.
- **Forward cost and lifecycle need requalification.** C also calls `rehash`
  while loading local names (`cache.c:1479,1541`); dynamic capacity alone is
  not the general table-sizing contract. Replacing the directory would require
  the ordinary forward corpus, publication/reload, exact row ordering and
  allocation checks again. The existing ordinary-five-case equality does not
  measure the added reverse name-index heap or this proposed directory.

Until those boundaries are resolved, retain the current private candidate and
its explicit multi-PTR limitation. No persistent-field addition or replacement
index is justified merely to remove the appearance of the old mismatch.

## Provenance

Matching `cache.c` SHA-256:
`51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`.
Retained C/before archive:
`c799b6ddbbbc5582c6da244d1e029e28ca7499b57f8a0b371ed7cb73c7a463a2`.
The six stdout hashes match the existing baseline manifest; their diagnostic
hashes and ordered role projections are in the adjacent derived JSON. The
new matrix remains source-predicted until its independently frozen C gate runs.
