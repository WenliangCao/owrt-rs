# Singleton index plus inline RDATA: source-only cost review

The direct composition has enough allocation-path evidence to justify a
bounded feasibility gate, but not product migration or another timing run
yet. It removes two different allocations for a fresh singleton address
record while adding one entry Arc. This is a new, testable allocation
prediction, not a claim that combining the passing metrics of two rejected
candidates produces a passing candidate. No implementation, build or new
measurement was made for this review.

The mechanisms remain exactly `One / Many(Vec<usize>)` and inline RDATA of
at most 16 bytes, with the existing shared entries and compact LRU links.
The separate [inline16](TCP_SNAPSHOT_INLINE16_RESULT.md) and
[one-index](TCP_SNAPSHOT_ONE_INDEX_RESULT.md) rejections stand. Neither
inline16's p95 failure nor the one-index +50.40% population window establishes
a stable size or cause for that regression. CPU costs are not additive:
Arc operations, branches, copies, allocator state and generated code remain.

This review uses the frozen `e77d966` layouts and allocation evidence, and
audits migration against product source `ac8a3b6`. The product still has
`Record.data: Vec<u8>` and no cache snapshot Clone implementation.

## What the allocation model actually predicts

The measured separate layouts are Slot 32 instead of deep's 160 bytes,
Entry 120, its Arc allocation 136, and both RDATA/index descriptors 24.
Composition must verify these again; they are not a new measured layout.
Let capacity be C, occupied records N, directly constructed nonempty inline
payloads S, and newly built name-index values that stay `One` U. With the
other paths unchanged, the allocation-call delta from deep is **N − S − U**.
For fresh push-built indexes, equal long-payload capacity/length and the
pinned 32-byte singleton Vec allocation, requested parent-heap delta is
**−128C + 136N − 32U − the removed inline payload bytes**. This excludes
temporary construction copies, allocator rounding and RSS/PSS.

At full occupancy, the resulting per-owner deltas are:

| Records at owner | Allocation calls vs deep | Requested parent bytes vs deep |
| --- | ---: | ---: |
| Fresh singleton A / AAAA | −1 | −28 / −40 |
| Fresh singleton nonempty payload d ≤ 16 | −1 | −24 − d |
| Fresh singleton empty negative | 0 | −24 |
| Fresh singleton payload d > 16 | 0 | −24 |
| m ≥ 2 A / AAAA records, Many index | 0 | +4m / −8m |
| m ≥ 2 empty or long records, Many index | +m | +8m |

Mixed-owner sets use the formula; they do not inherit the singleton saving.
`Many` retained down to one element stays `Many`, so even one remaining
record may have no index saving. Many promotion still allocates its Vec,
whose ordinary growth/order remains. Rebuilds, rotations, emptied-buffer
reuse and churn need their own accounting; their allocation history cannot
be inferred from final membership. If a deep long Vec has spare capacity q−d,
an exact heap slice can reduce live bytes by q−d, but constructing/shrinking
that slice may add calls. No such benefit is counted above.

The exact old address profiles yield these **predictions only**:

| Capacity / occupied | Population allocations | Parent bytes | 20 snapshots after lookup | Clone allocations |
| --- | ---: | ---: | ---: | ---: |
| 150 / 0 | 1 | 4,800 | 96,000 | 20 |
| 150 / 150 | 759 | 46,694 | 436,140 | 3,040 |
| 1,000 / 1,000 | 5,012 | 327,792 | 3,241,200 | 20,040 |
| 10,000 / 10,000 | 50,015 | 3,076,856 | 28,396,480 | 200,040 |

Population reallocations would remain 330 / 2,200 / 22,000 for full profiles.
The extra live snapshot bytes/calls equal one-index's: entries already share
their RDATA, so inlining it provides no additional snapshot-clone saving.
Lookup's owned temporary index vectors also remain. An entry mutation with
a retained Arc still detaches: one new Arc allocation, one record-name
allocation, an optional authority-name allocation, and one payload allocation
only when payload length exceeds 16. Local CNAME targets remain shared Arcs.

## Current construction and transfer boundaries

In [cache_engine.rs](../../components/dnsmasq/src/dns/cache_engine.rs), the
A/AAAA path already has a borrowed 4/16-byte packet slice after rebind checks.
Constructing inline storage there is a narrow change; constructing a Vec
first and converting it removes no allocation call. Empty bogus/ordinary
negative entries already allocate no payload and only need an empty value.
Slice-based answer writing is compatible, while address equality sites and
record constructors/tests need explicit conversion or slice comparisons.

Ordinary CNAME construction uses `Name::canonical_wire`, which allocates.
A short target's RDATA saving requires canonicalizing directly into inline
storage without changing `Name` ownership; `from_slice(canonical_wire())`
would hide that allocation. Long targets remain heap-backed. CNAME conflicts
normally leave a singleton owner, giving the table's short/long cases.
Name decoding, record-name cloning and local-target allocations remain.
The current insertion before acting on a malformed target must stay ordered.
Ordinary CNAME/address reads use packet bounds while generic embedded names
enforce RDLEN; a shared constructor must not silently tighten these rules.

Generic extraction in [wire.rs](../../components/dnsmasq/src/dns/wire.rs)
returns a Vec and may allocate decoded names and canonical name buffers.
Inlining that returned Vec saves retained heap, not the extraction allocation.
For long generic data, `from_slice(&vec)` adds another heap allocation and
temporarily retains both buffers. A consuming long-buffer conversion needs
separate accounting for any shrink/reallocation. An allocation-free generic
canonicalization builder would be an additional parser change, outside the
direct composition. Keep that boundary explicit; do not claim generic
construction savings from the primitive prepared-record driver.

A complete SOA has two names plus 20 fixed bytes and never fits inline;
the current negative-authority selector further requires at least 24 bytes.
It builds canonical data then clones it into a separate Generic(6) record.
Those allocations, the negative entry's authority-name clone and independent
SOA slot/TTL remain. A fresh negative plus SOA at distinct singleton owners
therefore predicts zero net allocation-call change and −48 parent bytes
under the table's exact-capacity assumptions, not two payload savings.

In [cache.rs](../../components/dnsmasq/src/dns/cache.rs), typed capture must
keep owned names, reverse pending order and successful-empty transactions.
Inline non-CNAME data can clone without allocation; long data still clones.
CNAME capture sends empty data. Import reconstructs CNAME data from the
preceding **parent insertion result**, and its current `canonical_wire`
allocation has the same short-target caveat. Never transfer an Arc/EntryId
or old local target to avoid this cost. Transaction Vec growth, authority
clones, absolute expiry, actual removal counters and failure prefix effects
remain. Production has no sender yet; private pipe decoders that allocate
a Vec before filling small RDATA would need a separate migration audit.
Shared-entry migration must detach at authority assignment, CNAME target/
referenced updates and commit marking, preserving every retained image.
One/Many must preserve lookup rotation and DHCP publication's collected order.

## Recommendation and stop conditions

The composition is worth a bounded next feasibility decision because the
singleton-address population call count improves beyond either rejected
mechanism. It is not yet worth a broad product/parser migration. Before any
subsequent experiment, freeze its own scope and full mixed-RR accounting,
including direct packet/transfer construction; the old four address profiles
alone cannot qualify empty/long Many records or a service workload.

Stop if composition changes the fixed layouts, expands into name ownership
or parser algorithms, needs Vec-first construction to claim the small-data
saving, or fails exact-C ordering/flags/TTL/counter/retained-state checks.
Stop if deterministic counts differ from the stated construction model or
if required mixed-RR costs cannot fit a separately declared resource budget.
Any eventual cost phase must retain all original thresholds and every window;
one failing guard rejects the complete candidate, with no retry, parameter
adjustment or combination of separate runs' best results. No new timing
window or product change follows from this review.
