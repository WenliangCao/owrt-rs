# D: conservative expiry bound research

Base is frozen candidate C `f7f7a2edd9f2ecfac72953e43cfc873a354b468b`.
Worktree `/Users/USER/Developer/owrt-perf-expiry-20261015`, branch
`perf/dnsmasq-expiry-20261015`. C remains immutable. During its Oracle timing,
this work is local only; no Oracle builds, counters or timing until root releases
the reservation. No router access.

## Current interface and remaining cost

`Cache::insert_at_counted` retains C's occupied-LRU-tail pressure trigger: scan
all slots for committed expired records in increasing slot order, then spill
the original conflicting RRset if necessary. Reverse insertion has a separate
scan that also removes a matching IP RRset; it must not be skipped. Metrics,
referenced CNAME target reuse, partial transaction failure and free/LRU order
remain externally significant.

The exact SDK A profile attributes 10.01% of UDP-miss instruction samples and
18.29% of TCP-miss samples to insertion. The new insertion-copy screen leaves
the full-pressure primitive at 1.919 billion instructions per 50,000 operations,
versus 0.239 billion for replacement. These are different workloads, so their
difference is not an exact attribution of the scan. It identifies a concrete
remaining cost rather than establishing a service benefit.

Historical EPS1 was retained but never adopted. Its result and counted-API
rebase are in `CACHE_EXPIRY_SCREEN_RESULT.md` and
`CACHE_EXPIRY_COUNTED_REBASE.md`; those old sources, gains, memory sizes and
reference-layout failures are not evidence of current-source acceptance.
The current implementation will be derived from present mutation paths,
without importing the historical patch or broad abstractions.

## Reviewed invariant and boundaries

One cache-local signed lower bound satisfies `bound <= expiry` for every
committed entry. Constructor/clear reset it to `i64::MAX`; each valid commit
lowers it with the actual committed deadline. Ordinary removal may leave an
obsolete early bound. Only when `Policy::expired(bound, now)` is false may the
existing occupied-tail global expiry loop be skipped. Otherwise the original
slot-order loop runs and recomputes the minimum from committed survivors.

`commit_inner` is the sole committed-state transition, shared by ordinary
commit, capture and imported transactions. Import's already-selected absolute
deadline is authoritative. Pending/aborted/discarded CNAME entries stay outside
the bound. No current setter changes entry deadlines or retention policy;
`set_max_reply_ttl` affects reply output only. Snapshot clone copies the scalar
by value; no extra COW or shared mutable metadata is allowed. Name-hint revision
checks remain independent and retain the original index mutation boundaries.

Independent current-source review found no invariant blocker. Required fresh
coverage includes exact expiry, finite/forever stale retention, backward clocks,
wide/wrapped TTLs, deleted minima, earlier replacement, failed batches, selective
DHCP invalidation, clear, snapshot divergence and parent import. The same i128
stale predicate must be used, without adding a stale allowance in i64. Current
layout, allocation counts, full exact-C gates and expiry-heavy/reverse/read-path
controls remain required. No stopping or adoption claim is justified yet.

## Paused at the user's C-first boundary

The local prototype now adds one scalar lower bound, maintained only at
constructor/clear, commit and the unchanged-order necessary pressure scan.
Independent static review found no blocker in the actual diff. Forty-one
native macOS cache tests pass. New coverage compares the candidate with a
forced-scan control through 6,000 rounds (12,000 insert attempts) across zero,
one, eight and 64 slots, three stale policies, failed/aborted batches, reverse
records, backward/extreme clocks and wrapped TTLs; it compares slot links,
record contents, indices and counters. Another test covers deleted minima,
parent/child bound independence, imported deadlines and clear. Existing
ownership checks now verify the conservative bound after mutations.

The first test-only compile attempt failed on integer type inference; its log
is retained and the explicit index type correction passes. This was not a
product failure. All-target compilation of **unchanged frozen C** also passed
locally before the D product source was edited.

No D Oracle build, counters, timing, current-source C differential gate, layout
or allocation measurement has run. The user prioritized completing C's full
Oracle, 44-family and device comparison before further optimization. D is
therefore preserved and paused here. Its active branch/worktree and all local
private logs remain intact; restart only after root releases that boundary,
with fresh profiling rather than transferring historical EPS1 percentages.
