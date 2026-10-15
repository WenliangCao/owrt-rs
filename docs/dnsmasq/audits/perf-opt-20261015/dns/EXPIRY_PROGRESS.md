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

## Resumed current-source counter screen

After C completed its first four full device scenes, root authorized this
screen while the remaining C sequence continues independently. Fresh profiling
of candidate C still attributes 11.09% of UDP-miss and 18.12% of TCP-miss
instruction samples to insertion; no historical gain was reused.

Oracle baseline is frozen C `f7f7a2ed`; D product source is `9f2a9052`. All 172
tracked component files were verified before host-local copying, and exactly
the two D cache/test files were patched and reverified. Frozen C was checked
unchanged afterwards. Only 33,792 bytes of patch, identity and probe source were
uploaded; the 34,019-byte derived result was retrieved. Raw artifacts remain
on Oracle. No router access or bulk source/artifact transfer occurred.

The existing insertion probe now also covers advancing-clock mixed TTLs and
finite stale retention, and reports actual type sizes. Native Linux cache
tests pass 41/41. Three-pass instruction medians versus C:

| Primitive | Change |
| --- | ---: |
| Full unexpired pressure | −84.540% |
| Advancing-clock expiry | −77.647% |
| Advancing-clock finite stale | −85.271% |
| Replacement | +0.103% |
| Reverse insertion | +0.002% |
| Binary long names | −0.090% |

All 32 allocation-scene outputs have identical allocation/reallocation counts,
requested bytes, live-byte deltas and checksums. Actual native Cache layout is
216 → 224 bytes (+8 fixed bytes); Entry remains 72 bytes. This fixed per-Cache
cost can affect enclosing service allocations and still requires final total
memory assessment. Whole-answer instruction controls are effectively flat for
hit/miss/eight-record/dynamic-CNAME, +0.009% configured CNAME and +0.519% hosts.
These are counter results only, not accepted CPU timing or device gains.
`expiry1-screen.json` retains every sample and raw/artifact identity. A root
quiet reservation is requested for plain timing; final exact-C/SDK gates are
still outstanding.

## Quiet plain screen

Reservation `expiry1-plain-20261015` completed all 120 declared windows with
fixed artifact hashes, and no replacement/repeat runs. Whole-process native
CPU improves for pressure (−80.300%, W 1.555%), expiry (−71.820%, W 0.717%) and
finite stale (−79.937%, W 0.784%), each in five of five pairs. Replacement,
reverse, long names, ordinary hit and eight-record answers are within their
measured variation. Marginal miss/host changes are not the proposed mechanism.

Two supplemental CNAME controls regress in all five pairs: dynamic CNAME
**+0.754%, W 0.612%**, and configured CNAME **+2.836%, W 0.266%**. These are
explicit screening caveats; no universal or device no-regression claim is made.
Their instruction counts were effectively unchanged and the read loops were
not edited, which suggests code-layout sensitivity but does not establish its
cause. Root will decide whether further attribution or full-candidate screening
is appropriate. No new timing is started autonomously.

`expiry1-timing.json` contains all 120 CPU samples, decisions and fixed artifact
identities. Only the 7,131-byte derived summary was retrieved; complete timing
rows/raw logs remain on Oracle with recorded hashes. The PMU and plain CPU probes
include fixture creation and priming, so these percentages are not steady-state
service or device predictions. Exact-source C differential, SDK, service and
final memory gates remain outstanding.
