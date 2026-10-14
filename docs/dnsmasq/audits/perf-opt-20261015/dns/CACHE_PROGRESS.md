# Cache research, second candidate batch

Independent source base: `70390467` (the DNS changes selected for candidate A).
Branch `perf/dnsmasq-cache-20261015`; worktree
`/Users/USER/Developer/owrt-perf-cache-20261015`. No DNS-3/4 code is present.

| Hypothesis | Evidence and decision |
| --- | --- |
| Shared initial empty ContentBlocks | Rejected before implementation: first insertion into a newly shared block would require a new infallible COW allocation, moving a startup failure boundary into a query. Existing TCP COW does not justify that new boundary. |
| Single Arc slice instead of Arc<ContentBlock{Box}> | Deferred: preserves startup capacity but changes private layout and four diagnostics. A safe constructor may also copy a full block. The 16 large block mappings remain, so do not claim to remove the startup mmap gap. |
| CACHE-CLEAR-1 | `Cache::clear` repeated `Arc::make_mut` for every slot; checking once per block removes 984 checks at capacity 1000. Allocation counts/requested bytes stay identical for capacity 0/6/150/1000 and retained snapshots. Native instructions −56.53%; isolated timing pending. |

Clear still visits content in slot order, detaches a shared block immediately
before visiting it, retains slot generations, then rebuilds the same free list
and 64 empty name roots. Reordering private slot-link resets after record drops
has no intervening callbacks or published state. The existing retained-view,
expiry, abort, handle-reuse and cache-transfer tests remain unchanged.

55 cache-related unit tests passed on macOS; the existing exact-C transfer
probe remains ignored in this standalone run and must run through its Oracle
fixture in the full gate. Raw data stays private; `clear1-screen.json` contains
derived counts. No router access, no new unsafe code, no capacity change.


CACHE-CLEAR-2 now screens the naturally idempotent empty-index case. It reuses
only an `Arc::get_mut`-proven unique root with **zero allocated buckets**.
Shared empty roots and every allocated HashMap are replaced at clear time,
so later insertions neither inherit an extra COW allocation nor retain old
bucket storage. The 64-element root vector is also reused. Source instrumentation
still has the original constructor/detach anchors; no diagnostic tool changes
or C expectation changes are required.

Counter screen: empty unique clear at all tested capacities drops 65
allocations/4608 requested bytes to zero; a retained-snapshot clear saves only
the 512-byte root-vector allocation (100→99 allocations), preserving actual
content/name detachment. Constructor counts remain exactly 99/93248B at 1000
slots. A million-slot-scale inference is not claimed. Native clear-1000
instructions fall 74.01% vs the original and 40.22% vs CLEAR-1; cycles remain
unqualified until a root-issued quiet slot. The new graph/bucket test and 55
existing cache-related tests pass; exact-C fixture/full gates are pending.


Independent baseline noise audit completed locally: `BASELINE_NOISE_PARTIAL.md`
and JSON verify37 C/deployed windows and1531 archived files, with every CPU and
p50/p95 value matching the primary analyzer. This audit does not review this
agent's candidates. It quantifies planning floors without changing W/4-of-5
or the CPU gate.

WRITER-1/DNS-4 was independently screened atop CLEAR-2: ordinary hit user
instructions −1.038%, miss +0.0275%, host −0.598%, CNAME −0.465%, auxiliary
8-RR −3.374%. The common-path saving is about54 instructions/query; expected
whole-daemon benefit is below the observed device noise/precision. Rejected
from B without full timing; exact offsets keep existing validation and24
wire tests passed. Experimental code is preserved on DNS branch30828e02;
`writer1-rejected.json` preserves all three counter rounds. The current branch
product remains only CLEAR-1/CLEAR-2.
