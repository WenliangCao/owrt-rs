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
