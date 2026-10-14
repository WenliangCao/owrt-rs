# DNS algorithm research progress

Source baseline: `51b039597af13f9c9cf07c9f80e388e25cd8ae5d`.
Protocol/correctness freeze: root commit `d358c3a0`; do not change it.
Branch: `perf/dnsmasq-dns-20261015`.

Current screened candidate: DNS-1 + DNS-1b + DNS-2; native focused timing passed the screen, all correctness/device gates remain pending. The independent correctness owner gates all
combined candidates; this branch only supplies reviewed research changes.

| Hypothesis | Mechanism and boundary | State |
| --- | --- | --- |
| DNS-1 | `PacketWriter::record_at` decodes an already-written owner into a discarded `Name`; validate the same compressed name without allocating or copying its output. Same length, pointer, label and error rules. | Retain for isolated timing: hit 5→4 allocations, 277→245 requested bytes; 8-RR hit 13→5 allocations. One-pass instructions −5.78%; cycles not qualified under concurrent load. |
| DNS-2 | Local-answer lookup converts wire names to dotted bytes twice when lease expiry is active; preserve the name once across expiry and lookup. No expiry/round-robin reordering. | Retain: reuse the expiry conversion and borrow CNAME traversal targets. With six unrelated leases, one fewer allocation/21 requested bytes per question; miss CPU −8.84%, hit CPU −10.44% vs baseline in isolated native screen. |
| DNS-3 | Read-only cache predicates copy lowercase names even though key lookup can borrow their wire bytes. | Await DNS-1 counts before selecting. |
| DNS-4 | Repeated full scans and record validation in the cache answer state machine. | Must isolate measurable work before proposing a change. |

Ownership: `dns/wire.rs`, `cache.rs`, `cache_engine.rs`, `cache_reply.rs`,
`cache_name_index.rs`, `local.rs`. `dns/lease_names.rs` belongs to the DHCP
researcher. Daemon, service, event loop and main are owned elsewhere.

Prior work rejected Name inline storage, a three-state EntryIds container,
fixed/adaptive UDP budget changes and extra caller gates without reliable
long-window gains. Do not repeat these as unmeasured novelty.

The diagnostic probe calls public `DnsDaemon::answer_local_or_cached` and the
actual allocator. Its scoped counts exclude setup, cache population, priming,
output and answer validation. Ordinary samples retain real name parsing,
local lookup, cache lookup/rotation and answer serialization. `hit-leases`
and `miss-leases` use unrelated synthetic leases to expose expiry-key work;
`hit-upper`, `host` and `rrset` are generality checks, not additional device
performance scenarios. Requested allocation bytes are **not copy bytes**.

Oracle scratch root: `/home/ubuntu/dnsmasq-perf-20261015/dns`; raw results
copy to ignored local `private/perf-opt-20261015/dns`. Never access the router.
Every timing measurement needs a root-issued quiet reservation and `taskset`.

DNS-1 native baseline/candidate screen is in `dns1-screen.json`. It removes one
23-byte expanded-name copy per ordinary answer and eight per 8-RR answer in this
synthetic corpus; these are the discarded decoder outputs, not total process
copy bytes. The common walker retains exact error ordering. Both paths still
follow pointers and retain the 255-hop and 255-wire-byte limits; no fallible
allocation boundary was replaced with an infallible one. Full correctness is
pending and these numbers cannot yet qualify a device candidate.


The first quiet CPU-2 slot completed 105/105 uninstrumented windows (seven
paths, baseline/DNS-1/DNS-2, five alternating rounds, 500,000 operations each).
`dns1-dns2-timing.json` gives every round and median/range. Native DNS-1 improves
hit CPU 3.94% and 8-record hits 13.42% beyond these microbench ranges; misses
are unchanged. DNS-2 includes DNS-1b, improves hit+leases CPU 10.44% and
miss+leases CPU 8.84% vs baseline. Host timing varies too much to rank. These
are whole-process diagnostic CPU costs including common fixture preparation,
not service microseconds on the device. DNS-1b has not been separately timed;
its two discarded decoder outputs are source-proven and still need the full
upstream correctness gate. Exact repeated field and byte checks remain in the
existing tests.

Next: measure a *local temporary* bounded dotted-name scratch, not an inline
persistent Name representation. Ordinary hit still allocates a 21-byte dotted
copy. Keep literal-dot rejection, binary labels, lowercase conversion and
root handling exact. Do not change public Name, cache/snapshot layout or
lookup ordering. Only adopt if allocation/PMU screen and isolated timing help.
