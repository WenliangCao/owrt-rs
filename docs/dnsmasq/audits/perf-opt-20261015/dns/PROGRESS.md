# DNS algorithm research progress

Source baseline: `51b039597af13f9c9cf07c9f80e388e25cd8ae5d`.
Protocol/correctness freeze: root commit `d358c3a0`; do not change it.
Branch: `perf/dnsmasq-dns-20261015`.

No selected product candidate yet. The independent correctness owner gates all
combined candidates; this branch only supplies reviewed research changes.

| Hypothesis | Mechanism and boundary | State |
| --- | --- | --- |
| DNS-1 | `PacketWriter::record_at` decodes an already-written owner into a discarded `Name`; validate the same compressed name without allocating or copying its output. Same length, pointer, label and error rules. | Baseline allocation screen being prepared. |
| DNS-2 | Local-answer lookup converts wire names to dotted bytes twice when lease expiry is active; preserve the name once across expiry and lookup. No expiry/round-robin reordering. | Read-only call-graph investigation. |
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
