# Stale cache reply and background refresh

Status: background refresh is now implemented for the current cached-answer
subset, with the bounded gates below passing. Complete cacheability, EDNS/EDE,
TCP and stale-service acceptance remain open.

The initial daemon accepted `use-stale-cache`, but its cached-answer return
did not start the refresh performed by C. Cache retention and zero-TTL
serialization alone did not implement this option.

Exact `forward.c:1957,2002-2032` distinguishes a stale answer from an ordinary
local answer. After sending the stale result, it increments stale answered,
restores the original query and calls `forward_query` with client descriptor
`-1`. The refresh follows normal coalescing/cache insertion but must not send a
second answer to a client that already received stale data. Record staleness
uses `crec_isstale`, strictly after expiry: TTL zero at exact expiry does not
by itself prove a stale answer. Packet TTL must not be used to infer this flag.

`dns_stale_refresh_diff.py` provides the isolated actual-service gate. Four
scenarios cover A, AAAA, a CNAME chain and NXDOMAIN. Both sides use identical
configuration, capacity, upstream port and requests. The controlled upstream
seeds a one-second TTL, waits three seconds, holds the refresh while a second
client queries, then releases changed data. The test observes the ordered
client replies, background request/coalescing, absence of second replies,
subsequent cache value and the complete upstream trace.

Only upstream transaction IDs and valid elapsed-clock variation in the fresh
120-second answer are normalized. Stale TTL zero, client IDs, flags, RDATA,
record/event order and request counts remain meaningful comparison fields.
All raw packets and actual fresh TTLs are retained; no sorting hides order.

The before-fix gate on product **2415216**, native Rust ELF
`1334f0dfbd9af3a38279a0fb69199be8193f7b5a3e710787a48fb33b37d786be`,
records **13 differences across 44 comparisons** (40 ordered event rows plus
four complete upstream traces). Both processes complete and are reaped; there
are no harness execution failures. The first report's `compared` field counted
only the 40 event rows. The explicit count audit corrects that denominator to
44 without changing the original report or any outputs; the tool now asserts
the complete 11-comparison count per scenario.

Evidence: `private/dnsmasq-rewrite/stale-refresh-20261001/before-01/`, including
`comparison-count-audit.json`. C calibrations require a seed response, an
actual background refresh, stale TTLs and no second replies; a deliberately
removed refresh is detected. `--c-baseline` can reuse these still-valid C
observations only with the same C ELF identity and identical configuration.

## Implemented behavior and final gates

The cache caller now returns both an optional packet and observed staleness.
An observed stale entry without a deliverable answer remains an ordinary
forwarding request. For a stale answer, main attempts the client send first,
then submits the original query with `reply_requested=false`. Its completion
still processes/cache-inserts the common response, while omitting a second
client delivery. Ordinary coalesced recipients retain their independent reply
flags. HUP cannot split the admitted answer, send and refresh sequence; socket
receive waits remain outside that event gate.

The CNAME/NXDOMAIN pre-scan can mark a newer typed answer stale. The caller now
prefers a valid typed answer over a coexisting old NXDOMAIN while preserving
that observed flag. Staleness uses the entry expiry, not the outgoing TTL.
The frozen-clock gate also found that `max-ttl` clips matching Answer A/AAAA/
CNAME TTLs **before** insertion; the independent authority SOA and negative
fallback follow their own paths. That caller bug is fixed. The main executable
still explicitly rejects `max-ttl`; its profile remains library-only.

The service tester now uses Linux kernel receive timestamps to compare the
client reply and upstream refresh across different sockets. Reading one socket
first is not evidence of packet order. The early prototype matched 44 protocol
and trace comparisons but failed all four newly checked ordering observations.
It is preserved as `send-order-negative-01`: **44 matches, four differences**,
exit 1. The corrected final gate is **48/48**, including send-before-refresh.

The final native Rust ELF is
`4f6825210ac22d3b513a18e3bfec5246b06fe2a83f199969885fde987389af28`.
Evidence in `private/dnsmasq-rewrite/stale-refresh-20261001/implementation/`
contains every service round, the ordering negative control, final binary,
and final shared-state **8/8**, DHCP/DNS **34/34**, and reload **23/23** gates.
The C protocol/order trace was reused after its identity and identical
configuration were checked.

`DNS_STALE_METADATA_ORACLE.md` supplies the independent C baseline for five
profiles, 1,100 commands and 685 queries. The Rust comparison now passes all
**1,100 observations**, including eight stale observations with no answer,
expiry equality, finite/forever policies, TTL clamps, rollback and reload.
The first Rust round had 34 differences, all in the library-only `max-ttl`
profile; those failures remain in `rust-01`. A deliberate flag mutation in
the final driver gives **1,099 matches/one difference**, exit 1.

Final source-bound results are `rust-04` and `rust-negative-02` under
`private/dnsmasq-rewrite/stale-metadata-20261001/`. A test-adapter Clippy error
had stopped an intermediate rebuild; `rust-03`/`rust-negative-01` reused the
prior executable and are explicitly **not** accepted as checks of the newly
hashed source. Their original data and source-binding audits remain intact.
`stale_metadata_diff.py` now performs a pinned successful source build, checks
source stability and freezes that exact driver before every comparison.

The final affected cache-answer/metrics gate passes **764 observations**.
Local-target regression preserves the prior result: 32 ordinary scenarios
have zero differences; the four C layout-defect scenarios retain two
differences and the complete gate exits 1. Host library tests pass **338**, with
seven ignored, and main tests pass **6**; fmt and musl all-targets Clippy pass.
Those ignored drivers are not counted as ordinary test passes. Host regression
logs are under the same stale-refresh directory's `host-final/`.

No component performance or full functional-equivalence claim follows from
this work. EDNS/EDE, all stale failure/retry combinations, TCP cache behavior,
local-target corner cases and complete live metrics remain separate gates.
