# Borrowed cache engine extraction

`dns/cache_engine.rs` now contains the existing cache answer, insertion and
local-target logic. `CacheContext` borrows `Cache` and its counters, copies the
two negative-cache settings, and takes a local-name generation as an argument.
It owns no transport, descriptor, entropy source or local-name snapshot.

The daemon keeps its existing fields, cache configuration/reload methods and
oracle entry points. Its wrappers create the borrowed context and preserve the
old wire/local error variants. `answer_udp` retains the ordinary OPT envelope;
`answer_records` exposes the same record builder without tying it to UDP;
`insert_reply` retains the existing insertion behavior. No clone, COW, TCP
writeback or new cache algorithm is included in this extraction.

The cache-sensitive tools now include `cache_engine.rs` in their explicit
source-identity lists. The frozen Rust source is retained as
`private/dnsmasq-rewrite/tcp-cache-20261001/extract-source-01.tar.gz` with a
per-file identity manifest. The three harness identity lists were updated
after that archive; `harness-update-01.json` records those exact tool hashes.

| Revalidation against independent C | Result |
|---|---|
| Cache answers/counters | 764 ordered observations, 164 queries; zero differences. Existing exact-C oracle reused after its identity check. |
| Empty OPT/stale/output limits | 155 steps, 143 queries; zero differences. |
| Clipped later sections | 96 steps, 64 queries; zero differences. |
| Local insertion/CNAME targets | 36 scenarios, 269 observations, 95 queries. All 32 ordinary scenarios retain zero differences; the reference-layout cohort retains its same two differences. Full gate exits 1. |
| Local checks | Library clippy passes with warnings denied; 12 cache units pass and the explicit C driver remains ignored in that ordinary test invocation. |

Gate outputs and failed-reference observations remain under
`private/dnsmasq-rewrite/tcp-cache-20261001/extract01/private/`.
The known malformed-replacement deletion difference remains open for the next
source-order transaction repair; this move does not claim to fix it. TCP cache
inheritance/writeback, target rebuilds and performance acceptance remain open.
