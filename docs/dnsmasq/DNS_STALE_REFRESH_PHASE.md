# Stale cache reply and background refresh

Status: a known runtime gap is confirmed; this phase is **not accepted**.
The daemon accepts `use-stale-cache`, but its current cached-answer return
does not start the refresh performed by C. Cache retention and zero-TTL
serialization alone do not implement this option.

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

Next: propagate source-derived stale metadata through the answer path, submit
the original request without client delivery, preserve coalescing, then run
this gate and affected cache/forwarding regressions. EDNS/EDE, stale age limits,
failure/retry, clock equality/rollback, local targets and all message counters
require additional source-driven boundaries before complete stale acceptance.
No performance result or functional-equivalence claim is made here.
