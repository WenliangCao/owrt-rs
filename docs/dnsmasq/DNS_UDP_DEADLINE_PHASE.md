# UDP reply deadline and conditional slot reuse

The daemon now selects `Lifetime::ForwardTable`: the existing forwarding table
decides reply validity using the wall-clock creation time and reclaims old
slots during new admission. It does not impose an independent monotonic timer
on those records. Standalone `UpstreamResolver::with_random(..., Duration)`
retains explicit `Lifetime::Fixed` behavior; the synchronous convenience API
always retains a bounded wait. `DaemonOptions::upstream_lifetime` makes the
choice explicit, and the containing runtime selects the forwarding-table mode.

This replaces the earlier fixed monotonic deadline, first ten seconds and then
an intermediate 40-second correction. Even a fixed 40-second cancellation can
discard a reply that C accepts after wall-clock rollback, and it frees an idle
frec earlier than C. Explicit short primitive-test deadlines remain unchanged.

The exact `forward.c::lookup_frec` rejects an idle reply at `4 * TIMEOUT`.
`get_new_frec` may reuse an old slot at `TIMEOUT` when no free slot is available;
the per-group fresh-query count also uses ten seconds. Those existing
conditional pressure/reuse rules are unchanged. The configured fast-retry
timeout is a different retry budget and is not changed by this correction.

`dns_forward_diff.py` adds lookups at ages 11, 39 and 40, and wall-clock
110 → 140 → 110 for a query created at 100. An expired lookup alone does not
unhash the frec, so rollback can make that query valid again; reclamation by a
new admission prevents revival. The complete extracted-C forwarding gate now
passes 1,285 operations with ASan/UBSan, retaining exact event order and the
ten-second reuse cases. A controlled transport test advances monotonic time
beyond 40 seconds, verifies wall-clock rejection/rollback acceptance, and then
checks actual admission releases the old transaction/socket. Evidence includes
`clock-lifetime-forward-diff/`, `lifetime-forward-final/` and
`lifetime-clock-tests.log` under `private/dnsmasq-rewrite/udp-policy-20261001/`.

`dns_udp_deadline_diff.py` freezes one real-daemon window per implementation:
an 11-second upstream response must arrive, a 41-second response must not, and
a fresh request at 42 seconds must complete. Both use the same configuration,
listen/upstream ports and response packets, with raw FD/thread/child samples
and process shutdown retained. `deadline-02/` completes that sole full window
for each daemon: both receive the delayed reply after 11 seconds, suppress the
41-second late reply, and complete the fresh probe at 42 seconds. Each side
issues three measured queries, receives exactly two replies and exits cleanly.
Client bytes and upstream semantics/order/counts match. The first attempt,
`deadline-01/`, is retained as a readiness-adapter failure: connected UDP saw
ECONNREFUSED before either listener bound; no measured-window query ran.

The frozen Rust ELF is
`3f77c3a4d1279c7fb342fc2281fb2dcf33d3f43d3695c3d943d83d24190dee9b`,
also used by the successful 43-event admission gate. All raw plans, packets,
timing samples and process results are in
`private/dnsmasq-rewrite/udp-policy-20261001/linux/deadline-02/`.
Those runtime measurements belong to the intermediate fixed-40-second version;
they are retained as evidence of the timer/lazy-reclamation difference, not as
final resource validation for `Lifetime::ForwardTable`.

| Observation | C FDs | Rust FDs |
| --- | ---: | ---: |
| Ready | 11 | 6 |
| Two pending queries | 13 | 8 |
| After 11-second success | 12 | 7 |
| At 40.5 seconds, before new admission | 12 | 6 |
| After fresh probe | 11 | 6 |

C has one thread and Rust three in this fixture; neither has child processes.
Both processes are reaped after SIGTERM. These are individual functional-window
observations, not throughput, tail-latency or exclusive-memory measurements.

The new forwarding-table lifetime removes that proactive cancellation instead
of adding deferred metric bookkeeping to it. A final real-daemon replay of the
new lifetime remains pending at this checkpoint. Actual counters require
accounting at their source events; neither the old FD difference nor the
corrected behavior is claimed as a performance improvement.
