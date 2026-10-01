# UDP reply deadline and conditional slot reuse

`DaemonOptions::default` now uses `forward::ABSOLUTE_TIMEOUT` (40 seconds).
The previous ten-second transport deadline could discard an otherwise valid
late reply even when no new request needed its forwarding slot. The containing
runtime uses the same constant; explicit short deadlines in isolated primitive
tests remain available.

The exact `forward.c::lookup_frec` rejects an idle reply at `4 * TIMEOUT`.
`get_new_frec` may reuse an old slot at `TIMEOUT` when no free slot is available;
the per-group fresh-query count also uses ten seconds. Those existing
conditional pressure/reuse rules are unchanged. The configured fast-retry
timeout is a different retry budget and is not changed by this correction.

`dns_forward_diff.py` adds lookups at ages 11, 39 and 40 before reclaiming the
old query. The complete extracted-C forwarding gate passes 1,277 operations
with ASan/UBSan, retaining exact event order and the ten-second reuse cases.
Evidence: `private/dnsmasq-rewrite/udp-policy-20261001/deadline-forward-diff/`.

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

The transport actively closes timed-out work at its deadline, while C may
retain an expired frec until a later admission performs reclamation. Equal
reply acceptance does not establish equal idle FD-retention timing, and no
resource improvement is inferred from this change. Actual counters and
resource windows require separate accounting at their source events.
