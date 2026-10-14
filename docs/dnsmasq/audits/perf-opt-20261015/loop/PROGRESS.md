# Owner/transport research progress

Branch `perf/dnsmasq-loop-20261015`, starts at `51b03959`. Freeze acknowledged:
`d358c3a0`; never accesses the router. Oracle root is
`/home/ubuntu/dnsmasq-perf-20261015/loop`. Raw artifacts stay in `private`.

Current best: unchanged v0.2.0 source. No candidate is qualified yet.

## Interface and compatibility audit

- UDP owner owns the 65,535-byte receive buffer, uses the immutable packet for
  admission, local/cache answer, forwarding and stale refresh. Only deferred
  interface admission, interface-record lookup and EDNS MAC lookup retain the
  received bytes beyond the current call. Every successful/failed actual
  receive preserves current resend invalidation ordering; speculative EAGAIN
  does not invalidate. Keep the fixed 16-packet fairness budget.
- TCP inbound `TcpFramer::push_frame` consumes at most one complete frame.
  Zero/oversized length is rejected before body consumption; valid preceding
  frames survive a later malformed frame. `finish` reports incomplete tails.
- TCP outbound `queue_answer` receives an already-owned payload. It currently
  copies it into a new contiguous length-prefixed Vec. Readiness, partial
  writes, close-after-100 and stale send-before-close/refresh are owner rules.
- Upstream `poll_with_context_filter` owns reply validation, timers and socket
  errors. It already has an empty-work early return, so an unconditional Rust
  call does not imply an extra syscall. When work exists it allocates token
  and fd vectors; owner readiness is not yet sufficient evidence to bypass
  its semantics.
- Shutdown explicitly drains helper/lookups and logging before returning.
  No evidence yet supports removing lifecycle work or changing cleanup.

## Experiments

| ID | Hypothesis | Screen / status |
| --- | --- | --- |
| L01 | Borrow UDP receive bytes until asynchronous retention is needed | planned; allocation/copy count first |
| L02 | Send TCP header + existing packet via vectored I/O | exact-source standalone allocation/instruction probe prepared |
| L03 | Complete TCP input need not round-trip through retained fragment buffer | same probe, fragmentation controls included |
| L04 | Reuse upstream poll interest vectors | inspect/profile after L01–L03; no timer/readiness shortcut |
| L05 | Startup/config stop-start overhead | trace lifecycle before any change |

Historical fixed UDP budget 1, opt-s, CPU-specific codegen and special owner
gates are rejected as starting points: `PERF_RESEARCH_UDP_DHCP_RELOAD.md` records
insufficient cross-scene benefit, including a saturation regression for budget
1. These are not newly measured rejections.

Next: capture framing baseline, implement independent candidates, compare
untimed allocation/copy and PMU instructions/cycles, request root scheduling
before any timing. Independent correctness review precedes eligibility.
