# Owner/transport research progress

Branch `perf/dnsmasq-loop-20261015`, starts at `51b03959`. Freeze acknowledged:
`d358c3a0`; never accesses the router. Oracle root is
`/home/ubuntu/dnsmasq-perf-20261015/loop`. Raw artifacts stay in `private`.

Current screened direction: TCP vectored answers + direct complete-frame input.
No candidate is qualified yet; full correctness and timing are pending.

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
| L01 | Borrow UDP receive bytes until asynchronous retention is needed | screened in: actual owner local-answer path 11 → 10 allocations/query, 566 → 538 allocated bytes for 28-byte query; 1000 correct responses each |
| L02 | Send TCP header + existing packet via vectored I/O | screened in: one framing allocation and payload copy removed; 32/1232/65535-byte instructions −37.3%/−45.2%/−49.6% in isolated framing loop |
| L03 | Complete TCP input need not round-trip through retained fragment buffer | screened in provisionally: complete 32/1232/65535-byte instructions −20.6%/−25.3%/−48.6%; small fragmented input +2.1–3.7% (10–18 instructions/frame), retain as explicit control |
| L04 | Reuse upstream poll interest vectors | screened in: actual pending upstream poll 2 → 0 allocations/poll, 16 → 0 newly allocated bytes with one socket, after warmup |
| L05 | Startup/config stop-start overhead | trace lifecycle before any change |

L01 uses `Cow<[u8]>`; pending interface admission still owns its original copy,
and deferred interface-record/MAC lookups materialize a Vec before returning.
The existing receive scratch is moved out only across synchronous processing
and is restored on every ordinary return. The actual-owner probe verifies its
65,535-byte length after every response. `enumerate_interfaces` queues work
without recursively receiving packets; no consumer can reuse that scratch in
the synchronous call. Upstream forwarding still takes its required ownership.
Oracle native diagnostic builds are private copies with a counting allocator;
they are never timing or product artifacts.

L04 preserves every poll, timer pass, EINTR retry, socket-readiness mapping and
failure cleanup. Only the two scratch Vec capacities survive the call. They
retain 16 bytes per maximum observed socket (8-byte token + 8-byte pollfd),
plus 48 inline bytes in the resolver; `reserve_exact` avoids growth beyond the
observed interest count. The actual pending-poll probe measured 2000 → 0
allocations / 16000 → 0 newly allocated bytes over 1000 calls. Data and exact
source/diagnostic identities are in `owner-screen.json`. Local upstream tests:
35 passed. Full correctness and end-to-end timing remain pending.

Historical fixed UDP budget 1, opt-s, CPU-specific codegen and special owner
gates are rejected as starting points: `PERF_RESEARCH_UDP_DHCP_RELOAD.md` records
insufficient cross-scene benefit, including a saturation regression for budget
1. These are not newly measured rejections.

Framing data: `transport-screen.json`. Each PMU screen executes 100,000 frames,
pinned to Oracle CPU 2. Uninstrumented source-extracted functions use rustc
1.98.1 `-O`; allocation probe is a separate ELF. These are mechanism screens,
not daemon end-to-end performance or device claims. Source complete-frame
copy bytes go from `2 * payload + 2` to `payload`; output framing copy goes
from `payload + 2` to zero. The answer payload's existing allocation remains.
The outbound inline prefix adds one word to an active TCP frame while removing
a second transient payload allocation. It retains the answer's original spare
capacity: a 60-byte answer with PacketWriter's 128-byte initial capacity keeps
128 heap bytes rather than the old exact 62 bytes, plus 8 inline bytes. Eight
blocked replies therefore retain 592 additional bytes in this example. The
separate resource probe also covers a 1232-byte packet with 2048-byte capacity
(+814 heap bytes) and maximum packets (−2 heap bytes). This explicit storage
tradeoff must be checked against complete daemon RSS and blocked-client cases;
the change is not described as unconditionally reducing resident memory.
No receive limit changed.

Local targeted service tests: 14 passed, including all split boundaries and
short writes through prefix/payload, maximum 65,535-byte payload, malformed
length controls. Full Linux/allocator/C gates remain pending.

Next: UDP borrowed input and upstream fd-buffer counts; request root timing
slot for all screened transport changes together. Independent correctness
review precedes eligibility.
