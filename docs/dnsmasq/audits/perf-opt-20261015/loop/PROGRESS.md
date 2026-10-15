# Owner/transport research progress

Initial branch `perf/dnsmasq-loop-20261015`, starts at `51b03959`; A loop changes
end at `e1bdcd4a`. B research continues on `perf/dnsmasq-loop-exit-20261015`.
C socket-creation research is on `perf/dnsmasq-loop-socket-20261015`.
Freeze acknowledged:
`d358c3a0`; never accesses the router. Oracle root is
`/home/ubuntu/dnsmasq-perf-20261015/loop`. Raw artifacts stay in `private`.

Current screened directions: A TCP framing/UDP borrowed input/upstream scratch;
B only final-process pure-memory cache retirement.
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
| L05 | Startup/config stop-start overhead | screened in: independent terminal-boundary review passed; actual daemon teardown 106 → 7 deallocations, removing 93,248 bytes of allocator cleanup; FD count restored 4 → 4 on both sides |
| L06 | recvmmsg removes terminal WouldBlock syscall without reducing the 16-packet fairness budget | reject unchecked batching: failure boundary changes; SO_ERROR-screen loses syscall saving and adds single-packet instructions |
| L07 | Avoid metrics snapshots when no DNS UBus subscriber exists | reject before edits: only 0.046%/0.124% of total instruction samples in control/A; no evidence for a measurable end-to-end gain |
| L08 | Inline the common single upstream-socket owner | reject isolated prototype: source/ELF-bound repeat saves ~610 instructions per single-owner lifetime, but 150-owner lifetime adds ~1373; projected 0.37% whole-miss instructions below frozen variation |
| L09 | Create upstream UDP descriptors with both flags atomically | screened in: 2 setup syscalls/socket removed; flags, bound tuples, port-range random calls, errors and FD cleanup verified |
| L10 | Reuse owner readiness instead of nested zero-timeout upstream ppoll | reject before product edits: projected 1.99% whole-miss instructions below deployed 4.60% CPU range and frozen 3.07% precision floor; token/epoch/error bookkeeping would reduce benefit |

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

## Second-round mechanism evidence

`lifecycle-v020-counts.json` and `lifecycle-c-counts.json` contain only counts,
never ptrace timings. Both use the frozen lifecycle tool, 8 hosts/6 leases,
20 fresh processes in loopback-only netns. C uses its exact image loader and
libraries; shell-wrapper startup is excluded before the final exec. Before the
first DNS receive C/Rust have 226/214 syscalls, including 20/36 mmap calls.
After SIGTERM C/Rust have exactly 12/52 calls: 0/27 munmap and 2/15 close.
The original Rust input was non-executable; the first diagnostic failed with
EACCES, remains archived and is excluded. A private chmodded copy has unchanged
deployed SHA256 `8472be5a…`, and all 20 subsequent runs were correct.

C closes its lease/log streams and unlinks the PID, then exits; Rust additionally
walks and frees its full heap. A blanket early exit is rejected: DHCP's
`BufWriter<File>` has a real Drop flush, and Helper/EndpointLookup have process
semantics. B only considers retiring the memory-only DNS Cache at the final
successful `run_inner` return; all IO objects still drop normally. Its only
caller is `run`, whose only caller is `main`; reloads, command-only actions and
errors do not pass that terminal site. Independent correctness review confirmed
these facts before the counter screen. An actual DnsDaemon with the explicit
1000-entry empty cache performs 106 deallocations/96,033 freed bytes normally,
versus 7/2,785 after terminal retirement; both restore FD count from 4 to 4.
The remaining 93,248 heap bytes are reclaimed by process exit, not retained by
a continuing daemon. The default upstream constructor has no cache; the first
diagnostic harness omitted `enable_cache`, was caught before execution, and
was rebuilt with the explicit 1000-entry configuration. Invalid builds remain
private and contribute no numbers. Local daemon tests: 61 passed, 3 existing
ignored. Data: `terminal-cache-screen.json`. Full shutdown/C and timing gates
are still required on the complete candidate.

All three lifecycle working directories under Oracle `/tmp` were archived and
copied locally with matching SHA256
`622a654ab4fc6f0eb472255f570e76062dfc84fb4bd6011add78343e854d6ae4`.
After verifying no lifecycle process remained, only those three owned `/tmp`
directories were removed. Source/build/probe evidence remains in the private
Oracle loop directory; no Docker or other service was touched.

The standalone recvmmsg screen uses the same IP_PKTINFO, 28-byte packet and
65,535-byte scratch. It reduces single-packet receive syscalls 2 → 1; total
instructions (including the same sender) fall 4.36%. Sixteen-packet batches
fall 4.93%. These are not daemon or device speedups. A positive batch return
does not report a later receive error; Linux documents that the deferred error
can be overwritten by another event ([recvmmsg manual](https://man7.org/linux/man-pages/man2/recvmmsg.2.html)).
The constructed invalid-second-iovec probe returns one packet/errno zero while
SO_ERROR contains EFAULT; this demonstrates ambiguity, not natural fault rate.
Adding SO_ERROR inspection restores two syscalls per single-packet batch and
increases instructions 3.57% in this screen. This specific replacement is
rejected before product edits/full timing; no claim that every possible receive
batching design is impossible. Data: `batch-receive-screen.json`.

## Residual release-owner profiling

`owner-profile-hit.json` binds the exact SDK recipe control
`2bf381716d0f460a6fbb2b87679c1950867f5df8a40cd4570b43bcba03836f1f`
and A `b353039e1e85cb2b91a9539460dc6623532757699e6a63f5cf20482d7946952e`
to their own linker maps and before/after process mappings. Neither control is
the deployed `8472…` file. Both diagnostic windows completed 4000 measured
queries; perf enable/disable ACKs bracket the full 5+20-second load. Instrumented
timing is ineligible. Initial unacknowledged control capture remains private
for qualitative context only.

The OpenWrt sstrip ELF lacks a section table. The new diagnostic parser checks
the exact ELF/build/map hashes, executable program headers, unchanged process
mappings and nonoverlapping GNU input-section ranges. It does not assign the
nearest symbol. Target ELF IPs have no gaps; unmapped user samples are solely
vDSO (44/12958 control, 99/12053 A). Unnamed input sections remain explicit,
29/64 samples respectively. `names_for` is exactly a 380-byte function range
ending at its final ARM64 `ret`: control `[0xdfcfc,0xdfe78)`, A
`[0xe01e0,0xe035c)`.

`Cache::names_for` remains 14.11%/15.36% of total instruction samples; the
generated code contains the existing bytewise FNV shard loop followed by one
bulk hasher call and HashMap probe, not per-byte Hasher::write calls. DNS core
is researching safe reuse of the read-only name lookup. Metrics is 6/15
samples, so L07 is not implemented. Kernel proportions and individual kernel
labels vary substantially between diagnostic windows; they are not precise
CPU shares or evidence that all remaining costs are irreducible. More DNS
scene profiles are in progress; A/B performance and full correctness remain
root-owned decisions.

`source-socket-screen.json` records L09. An SDK A miss strace window completed
1000 warmup + 4000 measured queries. It made exactly 5000 plain UDP socket
creates, 5000 FIONBIO ioctls and 5000 F_SETFD calls. The computed selected-call
total is 64,872 (an earlier hand sum was corrected); 10,000 removed setup calls
would be 15.4% of those calls, **not a measured latency/CPU speedup**.

Linux now supplies SOCK_NONBLOCK|SOCK_CLOEXEC to socket, matching the existing
listener/TCP factories. SDK headers confirm octal 04000/02000000. Source-bound
baseline/candidate bridges each ran six 1000-call cases: wildcard/bound IPv4
and IPv6, a two-port range, and an inverted invalid range. Returned nonblocking
and close-on-exec flags, selected address/port, random call counts, InvalidInput
with binding=false, and FD count 4→4 matched. Every successful factory case
removed exactly 1000 ioctls + 1000 F_SETFD calls; bind and IPv6-only option counts
were unchanged. Independent static review passed; 54 local upstream tests
passed. Linux full unit/C/upstream-bind/exec gates remain root-owned and pending.

The same trace contains 9943 zero-timeout ppoll calls, 9931 polling one fd,
within 19,879 total ppolls. Removing them safely requires accounting for fd
reuse, already-consumed POLLERR, new socket generations and unchanged timer/
reply ordering. The owner's readiness booleans are only wakeups: it can accept
new queries and consume errors before the nested transport phase. Reusing the
raw fd numbers alone would not preserve that boundary.

## Residual screen decisions and limits

`residual-counts.json` binds the standalone L08/L10 sources, exact native ELF
hashes, compiler versions and every invocation. Its 11 count-only cases passed
on Oracle CPU 2. The first receipt run lacked perf privilege, failed before any
measurement and remains archived; a separate explicit sudo run succeeded with
unchanged host policy. Earlier session counts remain archived too. The new run
fills their missing build-command receipt, not an acceptance rerun.

A one-fd zero-timeout ppoll costs about 1631–1636 extra instructions relative
to an ideal skip control, whether ready or empty. Applying the larger value
to every nested call in A's 5000-query miss trace projects 1.99% of the separate
816,869,505-instruction A miss profile. This is an intentionally generous screen
estimate before generation/error bookkeeping. The probe is native glibc, while
the DNS artifact uses exact SDK musl; it is not a mathematical speedup bound or
a device measurement. The fresh deployed baseline has UDP-miss CPU
522 [512,536] microseconds/query: its own range is 4.60%, and the frozen 8-tick
minimum is 3.07% at 5000 operations. L10's expected gain is below both, so no
readiness-state implementation is introduced.

The inline-owner set saves 610/534/366 instructions for 1/2/16-owner lifetimes
and adds 1373 for 150 owners. It also adds 16 inline bytes per set. Even assuming
one saved lifetime per miss, the projected whole-query instruction saving is
only 0.37%. L08 is rejected on measured cost and variation, without replacing
the existing HashSet or its caller/ownership rules.

`owner-profile-scenes.json` preserves four additional exact A SDK profiles,
locally revalidated against their ELF/map/process identities and perf ACKs;
each has 4000 correct measured queries plus warmup. TCP-hit's sampled kernel
share is 93.82%, but UDP-miss still has substantial user work. Cache insertion
accounts for 10.01% of all UDP-miss instruction samples and 18.29% of TCP-miss;
the DNS agent owns that investigation. The large inlined upstream send function
has 12.99% of UDP-miss samples and contains multiple map operations and socket
selection; its aggregate label is not evidence that all of it can be removed.
Do not claim all residual daemon work is irreducible from these profiles.

Independent correctness review of L09 was repeated against the retained SDK
headers: constants, immediate OwnedFd ownership, IPv6-only/source/interface
setup, port randomness, bind-error classification and single-close cleanup
have no blocker. Full fresh integrated candidate gates remain mandatory.
