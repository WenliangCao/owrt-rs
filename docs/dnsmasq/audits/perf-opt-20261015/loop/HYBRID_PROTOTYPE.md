# Local selective owner-wait prototype

Base: immutable E repair `4f869c885b47dcf60d56c872e5b0b3c62237beea`.
This separate branch contains an unqualified prototype, not a change to E.
Initial preparation used local Rust 1.98.1 `cargo check --frozen --jobs 1
--target aarch64-unknown-linux-musl --tests`; later authorized Linux evidence
is recorded separately below. No router was accessed.

The private binary module `owner_readiness.rs` takes the existing complete
PollFd slice plus marked eligible slots. It does not replace the shared ubus
poll function or change any library API. The existing normal/probe owners
still construct their explicit interests, deadlines and runnable state and
consume the same returned per-slot revents/counts in the same order.

Eligible descriptor lifetimes are explicit:

- DNS listener token plus UDP/TCP role. Deferred Arc ownership does not create
  a new numeric fd or reuse a retired listener token.
- Signal read pipe installed once in this SinglePoll and fixed RouteWatch
  descriptor. Keys are owner roles, not object/heap addresses. Probe construction
  marks neither role.
- Downstream TCP in Reading/Writing phases, with a checked monotonic accept
  generation retained across vector movement. Counter exhaustion leaves later
  connections on direct poll. TCP upstream, MAC-wait and closed-stream phases
  are never tagged by that accept generation.

Every other entry remains direct, including ephemeral UDP upstream, TCP
upstream, UBus, helper, collectors, file jobs, logs/dumps and TFTP. The exact-E
TCP-hit inventory below now identifies the complete 14-entry wait set for
that scene; this observation is not generalized to other configurations.

Registration stores its own checked monotonic event token. Removed lifetimes
are reconciled before additions, including reuse of a numeric fd. Duplicate
slots on the same eligible fd merge requested masks and expand back to their
individual masks and original ready-entry count. Conflicting keys for one fd,
unexpected input masks, allocation/control failure or stale event tokens
disable the optional backend and return to direct poll. Source descriptors
are never closed, duplicated or retained by the module.

There is no unconditional zero-timeout poll in front of the optimized wait.
The private eligibility contract requires a live owned descriptor throughout
the synchronous wait: only the owner may close/replace it, and must withdraw
or change its key. No production path or existing owner test was found which
manually closes one of these descriptors while retaining that same live key.
Initial invalid registration still falls back to original per-slot NVAL.
Descriptors without a demonstrable lifetime contract remain direct.

With no direct entries, one epoll_wait uses the original timeout. Mixed sets
use ppoll on direct entries plus the aggregate fd, then at most one nonblocking
event extraction sized for all registered members. No LT drain-to-empty loop,
RDHUP translation, signal-mask change or new timer policy is introduced.
Negative-fd placeholders remain zero in the original result but do not create
a spurious direct entry; a probe without an ICMP socket can use the same
single-wait path when all its actual descriptors are eligible.
EINTR repeats the supplied timeout as in the existing wrapper. Internal
error/stale-only fallback retains the remaining original wait budget: an
internal wake cannot masquerade as a full idle quarter-second to a DHCP probe.

Optional creation is attempted once. Scratch growth uses try_reserve; failure
drops the optional epoll fd, frees its scratch and permanently disables the
optimization. A failed backend does not retain a useless descriptor to match
a test baseline. Normal successful operation holds its constructor-created
fd until owner Drop, so its cost belongs in the process's initial fd set.
Reconciliation/expansion currently uses bounded linear searches. More than
64 tagged slots selects direct poll for that call, without changing the
product's connection limit or permanently disabling later small-set use.
The transition removes at most 64 preceding registrations so direct large
waits do not keep paying optional kernel callbacks. Later large waits have
none; returning to a small set can register again. Both transition costs must
be counted alongside steady fallback.

The initial eight Linux tests cover SDK event layout, duplicate masks and subset removal,
mixed direct regular-file readiness and unsupported registration fallback,
numeric fd replacement with a new generation/EOF comparison, initial NVAL,
64 simultaneously ready members and 65-entry fallback, stale-only wake idle
budget, and internal extraction failure idle budget. They are prepared for
the existing isolated Linux test gate after the Oracle reservation ends.
No runtime pass is claimed from local cross-compilation.

Independent caller tests (`44477146`, fixture correction `dd78a4a7`) additionally
exercise a queued normal-only signal across a full quiet probe interval,
subsequent normal signal drain and real UDP progress, and an expired ready TCP
client followed by a new client/probe turn with no inherited readiness. The
fixture has a real DnsDaemon; a missing-daemon draft was caught statically
before execution. Their module hook is included and the complete Linux-target
test build was cross-checked again.

After the coordinator released Oracle, the frozen f404337f prototype was built
with one job as a native Linux test artifact (`a216151d…`), verified against
the full baseline/patch/source manifest. Its eight module and two caller
controls passed in the existing net/mount/PID wrapper. This is not SDK/full
candidate qualification. Both source and outputs remain in the private
`hybrid-linux-20261015` attempt and are not overwritten by later fixes.

Independent actual-code review identified two remaining timeout details:
successful registration preparation must consume the caller's wait budget,
and a mixed aggregate wake with zero extracted/member readiness must not return
an early idle result. The follow-up uses the same remaining-time calculation
on success/fallback and a direct remaining-budget wait after empty extraction.
A ninth module control covers those two boundaries. The updated version needs
a new Linux artifact/run; the ten earlier passes do not transfer to it.

That fresh native run is now recorded in
`hybrid-native-validation.json`: commit `9ceab58d`, ELF `a77fe1d5…`, all source
inputs verified before and after the one-job build. Nine module controls,
two independent caller controls and 82 existing binary tests passed in the
existing isolated wrapper; the three ignored TFTP admission tests were then
run explicitly in that wrapper and passed. Total: 96 distinct tests, zero
failures. This is native functional evidence, not an SDK artifact, allocation
fault gate, full C-family result or performance acceptance. All raw logs stay
on Oracle; the verified derived summary copied locally is 20,914 bytes.

The separately authorized single exact-E TCP-hit diagnostic is recorded in
`exact-e-fd-inventory.json`. Its only driver change adds `-v` to strace so
ppoll input arrays are expanded. E ELF `8b8082b9…` and map `cbf86554…` match
the frozen SDK artifact. All 4,000 measured requests were sent and correct,
with no skip, timeout or transport failure. All 4,911 calls with input
`nfds=14` contain one route netlink fd, one signal pipe, IPv4 and IPv6 UDP/TCP
listeners, and eight downstream TCP connections. Thus every actual member
of this scene's steady wait set has an eligible owner lifetime. The 5.17 MB
raw trace remains private on Oracle; only a 5,624-byte derived role inventory
was transferred. Instrumented elapsed time is not acceptance evidence.

The paired actual-owner allocation/control diagnostic is recorded in
`hybrid-owner-allocation.json`. Both private native artifacts use the same
counting harness over exact E and 9ce sources, respectively. Source copies,
instrumented inputs and executables were hashed; builds used Rust 1.98.1,
one job and the shared build lock. Each isolated test passed, then a separate
syscall trace reproduced its allocation/layout records. An initial trace
omitted the native libc's `epoll_pwait` syscall and is retained but excluded
from totals; the complete trace explicitly includes that syscall.

Actual aarch64 layout adds 144 bytes to SinglePoll (7,360 to 7,504) and
16 bytes to each allocated PollTcpClient slot (1,960 to 1,976); TcpDnsWork
is unchanged. Construction adds one epoll fd but no heap allocation beyond
the existing 65,535-byte owner buffer. Optional backing capacities total
728 bytes at six interests, 1,624 at fourteen, and 7,176 at sixty-four.
These buffers retain their high-water capacity after oversized fallback and
return to fourteen. They exclude allocator metadata and kernel watch memory.
Both complete fixtures return from four initial fds to four final fds.

The first six-interest wait adds five allocations and one reallocation over
E. Warmed six/fourteen/sixty-four waits, steady sixty-five direct fallback,
mask changes and lifetime reconciliation add no allocations or reallocations.
The actual normal/probe pair still incurs the existing probe Vec cost on
both sides: one allocation and three reallocations per pair. Eight newly
ready downstream clients cause the same one-time ready_fds growth on both
sides. All these are allocation observations, not elapsed-time comparisons.

Steady eligible calls perform one `epoll_pwait` each, with no outer ppoll or
registration operations. A mask transition costs one MOD; retiring an already
closed client causes one tolerated DEL/EBADF followed by one ADD for the new
lifetime. Normal-to-probe removes two watches (route and signal), and return
to normal adds them again: four control calls per pair. The first sixty-five
interest fallback removes all sixty-four old watches once; subsequent large
waits use one ppoll and no controls. Returning to sixty-four adds sixty-four
watches. Truncating fifty clients then attempts fifty tolerated DEL/EBADF
operations. These transition costs remain part of any performance assessment.

The subsequent optimized native screen is recorded in
`hybrid-owner-instructions.json`. It reuses the same owner fixture and the
existing `perf stat -e instructions,cycles` measurement, with only an
environment-selected stage repetition count. The counting allocator is
removed from both private release-test artifacts: E `5bab8805…`, 9ce
`4c594274…`. No SDK build flags or product sources were changed. Eleven stages
ran on both artifacts five times (110/110 successful processes), with the
selected loop repeated 10,000 times and all other stages once. Each complete
process, including fixed setup and teardown, was counted. The setup control
is retained and never subtracted. Both PMU events reported 100% running for
every process; all source and executable identities were reverified afterward.

Paired total-instruction changes, candidate relative to E, were:

| Whole-process selected stage | Median change |
| --- | ---: |
| Fixed setup control | +5.17% |
| Repeated construction and drop | +11.88% |
| Six-interest ready normal waits | +24.73% |
| Fourteen-interest ready normal waits | +47.79% |
| Reading/writing mask transitions | +74.06% |
| Full connection-fixture lifetime churn | +0.42% |
| Normal/probe transitions | +89.25% |
| Sixty-four-interest runnable normal waits | +310.37% |
| Sixty-five-interest direct fallback | +9.35% |
| Sixty-four/sixty-five transitions | +784.35% |
| Fourteen interests, eight ready downstreams | +88.99% |

The lifetime-churn range crosses zero (-0.47% to +0.96%); its large counterpart
socket-fixture cost is included, so it does not establish a reconcile gain.
The other regressions are consistent across all five fixed pairs. These
results expose costs despite zero steady allocations and one wait syscall.
They do not measure deferred blocking cost and must not be generalized to
every possible readiness mechanism. The current prototype has no supporting
full-cost result for promotion to SDK qualification or plain timing. No plain
timing was run, no sample was replaced, and E remains unchanged. The 35,323-byte
derived summary was transferred; all raw counts, command records and source
copies remain private on Oracle.

Any future revised candidate still needs independent owner/fd-limit and
resource-cleanup review plus the unchanged complete unit, allocation, C-family
and eleven-scene performance/resource gates. No fallback rule or threshold
was changed to obtain a pass.
