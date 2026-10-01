# Immediate upstream resource failures — 2026-10-01

Exact `forward.c::forward_query` cancels its frec when every candidate fails
socket allocation or `sendto`, restores the first request ID and constructs a
local REFUSED. A client OPT receives EDE 23 (Network Error), with DO cleared.
The action increments `dns_local_answered`, not forwarded or unanswered.
For a background stale refresh, `udpfd == -1` suppresses wire delivery but
still increments local answered. No configured server is a separate REFUSED /
EDE 14 path. A successful server in the same send plan wins over other failures.

Rust's transport already cancels the failed transaction and preserves unrelated
pending work. The daemon now maps a terminal socket/send `ResolveError::Io` to
the corresponding local REFUSED/EDE 23; previously that error reached main and
the client received no reply. Main's existing background-refresh local-counter
hook accounts for this returned `Local` without sending a second reply.

The actual gate `dns_start_failure_diff.py` runs only in the build host's new
network/mount/PID namespaces. It asserts only loopback exists and both route
tables have no default or non-loopback route. The unreachable destinations are
198.18.0.53 and 2001:db8::53; strace must observe real `ENETUNREACH`, so no packet
can leave the namespace. FD pressure is applied with `prlimit` after readiness
and a successful UBus metrics call. Each process has zero allocatable FD slots
below its soft limit, while existing descriptors and `poll` remain usable.
The numeric limits reflect each process's different existing descriptors;
this is a functional zero-headroom test, not a resource-cost comparison.

Each case preserves IDs, question, RD/CD/AD handling, OPT size/DO/EDE, all 30
UBus metric fields, actual upstream sends, recovery and normal process exit.
Six request variants cover plain, CD, AD, ordinary OPT, DO and advertised size
zero. Error counters distinguish UDP `socket(..., SOCK_DGRAM)` failure from
unrelated TCP accept errors. Missing observations and counter mutations are
hard failures. Both daemons run as UID 0 inside the namespace; C receives its
root user/group launch flags because Rust has no privilege-drop implementation.

Private evidence is under
`/home/ubuntu/dns-start-failure-20261001/private/` and the local
`private/dnsmasq-rewrite/start-failure-20261001/`. The source baseline is commit
`5831e9731afbadb72142bd6b4dd9c9488c84d24f`; its native Rust ELF is
`10fe8dbc216c7eaec2ec38b20b25f65e94103fa9029e6a5e7551c64e9c8688d5`.
Exact native C remains
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

- `c-baseline-02`: all seven C profiles execute, 61 ordered observations.
  Runtime syscall coverage includes IPv4/IPv6 no route, FD exhaustion,
  mixed-server success, retained coalesced requests and stale refresh failure.
- `before-03`: 23 compared differences plus a pending-case test timing error.
  The old Rust daemon silently drops initial send errors and omits the local
  fallback count. FD pressure also exposes the separate TCP listener defect.
- `after-01`: 51 observations match for no-server, no-route IPv4/IPv6,
  mixed-server, retained pending/coalesced recipients and stale-FD profiles.
  The FD-full profile remains a hard coverage failure, so this full gate exits
  nonzero. Rust ELF:
  `4a7b37f629c5a06aaf19dc65120e166fc471d726ae61534971232ce0153063a1`.

The remaining FD-full failure is concrete: `accept4` returns EMFILE on Rust's
TCP thread, its catch-all error branch exits and closes the listening socket,
and the next UDP query reuses that descriptor. C retains its listener. The
TCP/main owner has the fix; the gate will not dynamically tighten the limit or
count later table-full replies as UDP socket-failure coverage.

Unsuccessful setup/calibration rounds are preserved. `c-baseline-01` used
RLIMIT zero and also invalidated poll, losing UBus metrics; `c-baseline-02`
corrects that boundary. Two isolated build attempts combined an old library
cache with newer main, then reused stale mtimes after archive extraction; a
fresh target directory fixed the build. `before-01` therefore had no binary.
`before-02` put unsupported user/group options in Rust's configuration and never
started the Rust service. The pending duplicate in `before-03` was submitted
after six Rust reply timeouts and could cross C's two-second late-duplicate
window; the corrected gate coalesces both recipients before the error sequence.

Host DNS tests (205 passed / four ignored) and all-targets Clippy with warnings
denied pass for the small daemon error mapping. Full acceptance is still open.
Transient send EINTR/EAGAIN retry behavior and failed same-frec client retries
need separate boundaries. Runtime entropy failure is not the same C contract:
`util.c::rand_init` reads and closes urandom at startup, then SURF generates IDs
in memory; Rust retains a fallible urandom reader. It never falls back to a
predictable ID, and this gate does not invent C runtime entropy-failure evidence.
