# UDP upstream transient send retries

The UDP resolver now retries EINTR and EAGAIN/EWOULDBLOCK on the same socket,
packet and selected server, following the pinned `util.c::retry_send` and
`forward.c::forward_query` caller. Previously those errors immediately advanced
the server plan or reached the daemon's local REFUSED/EDE 23 fallback.

The source contract is precise:

- EINTR resets the consecutive would-block retry count and retries immediately.
- Each would-block result waits with `nanosleep({0, 10000}, NULL)`, including
  the final attempt. An uninterrupted exhausted sequence has 1,001 send calls
  and 1,001 waits, with 1,000 additional send attempts.
- C checks errno after nanosleep. If the final wait is interrupted, it resets
  the count and retries instead of returning the original EAGAIN. The Rust
  wrapper keeps that boundary visible rather than hiding interruptions through
  `thread::sleep`. Earlier interrupted waits still consume an attempt.
- Other send failures finish that candidate immediately. Success elsewhere in
  the same plan wins; forwarding is counted once per successful action, not
  once per attempt or server. No successful candidate leaves the existing
  terminal error/cancellation path in control.

This is an attempt bound for consecutive would-block sends, not a one-second
wall-clock guarantee. Repeated EINTR or interrupted final waits can restart the
budget, as in C. No new socket, queue, allocation or resolver field is introduced.
The small private I/O hook exists to exercise the actual send-plan bookkeeping
with real owned sockets and controlled syscall outcomes.

The existing safe rejection of an impossible partial UDP send remains: Rust
returns WriteZero, while the C helper treats any nonnegative result as success.
Failed retries of an already forwarded client request remain a separate caller
policy audit; this change does not claim to close that contract.

## Source-derived oracle

`dns_send_retry_diff.py` verifies the complete pinned util.c and forward.c
hashes, copies the unchanged C retry_send function into a private driver, and
replaces only nanosleep with a controlled recorder. It extracts the private
Rust helper directly from current product source. Identical input streams
control send returns, send errno and wait errno. C runs first; Rust never
generates expected output. Results compare final return/error, attempted sends,
wait counts and the exact interleaved send/wait sequence. Successful C calls
must also clear a preexisting errno. Several calls run in one process, preserving
C's function-static retry counter across call boundaries.

Host `send-retry-host-02`: **53/53 cases**, **33,068 sends**, **32,018 waits**,
zero differences. The negative run adds one wait to Rust's observed trace:
52 matches, one difference and exit 1. Missing rows are independently rejected.
Coverage includes both would-block errno names, 999/1,000/1,001 boundaries,
EINTR resets, terminal errors, and sleep interruption before and at exhaustion.
This is controlled helper evidence, not naturally occurring network pressure.

Host Rust 1.98.1 DNS tests pass **209/0/4 ignored**; all-targets Clippy with
warnings denied passes. New transport tests exercise real socket identity,
unchanged bytes/destination, recovery after injected transient errors, exhausted
candidates on either side of a successful server, one forwarding increment,
terminal/partial sends and socket cleanup. A real nanosleep call checks the
native timespec boundary. An initial test compile omitted the second unwrap
of `Result<Option<Vec<u8>>>`; it ran no tests and was corrected before these
results. The earlier host helper run remains separate from the final formatted
source run. Linux replay and affected actual-daemon gates follow on a frozen
commit; no target, performance or whole-component acceptance is claimed.
