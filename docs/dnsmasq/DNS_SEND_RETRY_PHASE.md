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
source run. Target `aarch64-unknown-linux-musl` checking, the changed-file
formatter check, Python compilation and the whitespace check also pass.

## Frozen Linux replay

Source commit `45a934a961266b2ef6771b43b873446a9448f40a` was built with native
Linux aarch64 Rust 1.98.1. Release ELF SHA-256 is
`0d7bad659dd8ae14fa664410da7f9117f3b59eeaa3049e4f8aca083e4c3a4009`.
The product upstream.rs SHA-256 at this build is
`9193160a246a244e4714254d2713762202765baf177a0426c4cd3a88c666a2b5`;
the later safety-comment clarification changes no executable code.

- `helper-paired-01`: 53/53 source-derived cases match, with the same 33,068
  sends and 32,018 waits. `helper-negative-01` exits 1 with exactly one altered
  wait trace and 52 matches. Both source and binary identities are recorded.
- `dns-tests.log`: DNS tests inside a new loopback-only namespace pass
  209/0/4 ignored, including all four new transport/wait regressions.
- `daemon-paired-01`: the unchanged actual-daemon initial-failure gate passes
  all seven profiles and 61/61 ordered observations. Real no-route and UDP
  socket-EMFILE coverage remains satisfied, no poll EINVAL occurs, all 30
  counter fields match, mixed-server success and unrelated pending recipients
  survive, stale failure sends no second reply, and processes exit normally.
  Its counter-mutation and missing-observation calibrations remain active.

The native C ELF is unchanged:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Private evidence is retained remotely at
`/home/ubuntu/dns-resume-send-20261001/private/` and locally under the isolated
`private/dnsmasq-rewrite/resume-send-retry-20261001/private/linux-45a934a/`.
The host helper rounds are in that worktree's `private/send-retry-host-*`.

The syscall wrapper is validated for the project's 64-bit Linux/Darwin hosts
and aarch64 target contract. It is not a portability claim for 32-bit musl's
time64 ABI. Transient send outcomes are controlled helper/transport evidence;
the actual daemon replay covers hard failures, not naturally occurring EAGAIN
or signals interrupting a real exhausted send sequence. No target execution,
performance or whole-component acceptance is claimed.
