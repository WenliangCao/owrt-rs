# Owner wait interface and bounded cost hypothesis

Local-only audit during D's exclusive Oracle run. No Oracle command, build,
capture, product edit or backend implementation was performed. The inspected
main/upstream/ubus-sys/logging/dump files match frozen C `f7f7a2e` exactly.

`SinglePoll::wait_for_files` has concrete per-wait userspace work: it clears
and repopulates a retained descriptor Vec, computes deadlines and runnable
state, and scans returned entries into per-client and per-subsystem readiness.
Ordinary waits do not allocate a fresh Vec. This work is separate from actual
packet reads/writes. The kernel's descriptor-count-dependent poll setup and
scanning remain a plausible cost, but existing measurements do not isolate
that cost from sleeping, wakeup, network work and instrumentation.

## Existing counts and precision

The [C TCP-hit syscall receipt](owner-syscalls-c-tcp-hit.json) contains 5052
ppoll invocation entries, including the final detached wait. 4910 calls
(97.19%) contain 14 poll-array entries; the mean is 13.88, with 70,131 total
entries across the capture. The trace abbreviates the arrays, so these are
entry counts, not a proven count of distinct descriptors. Duplicate interests
are supported by the implementation. No zero-timeout ppoll was observed;
retained examples use the TCP deadline (about 150 seconds), with NULL when
idle. A complete timeout histogram was not retained in the small receipt.

The [C TCP-hit PMU receipt](owner-profile-c-tcp-hit.json) attributes 139 of
20,006 samples (0.695%) to `wait_for_files` itself. That excludes separately
attributed callees and is not an exact CPU bound. The large kernel-mode sample
proportion cannot be assigned wholesale to descriptor scanning.

The retained device TCP-hit comparison has p50 −4.06% against W=4.20%, and CPU
158→154 microseconds/operation against W=5.19%, only three concordant pairs and
failed CPU precision. The frozen greater-than-eight-tick requirement means a
median difference greater than 16 microseconds/operation for 5000 operations
at 100 Hz: about 10.13% of 158 or 10.39% of 154. This is precision context,
not qualification of the globally invalid C device attempt.

There is no supported case for adding persistent owner state merely to reduce
the sampled userspace reconstruction. The remaining kernel cardinality term
is not bounded by the prior one-fd zero-timeout screen. Multiplying that screen
by the current poll count gives a rough 3.14% instruction projection, but it
neither represents 14 entries nor an actual sleeping wait and is **not** a
valid upper bound for this hypothesis. The evidence does not establish that
all readiness work is below variation or irreducible.

## Interface and compatibility constraints

- **Call and ownership boundaries:** the normal daemon loop calls `step`, then
  `wait_for_files`. DHCP probing has a separate `wait_during_probe` wait that
  publishes into the same readiness fields while the lease provider is
  borrowed. It intentionally leaves signal/reload/inotify/route/DHCP work for
  the outer owner. A persistent global interest set cannot silently change
  that subset or reentrancy boundary.
- **Descriptor lifetime:** listeners are added/removed, clients use
  `swap_remove`, upstream sockets carry monotonic tokens, and logging, UBus,
  file, netlink and TFTP descriptors can close or reopen. Current client slots
  are attached before each wait, so a newly accepted client cannot inherit a
  reused fd's readiness. A later persistent design would need equivalent
  owner/generation invalidation and cleanup on every close/error path.
- **Masks and duplicate interests:** TCP alternates read/write/upstream-fd
  interests and sometimes has no fd while waiting for MAC or runnable work.
  The same numeric fd can have multiple logical consumers/masks. Current
  `fd_ready` merges matching results without allowing POLLOUT to authorize a
  read. Deduplicating registration would still need correct per-owner delivery.
- **Admission gates:** listeners are omitted during initial files/interface
  work or when TCP capacity is full. Upstream empty-error retries suppress
  interests until their deadline. Keeping every live fd permanently enabled
  could wake repeatedly while the owner is unable to consume it.
- **Logical work and timers:** queued UBus methods, signal counters, buffered
  TCP tails, transport budget tails, completed logging, interface collectors,
  reloads and helper work can be runnable without kernel readiness. Preserve
  immediate runnable turns, millisecond rounding, idle infinite waits, the
  one-hour active recheck and missing-signal-pipe fallback. The existing ubus
  poll wrapper retries EINTR with its supplied timeout; this audit does not
  redefine that behavior.
- **Failures and fairness:** preserve ERR/HUP/NVAL handling, normal poll-wide
  error propagation, duplicate-mask behavior, the 16-UDP-packet budget, the
  eight TCP work steps and timer/reply ordering. Changing to edge-triggered
  consumption cannot assume these consumers drain every source to EAGAIN.
- **Descriptor kinds:** this interface also accepts logging/stdout/stderr and
  dump-file interests, not only sockets. `Destination::File` and dump queues
  expose owned file descriptors while pending. Any backend proposal must
  establish support or a compatible fallback for these kinds and for reopen
  and FIFO transitions, rather than assuming uniform socket registration.

Existing tests already exercise duplicate masks, newly accepted client slots,
signal counters without pipe bytes, buffered TCP tails, transport budget tails,
upstream timeout-only wakes, and normal/probe-owner progress. They were read
here, not rerun or counted as fresh passes.

## Small next screen, only after timing release

The existing `loop_ppoll_screen.c` can support a bounded descriptor-count
screen without introducing a framework or product backend. Its current form
has one UDP socket and only zero-timeout skip/empty/ready loops, so it cannot
answer the 14-entry question as-is.

A narrow follow-up could parameterize that same file for 1, 6 and 14 separate
pre-created descriptors, retaining its explicit assertions and source/ELF
receipts. Compare zero-timeout empty calls and already-ready calls with the
ready entry first and last; also use a nonzero timeout on an already-ready
set, which returns immediately. Include a same-length skip control so array
handling is not attributed entirely to the syscall. Count instructions only,
outside the timing reservation, with the same compiler and fixed iteration
count. No socket creation or closure belongs inside that count loop.

The useful result is the incremental 14-versus-1 cost, projected with the
observed nfds distribution. Treat removing all of that incremental work as
an optimistic screen before bookkeeping costs. It still would not measure
the true sleep/wakeup registration path: that requires a separately controlled
wakeup experiment if the initial screen is material. No such extension or
experiment is implemented or authorized by this audit, and no epoll design is
selected. Only a meaningful mechanism result should justify further scope.

Reviewed main SHA256: `18d170499a393ada3e2c4af7fdf00b49a92794dee982761a476a8f6745729283`.
Existing harness SHA256: `4978ae52c95be1cfaccb5efea89b734430ee310bd92d0c88db738c5029b6e5de`.
Retained C summary SHA256: `6cfcf047f3c7550e28780944e4431beae4aaf3909e0d84f0ab2ba60c0587a052`.
