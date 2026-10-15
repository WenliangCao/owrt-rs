# Prepared descriptor-count control

Only `tools/dnsmasq/loop_ppoll_screen.c` was extended. No product/backend/API
or driver framework changed. The file is prepared locally; no Linux compile,
Oracle execution or performance result is claimed. Oracle work must wait for
the coordinator to release D's exclusive timing reservation.

Independent static review found no blocker under the existing assertion-enabled
`gcc -O2 -Wall -Wextra -Werror` build. The file explicitly rejects `NDEBUG`,
because its assertions perform required I/O. Compile/runtime validation is
still pending. New helper/setup and skip-loop overhead means old one-fd data
must remain historical evidence, not pooled as a byte-identical control.

Invocation is `MODE ITERATIONS [FDS [READY_INDEX]]`. Existing `skip`, `empty`
and `ready` commands with only MODE/ITERATIONS keep their one-UDP-descriptor
behavior and existing JSON result fields. Optional FDS is restricted to 1, 6
or 14; READY_INDEX can select the first or last entry. All descriptors are
distinct and created before the iteration loop.

| Mode | Readiness and timeout | Interpretation |
| --- | --- | --- |
| `skip` | Scan initialized revents without a syscall | Userspace control for the chosen array length |
| `empty` | Idle UDP descriptors; zero timeout | Immediate empty scan, never a blocking-wait control |
| `ready` | One queued UDP datagram remains unread; zero timeout | Immediate ready scan |
| `ready-wait` | Same queued datagram; one-second timeout | Already-ready finite-timeout path, not proof of blocking |
| `deferred` | One timerfd plus idle UDP descriptors; infinite timeout | Periodic deferred-readiness control, with evidence below |

The deferred timer is armed once at a 1-ms period. Every iteration makes one
**additional one-fd zero-timeout precheck**, then the N-fd wait, then one
nonblocking eight-byte timer read. The precheck and timer read are common work
for every cardinality. Compare 1/6/14 **within the same mode**; never treat the
deferred total as application cost or subtract a zero-timeout mode as though
it removed only registration. External perf also counts process setup,
cleanup, assertions and JSON output. The final interpretation must retain
those fixed overheads.

The JSON separately records prechecks that found readiness already present
and absent, total/max timer expirations, reads with coalesced expirations,
poll EINTR retries, and voluntary/involuntary context-switch deltas around the
loop. A nonzero timeout alone does not establish a blocking control. Absent
readiness before waits together with voluntary switches supports actual
deferred blocking; a timer can still fire between the precheck and the main
wait, so the precheck count is not an exact count of blocked waits. Context
switches are process totals rather than a scheduler trace. Preserve immediate
readiness and coalescing differences instead of discarding or replacing an
unfavorable run. No wall-time acceptance result is emitted.

The old immediate cases allow up to one million iterations. Deferred runs are
capped at 10,000 to bound the intended timer workload; scheduling can extend
their elapsed duration. A small first run after authorization can use 100,000
immediate iterations and 1000 deferred iterations, with identical compiler,
affinity and counts across each 1/6/14 comparison, inside the existing
loopback-only namespace wrapper. First/last-ready placement
is an explicit dimension, not a best-result selection. Record all source,
ELF, command, perf and JSON identities using the existing evidence process.

This measures a primitive cardinality term. Timerfd wakeups are not TCP packet
arrivals, idle UDP descriptors do not reproduce every owner descriptor type,
and no registration churn is modeled. Results can justify or reject further
bounded research; they cannot select a persistent backend, claim an epoll
speedup or replace the frozen complete-workload gates.
