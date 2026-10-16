# Avoid clock reads whose wait diagnostics are disabled

Independent source722d2762 is a child of185, with only an eight-line/two-line
main.rs change. It is not part of185's frozen build or next measurement.

The owner always computed `started.elapsed()` after poll, even when the
diagnostic feature's inline stub ignored it. A second fresh timestamp was also
obtained before indefinite polls, although `owner_poll_timeout` returns0 for
runnable work and−1 for no deadline without reading that timestamp. These
clock calls survive the original final local cross-link; they are not merely
dead source expressions already removed by LLVM.

The prototype skips elapsed measurement when diagnostics are disabled, and
uses the already captured timestamp when neither a deadline nor active
diagnostics needs a new pre-poll read. Some(deadline) retains a fresh read,
including runnable turns. Enabled diagnostics retain both the original fresh
start and elapsed interval. Its enable flag is fixed at construction; no
poll-time mutation changes that decision. Poll error recovery, readiness,
signal ordering, timeout ceiling/saturation and the one-hour recheck cap are
unchanged. The earlier upstream no-work clock guard is a different mechanism.

Default and m6b-feature musl all-target checks pass, and independent source
reviewc04e4d6a finds no boundary change. [Local final codegen](owner-clock-local-codegen.json)
shows wait_for_files7,304→7,192B with the same352B frame. Static calls to
Timespec::now decrease6→4 across the entire function, including conditional
branches. This is not six/four calls per query. Exact SDK, Linux runtime gates,
actual A53 clock frequency/cost and performance remain unmeasured. Keep this
separate; it cannot be added to185's expected or measured result.
