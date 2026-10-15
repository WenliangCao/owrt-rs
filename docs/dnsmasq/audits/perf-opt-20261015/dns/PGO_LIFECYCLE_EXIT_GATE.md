# Training-only lifecycle exit evidence

The existing `device_perf_lifecycle.c` considers a reaped child successful
without checking its wait status; it also accepts ECHILD. Its ordinary
helper exit code therefore cannot establish every daemon's normal-zero exit.
This is a prospective PGO training evidence gap, not a retrospective change
to the frozen performance measurements.

The [small training fragment](../../../../../tools/dnsmasq/pgo_lifecycle_exit.c)
replaces only that source's `end_child` block in a private generated copy.
It preserves the launch/configuration/query workload, two-second TERM grace
and forced-KILL cleanup. Every reaped or failed wait emits one
`pgo_child_exit` JSON row with PID, raw wait status, wait errno, exit code,
signal and forced-cleanup flag. Only a normally exited status-zero child
passes. The initial config-mode daemon uses this same endpoint and is
recorded even though it is absent from the 20 measurement rows. The original
helper source and all frozen helper binaries remain unchanged.

The [local regression](../../../../../tools/dnsmasq/test_pgo_lifecycle_exit.py)
compiles a temporary copy with this exact fragment and exercises real children:
exit0 passes; exit7, SIGKILL termination and an already-reaped child fail with
one recorded row each. All four outcomes pass their assertions. The Mac test
defines the unavailable `SOCK_CLOEXEC` macro as zero solely to compile unused
original Linux socket code; it executes no socket/lifecycle workload. That
test-only portability flag is not part of the future Linux training build.

The first local compile exposed that Mac-only macro absence before executing
any case; the portability adaptation above resolved the test harness issue.
Actual Linux helper compilation and training remain pending. The future
training manifest must bind the original source, replacement fragment,
generated complete source, compiler command and final helper ELF. All
profile collection and correctness failures remain visible; none may be
replaced by a successful retry within the same attempt.
