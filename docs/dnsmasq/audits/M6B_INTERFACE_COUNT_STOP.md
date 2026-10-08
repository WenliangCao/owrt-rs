# Interface same-cycle tracer stop handshake

Tool-only follow-up to the two `interface-enum-*-same-cycle` timeouts. The old
`stage=count` tracer checked `.stop` only after a syscall stop. Once both DNS
replies had arrived, a genuinely idle Rust daemon could remain inside `ppoll`
for its real timer deadline, preventing the controller's five-second wait from
finishing. This is a harness cleanup defect, not an extra DNS request to perform.

## Change and boundary

Only enumeration **count** attachment changes from `PTRACE_ATTACH` to
`PTRACE_SEIZE` with `TRACESYSGOOD`. An initial `PTRACE_INTERRUPT` freezes the owner
before the controller queues the existing UDP/TCP pair. `.ready`, `.go`, actual
queued packets, topology, answer checks, enumeration events and poll-cycle
checks remain in place. Fault-injection stages retain their existing attachment
and injection path.

After receiving and validating the two replies, `stop_enumeration_count()`
atomically publishes `.stop`. The tracer's `waitpid(WNOHANG)` loop checks that
marker at intervals of at most its requested one-millisecond sleep; it never
blocks indefinitely in `waitpid`. If the owner is still running in `ppoll`, the
tracer issues `PTRACE_INTERRUPT`, waits at most two seconds for a real ptrace
stop, and detaches. The controller retains a five-second exit gate. No request,
HUP, reload, SIGCONT or normal daemon signal is added. No signal is sent to the
tracer, avoiding a notification-versus-exit race.

A kernel interrupt may produce a syscall-exit-stop. The active syscall and raw
detach stop are recorded as `trace_control.cutoff_syscall` and `detach_stop`.
That cleanup stop does not create a normal completed poll or enumeration event.
Existing events/polls are retained; `syscalls` additionally records actual
entry/exit stops processed before the cutoff. These instrumented counts are
never product throughput/CPU evidence.

Non-`TRACESYSGOOD` stops are classified separately. Real signal-delivery stops
are resumed or detached with their original signal. Real group-stops use
`PTRACE_LISTEN` instead of spuriously running the owner. At detach, only an
already-observed external stopping signal is requeued to preserve the stopped
state; an initially group-stopped daemon is rejected as a valid count fixture.
Signal/event stops and the original initial stop are retained in the report.
The Linux [ptrace contract](https://man7.org/linux/man-pages/man2/ptrace.2.html)
defines the interrupt, restart and group-stop behavior used here.

Failure cleanup first requests the same graceful stop with a distinct
`controller cleanup` marker; it cannot claim both replies were received. A
tracer exceeding the controller bound is killed and rejected, with
`forced_kill` and its exit retained in `.controller.json`. Tracee exit,
unexpected events, failed detach and missing interrupt acknowledgement are
failures, not successful cleanup. The count witness additionally requires
`completed` and an acknowledged `detached` receipt.

## Prepared checks and remaining qualification

`test_m5_interface_count_stop.py` prepares 14 offline controls for blocked
ppoll, already-waitable stops, EIO interrupt races, original signal delivery,
group-stop handling, initial freeze, running-owner cleanup, two-second timeout,
owner exit, controller notification/abort and forced-kill rejection. A fake
AArch64 syscall sequence also checks that an interrupted second ppoll remains
a cutoff: two entries, one real exit and one completed poll, without a fabricated
extra completion.

**No tests, builds or Oracle runs were performed in this task.** Main must run
these offline controls and rerun both fresh mirrored-C/Rust same-cycle cases
before declaring the harness defect closed. The rerun must retain the complete
trace reports and controller receipts and satisfy the unchanged answer,
enumeration-family and poll-cycle assertions. This change touches no product
source and opens no new behavior exception.

## Offline ABI correction

Root's first actual offline run retained seven failures out of 14 in
`E/M6B/interface-ae1-failed-01/count-stop-unit.log`. All seven rejected event 128
because macOS `WSTOPSIG(status)` shifts by eight without masking Linux ptrace's
high event byte. macOS additionally treats stopping signal 19 as continued,
and its SIGSTOP/TSTP numbers differ from Linux. The initial mocks encoded a
Linux event status but then used the host's incompatible wait macros.

Count-stop decoding now explicitly uses the already-pinned Linux wait ABI:
low byte `0x7f`, stopping signal `(status >> 8) & 0xff`, event `status >> 16`;
SIGTRAP 5 and the four job-control signals 19/20/21/22. These fields match
[Linux signal UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/signal.h)
and [Linux wait macros](https://github.com/bminor/glibc/blob/master/bits/waitstatus.h).
Fixtures likewise use Linux signal numbers. Unknown events and invalid event-128 signals remain
rejected, and their already-reaped stop remains available to failure detach.
This follow-up did not run tests, builds or Oracle; root must rerun all 14
controls and both real Linux same-cycle pairs. The original failed run remains
red evidence, not a product failure or a successful gate.
