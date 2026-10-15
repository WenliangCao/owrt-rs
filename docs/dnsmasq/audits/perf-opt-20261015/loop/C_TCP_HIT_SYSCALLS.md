# Candidate C TCP-hit syscall follow-up

One fresh window used the unchanged `--strace` mode with exact candidate C
`b4c4a8e…` and its `9ed8e0a…` map. All 1000 warmup and 4000 measured queries
were correct, without skips/timeouts/wrong replies/transport errors. Upstream
traffic was limited to the 800 UDP prewarm requests. No product/tool change or
additional capture followed. [The receipt](owner-syscalls-c-tcp-hit.json)
binds the raw files, source review and verified 9195-byte derived-summary copy;
the raw trace remains on Oracle.

| Observed invocation | Count |
| --- | ---: |
| `ppoll` | 5052 |
| `accept4` | 56 |
| `getsockname` | 56 |
| `ioctl(FIONBIO)` | 56 |
| `recvfrom` | 5000 positive reads + 8 EOF reads |
| `close` | 56 |
| `getpeername`, zero-timeout `ppoll`, syscall errors | 0 |

The ppoll count includes the final detached in-progress wait. It is an entry
count, not 5052 completed waits. The window uses 56 downstream connections
including 48 reconnections; local endpoint and nonblocking setup each occur
once per accepted connection. No repeated per-query endpoint call was found.

There is a material filter limit: `trace=network,ppoll,close,fcntl,ioctl` omits
`writev` and ordinary `write`. `TcpWriteFrame::write_from` calls the standard
vectored writer; the pinned Rust 1.98.1 Unix path delegates to `libc::writev`,
which is also present in C's exact link map. Its absence from this trace is
not a zero-send result. Reply-write counts and read-to-send syscall adjacency
are unmeasured; the filter was not changed and the window was not repeated.

Frozen source `f7f7a2e` shows no unconditional wait added by `queue_answer`:
the ordinary complete-query path sets `writable=true`, and the next iteration
of the existing eight-step work loop attempts the answer write. Partial writes,
EAGAIN and the fairness budget still yield as designed. Reading clears its
readiness flag before the actual receive; after the answer, fully consumed
input waits for new readiness. The 5000 positive receives, eight final EOFs
and no receive errors are consistent with that path, rather than a terminal
EAGAIN receive after every answer.

This window therefore does not demonstrate redundant per-query endpoint or
zero-timeout polling work. It does not establish that remaining waits, writes,
kernel work or TCP lifecycle costs are irreducible. All strace timings remain
excluded from performance acceptance; the prior PMU kernel sample proportion
is not converted into a CPU-cost bound.
