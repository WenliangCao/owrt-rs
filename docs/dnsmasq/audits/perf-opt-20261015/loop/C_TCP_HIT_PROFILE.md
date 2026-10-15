# Exact candidate C TCP-hit attribution

The remaining DNS scene was captured once using the unchanged existing
profile tool and exact C `b4c4a8e…` / map `9ed8e0a…`. The
[receipt](owner-profile-c-tcp-hit.json) completes the five DNS scenes' current
C coverage. All raw files remain on Oracle; only a verified 16,708-byte derived
summary was downloaded during the device run.

The parent was prewarmed with 1000 correct UDP queries. Its upstream observed
exactly 800 UDP requests/replies, matching the 800 distinct hot names, and zero
TCP requests. The subsequent TCP warmup/measurement completed 1000/4000 correct
queries without errors or skipped operations. There was no additional upstream
traffic after the required prewarm misses. ELF/map/process mappings and the
perf enable/disable ACK brackets passed; 20,006 samples had zero reported loss.

## Process scope

The recorded PID and every sample PID/TID are `4170432`; the saved process stat
reports one thread. The saved perf event attributes have `inherit=1` for the
instruction event and `inherit=1,task=1,mmap=1,mmap2=1` for metadata. Inherited
work was not disabled through `--no-inherit`.

The analyzer **rejects** a sample PID different from its recorded daemon. It
does not silently remove child userspace samples, but it is also not a generic
fork-worker aggregator. The frozen C source clarifies the applicable model:
`--keep-in-foreground` bypasses startup daemonization; `finish_tcp_accept`
constructs `TcpDnsWork` and private hosts/cache snapshots in `SinglePoll.clients`;
`step_tcp_clients` runs them in the same daemon thread. These snapshots are
objects, not child processes. Thread spawns in the inspected DNS source are
test code. The sample inventory therefore matches the configured C TCP owner.

A separate live task/children read arrived after the daemon had exited and
failed with ENOENT. No successful live child census is claimed. This profile
covers the observed daemon context, including its kernel-mode execution;
it excludes the separate load generator/upstream and systemwide kernel work.

## What the samples support

19,311 samples are kernel mode; 659 are attributed target userspace and 36 are
explicit vDSO samples. The 96.53% kernel-mode sample proportion is **not** an
exact CPU share, complete system cost or evidence that TCP is irreducible.
There are only 695 user-mode samples, and inlining/sample skid limits fine
attribution.

The largest named user sections are `SinglePoll::wait_for_files` (139 samples),
cache answer-record processing (53), time subtraction (39), `step_udp` (34),
`step_tcp_accept` (31), and `TcpDnsWork::answer_query` (24). Explicit allocator
and drop labels total only 39 samples (0.195% of all samples), including 18 in
free and 13 in malloc. No separately attributed clone label establishes a
dominant cloning cost; inlined cloning can reside in a caller's section.

Source confirms accept-time hosts/cache/service snapshots and per-answer owned
buffers. This profile supplies neither allocation counts nor byte counts and
does not justify an allocator or snapshot-lifecycle rewrite. A targeted
mechanism screen would be required for any such later proposal.

The simultaneous PMU total is 263,529,427 instructions, versus 277,771,676 in
historical A's separate diagnostic. A ran nice0 and C nice10; the difference
is not a paired performance result. Device acceptance remains the coordinator's
unchanged five-pair workload/statistical decision.

The first remote analyzer invocation could not locate an unversioned
`llvm-cxxfilt`. A private PATH alias to the installed `llvm-cxxfilt-18` allowed
the unchanged analyzer to finish. No code, measurement window or result was
replaced, and no additional runtime capture followed.
