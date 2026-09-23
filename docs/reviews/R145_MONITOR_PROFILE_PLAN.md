# R145 monitor profile preparation

This is diagnosis of the existing exact C and generic R136 daemons, not a candidate or a performance acceptance test. R142 remains rejected. Oracle sampling cannot establish the corresponding A53/router cost proportions or explain latency by subtracting CPU from wall time.

## Identity prerequisite

The R136 release is `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`. Its saved release and pre-sstrip artifacts contain no function symbols; no existing exact linker map was found. `tools/r145/build_symbols.py` reuses the frozen R135 recipe and R137 private namespace, the same 30 R140 control source inputs, original canonical path, toolchain and RUSTFLAGS. It runs a fresh original control followed by one diagnostic build using R121's `cargo rustc` final-link map option. Both full sstripped ELF hashes must equal R136. A text-only match is not accepted. This does not change the SDK, original artifacts, source or runtime configuration.

The C sidecar from R121 must match the exact C executable's allocated code bytes and addresses. The unchanged native monitor helper `1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499` has its own symbol table. Exact loaded musl/libubus/libubox libraries use verified dynamic function ranges; hidden functions remain unknown. Reuse `tools/r121_symbolize.py`, which does not invent nearest-symbol ranges or inline-call attribution. Host paths and build identities stay in the private records.

## Fixed collection budget (accepted before collection)

Four fresh-daemon phases, **C, R136, R136, C**. Each phase runs the original helper ten times as `event-stress SOCKET monitor 5000 SUBJECT_PID`: caller CPU0, daemon CPU1, original 20 warmups each invocation. Total: 40 invocations, 200000 measured cycles and 800 warmups. No extension based on sample count or results.

Reuse R121's one `cpu-clock` event at `-F 499 --strict-freq`, 8 MiB buffer, timestamps and periods, no callgraph or second event. Attach daemon sampling by PID; explicit enable/disable acknowledgements bracket each whole helper invocation. Caller sampling records the exact helper command separately. The helper has no perf handshake, so profiles include initialization, warmup, cleanup and output; they must not be described as sampling only the timed loop. Final launch commands and process-identity checks will be frozen before execution.

The existing **Oracle** C/R136 small-monitor data suggests about 3.3 seconds daemon CPU and 4.5 seconds caller CPU per phase, approximately 1640 and 2250 samples at 499 Hz. Estimated timed workload wall is 24 seconds total; orchestration and identity capture may bring this to 1–2 minutes. These are planning estimates, not a stop rule. If fewer than 1000 valid daemon samples arrive in a phase, retain the result as undersampled without collecting more.

Retain raw perf data, all IPs, reports, user/kernel mode, PID/MMAP/library identities, commands, affinity, helper correctness/cleanup and sample/loss/throttle records. Require zero lost/throttled events. Report both all-sample and user-only denominators, unknown fractions and separate daemon/caller results. Flat samples identify emitted-code self time, not calls, inclusive cost, waiting, or causal latency improvement. Allocation/copy/encoding attributions require exact symbol coverage; inlined work may remain inseparable.

The [Linux v6.17 perf-record source documentation](https://github.com/torvalds/linux/blob/v6.17/tools/perf/Documentation/perf-record.txt) defines PID attachment, frequency, strict-frequency failure, command recording and control acknowledgements. The [GNU ld documentation](https://sourceware.org/binutils/docs/ld/Options.html) defines map output. R121/R125 establish the local collection and symbol-verification precedent. No profiling starts until the private collection plan is frozen and root releases the launch.
