# R100: registration reply/event candidate CPU comparison

Status: the 30-window router series completed and passed collection/cleanup validation. The candidate remains experimental; no deployment or automatic retention decision follows from this report.

## Measurement

The exact AX3000T router ran three separately planned comparisons: the exact image C daemon, formal R89, and the repaired accepted Rust baseline (`042610fd…`, event-epoch fix). The candidate is the repaired R100 registration stack (`5083f49b…`), combining the fixed DATA reply path, borrowed credentials, event borrow/lazy path and fixed stack reply, rebased on the epoch repair. Each comparison has ten independent physical windows. In each window two daemons were started independently and pinned to CPU 1; one serial Rust benchmark client was pinned to CPU 0. Ten ABBA/BAAB quartets gave 20 equal-size segments per side. The segment totals were aggregated before calculating one ratio per window.

CPU clocks were read around the complete ADD/REMOVE loop, outside the loop. The benchmark validates the full method signature and final empty lookup outside measurement. Each window records daemon/client PID, start ticks, masks, clocks, frequencies, binary identities and cleanup. All 30 windows passed with unchanged boot/configuration/host mounts and production C.

The verifier reports exact rank intervals with 12 planned intervals per comparator (three comparators × four metrics). Segment observations are not independent trials. Effects below are candidate divided by baseline; negative means candidate used less CPU/time.

| Baseline | Daemon CPU median (interval) | Client CPU median (interval) | Total CPU median (interval) | Wall median (interval) |
| --- | ---: | ---: | ---: | ---: |
| Exact image C | −5.41% (−7.59%, −4.29%) | +0.16% (−0.86%, +0.73%) | −2.32% (−3.98%, −1.77%) | −3.23% (−5.70%, −2.07%) |
| R89 | −31.09% (−31.57%, −30.28%) | −0.69% (−1.20%, −0.34%) | −17.04% (−17.49%, −16.58%) | −12.35% (−13.95%, −11.44%) |
| Repaired Rust baseline | −21.96% (−23.33%, −20.95%) | −0.47% (−0.98%, −0.10%) | −11.37% (−12.34%, −10.77%) | −8.38% (−10.41%, −7.58%) |

Against C, the candidate's total CPU and wall intervals are entirely below one; the client CPU interval crosses one. Thus this test establishes a strong daemon-side and total loop improvement for this one-method registration workload, while not proving every client condition or whole-system superiority. The R89 and repaired-baseline comparisons are materially lower in all four metrics under this condition.

## Memory and correctness boundaries

The separate physical requested-Rust-heap diagnostic found unchanged retained heap and no higher construction peak in all seven registry scenarios, while the 128-object one-method case reduced allocation calls from 2090 to 1066 and reallocations from 1799 to 519. This excludes allocator rounding, RSS/PSS, kernel buffers, code and C-client memory.

The repaired u32 event epoch wrap is included in the candidate. The old omission was reproduced on the router and the repair passed 32 unit tests, seven byte-level protocol differentials and six host gates. The candidate passed 35 unit tests, the same protocol differentials, four physical heap windows and the rechecked recovery group. A first recovery run exposed an original-C `netifd` observation timeout; its evidence is retained, and the unchanged recovery group passed on a second run after the SDK build completed. No candidate failure is hidden.

An independent exact-image `libubus` C-client smoke passed full signature checking, fresh type IDs, final empty lookup, CPU masks and exact image library hashes. It is an instrumentation check only; its single paired result is not pooled with this Rust-client series or used as a performance interval.

Machine-readable data: [`r100-stack-cpu-summary.json`](r100-stack-cpu-summary.json), the three per-comparator result files, [`r100-stack-memory-results.json`](r100-stack-memory-results.json), and [`r101-libubus-paired-smoke-results.json`](r101-libubus-paired-smoke-results.json). The router's final stock/cleanup evidence is recorded in `private/r100/registration-stack/final-health/`.

The candidate is not yet accepted as the new runtime. A complete exact-image C-client paired series and broader workloads remain before making a whole-component superiority claim. Other untested algorithmic directions also remain open.
