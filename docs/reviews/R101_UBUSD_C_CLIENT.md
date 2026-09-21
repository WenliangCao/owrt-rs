# R101: exact-image C caller cross-check

Status updated 2026-09-21: the ten-window physical C-caller comparison is complete. The smoke and collection notes below record the earlier stage; see the completed series at the end.

The R100 CPU series uses a frozen Rust caller. A separate caller using the image's original libubus is needed to establish whether daemon improvements transfer to C applications. Results from different callers must not be pooled.

`tools/benchmark/register_libubus.c` registers and removes `bench.cycle`, with one eight-byte method name and one INT32 policy. Preflight checks the entire signature payload and object/type identity. Every timed cycle requires a fresh type ID before ADD and cleared object/type IDs after REMOVE. The final lookup must be empty. Warmup and signature lookup are outside the measured interval; clocks are read only around the complete loop. External daemon process CPU, caller process CPU and monotonic wall time are recorded separately. Only the disposable caller is pinned by the client; the harness starts its daemon on CPU 1 and the caller checks both masks.

The exact source revision's `libubus-obj.c` clears the cached type ID when REMOVE replies with OBJTYPE. This ensures repeated single-object registration rebuilds its signature rather than silently benchmarking cached-type reuse. See the [upstream implementation](https://lxr.openwrt.org/source/ubus/libubus-obj.c); matching local revision `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` is authoritative. CPU clock semantics were checked against [clock_getcpuclockid](https://man7.org/linux/man-pages/man3/clock_getcpuclockid.3.html); affinity checks follow [sched_setaffinity](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html).

## Build and runtime identity

The image libraries lack ELF section headers and cannot be used directly as linker inputs. `build-register-libubus.sh SDK COMPONENT_SOURCES NEW_OUTPUT_DIR` rebuilds matching sources solely to supply linker symbols and the image's SONAMEs. Never upload its `link-only/` directory. Only the client ELF is uploaded. Its dynamic dependencies are libubus.so.20251202, libubox.so.20260213, libgcc_s.so.1 and libc.so, with no RPATH/RUNPATH. The smoke unsets LD_PRELOAD and LD_LIBRARY_PATH and hashes all four image libraries before and after execution. These hashes match the extracted image.

The client was built with SDK GCC 14.3, -O2, -Wall -Wextra -Werror. The SDK's emulator wrapper emitted ignored runas.so preload diagnostics; compilation and linking exited zero. Public build wrapper syntax was checked; the equivalent private build commands produced the tested artifact.

## Physical smoke

One guarded router namespace ran C, accepted epoch-fixed Rust and the experimental stack/event candidate sequentially, each with 100 warmup and 1000 measured cycles. All protocol and clock checks passed. Subject PID/start time and single-thread status remained stable. Production C, boot, configuration and host mounts were unchanged, and cleanup passed. Identities are recorded in `r101-libubus-client-smoke.json`.

These short runs validate the instrument, not relative speed. No C-client calibration or complete paired comparison exists yet. Future measurement must also validate the per-window process identity, library hashes and aggregated sampling unit before making an inference. RSS/PSS, kernel buffers and integrated-system behaviour remain outside this diagnostic.

## Paired collection tooling

The new paired harness alternates ten ABBA/BAAB quartets with serial requests. It records subject stat/status before and after every segment, frozen library hashes and all existing router cleanup checks. The report validates identity, start ticks, one thread, masks, full signature/type-reset checks, positive bounded CPU intervals and exact segment count. It aggregates equal-size segments into one ratio per physical window.

Four verifier tests include thirteen corrupted-field cases, PID reuse, affinity/thread changes and a process name containing parentheses. They pass, as does verification of all three real smoke samples. The full paired harness has not yet run on the router; its single-window smoke plan is frozen separately. It will run only after the current R100 series and cleanup. No C-caller performance inference is authorized by this smoke.

## Completed paired comparison and 2026-09-21 evidence audit

The ten-window series in [`r101-libubus-cpu-results.json`](r101-libubus-cpu-results.json)
compares the R100 stack/event candidate `5083f49b…` with the exact image C daemon,
using the exact image libubus caller. Each side completed 200,000 timed cycles per
window; 40 serial segments produce one paired ratio, not 40 independent trials.
On 2026-09-21 the raw files were rechecked with `verify_window`: all ten archive
hashes, result hashes, aggregates, paired ratios and exact rank intervals match
the committed report. Production C and cleanup checks passed in every window.

| Metric | Candidate/C median change | Exact median rank interval |
| --- | ---: | ---: |
| Daemon CPU/cycle | −5.66% | −6.29% to −4.10% |
| Caller CPU/cycle | +0.27% | −0.12% to +0.44% |
| Daemon + caller CPU/cycle | −2.85% | −3.13% to −1.93% |
| Wall time/cycle | −3.92% | −4.65% to −2.35% |

These are the four frozen family-adjusted intervals, subject to the independent
paired-window assumptions. Caller CPU is unresolved, not proven equal. This is
one-method, eight-byte-name registration with this caller; it is not a tail-latency,
RSS/PSS, all-registration or full-system verdict. It is not pooled with R100's Rust
caller, nor is the combined gain attributed solely to the reply allocation change.
The measured ELF is R100; R103 later retained these changes and additionally changed
user-event handling. The source was accepted in `bd6b6db`; no deployment followed.
