# UDP read-one: low-load mechanism works, high-load cost rejects this variant

The independent F/read-one screen completed all36 declared windows:4 strace,
12 separate grouped PMU and20 plain windows. All scheduled/sent/correct counts
match, cohorts are nonempty and timeout/wrong/transport/skipped counts are zero.
All PMU events are unscaled. The fixed single-packet variant is not selected:
the expected idle-load syscall saving comes with a substantial busy-load cost.

The shipping SDK F control reproduced ELF `b7926bcf…`; read-one is source
`4bd3c9a4…`, ELF `5216c41d…`. Both are2136859B. These compare independent F
artifacts, not E or exact C, and do not change the accepted E baseline.

CPU, PMU and syscall per-query values use the actual warmup plus measurement
completion count (5000 at low load). The observation also includes the fixed
one-second grace. Throughput and latency use only the 20-second measurement
cohort; the grace is not counted as an extra query.

| Observation | F | Read-one |
| --- | ---: | ---: |
| Low recvmsg/query | 2.000 | 1.000 |
| Low EAGAIN receives /5000 queries | 5000 | 0 |
| Low ppoll entered/query | 1.0002 | 1.0002 |
| Low sendmsg/query | 1.000 | 1.000 |
| High recvmsg/query (traced) | 1.000003 | 1.000000 |
| High ppoll entered/query (traced) | 0.062505 | 1.000005 |

The extra entered ppoll at each observation boundary is retained rather than
counted as a completed query. One final high-load F EAGAIN is also retained.
Traced query counts are 295079 and 191586; traced throughput is not a speed
measurement. JSON retains all observed syscall kinds, selected parameter
counts on completed calls, and pending syscall names. It does not contain
every per-call argument: the full trace remains private, and the pending
boundary `ppoll` is listed by name without its arguments.

The parameter aggregates show receive flags `0`, iovec length 65535 and
control length `0`; sends show flags `0`, lengths 48/60 and control length `0`.
Completed polls show six descriptors, an infinite timeout and six `POLLIN`
interests. Receive iovec/control fields are counted only as many times as
successful receives, rather than all completed calls including EAGAIN. Errors,
fd roles and flags are retained, but the derived file cannot establish full
message/iovec arguments for each failed receive.

| Plain five-pair result | F median | Read-one median | Change | W |
| --- | ---: | ---: | ---: | ---: |
| Low CPU µs/query | 28 | 24 | −14.286% | 16.667% |
| Low p50 µs | 53.281 | 48.041 | −9.835% | 13.889% |
| Low p95 µs | 82.600 | 79.041 | −4.309% | 14.771% |
| High CPU µs/query | 4.6747 | 6.0222 | +28.826% | 1.359% |
| High completed queries/s | 213790.90 | 166067.75 | −22.322% | 1.189% |
| High p50 µs | 144.721 | 188.802 | +30.459% | 1.314% |
| High p95 µs | 159.401 | 207.042 | +29.888% | 2.724% |

Low CPU is five pairs in the favorable direction, but the median difference is
only2ticks, below the strict >8-tick threshold, and smaller than W. No low-load
CPU/latency improvement is accepted. High CPU/throughput/latency changes are
all five pairs in the adverse direction and exceed W. High CPU uses the actual
variable query counts and is descriptive saturation evidence; the fixed-N
acceptance tick-difference rule is not applied to it. Sender CPU is 99.60–99.89%
in the high plain windows, and the daemon also consumes nearly one CPU. The
high PMU windows show 99.56–99.63% sender CPU; the heavily instrumented high
strace windows show only 9.00–13.64%. The plain rates are observed closed-loop
pipeline rates, not an isolated server capacity estimate.

| Median PMU /query | Low F | Low read-one | High F | High read-one |
| --- | ---: | ---: | ---: | ---: |
| User instructions | 8955.75 | 8693.00 | 6766.38 | 8698.74 |
| User cycles | 20564.07 | 20386.83 | 4409.10 | 6278.57 |
| Kernel instructions | 32835.57 | 23898.15 | 12996.13 | 15678.35 |
| Kernel cycles | 50647.36 | 42258.21 | 9512.18 | 11617.99 |
| Per-window user IPC median | 0.43550 | 0.42638 | 1.53460 | 1.38546 |

The low saving is primarily kernel work. At high load, the original bounded
batch amortizes poll and owner work over16 packets; read-one pays it for each
packet. This motivates a separate idle/busy scheduling prototype that reuses
the owner's existing poll-wait duration, rather than selecting this variant
or hiding its high-load regression. The independent local/cache layout screen
still runs before any next candidate decision.

The first wrapper attempt failed before daemon or window creation because it
used the unit-test PID namespace rather than the existing profile netns-only
wrapper; it remains in `udp-read-one-screen1`. No measured window was rerun.
The raw analysis also retained two failed invocations (missing parser import,
then read permission on the root-owned daemon log); adding the exact helper
and using read-only sudo analysis reused all original captures. No product or
measurement code was changed for those analysis failures.

Raw evidence remains private on Oracle `root/private/udp-read-one-screen2`.
The complete derived file records every window, raw file digest, counters,
latency distributions and pair decisions:
[results](udp-read-one-screen-result.json),
[derivation using existing parsers](analyze_udp_owner_screen.py).
