# Frozen G / 5c exact-SDK owner32 result

All 32 original windows completed once. High-load CPU/query and p50 were
discernibly lower under the original rule. High-load send-lag p95 was slower:
5.32 to 6.32 us, +18.797%, exceeding W=14.557%, all five pairs in the same
direction. Preserve that adverse sender diagnostic. Throughput, high p95 and
all low-load comparisons remain inconclusive.

This compares frozen G185 with `5c995a8564ce04b81e42c7f1c581bb06e691d87a`,
including inherited 6ab changes plus 025 and dump outlines. It is not an
isolated frame-only comparison and contains no 1df/803 overlay. The
[final plan](owner-ready-frames-owner32-plan.json) keeps the original windows,
workload, order, placement, counters and statistical rules. No native240 was
run; prior 6ab native adverse results remain evidence, not 5c measurements.

| Plain metric | G median | 5c median | Change | W | Same pairs | Original decision |
|---|---:|---:|---:|---:|---:|---|
| low CPU, us/query | 26.000000 | 26.000000 | +0.000% | 23.077% | 0/5 | inconclusive |
| low throughput, query/s | 200.000000 | 200.000000 | +0.000% | 0.000% | 0/5 | inconclusive |
| low p50, us | 52.320000 | 51.201000 | -2.139% | 16.435% | 2/5 | inconclusive |
| low p95, us | 79.001000 | 79.281000 | +0.354% | 20.535% | 3/5 | inconclusive |
| low send-lag p95, us | 82.047000 | 81.621000 | -0.519% | 3.771% | 3/5 | inconclusive |
| high CPU, us/query | 4.305274 | 4.250317 | -1.277% | 0.916% | 5/5 | faster |
| high throughput, query/s | 232292.650000 | 235238.000000 | +1.268% | 1.330% | 5/5 | inconclusive |
| high p50, us | 131.641000 | 130.001000 | -1.246% | 0.941% | 5/5 | faster |
| high p95, us | 146.721000 | 144.282000 | -1.662% | 1.690% | 5/5 | inconclusive |
| high send-lag p95, us | 5.320000 | 6.320000 | +18.797% | 14.557% | 5/5 | slower |

Low CPU precision fails: G ticks `[12,12,13,13,15]`, 5c ticks
`[13,12,14,14,13]`. High CPU uses variable query counts; its precision remains
null and the favorable decision is a saturation diagnostic, not a fixed-cohort
precision pass. High sender CPU was 99.583–99.901%; throughput and send lag
describe the pipeline, not isolated server capacity. Send-lag p50 is
inconclusive at both loads. The [full result](owner-ready-frames-owner32-result.json)
retains every round, range, percentile and original decision.

| PMU median per query | Low G | Low 5c | High G | High 5c |
|---|---:|---:|---:|---:|
| instructions:u | 7691.146000 | 7197.847600 | 5501.447657 | 5291.847932 |
| instructions:k | 25685.744400 | 25753.138600 | 12987.463248 | 12992.223870 |
| cycles:u | 17052.341200 | 15829.804400 | 3495.813574 | 3293.346823 |
| cycles:k | 38285.320200 | 37003.520400 | 9258.581677 | 9358.965209 |
| IPC:u | 0.451032 | 0.454692 | 1.573725 | 1.606830 |

The 12 stat and 20 plain windows ran from 09:48:07 to 10:04:47 UTC on
2026-10-16. All exited zero and their process groups exited. No measured
failure, replacement or retry occurred. All 48 PMU events were unscaled.
The original adapted analyzer, SHA-256
`1767512f8d791d815f4ac9a57cbe5a5294667b09adc4b39ae09e377a5af6e0bf`,
ran once as root on CPU0, read all latency/send-lag bins and exited zero with
empty stderr. Its result SHA-256 is
`c4b3b656878a7bc2424fe2fb8aeaf58a6950c8e0327101661f5752268f3daafa`.

The [postflight](owner-ready-frames-owner32-postflight.json), SHA-256
`a7b3210994a7e7ef6de15e5c232ec5201c2220fb05417664f2826be7f7bc83cd`,
rechecks 1,264 raw files, 3,590,643,600 bytes of bins, both 179-file source
manifests and exact SDK triples. The private 965,986-byte smallraw archive
has SHA-256
`4ecfa0706ac793d948a6faf2af453a554dc602085cb60b7d0b7a62a8423234e8`;
collection SHA-256:
`beef8889adb3f8f3fefa99b375d0ba1323e0afb97099c796baeef32e89a00e2e`.
All 1,172 transferred members were rehashed under
`private/perf-opt-20261015/owner-ready-frames-owner32-results/`. The 128 bins
and 64 repeated ELF/map copies are omitted only from transfer, retained
remotely and included in analysis.

The earlier [metadata adapter failure](owner-ready-frames-owner32-prelaunch-metadata-failure.json)
remains recorded: an old script filename failed verification before any
remote plan write or measured window. Correcting that filename did not
rerun or replace measurement. Both adapter versions and failed stderr remain
private; the successful ready and launch receipts bind the correction.

The [quiet handoff](owner-ready-frames-owner32-release-to-correctness.json),
SHA-256 `7ece1ca9db618742ef692cd111fbbedaadc5b6070af27492da0514ece7a7d04d`,
records exited controller/analyzer, completed transfers, no research processes
including exact C, three free locks and the unchanged actual standalone signal
result. The completed [independent audit](../correctness/owner-ready-frames-owner32-independent-audit.json),
commit `732e7884`, SHA-256
`24dc7833258c7f2400cd2015caa100e57b1aad8eccbf0ba8ae076674b7fc374d`,
rechecked all 1,264 raw files, CPU/PMU/statistical calculations and 128 bins.
Its original full-bin analyzer replay produced the byte-identical result
`c4b3b656878a7bc2424fe2fb8aeaf58a6950c8e0327101661f5752268f3daafa`
and retained the high-load send-lag p95 regression. The
[completed closeout](../correctness/owner-ready-frames-screen-closeout-and-root-handoff.json),
commit `457b640e`, records the final quiet release SHA-256
`7420a7cc401c2a28b6d14f1c38b400f050aee155d9f7133e156e2ce30bd66c8d`.
The device ten-window independent audit `e99b91a1`,
SHA-256 `b4a08d198e4ac86427e78e779902726d4cadd7e642cb897ad3ddf6c8c228c22a`,
found all three primary comparisons inconclusive and verified restoration.
These host diagnostics establish neither physical-device gain nor complete
qualification. Independent review and quiet release are complete; the next
queue remains subject to root selection. No full110 or new experiment is authorized
by this result alone.
