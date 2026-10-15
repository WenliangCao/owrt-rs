# host-miss: complete independent native240 result

All 240 fixed windows and 244 commands completed successfully, with no failed
measurement, supplement or selective rerun. The frozen CPU rule finds
11 faster, 3 slower and 1 within-variation scenes. All 15 scenes, including adverse
controls, are reported below. This screen does not select a candidate or
establish full correctness, SDK performance or physical-device acceptance.

## Frozen experiment

The exact source is `5d94139b4ad19753e0a14a725a7128f110a83e13`, compared independently to F
`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`. The source trees and prior results
of other prototypes remain separate. Plan commit `7ea56827` binds
[host-miss-native-plan.json](../dns/host-miss-native-plan.json),
SHA256 `29abda2498088fe043cfe9442fed416afc85915fc0eea99276edfb1d38651dea`.

The existing runner has SHA256
`e5c6e155a351e9f77dd9012fb11a3dddcf53732acf13b4ca078801daf99fe6ff`.
Its only change from historical runner `9d5bc3ab` is the final row-cardinality
assertion, now derived from the fixed plan dimensions. Measurement loops,
commands, source checks and stop-on-failure behavior are unchanged. Probe
`72d836d1…6bd` is unchanged. The inherited plan prose mentions three probes;
the executable plan has exactly two sources, hence two library and two probe
builds. All four build commands finished before the first measured window.

Each scene has three grouped user-PMU pairs at 200,000 operations and five
plain CPU pairs at 2,000,000 operations, except raw-address and configured
CNAME at 200,000. F is first in odd pairs, the prototype in even pairs. Native
measurements use CPU 2/nice 10, builds CPU 0/one job. Every scene/operation/
checksum control passed. Allocation tracking is disabled; zero emitted fields
do not mean zero allocations.

Before timing, this exact source's 934 related Linux tests and unchanged SDK
build completed. The three-source qualification receipt records 2,803 related
passes, 537 source rechecks, 30 log hashes and six test-artifact hashes:
`5e024edd370116758ac9f184347b55a194efaf28f935a872fbb4cd60a748e663`.
These related gates are not full frozen-C qualification. The exact SDK artifact
bound by the launch is `081ac4a295117045f320bcd7f218a1280c8ebeebcc1511673ae7c26e9e557066`;
it remains separate from the native probes measured here.

PGO smoke2 had terminated at its exact-E control identity gate, with no generate
or runtime pending. DNS explicitly released its reservation and final metadata
transfer before cold-metadata began. All three SDK bundles were downloaded and
verified by DHCP before timing. SDK/native locks were available and the
root-readable Oracle research-process inventory was empty before this launch.
The three independent rounds run in cold/frame/host order without overlapping
builds or timing. No SDK32 follow-up was launched by this work.

## All 15 scenes

CPU is the original whole-process RUSAGE_CHILDREN user+system delta per operation,
including taskset, setup, priming and teardown. W is the maximum of each side's
(max−min)/median. A discernible change requires |change| > W and at least four
of five pairs in that direction. The unchanged native compare call has no daemon
tick gate, so these results cannot substitute for fixed-cohort SDK acceptance.

PMU columns use three separate windows. Each has grouped, inherited user
instructions/cycles, positive equal enabled/running times and no scaling. IPC
is formed from the same window's raw counters, then the three IPCs are medianed.
PMU changes are descriptive and do not replace the plain CPU decision.

| Scene | CPU change | W | Same direction | CPU decision | User cycles change | User instructions change | User IPC F → prototype |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| hit | -10.340% | 0.417% | 5/5 | faster | -10.406% | -7.062% | 2.62750 → 2.72557 |
| hit-upper | -9.989% | 0.502% | 5/5 | faster | -9.841% | -6.885% | 2.61929 → 2.70509 |
| hit-leases | -9.270% | 0.269% | 5/5 | faster | -9.231% | -5.869% | 2.68058 → 2.77979 |
| hit-typed | -10.569% | 0.448% | 5/5 | faster | -10.459% | -7.059% | 2.62329 → 2.72297 |
| miss | -15.289% | 1.029% | 5/5 | faster | -14.980% | -11.083% | 2.62759 → 2.74804 |
| miss-leases | -12.590% | 1.063% | 5/5 | faster | -12.456% | -8.426% | 2.71544 → 2.84033 |
| host | +6.579% | 1.872% | 5/5 | slower | +7.000% | +6.785% | 2.61739 → 2.61600 |
| host-localise | +4.817% | 5.142% | 5/5 | within variation | +5.387% | +5.223% | 2.67401 → 2.66537 |
| raw-address | +1.012% | 0.623% | 5/5 | slower | +0.939% | +0.885% | 2.92820 → 2.92419 |
| synth-address | -7.956% | 0.177% | 5/5 | faster | -7.969% | -5.492% | 2.69144 → 2.76389 |
| lease-address | -7.463% | 0.178% | 5/5 | faster | -7.579% | -5.628% | 2.71567 → 2.77284 |
| rrset | -3.190% | 0.557% | 5/5 | faster | -3.074% | -2.528% | 2.84946 → 2.86553 |
| cname | -4.331% | 0.558% | 5/5 | faster | -4.538% | -3.730% | 2.66593 → 2.68847 |
| cname-leases | -4.039% | 0.751% | 5/5 | faster | -4.654% | -2.997% | 2.72044 → 2.76764 |
| cname-config | +2.602% | 0.116% | 5/5 | slower | +2.677% | +0.231% | 3.27221 → 3.19454 |

The discernible slower scenes are host, raw-address, cname-config.
They remain part of the decision and are not hidden by a favorable hit subset.
This variant does not clear a requirement of no performance regressions.

The indexed-miss mechanism helps the four cached-hit scenes (−9.270% to
−10.569%) and plain miss (−15.289%), but indexed host hits incur +6.579%
CPU with W 1.872%. Raw-address is +1.012% with W 0.623%, and configured CNAME
is +2.602% with W 0.116%. All three adverse cases have five adverse pairs and
higher user-cycle medians. Host-localise also rises +4.817% in all five pairs,
but remains below its W of 5.142%; that observation is retained rather than
described as unchanged. The favorable majority does not waive these controls.

## Evidence verification

All 578 small raw stdout/stderr/PMU CSV files were independently rehashed after
completion. All 162 source hashes per side and both final probe ELF hashes
matched. Every planned label/order, checksum, recorded unscaled event field,
same-window IPC and CPU/wall derivation passed verification. Controller stderr
is empty, and all 244 command exit codes are zero.

The existing analyzer was adapted only for input/plan/output locations, scope
text and the two fixed cardinalities (240 rows/244 commands). Its median/IPC
logic and `perf_opt_analyze.compare` are unchanged. All five CPU pairs, three
PMU windows per side, checksums, 15 summaries and review metadata are retained
in [the derived result](host-miss-native-screen-result.json); see also
[the launch receipt](host-miss-native-launch.json) and
[the adapted analyzer](analyze_host_miss_native.py).

Raw result metadata is 347,932 bytes, SHA256
`e814e83642aed36b9ff2df813d80b7a8ef510ee29182459b129126609c82dcc3`. Full command outputs and native binaries remain
private on Oracle `root/private/host-miss-native-screen1`. Only small result
metadata was transferred. No physical router was accessed or changed by this
work. Full correctness, complete acceptance matrices and an independent physical
comparison to E remain necessary for any future immutable candidate.
