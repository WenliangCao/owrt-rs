# cold-metadata: complete independent native240 result

All 240 fixed windows and 244 commands completed successfully, with no failed
measurement, supplement or selective rerun. The frozen CPU rule finds
1 faster, 5 slower and 9 within-variation scenes. All 15 scenes, including adverse
controls, are reported below. This screen does not select a candidate or
establish full correctness, SDK performance or physical-device acceptance.

## Frozen experiment

The exact source is `40cc86fef86553f12834af36e0e2ccc23aa913ef`, compared independently to F
`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`. The source trees and prior results
of other prototypes remain separate. Plan commit `7ea56827` binds
[cold-metadata-native-plan.json](../dns/cold-metadata-native-plan.json),
SHA256 `99423ef51eac597f9eb21c29e0db73c72f4ab89867a8b6b3c254c59262bd8ab0`.

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
bound by the launch is `ed91f32912144f1a25f7ab388047dea8b2ee07f83af3138fce63d763082949b7`;
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
| hit | -0.860% | 0.611% | 5/5 | faster | -0.705% | -0.315% | 2.62744 → 2.63770 |
| hit-upper | -0.039% | 1.027% | 3/5 | within variation | -0.526% | -0.303% | 2.61559 → 2.62156 |
| hit-leases | -0.172% | 1.593% | 3/5 | within variation | +0.594% | -0.269% | 2.68817 → 2.66521 |
| hit-typed | -0.480% | 1.164% | 5/5 | within variation | -1.017% | -0.307% | 2.61836 → 2.63710 |
| miss | +1.115% | 0.412% | 5/5 | slower | +1.000% | -0.000% | 2.62274 → 2.59676 |
| miss-leases | +1.290% | 1.832% | 4/5 | within variation | +1.216% | +0.008% | 2.71758 → 2.68437 |
| host | -0.084% | 2.136% | 1/5 | within variation | +1.467% | +0.620% | 2.61328 → 2.59778 |
| host-localise | -1.912% | 5.103% | 3/5 | within variation | +0.862% | -0.742% | 2.68979 → 2.66226 |
| raw-address | +0.289% | 0.681% | 4/5 | within variation | +0.102% | -0.101% | 2.93033 → 2.92450 |
| synth-address | +0.554% | 0.374% | 5/5 | slower | +0.586% | -0.016% | 2.68979 → 2.67370 |
| lease-address | +1.088% | 0.440% | 5/5 | slower | +1.072% | -0.005% | 2.71630 → 2.68719 |
| rrset | +0.052% | 0.482% | 4/5 | within variation | +0.260% | -0.380% | 2.85004 → 2.83183 |
| cname | +0.332% | 0.466% | 5/5 | within variation | +0.641% | -0.227% | 2.65967 → 2.63687 |
| cname-leases | +1.387% | 0.635% | 5/5 | slower | +0.924% | -0.187% | 2.72725 → 2.69717 |
| cname-config | +5.201% | 0.420% | 5/5 | slower | +5.219% | +0.049% | 3.27199 → 3.11039 |

The discernible slower scenes are miss, synth-address, lease-address, cname-leases, cname-config.
They remain part of the decision and are not hidden by a favorable hit subset.
This variant does not clear a requirement of no performance regressions.

The largest regression is configured CNAME (+5.201%, W 0.420%, five adverse
pairs), accompanied by +5.219% user cycles. The sole discernible gain is hit
(−0.860%, W 0.611%). This does not establish a general CPU benefit from smaller
ordinary cache entries. Metadata insertion allocation and CNAME/negative-path
indirection remain explicit tradeoffs in the frozen plan; no A53 cache-miss or
IPC claim is inferred from layout size.

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
in [the derived result](cold-metadata-native-screen-result.json); see also
[the launch receipt](cold-metadata-native-launch.json) and
[the adapted analyzer](analyze_cold_metadata_native.py).

Raw result metadata is 354,657 bytes, SHA256
`b9721b60b51231a63d0fd5d507f4d92449610a942825e65acc3cc35e60dae2dd`. Full command outputs and native binaries remain
private on Oracle `root/private/cold-metadata-native-screen1`. Only small result
metadata was transferred. No physical router was accessed or changed by this
work. Full correctness, complete acceptance matrices and an independent physical
comparison to E remain necessary for any future immutable candidate.
