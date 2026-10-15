# fresh-frame: complete independent native240 result

All 240 fixed windows and 244 commands completed successfully, with no failed
measurement, supplement or selective rerun. The frozen CPU rule finds
5 faster, 5 slower and 5 within-variation scenes. All 15 scenes, including adverse
controls, are reported below. This screen does not select a candidate or
establish full correctness, SDK performance or physical-device acceptance.

## Frozen experiment

The exact source is `b343df112e430f16e21026645e56755f2d0fc391`, compared independently to F
`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`. The source trees and prior results
of other prototypes remain separate. Plan commit `7ea56827` binds
[fresh-frame-native-plan.json](../dns/fresh-frame-native-plan.json),
SHA256 `7e1b32034eef89a841393098bced52c0e9680011d41b10d8501b25697eeb746e`.

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

Before timing, this exact source's 935 related Linux tests and unchanged SDK
build completed. The three-source qualification receipt records 2,803 related
passes, 537 source rechecks, 30 log hashes and six test-artifact hashes:
`5e024edd370116758ac9f184347b55a194efaf28f935a872fbb4cd60a748e663`.
These related gates are not full frozen-C qualification. The exact SDK artifact
bound by the launch is `02b500e55acc65d7099612801d89ea8e19a20ae9884e0a86edfdd051a3b057ad`;
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
| hit | -10.121% | 0.526% | 5/5 | faster | -9.938% | -12.852% | 2.62449 → 2.53956 |
| hit-upper | -9.826% | 0.332% | 5/5 | faster | -9.917% | -12.531% | 2.61543 → 2.53947 |
| hit-leases | -7.974% | 0.262% | 5/5 | faster | -8.146% | -10.772% | 2.68119 → 2.60480 |
| hit-typed | -10.104% | 0.631% | 5/5 | faster | -9.931% | -12.850% | 2.62731 → 2.54217 |
| miss | +1.842% | 2.090% | 4/5 | within variation | +2.259% | +0.822% | 2.62460 → 2.58770 |
| miss-leases | +2.074% | 0.626% | 5/5 | slower | +2.041% | +0.627% | 2.71502 → 2.67741 |
| host | +0.868% | 3.116% | 3/5 | within variation | +0.948% | +0.988% | 2.61530 → 2.61730 |
| host-localise | +2.967% | 4.764% | 4/5 | within variation | -1.442% | -2.339% | 2.69453 → 2.67534 |
| raw-address | +0.003% | 0.605% | 2/5 | within variation | +0.200% | +0.067% | 2.92823 → 2.92561 |
| synth-address | +0.912% | 0.173% | 5/5 | slower | +0.553% | +0.047% | 2.68706 → 2.67351 |
| lease-address | +0.986% | 1.987% | 5/5 | within variation | +1.080% | +0.041% | 2.71733 → 2.68928 |
| rrset | +0.676% | 0.270% | 5/5 | slower | +0.435% | +0.195% | 2.84109 → 2.83431 |
| cname | +1.191% | 0.448% | 5/5 | slower | +1.074% | +0.951% | 2.66330 → 2.66020 |
| cname-leases | +2.420% | 1.138% | 5/5 | slower | +2.254% | +0.774% | 2.73254 → 2.69302 |
| cname-config | -1.337% | 0.167% | 5/5 | faster | -1.346% | -0.016% | 3.27309 → 3.31646 |

The discernible slower scenes are miss-leases, synth-address, rrset, cname, cname-leases.
They remain part of the decision and are not hidden by a favorable hit subset.
This variant does not clear a requirement of no performance regressions.

## Parent regressions remain separate

The parent `2a9d53b0` had eight adverse native scenes. The following independent
F comparisons retain both outcomes; they are not pooled or a paired direct
parent/refinement test. A within-variation new result is not proof of equivalence.

| Scene | Parent CPU change / W | Parent decision | Refined CPU change / W | Refined decision |
| --- | ---: | --- | ---: | --- |
| miss | +3.399% / 2.984% | slower | +1.842% / 2.090% | within variation |
| miss-leases | +2.933% / 0.464% | slower | +2.074% / 0.626% | slower |
| synth-address | +1.012% / 0.388% | slower | +0.912% / 0.173% | slower |
| lease-address | +2.136% / 0.604% | slower | +0.986% / 1.987% | within variation |
| rrset | +2.531% / 1.744% | slower | +0.676% / 0.270% | slower |
| cname | +1.303% / 0.922% | slower | +1.191% / 0.448% | slower |
| cname-leases | +1.858% / 0.657% | slower | +2.420% / 1.138% | slower |
| cname-config | +2.162% / 0.226% | slower | -1.337% / 0.167% | faster |

The [parent report](FRESH_ADDRESS_NATIVE_RESULT.md) and all original samples
remain unchanged. No static frame observation is used as a speed measurement.

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
in [the derived result](fresh-frame-native-screen-result.json); see also
[the launch receipt](fresh-frame-native-launch.json) and
[the adapted analyzer](analyze_fresh_frame_native.py).

Raw result metadata is 351,271 bytes, SHA256
`89d2cb02820071deb3a46a1b2d2c8cacd27dcc4c8f55c2465334b86631a35320`. Full command outputs and native binaries remain
private on Oracle `root/private/fresh-frame-native-screen1`. Only small result
metadata was transferred. No physical router was accessed or changed by this
work. Full correctness, complete acceptance matrices and an independent physical
comparison to E remain necessary for any future immutable candidate.
