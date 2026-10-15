# Local/cache integration: large hit gains with eight retained regressions

The independent native240 screen completed all 240 windows and 244 commands
without failure or replacement. Seven scenes are faster and eight are slower;
every change exceeds its own W and has five of five pairs in that direction.
Cached hits improve about 25–31%, but host/lease/local fallbacks regress,
including lease-address at +29.770%. This source does not clear a no-regression
requirement and is not selected as a candidate by this screen.

## Frozen experiment and prerequisite evidence

The tested integration is `8d572ba1348037420da6c6a36dd8623a08572f25`, compared to
F `3a3d8e3e848b93b0309353acfa0033d0b01a7cd0` under its own alternating controls.
It integrates the fresh writer refinement and bounded local-ownership miss check.
No standalone timing gain is added to another, and all previous variants/results
remain separate. The [frozen plan](../dns/local-cache-integration-native-plan.json)
is commit `39deb82af140357a64e9beebbeba110170508f30`, SHA256
`70c4bf543850bea421372e60c442dac4009d9e76bc247861fc3940aa996c9993`.

Related exact-source Linux gates passed 938 tests for this source; the three-source
batch passed 2,809 with 537 source files, 30 logs and six test artifacts rechecked.
Receipt SHA256 is `050fe64b167ad1c449449e074ff62df876ab132285317a18fa38813a25f43c53`.
The separate original-SDK build passed its original budget at 2,140,955 bytes,
ELF `8048d5129f02f643774bd30a3d695f741dfbb94ebaf5eafc5cc7146015e83b83`.
These related gates and SDK prerequisites are not full frozen-C qualification.
The ELF measured in this screen is the separately built native probe, not the SDK
artifact.

All three pending SDK builds, PGO smoke3's complete exit/cleanup and DHCP's
three-bundle pre-download/identity check completed before launch. The root-readable
Oracle workload inventory was empty and SDK/native locks were available. The
coordinator authorized only this integration screen. Bounded-miss and owned-miss
native plans, and both frozen owner32 controllers, remain unstarted by this work.

The existing native runner `e5c6e155…fe6ff` and probe `72d836d1…6bd` are unchanged.
Each source's library and probe were built before any measured command: four
builds, then 90 PMU and 150 plain windows. Each of 15 scenes has three PMU pairs at
200,000 operations and five plain pairs at 2,000,000, except raw-address and
configured CNAME at 200,000. Odd pairs run F first; even pairs run integration first.
CPU placement remains build CPU 0/one job and measurement CPU 2/nice 10. Allocation
tracking is disabled; zero emitted allocation fields do not imply zero allocations.

## All 15 scene results

Plain CPU uses whole-process RUSAGE_CHILDREN user+system deltas, including setup,
priming, taskset and teardown. W is the larger side's (max−min)/median. The original
rule requires |change| > W and at least four of five same-direction pairs. Native
comparison does not use the daemon tick gate and cannot establish fixed-cohort SDK
or device acceptance. Separate three-window PMU medians are descriptive. Each
PMU window is inherited, grouped and unscaled; IPC uses its own raw user counts.

| Scene | CPU change | W | Same direction | CPU decision | User cycles change | User instructions change | User IPC F → integration |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| hit | -31.246% | 0.317% | 5/5 | faster | -30.987% | -31.571% | 2.62598 → 2.60401 |
| hit-upper | -31.032% | 0.501% | 5/5 | faster | -30.780% | -30.854% | 2.61567 → 2.61298 |
| hit-leases | -24.920% | 1.157% | 5/5 | faster | -24.950% | -28.367% | 2.67836 → 2.55648 |
| hit-typed | -31.326% | 3.356% | 5/5 | faster | -31.312% | -31.566% | 2.62847 → 2.61858 |
| miss | -31.869% | 1.402% | 5/5 | faster | -31.941% | -28.485% | 2.62673 → 2.76011 |
| miss-leases | -27.602% | 1.290% | 5/5 | faster | -27.703% | -24.596% | 2.71806 → 2.83540 |
| host | +14.252% | 2.397% | 5/5 | slower | +13.467% | +12.826% | 2.61432 → 2.59756 |
| host-localise | +8.900% | 5.366% | 5/5 | slower | +9.264% | +6.582% | 2.68050 → 2.61469 |
| raw-address | +0.815% | 0.474% | 5/5 | slower | +0.878% | +0.280% | 2.93016 → 2.91199 |
| synth-address | +2.783% | 0.929% | 5/5 | slower | +2.304% | +1.024% | 2.68740 → 2.65378 |
| lease-address | +29.770% | 0.485% | 5/5 | slower | +29.667% | +28.561% | 2.71487 → 2.69171 |
| rrset | -7.463% | 0.153% | 5/5 | faster | -7.545% | -6.521% | 2.85021 → 2.88178 |
| cname | +5.833% | 0.919% | 5/5 | slower | +5.651% | +5.877% | 2.66027 → 2.66605 |
| cname-leases | +3.427% | 0.967% | 5/5 | slower | +4.040% | +0.853% | 2.74329 → 2.65915 |
| cname-config | +5.370% | 0.240% | 5/5 | slower | +5.097% | +0.062% | 3.27291 → 3.11533 |

The eight adverse controls are host (+14.252%), host-localise (+8.900%),
raw-address (+0.815%), synth-address (+2.783%), lease-address (+29.770%), CNAME
(+5.833%), CNAME-with-leases (+3.427%) and configured CNAME (+5.370%). Each has
higher median user cycles as well as a plain CPU increase beyond W. Lease-address
also has +28.561% user instructions. The hit/miss gains do not cancel these costs;
no aggregate score or favorable subset is used to promote the integration.

The local allocation controls and static frame observations in the preparation
report remain distinct evidence. They do not prove that rejecting the shortcut
is free, and these native measurements do not establish the exact cause or A53
magnitude of each regression. No hardware result is inferred or imported here.

## Verification and retained scope

The reviewer rehashed all 578 small raw stdout/stderr/PMU CSV files, both final
probe ELFs and all 162 source files per side. All planned labels/order, operation
counts, output checksums, unscaled event fields, same-window IPC and CPU/wall
derivations matched. All command exit codes are zero and controller stderr is
empty. The source and input artifacts remain unchanged.

The existing analyzer changes only input/output paths, plan path, scope text
and fixed 240/244 cardinalities. Its statistics and original compare function
are unchanged. All 15 summaries, five plain pairs and three PMU windows per side
are retained in [the derived result](local-cache-integration-native-screen-result.json),
with the [launch receipt](local-cache-integration-native-launch.json) and
[minimally adapted analyzer](analyze_local_cache_integration_native.py).

Raw result metadata is 371,234 bytes, SHA256
`b3b96033348d1e2d6dd338b2a551e866c2d5b62e50fc423ba00aa6fa43e75031`.
Full outputs and probe binaries remain private on Oracle
`root/private/local-cache-integration-native-screen1`. Only small result metadata
was transferred. No measured window was replaced and no router was accessed by
this work.

[The completion receipt](local-cache-integration-native-completion.json) records
controller exit, an empty root-readable research inventory and both locks
available at 2026-10-15 23:44:47 UTC. No following native or owner32 screen was
started; the coordinator receives these complete results before deciding the next
step. Full correctness, all acceptance matrices and independent physical
qualification against E remain mandatory for any future immutable candidate.
