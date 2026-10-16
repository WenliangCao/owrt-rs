# Cached-only local bypass: hit gains with four retained regressions

The exact `54bd1e56` prototype completed all 240 native windows and 244 commands
without failed measurement or replacement. Six scenes are faster, four slower
and five within variation under the unchanged rule. Fresh cached hits improve
17–26%, while miss, miss-with-leases, synthetic-address and lease-address retain
smaller but discernible regressions. This is not a regression-free candidate.

## Independent source and fixed experiment

Source `54bd1e56f3388bb704cead10bf2d02433ffbd369` is compared to F
`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`, using its own alternating controls.
The ordinary local-answer expiry and name inspection precede a read-only cached
eligibility check; only an eligible fresh single A/AAAA can reach the additional
ownership guard. Original cache promotion remains separate. The previously
measured `8d572ba1` integration and later name-buffer composition `0161ad9c`
are different sources. Their samples are not pooled into this result.

[Plan a60d358b](../dns/cached-local-miss-native-plan.json), SHA256
`4164adeed24c9a0291a39cdb0ee7dfb6fe6bd86aa9680de2f52411632e69475d`, retains
15 scenes, three grouped PMU pairs at 200,000 operations and five plain CPU
pairs at 2,000,000 operations, except raw-address and configured CNAME at
200,000. F is first in odd pairs and the prototype first in even pairs. Native
measurements use CPU 2/nice 10; builds use CPU 0/one job. Two library and two probe
builds precede all 90 PMU and 150 plain windows. Runner `e5c6e155…fe6ff` and
probe `72d836d1…6bd` are unchanged from the previous 240-window screens.

Exact-source related Linux gates passed 938 tests, bound by receipt
`cb9ceed13e8e9441a8b3465cd51af23bb67c80fd2405df9b26f2b6a72aac2fa4`.
The unchanged SDK build is 2,140,955 bytes, ELF
`36e4cdde1fd0ea25d55599a37cf8fc7eb78e933c953b719c8a09af715d1b1b3f`.
It passes the original size and static-PIE/RELRO/NX checks; the measured native
probe is a separate artifact. These prerequisites are related gates only,
not full frozen-C correctness or performance acceptance.

Both `54bd` and `0161` SDK builds completed before timing. DNS and DHCP explicitly
finished artifact downloads/input preparation; the prior hot250 build had exited.
The root-readable research inventory was empty and both SDK/native locks were
available before launch. No build or other Oracle workload overlapped the screen.
No product or workload input changed during the run.

## All 15 scenes

CPU uses the original whole-process RUSAGE_CHILDREN user+system delta per
operation, including taskset, setup, priming and teardown. W is the larger side's
(max−min)/median; a discernible result requires |change| > W and at least four of
five same-direction pairs. This native comparison does not apply daemon tick
precision and cannot substitute for SDK or physical fixed-cohort acceptance.

Separate PMU windows are inherited, grouped and unscaled, with positive equal
enabled/running times. Reported IPC is the median of each window's own raw
user-instructions/user-cycles ratio. PMU columns do not replace the plain CPU
comparison. Allocation tracking is disabled; zero emitted allocation fields
are not a zero-allocation claim.

| Scene | CPU change | W | Same direction | CPU decision | User cycles change | User instructions change | User IPC F → prototype |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| hit | -25.892% | 0.356% | 5/5 | faster | -25.737% | -27.221% | 2.62485 → 2.57241 |
| hit-upper | -25.186% | 0.298% | 5/5 | faster | -24.887% | -26.525% | 2.61495 → 2.55795 |
| hit-leases | -17.383% | 0.324% | 5/5 | faster | -17.398% | -16.135% | 2.68339 → 2.72397 |
| hit-typed | -25.793% | 0.986% | 5/5 | faster | -25.623% | -27.221% | 2.62685 → 2.57041 |
| miss | +2.180% | 1.266% | 5/5 | slower | +1.685% | +0.679% | 2.62631 → 2.60033 |
| miss-leases | +2.101% | 0.332% | 5/5 | slower | +2.286% | +0.702% | 2.71638 → 2.67424 |
| host | +1.602% | 3.336% | 5/5 | within variation | +1.391% | +1.201% | 2.61484 → 2.60543 |
| host-localise | +1.419% | 3.852% | 5/5 | within variation | -0.330% | -0.505% | 2.67797 → 2.67445 |
| raw-address | +0.099% | 0.210% | 4/5 | within variation | +0.140% | +0.040% | 2.92757 → 2.92503 |
| synth-address | +0.797% | 0.150% | 5/5 | slower | +0.809% | -0.062% | 2.69105 → 2.66780 |
| lease-address | +0.622% | 0.539% | 5/5 | slower | +0.435% | +0.052% | 2.71000 → 2.69935 |
| rrset | +0.832% | 1.734% | 4/5 | within variation | +0.896% | +0.203% | 2.83804 → 2.81853 |
| cname | -6.866% | 0.306% | 5/5 | faster | -7.392% | -6.308% | 2.65644 → 2.68754 |
| cname-leases | -3.890% | 1.521% | 5/5 | faster | -3.340% | -1.919% | 2.74079 → 2.78103 |
| cname-config | -0.200% | 0.256% | 5/5 | within variation | -0.165% | +0.039% | 3.27417 → 3.28101 |

Four hit scenes and both dynamic CNAME scenes are faster. The latter may reach
fresh cached targets through existing recursion; the result does not imply
that the initial CNAME bypasses its original path. Miss (+2.180%, W 1.266%),
miss-with-leases (+2.101%, W 0.332%), synthetic-address (+0.797%, W 0.150%) and
lease-address (+0.622%, W 0.539%) have five adverse pairs and exceed W. All four
also have higher median user cycles. They remain part of the candidate decision.

Host (+1.602%), host-localise (+1.419%), raw-address (+0.099%) and RRset
(+0.832%) are positive point estimates within their respective W. Configured
CNAME is −0.200% within W. These are not equivalence proofs and are not called
zero-overhead paths.

## Prior integration regressions remain separate

The previous `8d572ba1` integration had eight adverse scenes. The following
independent F comparisons retain both observations; they are not pooled or a
paired direct old/new experiment. The current source also gives up the prior
ordinary-miss acceleration, reflected in the two adverse miss results above.

| Scene | Prior integration CPU change / W | Prior decision | Cached-only CPU change / W | Current decision |
| --- | ---: | --- | ---: | --- |
| host | +14.252% / 2.397% | slower | +1.602% / 3.336% | within variation |
| host-localise | +8.900% / 5.366% | slower | +1.419% / 3.852% | within variation |
| raw-address | +0.815% / 0.474% | slower | +0.099% / 0.210% | within variation |
| synth-address | +2.783% / 0.929% | slower | +0.797% / 0.150% | slower |
| lease-address | +29.770% / 0.485% | slower | +0.622% / 0.539% | slower |
| cname | +5.833% / 0.919% | slower | -6.866% / 0.306% | faster |
| cname-leases | +3.427% / 0.967% | slower | -3.890% / 1.521% | faster |
| cname-config | +5.370% / 0.240% | slower | -0.200% / 0.256% | within variation |

The [original integration report](LOCAL_CACHE_INTEGRATION_NATIVE_RESULT.md) and
all its raw samples remain unchanged. Static structure or allocation savings
alone do not predict the remaining regressions or establish their exact cause.

## Verified evidence and handoff

Independent postflight rehashed all 578 small raw stdout/stderr/PMU CSV files,
all 162 source files per side and both final probe ELFs. Every planned label,
operation count, checksum, grouped/unscaled event field, same-window IPC and
CPU/wall derivation matched. All command exit codes are zero and controller
stderr is empty. All 15 CPU comparisons were locally rederived with the unchanged
compare implementation. The existing analyzer changes only paths, scope and
240/244 cardinalities.

Raw result metadata is 361,222 bytes, SHA256
`dd81b34e96a63ac9b7e7d7438dc369778744b2ba3d56da29f5f75acf3aa67c6a`.
Full outputs and native probe binaries remain private on Oracle
`root/private/cached-local-miss-native-screen1`. Only small result metadata was
transferred. See [all rows/statistics/audit](cached-local-miss-native-screen-result.json),
[launch](cached-local-miss-native-launch.json),
[analyzer](analyze_cached_local_miss_native.py) and
[release receipt](cached-local-miss-native-release.json).

At 2026-10-16 00:39:58 UTC the controller had exited, the research inventory
was empty and both locks were available. All metadata collection finished before
Oracle was explicitly handed to DNS for its separately frozen `0161ad9c` versus
accepted E owner32. That baseline is E, not this run's F control, and those
results require their own interpretation. No physical router was accessed by
this work. Full correctness, complete matrices and independent physical
qualification remain required for any eventual immutable candidate.
