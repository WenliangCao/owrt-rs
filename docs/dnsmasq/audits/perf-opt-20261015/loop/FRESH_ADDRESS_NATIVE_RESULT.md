# Fresh-address and singleton-slice: all 15 native scenes retained

The fixed native screen completed all 480 windows and all 486 commands without
failure or replacement. Fresh-address improves four cached-hit scenes but
regresses eight fallback scenes under the frozen CPU rule. Singleton-slice
improves six scenes; synth-address still regresses. Neither prototype clears a
requirement of no performance regressions, and neither is selected by this report.

This is an independent F comparison for each prototype, not a comparison to E,
exact C or a physical router. The original singleton `b1180f72` results remain
unchanged and separate. Its four adverse scenes are not removed or pooled with
the refinement's measurements.

## Frozen inputs and completed controls

[Plan commit 9e1856a6](../dns/FRESH_ADDRESS_PLAN.md) binds F
`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`, fresh-address
`2a9d53b00fb009bfa494de4e1de9fd37d2e5c2fb`, and singleton-slice
`8ed0cfdff8dfea18b438c298727f772813af5758`. Fresh-address is a direct F child;
singleton-slice adds only the one-slice refinement to the earlier singleton.
No name-buffer, dotted-name or event-loop prototype is combined with them.

The exact fresh-address Linux related gates passed 935 tests before launch;
receipt `d63e14d8024798fa94d1486b68698e44696a2dbcfc5ad6e0df8bddea1b5fe384`
also records that all gate processes exited. The separate unchanged SDK build
completed before launch with ELF `b52432a2…cce7f`, 2,136,859 bytes and its original
size gate passing. These prerequisites are not full correctness qualification.

The runner is byte-identical to the previous layout screen
(`9d5bc3ab…7091`), as is probe `72d836d1…6bd`. All three library/probe builds
completed before the first measured command. Each of 15 scenes has three PMU
pairs at 200,000 operations and five plain pairs at 2,000,000 operations, except
raw-address and configured CNAME at 200,000. Pair order alternates F/prototype
and prototype/F. Native runs use CPU 2, nice 10; builds use CPU 0 and one job.
The Oracle host was exclusively reserved and had no other research workload
at launch. No prior result is included in these statistics.

All 480 scene/operation/checksum controls passed. Allocation tracking is disabled
in these builds; zero emitted allocation fields do not mean zero allocations.
All 180 PMU windows retain grouped, inherited user instructions/cycles with
identical positive enabled/running times and no scaling. IPC is calculated from
the same window's two raw counters. Plain CPU is the existing RUSAGE_CHILDREN
user+system delta, including taskset, setup, priming and teardown; PMU also
covers the whole process. These are not isolated inner-loop or daemon costs.

## All 15 scenes for each independent comparison

CPU change uses five plain-pair medians. W is the larger of each side's
(max−min)/median, and a discernible change requires |change| > W with at least
four of five pairs in that direction. PMU columns use separate three-window
medians; they are descriptive, not substitutes for the plain CPU decision.
Native CPU uses the original compare call without a daemon tick gate and cannot
establish fixed-cohort SDK or device acceptance. All absolute values and pairs
are retained in the derived JSON.

### fresh-address versus F

| Scene | CPU change | W | Same direction | CPU decision | User cycles change | User instructions change | User IPC F → prototype |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| hit | -10.114% | 0.412% | 5/5 | faster | -10.000% | -12.831% | 2.62650 → 2.54387 |
| hit-upper | -10.353% | 0.638% | 5/5 | faster | -10.127% | -12.513% | 2.61573 → 2.54628 |
| hit-leases | -7.969% | 0.347% | 5/5 | faster | -7.986% | -10.751% | 2.68425 → 2.60361 |
| hit-typed | -10.002% | 0.976% | 5/5 | faster | -10.248% | -12.834% | 2.62480 → 2.54916 |
| miss | +3.399% | 2.984% | 5/5 | slower | +3.509% | +1.031% | 2.62227 → 2.55949 |
| miss-leases | +2.933% | 0.464% | 5/5 | slower | +2.878% | +0.788% | 2.72052 → 2.66555 |
| host | +0.832% | 1.071% | 3/5 | within variation | -0.394% | -0.758% | 2.61893 → 2.61399 |
| host-localise | +0.870% | 3.180% | 4/5 | within variation | +1.227% | +1.670% | 2.67667 → 2.68538 |
| raw-address | -0.171% | 0.623% | 3/5 | within variation | -0.195% | -0.058% | 2.92513 → 2.92915 |
| synth-address | +1.012% | 0.388% | 5/5 | slower | +1.189% | +0.047% | 2.68932 → 2.65896 |
| lease-address | +2.136% | 0.604% | 5/5 | slower | +1.709% | +0.051% | 2.70797 → 2.66448 |
| rrset | +2.531% | 1.744% | 5/5 | slower | +2.833% | +0.219% | 2.85019 → 2.77774 |
| cname | +1.303% | 0.922% | 5/5 | slower | +1.329% | +0.989% | 2.66466 → 2.65564 |
| cname-leases | +1.858% | 0.657% | 5/5 | slower | +1.694% | +0.802% | 2.73453 → 2.71050 |
| cname-config | +2.162% | 0.226% | 5/5 | slower | +2.331% | +0.062% | 3.27434 → 3.20172 |

### singleton-slice versus F

| Scene | CPU change | W | Same direction | CPU decision | User cycles change | User instructions change | User IPC F → prototype |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| hit | -4.493% | 2.374% | 5/5 | faster | -4.730% | -5.177% | 2.62706 → 2.61471 |
| hit-upper | -4.244% | 0.338% | 5/5 | faster | -4.361% | -5.051% | 2.61157 → 2.59273 |
| hit-leases | -3.756% | 0.785% | 5/5 | faster | -3.550% | -4.340% | 2.68698 → 2.66474 |
| hit-typed | -4.605% | 0.497% | 5/5 | faster | -4.771% | -5.179% | 2.62206 → 2.61095 |
| miss | +0.096% | 1.470% | 4/5 | within variation | +0.262% | -0.045% | 2.62636 → 2.61832 |
| miss-leases | +0.363% | 1.023% | 4/5 | within variation | +0.413% | -0.036% | 2.71105 → 2.69902 |
| host | -0.518% | 1.778% | 4/5 | within variation | +0.558% | +1.005% | 2.61004 → 2.61990 |
| host-localise | +0.799% | 5.071% | 4/5 | within variation | +0.995% | +1.233% | 2.66564 → 2.66360 |
| raw-address | +0.088% | 0.564% | 4/5 | within variation | -0.000% | -0.083% | 2.93235 → 2.93069 |
| synth-address | +0.770% | 0.337% | 5/5 | slower | +0.688% | +0.000% | 2.69042 → 2.67203 |
| lease-address | +0.202% | 0.421% | 4/5 | within variation | +0.341% | +0.008% | 2.71759 → 2.70875 |
| rrset | +0.631% | 0.694% | 5/5 | within variation | +0.711% | +0.029% | 2.84989 → 2.83088 |
| cname | -2.533% | 1.559% | 5/5 | faster | -2.378% | -2.341% | 2.66882 → 2.66983 |
| cname-leases | -1.863% | 1.521% | 5/5 | faster | -1.668% | -1.907% | 2.74003 → 2.73328 |
| cname-config | -0.136% | 0.250% | 4/5 | within variation | -0.280% | -0.007% | 3.27315 → 3.28057 |

Fresh-address's cached-hit CPU changes are −7.969% to −10.353%, accompanied by
lower user instructions and cycles. Its eight slower scenes are miss,
miss-leases, synth-address, lease-address, RRset, CNAME, CNAME with leases and
configured CNAME. Every one has five adverse pairs and a CPU change greater
than W. Their user-cycle medians also rise. The fallback regression remains
part of the result even where the intended fast path succeeds.

Singleton-slice has six faster, one slower and eight within-variation scenes.
The remaining synth-address increase is +0.770%, W 0.337%, five adverse pairs;
its user-cycle median increases +0.688%. No assertion that all original
singleton regressions were fixed is justified.

## Original singleton regressions remain separate

The old comparison below is the previously frozen F versus `b1180f72` screen;
the new comparison is this run's F versus `8ed0cfdf`. They have independent
controls and are not pooled, subtracted or treated as a direct old/new trial.

| Scene | Original singleton CPU change / W | Original decision | New singleton-slice CPU change / W | New decision |
| --- | ---: | --- | ---: | --- |
| miss | +0.627% / 0.354% | slower | +0.096% / 1.470% | within variation |
| synth-address | +2.214% / 1.244% | slower | +0.770% / 0.337% | slower |
| lease-address | +0.421% / 0.373% | slower | +0.202% / 0.421% | within variation |
| rrset | +1.683% / 0.654% | slower | +0.631% / 0.694% | within variation |

The new miss, lease-address and RRset changes do not exceed their own W;
this is a within-variation result, not an equivalence proof. The old four
adverse results remain in [the original report](../dns/POST_F_NATIVE_CPU_RESULT.md).

## Evidence and review boundary

The reviewer rehashed all 1,152 raw stdout/stderr/PMU CSV files, all 162 source
files per side and the three final probe ELFs after completion. Every planned
label/order, output checksum, recorded unscaled PMU field, same-window IPC and
plain CPU/wall derivation matched. The analyzer changes only the input directory,
plan path and scope text from the original layout analyzer and retains the same
`perf_opt_analyze.compare` implementation. No measured window was rerun.

The 709,528-byte native result metadata was transferred with SHA256
`d219e70324d169d428fff04853dcc8f84162a89fc3d2377b2fe30150bdbb53a6`.
Raw outputs and native binaries remain private on Oracle
`root/private/fresh-address-native-screen1`. See the
[launch receipt](fresh-address-native-launch.json),
[derived rows, statistics and audit](fresh-address-native-screen-result.json),
and [minimally adapted analyzer](analyze_fresh_address_native_screen.py).

After this native screen completed, DHCP downloaded and verified both requested
SDK artifact bundles in the matrix gap. Only after its explicit transfer-complete
receipt was the separate fresh-address/F SDK owner32 launched. That experiment
is reported independently; neither native gains nor the continued experiment
waive the retained regressions, full correctness, full matrices or physical
qualification requirements.
