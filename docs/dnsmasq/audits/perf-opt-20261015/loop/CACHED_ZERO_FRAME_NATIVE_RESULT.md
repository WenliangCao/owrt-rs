# Direct E/185 native screen: six gains and seven retained regressions

The fixed native240 experiment completed all 240 windows and 244 commands,
with no failed measurement, supplement or selective rerun. Six scenes are
faster, seven slower and two within variation under the frozen rule. Four hit
scenes improve 18–34%, while seven miss/local/fallback controls regress about
0.5–2.7%. The complete result does not meet a no-regression requirement and does
not select or fully qualify a candidate.

## Direct baseline and measurement boundary

Every control in this experiment is a fresh native build of accepted E source
`4f869c885b47dcf60d56c872e5b0b3c62237beea`. The candidate is the exact composition
`185db90c9cabd26c0af09765636ef15bf6d35f79`, combining the independently retained
reply-storage and local-frame changes. No F or 0161 sample is relabelled as E;
no historical delta or standalone gain is added to this result. Earlier 54bd,
0161, 8d and independent-child observations remain separate.

The existing public hot15 probe does **not** recycle owner replies. This run
checks the shared local/cache implementation and all cold/fallback controls;
it cannot measure the reply-buffer reuse mechanism's owner CPU benefit. The
separate E/185 original-SDK owner32 and A53 ten-window comparisons have their
own controls and are required for their respective workload conclusions.
Static helper/frame reservations and local prepared-query allocation counts
are not substituted for these measurements.

[Protocol b17f4010](../dns/CACHED_ZERO_FRAME_PLAN.md) retains all 15 scenes,
three grouped user-PMU pairs at 200,000 operations and five plain CPU pairs at
2,000,000, except raw-address/configured-CNAME at 200,000. The concrete
[plan](cached-zero-frame-native-plan.json) SHA256 is
`beb36e4de69550564afb00d5c7f7456f767edad7e0022818330ed398f061e3bc`.
[Runner](run_cached_zero_frame_native.py) SHA256
`119d49a162d47c9dc7b8f7b88de6f4a0119b6a0126cca4ce19fb81ca138d94be`
differs from the existing 240-window runner only in the alternating baseline
label F→E and its scope docstring. Probe `72d836d1…6bd`, command lines, operation
counts, checksums, PMU, failure policy and W/direction rules are unchanged.

Both libraries and both probes are built before any measurement: four builds,
then 90 PMU and 150 plain windows. Odd pairs run E first; even pairs run the
candidate first. Builds use CPU 0/one job, measurements CPU 2/nice 10. Every
scene/operation/checksum control passed. Allocation tracking is disabled;
zero emitted allocation fields are not an allocation measurement.

## Prerequisites and immutable artifacts

Exact185 original related Linux gates passed 940 tests, receipt
`b5089b4b54bcde00a4d887453a1912965c10062066bb48323ea7607f2b651501`.
The separate unchanged canonical SDK artifact is 2,145,051 bytes, ELF
`9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99`,
with original size and static-PIE/RELRO/NX gates passing. Its source179 identity,
same-link map and build receipt are bound in
[the SDK result](cached-zero-frame-sdk-result.json). This native experiment
measures separately built probes, not that shipping SDK ELF.

DNS and DHCP explicitly completed artifact downloads and input pre-transfers;
correctness independently verified the actual SDK triples, source179 Git blobs,
budget and hash-bound static hardening report. The root-readable Oracle process
inventory was empty and SDK/native locks were available before launch. Oracle
remained exclusive through all windows. Full44 and complete acceptance matrices
were not claimed by the related gates or by this native screen.

## All 15 scenes

Plain CPU is whole-process RUSAGE_CHILDREN user+system time per operation,
including taskset, setup, priming and teardown. W is the larger of each side's
(max−min)/median; a discernible result requires |change| > W and at least four
of five pairs in that direction. Native comparison has no daemon tick gate
and cannot substitute for fixed-cohort SDK or physical precision acceptance.

PMU values use separate three-window medians. Each window has grouped inherited
user instructions/cycles, positive identical enabled/running times and no scaling.
IPC is first calculated from the same window's raw counters and then medianed;
PMU values do not replace the plain CPU decision.

| Scene | CPU change | W | Same direction | CPU decision | User cycles change | User instructions change | User IPC E → 185 |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| hit | -26.214% | 0.393% | 5/5 | faster | -26.553% | -28.043% | 2.66756 → 2.61343 |
| hit-upper | -26.078% | 0.690% | 5/5 | faster | -25.951% | -26.928% | 2.64979 → 2.61472 |
| hit-leases | -18.320% | 0.539% | 5/5 | faster | -18.211% | -17.074% | 2.71687 → 2.75462 |
| hit-typed | -33.530% | 0.925% | 5/5 | faster | -33.359% | -35.774% | 2.70388 → 2.60589 |
| miss | +2.421% | 0.449% | 5/5 | slower | +2.558% | -1.150% | 2.66126 → 2.56505 |
| miss-leases | +2.688% | 1.071% | 5/5 | slower | +2.557% | -0.638% | 2.73916 → 2.65393 |
| host | +1.516% | 3.747% | 5/5 | within variation | +2.020% | +1.869% | 2.61391 → 2.59861 |
| host-localise | +1.676% | 5.554% | 3/5 | within variation | +0.751% | +0.240% | 2.66328 → 2.65336 |
| raw-address | +0.481% | 0.358% | 5/5 | slower | +0.438% | +0.254% | 2.92783 → 2.92495 |
| synth-address | +1.666% | 1.077% | 5/5 | slower | +2.033% | -0.107% | 2.68692 → 2.63057 |
| lease-address | +2.124% | 0.359% | 5/5 | slower | +2.220% | -0.014% | 2.74292 → 2.68353 |
| rrset | +1.121% | 0.962% | 5/5 | slower | +1.301% | +0.255% | 2.84786 → 2.81846 |
| cname | -8.793% | 1.179% | 5/5 | faster | -8.744% | -7.352% | 2.66632 → 2.70702 |
| cname-leases | -4.796% | 0.752% | 5/5 | faster | -4.720% | -2.823% | 2.73797 → 2.79261 |
| cname-config | +1.513% | 0.284% | 5/5 | slower | +1.675% | -0.011% | 3.27172 → 3.21732 |

The seven adverse CPU controls are miss (+2.421%, W 0.449%), miss-with-leases
(+2.688%, W 1.071%), raw-address (+0.481%, W 0.358%), synth-address (+1.666%,
W 1.077%), lease-address (+2.124%, W 0.359%), RRset (+1.121%, W 0.962%) and
configured CNAME (+1.513%, W 0.284%). All seven have five adverse pairs and
higher median user cycles. Some have slightly fewer user instructions; that
is not evidence of a CPU improvement. No adverse scene is dropped or offset
against favorable cached hits/CNAMEs.

Host (+1.516%, W 3.747%) and host-localise (+1.676%, W 5.554%) remain within
variation. These are positive point estimates, not equivalence or zero-overhead
proofs. The native observation alone does not determine whole-owner behavior
or establish the causal cost of the helper/frame and reply-buffer changes.

## Verification and complete raw handoff

Postflight rehashed all 578 original stdout/stderr/PMU CSV files, all 162 source
files on each side and both native probe ELFs. Every planned label/order,
operation count, checksum, recorded unscaled event field, same-window IPC and
CPU/wall derivation matched. All command exit codes are zero, controller stderr
is empty, and all 15 CPU comparisons were locally rederived with the unchanged
compare implementation. The analyzer changes only E label, paths, scope and
240/244 cardinalities.

All 578 raw files were then downloaded in the post-timing gap and locally
rehashed against the immutable result's recorded hashes: 212,152 raw bytes,
18,787-byte gzip tar SHA256
`4f00e6e2818859aaa88e74deb14bd1b13becb46f9ddf74e5e17f09f724a3d2d4`.
They are available to correctness for independent raw semantic re-parsing.
This report establishes transfer integrity and the stated field/statistics
checks; it does not label that separate correctness audit complete.

Raw result metadata is 361,241 bytes, SHA256
`f85d804f8ddf24f10f70315b2bb16f2b5c9db3a1cea2667be41531170023dc92`.
The [derived result](cached-zero-frame-native-screen-result.json) retains all
240 rows, 15 summaries, launch/source identities, raw digest inventories and
review boundaries. See also [launch](cached-zero-frame-native-launch.json),
[analyzer](analyze_cached_zero_frame_native.py) and
[release](cached-zero-frame-native-release.json). Full command outputs and
binaries remain private; raw text/CSV copies are also private locally, not Git.

At 2026-10-16 01:19:39 UTC the controller had exited, no research process
remained and both SDK/native locks were available. All metadata and raw-file
collection finished before DNS was awakened to execute the separately frozen
E/185 owner32. No physical router was accessed by this work. Complete frozen-C
correctness, all acceptance matrices and independent physical performance
remain necessary for any eventual immutable candidate.
