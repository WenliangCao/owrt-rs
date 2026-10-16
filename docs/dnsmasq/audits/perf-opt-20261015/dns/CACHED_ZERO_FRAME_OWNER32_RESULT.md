# 185 / accepted E owner32: saturation gain, low-load CPU remains inconclusive

The frozen exact-SDK screen completed all 32 windows with no failed measurement
or replacement sample. Low-load CPU is 28→26 us/query, but its one-tick median
difference fails the original precision gate and the change remains below W.
At saturation, CPU/query, throughput and p50/p95 latency improve beyond W in all
five pairs. Both send-lag percentiles regress beyond W. These variable-query
closed-loop results do not select the candidate or constitute full acceptance.

The [frozen plan](CACHED_ZERO_FRAME_OWNER32.md), commit `73ad729e`, compares
candidate `185db90c9cabd26c0af09765636ef15bf6d35f79` directly with accepted E
`4f869c885b47dcf60d56c872e5b0b3c62237beea`. Old 0161, F and standalone-child
controls are not pooled. The owner-clock prototype is excluded. Candidate ELF
`9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99` is
2,145,051 bytes; E ELF
`8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27` is
2,136,859 bytes. Both original SDK receipts remain `built-unqualified`, with
unchanged release budgets/hardening. The prerequisite is the bound 940 related
Linux passes, not full 44-family qualification. Frozen exact C is unchanged.

## Execution and retained prelaunch failure

The original driver ran 12 PMU and 20 plain windows: stat low three pairs, stat
high three pairs, plain low five pairs, then plain high five pairs. E was first
in odd pairs and the candidate in even pairs. Every window retained 800 names,
A/AAAA70/30, 1,000-query prewarm, 5-second warmup, 20-second measured cohort,
1-second drain, and the original CPU/nice placement. All traffic, PID/starttime
and complete tree-tail gates passed. Every window and its process group exited;
controller 663879 exited with empty stderr. The run ended at 2026-10-16
01:38:28 UTC. No router was accessed or changed by this screen.

The first launch-wrapper attempt stopped before creating the output directory,
controller logs or a daemon: its read-only process check classified its own
remote `bash -c` here-document wrapper (PID663560) as a research process because
the command contained the research path. Replacing that wrapper with
`exec python3` removed the self-match. The frozen runner, plan, driver and
32-window order were unchanged. No measured window existed or was rerun. The
private failure record retains the stage and cause and identifies the original
stderr in the Codex tool transcript; no standalone original stderr file was
captured for that prelaunch failure. The successful launch found no research
processes and both SDK/native locks obtainable.

All builds and transfers preceded timing. After all 32 windows, the original
analyzer completed with exit 0 and empty stderr. Postflight rehashed both SDK
ELF/map/build triples, all 358 source files and bound tools; no research process
remained and both native/SDK locks were obtainable. The 1,464,132-byte metadata
archive contains 1,212 files plus its collection receipt, verified locally by
SHA256. The 32 latency binaries, 32 send-lag binaries and 32 per-window maps
remain private on Oracle, with their sizes/digests preserved in every row.
Original candidate/E maps were already retained locally. Oracle was explicitly
released after analysis and metadata transfer.

## Plain five-pair comparisons

CPU and PMU divide actual warmup plus measurement completion count N; prewarm
is excluded. Throughput and latency use the measured 20-second cohort. Low N
is 5,000, giving a 2 us/query tick quantum. Low CPU ticks are E
`[12,14,15,14,14]` and candidate `[13,13,13,12,13]`: median14→13, only one tick.
The original strict >8-tick gate fails. Its 7.143% CPU change is also below
W=21.429%, despite 4/5 improving pairs.

| Metric | E median | 185 median | Change | W | Beyond original W/direction |
| --- | ---: | ---: | ---: | ---: | --- |
| Low CPU us/query | 28.000000 | 26.000000 | -7.143% | 21.429% | No; tick precision fails |
| Low Throughput queries/s | 200.000000 | 200.000000 | +0.000% | 0.000% | No |
| Low Latency p50 us | 53.760000 | 54.681000 | +1.713% | 10.975% | No |
| Low Latency p95 us | 82.801000 | 78.920000 | -4.687% | 14.058% | No |
| Low Send lag p50 us | 70.402000 | 70.588000 | +0.264% | 3.902% | No |
| Low Send lag p95 us | 81.742000 | 81.975000 | +0.285% | 12.026% | No |
| High CPU us/query | 4.877504 | 4.286895 | -12.109% | 0.829% | Yes, 5/5; diagnostic only |
| High Throughput queries/s | 204855.450000 | 233398.750000 | +13.933% | 1.267% | Yes, 5/5 |
| High Latency p50 us | 151.641000 | 131.161000 | -13.506% | 0.732% | Yes, 5/5 |
| High Latency p95 us | 166.482000 | 145.601000 | -12.542% | 1.705% | Yes, 5/5 |
| High Send lag p50 us | 0.680000 | 2.760000 | +305.882% | 64.706% | Yes, 5/5 |
| High Send lag p95 us | 3.240000 | 5.680000 | +75.309% | 17.606% | Yes, 5/5 |

High plain N is 5,069,586–5,132,194 for E and 5,819,978–5,856,987 for the
candidate. Each daemon consumes about one CPU; sender CPU is 99.513–99.900%.
This measures the closed-loop sender/server pipeline, not isolated server
capacity. High CPU explicitly retains `precision_ok: null`; passing W and
direction does not manufacture a fixed-cohort tick-precision pass. The adverse
send-lag changes remain: p50 rises 0.68→2.76 us (+2.08 us, +305.882%) and p95
3.24→5.68 us (+2.44 us, +75.309%), both 5/5 and beyond W. Neither low latency
nor low send-lag change is discernible.

All 20 plain observations follow, in actual execution order. The JSON also
retains sender CPU, latency/send-lag/scheduled-latency quantiles, raw file
digests and both phase counts for every window.

| Load/pair/side | N | CPU ticks | CPU us/query | Queries/s | p50 us | p95 us | Send p50 us | Send p95 us |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| low / 1 / E | 5,000 | 12 | 24.000000 | 200.00 | 51.361 | 81.121 | 68.403 | 90.489 |
| low / 1 / 185 | 5,000 | 13 | 26.000000 | 200.00 | 55.841 | 79.361 | 71.787 | 84.915 |
| low / 2 / 185 | 5,000 | 13 | 26.000000 | 200.00 | 54.681 | 77.760 | 70.581 | 81.507 |
| low / 2 / E | 5,000 | 14 | 28.000000 | 200.00 | 52.440 | 82.801 | 70.462 | 81.698 |
| low / 3 / E | 5,000 | 15 | 30.000000 | 200.00 | 53.760 | 92.761 | 68.432 | 80.659 |
| low / 3 / 185 | 5,000 | 13 | 26.000000 | 200.00 | 49.840 | 78.920 | 70.449 | 81.748 |
| low / 4 / 185 | 5,000 | 12 | 24.000000 | 200.00 | 55.721 | 78.241 | 70.588 | 82.046 |
| low / 4 / E | 5,000 | 14 | 28.000000 | 200.00 | 56.200 | 81.561 | 70.402 | 81.742 |
| low / 5 / E | 5,000 | 14 | 28.000000 | 200.00 | 56.841 | 83.920 | 71.150 | 82.915 |
| low / 5 / 185 | 5,000 | 13 | 26.000000 | 200.00 | 53.521 | 85.161 | 70.610 | 81.975 |
| high / 1 / E | 5,122,175 | 2498 | 4.876835 | 204899.35 | 151.641 | 166.482 | 1.080 | 3.320 |
| high / 1 / 185 | 5,819,978 | 2499 | 4.293831 | 233008.95 | 131.281 | 146.401 | 2.760 | 6.400 |
| high / 2 / 185 | 5,822,237 | 2499 | 4.292165 | 232909.95 | 131.481 | 145.601 | 2.800 | 5.600 |
| high / 2 / E | 5,069,586 | 2490 | 4.911644 | 202771.05 | 152.441 | 168.361 | 0.640 | 3.240 |
| high / 3 / E | 5,121,472 | 2498 | 4.877504 | 204855.45 | 151.482 | 166.241 | 0.680 | 3.240 |
| high / 3 / 185 | 5,852,196 | 2498 | 4.268483 | 234268.10 | 130.681 | 144.802 | 2.760 | 5.680 |
| high / 4 / 185 | 5,856,987 | 2499 | 4.266699 | 234472.00 | 130.521 | 144.761 | 2.760 | 5.400 |
| high / 4 / E | 5,132,194 | 2500 | 4.871211 | 205365.60 | 151.361 | 165.522 | 0.680 | 3.240 |
| high / 5 / E | 5,104,607 | 2498 | 4.893619 | 204119.50 | 152.241 | 166.521 | 0.640 | 3.200 |
| high / 5 / 185 | 5,827,061 | 2498 | 4.286895 | 233398.75 | 131.161 | 145.601 | 2.760 | 5.720 |

## Separate PMU observations

All 12 windows used one inherited group of unscaled user/kernel instructions
and cycles. Enabled/running times are equal across all four events in each
window. IPC is each window's raw user instructions divided by its raw user
cycles. The three-window medians are:

| Metric per query | Low E | Low 185 | High E | High 185 |
| --- | ---: | ---: | ---: | ---: |
| instructions:u | 9534.79620 | 7690.88720 | 7351.13277 | 5501.49290 |
| cycles:u | 20892.38400 | 17547.31540 | 4713.69821 | 3506.26050 |
| instructions:k | 25873.47720 | 25836.61200 | 13279.12106 | 13004.95626 |
| cycles:k | 39030.32220 | 39148.27220 | 9830.96147 | 9280.55174 |
| user_ipc | 0.45641 | 0.43829 | 1.55961 | 1.56915 |

User instructions decrease 19.339% at low load and 25.161% at high load; user
cycles decrease 16.011% and 25.616%. Low kernel cycles increase 0.302%. These
separate mechanism observations do not replace the plain low-load CPU failure.
All 12 PMU observations are retained below, without pooling with plain windows.

| Load/pair/side | N | User instructions/query | User cycles/query | Kernel instructions/query | Kernel cycles/query | Same-window user IPC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| low / 1 / E | 5,000 | 9535.496 | 20892.384 | 25864.455 | 39030.322 | 0.456410 |
| low / 1 / 185 | 5,000 | 7690.830 | 17547.315 | 30511.813 | 48457.328 | 0.438291 |
| low / 2 / 185 | 5,000 | 7691.303 | 17887.509 | 25836.612 | 39148.272 | 0.429982 |
| low / 2 / E | 5,000 | 9534.796 | 20454.176 | 25873.477 | 38450.800 | 0.466154 |
| low / 3 / E | 5,000 | 9534.543 | 23111.668 | 29466.854 | 49266.350 | 0.412542 |
| low / 3 / 185 | 5,000 | 7690.887 | 17091.424 | 25678.435 | 38038.893 | 0.449985 |
| high / 1 / E | 5,075,872 | 7351.133 | 4724.012 | 13294.482 | 9815.401 | 1.556121 |
| high / 1 / 185 | 5,795,924 | 5501.849 | 3506.261 | 13007.469 | 9280.552 | 1.569150 |
| high / 2 / 185 | 5,801,616 | 5501.424 | 3506.354 | 13001.467 | 9265.825 | 1.568987 |
| high / 2 / E | 5,069,994 | 7351.543 | 4713.698 | 13279.121 | 9904.037 | 1.559613 |
| high / 3 / E | 5,098,050 | 7350.680 | 4695.350 | 13276.301 | 9830.961 | 1.565523 |
| high / 3 / 185 | 5,790,670 | 5501.493 | 3492.015 | 13004.956 | 9296.980 | 1.575450 |

## Audit boundary

The author recomputed all 32 CPU tick/starttime/count scopes and checked all 12
PMU equal enabled/running times, unscaled counts and same-window IPC after local
metadata verification. Independent audit `96dd984b` passed all 1,212 small
files and archive members, all 32 count/CPU/starttime scopes, all 12 actual
four-event CSV/stderr groups, and all row fields and summary/W aggregates.
The [separate audit receipt](../correctness/cached-zero-frame-owner32-independent-audit.json)
has SHA256 `f8076829c4f5da0a8fab119161301810103537078aacb0653e905afe10d15c83`.
Large latency/send-lag quantiles come from the original analyzer reading every
retained binary; the independent auditor rechecked their five-pair aggregates
but did not reread the binaries. No additional samples, approximations or
acceptance rules were introduced. The result JSON retains its original
pre-review snapshot unchanged.

The original summary SHA256 is
`250437be6c83ef0dbb094e7b268b2fad259a86d19f29039e5ec12794c1287c95`;
metadata archive SHA256 is
`051e92355c18a22388764f74d6255df4e500181f5b14616d49872a08d5a806fe`.
[The complete derived result](cached-zero-frame-owner32-result.json) preserves
all 32 rows, original comparisons, identities, progress, prelaunch failure and
postflight scope. This screen does not supersede separate native240/A53 results,
the full correctness families or the fixed 11-scene qualification.
