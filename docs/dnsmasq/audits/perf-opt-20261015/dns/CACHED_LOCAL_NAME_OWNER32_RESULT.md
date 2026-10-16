# 0161 / accepted E owner32: saturation gain, no low-load CPU gain

The frozen exact-SDK screen completed all 32 windows with no failed or replacement
sample. Low-load CPU is unchanged and fails the original tick-precision gate.
At saturation, CPU/query, throughput and p50/p95 latency improve beyond W in all
five pairs. Both send-lag percentiles regress beyond W. These variable-query
closed-loop results do not select the candidate or constitute full acceptance.

The [frozen plan](CACHED_LOCAL_NAME_OWNER32.md), preparation commit `5acf849a`,
compares candidate `0161ad9c103459c7f59c44ebce9600db1f1697c6` directly with
accepted E `4f869c885b47dcf60d56c872e5b0b3c62237beea`. Old F, standalone
name-buffer and earlier cached-only controls are not pooled. Candidate ELF
`f4230f03137bd235489cda2cfa186e44aefe390d9a5f9afd8368c80e73658aff` is
2,140,955 bytes; E ELF
`8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27` is
2,136,859 bytes. Both original SDK receipts remain `built-unqualified`, with
unchanged release budgets/hardening. The prerequisite is the bound 939 related
Linux passes, not full 44-family qualification. Frozen exact C is unchanged.

## Execution and evidence

The original driver ran 12 PMU and 20 plain windows: stat low three pairs, stat
high three pairs, plain low five pairs, then plain high five pairs. E was first
in odd pairs and the candidate in even pairs. Every window retained the 800-name
A/AAAA 70/30 fixture, 1,000-query prewarm, 5-second warmup, 20-second measured
cohort and 1-second drain. CPU placement and nice values were unchanged. All
counts, PID/start identities and complete tree-tail gates passed. Every window
and its process group exited; controller 644847 exited with empty stderr. The
run ended at 2026-10-16 00:57:07 UTC. No router was accessed or changed.

All builds and transfers preceded timing. After all 32 windows, the unchanged
analysis completed with exit 0 and empty stderr. Postflight rehashed both SDK
ELF/map/build triples, all 358 source files and bound tools; no research process
remained and both native/SDK locks were obtainable. The 1,465,633-byte metadata
archive contains 1,211 files plus its collection receipt, verified locally by
SHA256. The 32 latency binaries, 32 send-lag binaries and 32 per-window maps
remain private on Oracle; their sizes/digests remain in every row. Original
candidate/E maps were already retained locally. Oracle was explicitly released
after analysis and metadata transfer.

## Plain five-pair comparisons

CPU and PMU divide the actual warmup plus measurement completion count N;
prewarm is excluded. Throughput and latency use the measured 20-second cohort.
Low N is 5,000, giving a 2 microsecond/query tick quantum. Low CPU ticks are E
`[16,13,14,14,14]` and candidate `[12,12,14,14,17]`: both medians are 14, so the
original strict >8-tick difference gate fails.

| Metric | E median | 0161 median | Change | W | Beyond original W/direction |
| --- | ---: | ---: | ---: | ---: | --- |
| Low CPU us/query | 28.000000 | 28.000000 | +0.000% | 35.714% | No; tick precision fails |
| Low Throughput queries/s | 200.000000 | 200.000000 | +0.000% | 0.000% | No |
| Low Latency p50 us | 53.041000 | 52.840000 | -0.379% | 16.349% | No |
| Low Latency p95 us | 83.080000 | 81.041000 | -2.454% | 21.717% | No |
| Low Send lag p50 us | 70.370000 | 70.255000 | -0.163% | 4.608% | No |
| Low Send lag p95 us | 81.689000 | 82.001000 | +0.382% | 11.028% | No |
| High CPU us/query | 4.865028 | 4.373513 | -10.103% | 0.837% | Yes, 5/5; diagnostic only |
| High Throughput queries/s | 205477.650000 | 228408.000000 | +11.160% | 0.872% | Yes, 5/5 |
| High Latency p50 us | 151.002000 | 134.401000 | -10.994% | 0.982% | Yes, 5/5 |
| High Latency p95 us | 166.321000 | 148.961000 | -10.438% | 1.780% | Yes, 5/5 |
| High Send lag p50 us | 0.680000 | 2.720000 | +300.000% | 64.706% | Yes, 5/5 |
| High Send lag p95 us | 3.240000 | 5.080000 | +56.790% | 2.469% | Yes, 5/5 |

High plain N is 5,116,929–5,149,168 for E and 5,689,696–5,737,523 for the
candidate. Each daemon consumes about one CPU; sender CPU is 99.813–99.880%.
This measures the closed-loop sender/server pipeline, not isolated server
capacity. High CPU explicitly retains `precision_ok: null`; passing W and
direction does not manufacture a fixed-cohort tick-precision pass. The adverse
send-lag changes are retained: p50 rises 0.68→2.72 us (+2.04 us, +300%) and p95
3.24→5.08 us (+1.84 us, +56.790%), both 5/5 and beyond W. Neither low latency
nor low send-lag change is discernible.

All 20 plain observations follow, in their actual execution order. The JSON
also retains sender CPU, all latency/send-lag/scheduled-latency quantiles, raw
file digests and both phase counts for every window.

| Load/pair/side | N | CPU ticks | CPU us/query | Queries/s | p50 us | p95 us | Send p50 us | Send p95 us |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| low / 1 / E | 5,000 | 16 | 32.000000 | 200.00 | 53.041 | 81.121 | 70.370 | 81.689 |
| low / 1 / 0161 | 5,000 | 12 | 24.000000 | 200.00 | 49.681 | 75.961 | 70.068 | 81.575 |
| low / 2 / 0161 | 5,000 | 12 | 24.000000 | 200.00 | 50.001 | 81.041 | 69.629 | 81.131 |
| low / 2 / E | 5,000 | 13 | 26.000000 | 200.00 | 49.521 | 83.080 | 69.723 | 81.226 |
| low / 3 / E | 5,000 | 14 | 28.000000 | 200.00 | 52.080 | 81.081 | 69.887 | 81.269 |
| low / 3 / 0161 | 5,000 | 14 | 28.000000 | 200.00 | 58.000 | 87.600 | 70.961 | 85.284 |
| low / 4 / 0161 | 5,000 | 14 | 28.000000 | 200.00 | 52.840 | 80.161 | 70.255 | 82.001 |
| low / 4 / E | 5,000 | 14 | 28.000000 | 200.00 | 53.401 | 88.121 | 72.966 | 90.235 |
| low / 5 / E | 5,000 | 14 | 28.000000 | 200.00 | 56.441 | 83.641 | 70.837 | 83.073 |
| low / 5 / 0161 | 5,000 | 17 | 34.000000 | 200.00 | 58.320 | 93.561 | 71.399 | 83.593 |
| high / 1 / E | 5,149,168 | 2498 | 4.851269 | 206121.05 | 150.961 | 164.481 | 0.720 | 3.240 |
| high / 1 / 0161 | 5,695,721 | 2499 | 4.387504 | 227993.45 | 134.761 | 149.081 | 2.720 | 5.080 |
| high / 2 / 0161 | 5,711,656 | 2498 | 4.373513 | 228408.00 | 134.401 | 148.841 | 2.720 | 5.040 |
| high / 2 / E | 5,134,606 | 2498 | 4.865028 | 205477.65 | 151.002 | 166.521 | 0.640 | 3.200 |
| high / 3 / E | 5,147,466 | 2498 | 4.852873 | 206002.10 | 150.801 | 165.522 | 1.080 | 3.280 |
| high / 3 / 0161 | 5,689,696 | 2498 | 4.390393 | 227632.75 | 134.921 | 149.241 | 2.720 | 5.040 |
| high / 4 / 0161 | 5,714,405 | 2498 | 4.371409 | 228560.40 | 134.121 | 148.961 | 2.760 | 5.120 |
| high / 4 / E | 5,116,929 | 2497 | 4.879880 | 204666.35 | 151.602 | 167.441 | 0.640 | 3.240 |
| high / 5 / E | 5,128,995 | 2498 | 4.870350 | 205271.70 | 151.201 | 166.321 | 0.680 | 3.280 |
| high / 5 / 0161 | 5,737,523 | 2498 | 4.353795 | 229624.80 | 133.601 | 148.041 | 2.760 | 5.160 |

## Separate PMU observations

All 12 windows used one inherited group of unscaled user/kernel instructions
and cycles; enabled/running times are equal across all four events in each
window. IPC is each window's raw user instructions divided by its raw user
cycles. The three-window medians are:

| Metric per query | Low E | Low 0161 | High E | High 0161 |
| --- | ---: | ---: | ---: | ---: |
| instructions:u | 9535.02240 | 7956.42200 | 7350.71209 | 5767.28342 |
| cycles:u | 20955.27380 | 17706.39760 | 4709.91105 | 3640.90788 |
| instructions:k | 26057.24120 | 25616.76440 | 13284.04313 | 13013.44333 |
| cycles:k | 40478.03660 | 37922.67080 | 9791.81809 | 9419.95273 |
| user_ipc | 0.45502 | 0.44935 | 1.56057 | 1.58402 |

User instructions decrease 16.556% at low load and 21.541% at high load; user
cycles decrease 15.504% and 22.697%. These are separate mechanism observations
and do not replace the plain low-load CPU failure. All 12 PMU observations are
retained below, without pooling their values with plain windows.

| Load/pair/side | N | User instructions/query | User cycles/query | Kernel instructions/query | Kernel cycles/query | Same-window user IPC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| low / 1 / E | 5,000 | 9535.022 | 20955.274 | 25836.408 | 39690.583 | 0.455018 |
| low / 1 / 0161 | 5,000 | 7956.422 | 17706.398 | 25616.764 | 38381.393 | 0.449353 |
| low / 2 / 0161 | 5,000 | 7956.399 | 17538.006 | 25778.708 | 37922.671 | 0.453666 |
| low / 2 / E | 5,000 | 9535.583 | 21515.002 | 26057.241 | 40478.037 | 0.443206 |
| low / 3 / E | 5,000 | 9534.721 | 20719.629 | 26145.046 | 40955.649 | 0.460178 |
| low / 3 / 0161 | 5,000 | 7956.782 | 17802.065 | 25503.509 | 36172.475 | 0.446958 |
| high / 1 / E | 5,078,309 | 7350.712 | 4715.703 | 13279.873 | 9852.972 | 1.558773 |
| high / 1 / 0161 | 5,677,460 | 5766.914 | 3618.794 | 13013.443 | 9419.953 | 1.593601 |
| high / 2 / 0161 | 5,628,788 | 5767.329 | 3646.444 | 13012.356 | 9469.885 | 1.581631 |
| high / 2 / E | 5,114,607 | 7350.149 | 4709.911 | 13284.043 | 9778.338 | 1.560571 |
| high / 3 / E | 5,107,191 | 7351.020 | 4693.806 | 13289.772 | 9791.818 | 1.566111 |
| high / 3 / 0161 | 5,670,339 | 5767.283 | 3640.908 | 13018.434 | 9411.660 | 1.584023 |

## Audit boundary

The author recomputed all 32 CPU tick/starttime/count scopes and checked all 12
PMU equal enabled/running times, unscaled counts and same-window IPC after local
metadata verification. Independent audit `30633841` passed all 1,211 small
file hashes and archive members, all 32 count/CPU/starttime scopes, all 12 raw
four-event CSV/stderr groups, and all published row fields and W aggregates.
Its [separate receipt](../correctness/cached-local-name-owner32-independent-audit.json)
has SHA256 `a8dcc53d2a55ef5ebb05e78bc76dedd36852b314b90436b45de07d31ecba0c28`.
Large latency/send-lag quantiles come from the original analyzer reading every
retained binary; the independent auditor recomputed their five-pair aggregates
but did not reread those binaries. No additional samples, approximations or
acceptance rules were introduced. The derived JSON retains its original
pre-review snapshot unchanged.

The original summary SHA256 is
`ba7fc3d712a0dba4169959e6841a92a977807741117fa2370b4c72822d053c83`;
metadata archive SHA256 is
`5c9eb12178c5fda2700a81a2f68da03e12de20bf283978dab2c8424a8a091ede`.
[The complete derived result](cached-local-name-owner32-result.json) preserves
all 32 rows, original comparisons, identities, progress and postflight scope.
This screen does not supersede separate A53 results, the full correctness
families or the fixed 11-scene qualification.
