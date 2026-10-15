# Frozen performance report tables

These tables report analyzer results, not final candidate acceptance. Correctness, client health and justification of memory/ELF growth remain separate gates. Summary consistency is checked here; raw-file verification is performed by the analyzer.

**Baseline-only: no fresh deployed/candidate device comparison is supplied; candidate acceptance is unavailable.**

## Context only — earlier exact-C / deployed DEVICE baseline

Input: `base2-summary.json`; SHA256 `01bef643b5ef40489d50bb28987254b492a5b505ce2cd6a529ab1267dff40a7e`.
Complete: 11 scenes, five alternating pairs each, 110 valid verified windows.

| Side | ELF SHA256 | ELF bytes |
| --- | --- | --- |
| Exact-image C | 097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87 | not supplied |
| Deployed v0.2.0 | 8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7 | not supplied |

All intervals are median [minimum, maximum] of the five per-round statistics; individual operations and historical rounds are never pooled. Δ is right relative to left. Pairs count agreement with the median direction. “Inconclusive” is not proof of equivalence.

| Scene | Metric | Exact-image C | Deployed v0.2.0 | Δ | W | Pairs | CPU precision | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | p50_ms | 0.135418 [0.127263, 0.140188] | 0.194974 [0.190204, 0.201127] | +43.979% | 9.545% | 5/5 | — | slower |
| udp-hit | p95_ms | 0.299076 [0.202281, 0.373786] | 0.404637 [0.300925, 0.550288] | +35.296% | 61.626% | 5/5 | — | inconclusive |
| udp-hit | cpu_us | 82 [74, 84] | 138 [130, 144] | +68.293% | 12.195% | 5/5 | yes | slower |
| udp-miss | p50_ms | 1.64662 [1.63062, 1.66148] | 1.73472 [1.71995, 1.73664] | +5.350% | 1.874% | 5/5 | — | slower |
| udp-miss | p95_ms | 2.91362 [1.93677, 3.67466] | 2.26261 [2.14438, 2.6491] | -22.344% | 59.647% | 3/5 | — | inconclusive |
| udp-miss | cpu_us | 406 [380, 422] | 522 [512, 536] | +28.571% | 10.345% | 5/5 | yes | slower |
| udp-mixed | p50_ms | 0.148343 [0.135572, 0.155038] | 0.207436 [0.203048, 0.208514] | +39.835% | 13.122% | 5/5 | — | slower |
| udp-mixed | p95_ms | 1.74297 [1.69179, 1.9958] | 1.80967 [1.78467, 1.82374] | +3.827% | 17.442% | 4/5 | — | inconclusive |
| udp-mixed | cpu_us | 148 [142, 148] | 218 [216, 218] | +47.297% | 4.054% | 5/5 | yes | slower |
| tcp-hit | p50_ms | 0.178043 [0.173888, 0.179429] | 0.219976 [0.213515, 0.231751] | +23.552% | 8.290% | 5/5 | — | slower |
| tcp-hit | p95_ms | 0.324698 [0.304538, 0.895685] | 0.509277 [0.355937, 0.532058] | +56.846% | 182.061% | 4/5 | — | inconclusive |
| tcp-hit | cpu_us | 114 [112, 114] | 166 [154, 178] | +45.614% | 14.458% | 5/5 | yes | slower |
| tcp-miss | p50_ms | 1.92828 [1.92802, 1.93652] | 1.72345 [1.71146, 1.74526] | -10.622% | 1.961% | 5/5 | — | faster |
| tcp-miss | p95_ms | 2.46624 [2.15817, 4.15773] | 2.31106 [2.06569, 2.59534] | -6.292% | 81.077% | 4/5 | — | inconclusive |
| tcp-miss | cpu_us | 630 [622, 652] | 486 [472, 488] | -22.857% | 4.762% | 5/5 | yes | faster |
| dhcp-home6 | p50_ms | 0.543445 [0.541213, 0.575298] | 0.387712 [0.384789, 0.390869] | -28.657% | 6.272% | 5/5 | — | faster |
| dhcp-home6 | p95_ms | 0.860064 [0.76889, 0.937234] | 0.688561 [0.64147, 0.835678] | -19.941% | 28.205% | 5/5 | — | inconclusive |
| dhcp-home6 | cpu_us | 464 [460, 468] | 400 [396, 404] | -13.793% | 2.000% | 5/5 | yes | faster |
| dhcp-home6 | dora_p50_ms | 2.01629 [1.98982, 2.31228] | 1.82424 [1.80178, 1.84692] | — | — | — | — | descriptive only |
| dhcp-home6 | dora_p95_ms | 2.33613 [2.20101, 3.04348] | 2.12316 [2.05954, 3.61399] | — | — | — | — | descriptive only |
| dhcp | p50_ms | 6.26957 [6.23896, 6.3609] | 3.92513 [3.85159, 4.04839] | -37.394% | 5.014% | 5/5 | — | faster |
| dhcp | p95_ms | 6.87797 [6.65912, 405.894] | 5.45761 [4.56667, 69.7405] | -20.651% | 5804.545% | 4/5 | — | inconclusive |
| dhcp | cpu_us | 5936 [5916, 6024] | 3912 [3876, 3952] | -34.097% | 1.943% | 5/5 | yes | faster |
| dhcp | dora_p50_ms | 3.59544 [3.5232, 3.63746] | 2.9148 [2.82686, 3.31121] | -18.930% | 16.617% | 5/5 | — | faster |
| dhcp | dora_p95_ms | 6.54328 [6.44799, 6.92367] | 4.4978 [4.40541, 25.9984] | -31.261% | 480.079% | 4/5 | — | inconclusive |
| startup-small | p50_ms | 4.1468 [4.12256, 4.2156] | 4.75425 [4.7131, 4.79059] | +14.649% | 2.244% | 5/5 | — | inconclusive |
| startup-small | p95_ms | 4.59153 [4.37478, 7.11816] | 5.30017 [5.06696, 7.47585] | +15.434% | 59.749% | 3/5 | — | inconclusive |
| startup-small | cpu_us | 4671.65 [4637.5, 4759.5] | 5823.7 [5799.85, 6024.35] | +24.660% | 3.855% | 5/5 | no | inconclusive |
| config-small | p50_ms | 5.35515 [5.27174, 5.41298] | 6.99029 [6.98165, 7.10619] | +30.534% | 2.638% | 5/5 | — | slower |
| config-small | p95_ms | 5.64191 [5.43247, 5.72385] | 7.38279 [7.1412, 13.6615] | +30.856% | 88.318% | 5/5 | — | inconclusive |
| config-small | cpu_us | 4917.45 [4877.55, 4960.7] | 6144.25 [6118, 6220.4] | +24.948% | 1.691% | 5/5 | no | inconclusive |
| hup-small | p50_ms | 0.625307 [0.623921, 0.633239] | 1.07849 [1.07303, 1.08342] | +72.474% | 1.490% | 5/5 | — | inconclusive |
| hup-small | p95_ms | 0.666162 [0.639693, 0.704325] | 1.29793 [1.13151, 1.48713] | +94.837% | 27.399% | 5/5 | — | inconclusive |
| hup-small | cpu_us | 799.7 [790.8, 808.8] | 1324.4 [1309.05, 1341.2] | +65.612% | 2.428% | 5/5 | no | inconclusive |
| hup-large | p50_ms | 22.1415 [21.9207, 22.7599] | 17.3546 [16.9932, 17.7459] | -21.619% | 4.337% | 5/5 | — | faster |
| hup-large | p95_ms | 23.2813 [22.6292, 28.4144] | 20.4609 [17.8538, 25.6208] | -12.115% | 37.960% | 4/5 | — | inconclusive |
| hup-large | cpu_us | 24545.4 [24109.9, 25077.1] | 18969.2 [18745, 19846.6] | -22.718% | 5.808% | 5/5 | yes | faster |

CPU is µs/operation; all CPU rounds need ≥10 ticks and the median difference must exceed 8 ticks. Lifecycle latency uses a 1 ms observation floor; lifecycle CPU includes startup, idle and shutdown for the whole round. Home6 DORA has only six samples per round and is not ranked.

| Scene | Side | RSS median KiB | RSS peak KiB | Anon peak KiB | File peak KiB | Shmem peak KiB | Tree FD peak | Parent FD peak |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | Exact-image C | 1244 [1212, 1244] | 1244 [1212, 1244] | 228 [228, 228] | 764 [732, 764] | 252 [252, 252] | 11 [11, 11] | 11 [11, 11] |
| udp-hit | Deployed v0.2.0 | 2304 [2208, 2320] | 2304 [2208, 2320] | 516 [512, 516] | 4 [4, 4] | 1784 [1692, 1800] | 12 [12, 12] | 12 [12, 12] |
| udp-miss | Exact-image C | 1244 [1216, 1248] | 1244 [1216, 1248] | 228 [228, 232] | 764 [736, 764] | 252 [252, 252] | 12 [12, 12] | 12 [12, 12] |
| udp-miss | Deployed v0.2.0 | 2428 [2342, 2460] | 2476 [2392, 2512] | 676 [668, 692] | 4 [4, 4] | 1800 [1700, 1832] | 13 [13, 13] | 13 [13, 13] |
| udp-mixed | Exact-image C | 1228 [1216, 1236] | 1228 [1216, 1236] | 228 [228, 228] | 748 [736, 756] | 252 [252, 252] | 11 [11, 11] | 11 [11, 11] |
| udp-mixed | Deployed v0.2.0 | 2408 [2294, 2452] | 2420 [2304, 2456] | 612 [608, 624] | 4 [4, 4] | 1804 [1692, 1840] | 12 [12, 12] | 12 [12, 12] |
| tcp-hit | Exact-image C | 1244 [1232, 1248] | 1244 [1232, 1248] | 232 [228, 232] | 764 [748, 764] | 252 [252, 252] | 143 [143, 143] | 19 [19, 19] |
| tcp-hit | Deployed v0.2.0 | 2512 [2496, 2516] | 2512 [2496, 2516] | 716 [712, 716] | 4 [4, 4] | 1792 [1780, 1796] | 20 [20, 20] | 20 [20, 20] |
| tcp-miss | Exact-image C | 1208 [1168, 1240] | 1208 [1168, 1240] | 224 [220, 224] | 732 [696, 764] | 252 [252, 252] | 151 [151, 151] | 19 [19, 19] |
| tcp-miss | Deployed v0.2.0 | 3518 [3378, 3568] | 3940 [3808, 3980] | 2164 [2120, 2172] | 4 [4, 4] | 1804 [1636, 1812] | 28 [28, 28] | 28 [28, 28] |
| dhcp-home6 | Exact-image C | 1244 [1176, 1248] | 1244 [1176, 1248] | 228 [228, 232] | 764 [696, 764] | 252 [252, 252] | 13 [13, 13] | 13 [13, 13] |
| dhcp-home6 | Deployed v0.2.0 | 2300 [2240, 2320] | 2300 [2240, 2320] | 356 [352, 356] | 4 [4, 4] | 1940 [1880, 1960] | 18 [18, 18] | 18 [18, 18] |
| dhcp | Exact-image C | 1328 [1312, 1340] | 1328 [1312, 1340] | 324 [324, 324] | 752 [736, 764] | 252 [252, 252] | 13 [13, 13] | 13 [13, 13] |
| dhcp | Deployed v0.2.0 | 2860 [2760, 2884] | 2868 [2812, 2892] | 924 [920, 924] | 4 [4, 4] | 1940 [1884, 1968] | 18 [18, 18] | 18 [18, 18] |
| startup-small | Exact-image C | 1240 [1236, 1252] | 1252 [1252, 1256] | 240 [236, 240] | 764 [764, 764] | 252 [252, 252] | 13 [13, 13] | 13 [13, 13] |
| startup-small | Deployed v0.2.0 | 2216 [2210, 2216] | 2256 [2252, 2260] | 352 [352, 352] | 4 [4, 4] | 1904 [1900, 1904] | 18 [18, 18] | 18 [18, 18] |
| config-small | Exact-image C | 1240 [1234, 1244] | 1252 [1252, 1256] | 240 [236, 240] | 764 [764, 764] | 252 [252, 252] | 13 [13, 13] | 13 [13, 13] |
| config-small | Deployed v0.2.0 | 2214 [2208, 2222] | 2260 [2256, 2260] | 352 [352, 352] | 4 [4, 4] | 1904 [1900, 1904] | 18 [18, 18] | 18 [18, 18] |
| hup-small | Exact-image C | 1188 [1188, 1252] | 1188 [1188, 1252] | 240 [236, 240] | 696 [696, 764] | 252 [252, 252] | 13 [13, 13] | 13 [13, 13] |
| hup-small | Deployed v0.2.0 | 2216 [2216, 2268] | 2216 [2216, 2268] | 364 [360, 364] | 4 [4, 4] | 1852 [1848, 1904] | 18 [18, 18] | 18 [18, 18] |
| hup-large | Exact-image C | 1428 [1372, 1440] | 1428 [1372, 1440] | 424 [420, 424] | 752 [696, 764] | 252 [252, 252] | 13 [13, 13] | 13 [13, 13] |
| hup-large | Deployed v0.2.0 | 3252 [3224, 3268] | 3292 [3264, 3308] | 1436 [1432, 1436] | 4 [4, 4] | 1856 [1824, 1868] | 18 [18, 18] | 18 [18, 18] |

Lifecycle memory/FD values are readiness snapshots, not transient peaks. RSS and RssAnon are not private memory; device PSS/USS are unavailable. ELF byte sizes are measured only when matching local files are supplied with `--elf`.
