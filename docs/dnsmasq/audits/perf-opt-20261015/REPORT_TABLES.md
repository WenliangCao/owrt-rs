# Frozen performance report tables

These tables report analyzer results, not final candidate acceptance. Correctness, client health and justification of memory/ELF growth remain separate gates. Summary consistency is checked here; raw-file verification is performed by the analyzer.

Separate compatibility correction: Authorized stale CNAME repair b1136023 is separate from performance changes; whole-artifact timing includes its layout, but the benchmark does not trigger that expired-negative terminal case.
It is not classified as a performance optimization; whole-artifact timing cannot attribute its individual effect.

**Baseline-only: no fresh deployed/candidate device comparison is supplied; candidate acceptance is unavailable.**

## Context only — earlier exact-C / deployed DEVICE baseline

Input: `base2-summary.json`; SHA256 `01bef643b5ef40489d50bb28987254b492a5b505ce2cd6a529ab1267dff40a7e`.
Complete: 11 scenes, five alternating pairs each, 110 valid verified windows.

| Side | ELF SHA256 | ELF bytes |
| --- | --- | --- |
| Exact-image C | 097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87 | 269305 |
| Deployed v0.2.0 | 8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7 | 2124571 |

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

## ORACLE screen only — not device measurements or acceptance

Input: `oracle-c-summary.json`; SHA256 `2d492f076fe77007704ceabcf8b160913c1b5ca04583d2466ac045f2900b8a6a`.
Complete: 11 scenes, five alternating pairs each, 110 valid verified windows.

| Side | ELF SHA256 | ELF bytes |
| --- | --- | --- |
| Oracle baseline | 8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7 | 2124571 |
| Oracle candidate | b4c4a8e40698feb7aa57da09699bb2988ac1cf4bb54345474a9f659a12edcda1 | 2136859 |

All intervals are median [minimum, maximum] of the five per-round statistics; individual operations and historical rounds are never pooled. Δ is right relative to left. Pairs count agreement with the median direction. “Inconclusive” is not proof of equivalence.

| Scene | Metric | Oracle baseline | Oracle candidate | Δ | W | Pairs | CPU precision | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | p50_ms | 0.0358 [0.033961, 0.03932] | 0.034521 [0.03384, 0.03584] | -3.573% | 14.969% | 3/5 | — | inconclusive |
| udp-hit | p95_ms | 0.062321 [0.06076, 0.076001] | 0.06128 [0.061, 0.06232] | -1.670% | 24.456% | 4/5 | — | inconclusive |
| udp-hit | cpu_us | 28 [26, 30] | 26 [26, 28] | -7.143% | 14.286% | 2/5 | no | inconclusive |
| udp-miss | p50_ms | 1.18641 [1.18077, 1.18785] | 1.18089 [1.17809, 1.20917] | -0.465% | 2.632% | 3/5 | — | inconclusive |
| udp-miss | p95_ms | 1.22817 [1.20613, 1.23757] | 1.22645 [1.22441, 1.24949] | -0.140% | 2.560% | 2/5 | — | inconclusive |
| udp-miss | cpu_us | 88 [84, 92] | 86 [80, 94] | -2.273% | 16.279% | 3/5 | no | inconclusive |
| udp-mixed | p50_ms | 0.039441 [0.03872, 0.05768] | 0.03832 [0.037361, 0.038761] | -2.842% | 48.072% | 4/5 | — | inconclusive |
| udp-mixed | p95_ms | 1.25701 [1.24409, 1.27057] | 1.25213 [1.24877, 1.25741] | -0.388% | 2.107% | 4/5 | — | inconclusive |
| udp-mixed | cpu_us | 48 [44, 50] | 44 [44, 46] | -8.333% | 12.500% | 3/5 | no | inconclusive |
| tcp-hit | p50_ms | 0.044601 [0.04364, 0.05152] | 0.04248 [0.0414, 0.04468] | -4.755% | 17.668% | 4/5 | — | inconclusive |
| tcp-hit | p95_ms | 0.076721 [0.075601, 0.089] | 0.076881 [0.0744, 0.097881] | +0.209% | 30.542% | 3/5 | — | inconclusive |
| tcp-hit | cpu_us | 36 [32, 38] | 34 [32, 36] | -5.556% | 16.667% | 2/5 | no | inconclusive |
| tcp-miss | p50_ms | 1.19697 [1.19125, 1.21529] | 1.19789 [1.19177, 1.21109] | +0.077% | 2.008% | 3/5 | — | inconclusive |
| tcp-miss | p95_ms | 1.24305 [1.24053, 1.25457] | 1.25013 [1.23241, 1.26597] | +0.570% | 2.685% | 2/5 | — | inconclusive |
| tcp-miss | cpu_us | 90 [86, 92] | 88 [86, 98] | -2.222% | 13.636% | 2/5 | no | inconclusive |
| dhcp-home6 | p50_ms | 0.059841 [0.05932, 0.067761] | 0.062161 [0.060401, 0.068721] | +3.877% | 14.106% | 4/5 | — | inconclusive |
| dhcp-home6 | p95_ms | 2.0613 [1.90194, 2.3327] | 2.15734 [1.83478, 2.27738] | +4.659% | 20.898% | 4/5 | — | inconclusive |
| dhcp-home6 | cpu_us | 80 [76, 84] | 80 [76, 84] | +0.000% | 10.000% | 0/5 | no | inconclusive |
| dhcp-home6 | dora_p50_ms | 2.56766 [2.3689, 2.68446] | 2.59106 [2.38142, 2.88406] | — | — | — | — | descriptive only |
| dhcp-home6 | dora_p95_ms | 5.0324 [3.49723, 7.8025] | 4.01191 [2.98407, 5.23408] | — | — | — | — | descriptive only |
| dhcp | p50_ms | 2.83478 [2.7877, 2.97959] | 2.63406 [2.54946, 2.76914] | -7.081% | 8.340% | 5/5 | — | inconclusive |
| dhcp | p95_ms | 3.32159 [3.23055, 3.57235] | 3.13403 [3.08783, 3.21843] | -5.647% | 10.290% | 5/5 | — | inconclusive |
| dhcp | cpu_us | 732 [712, 892] | 544 [520, 552] | -25.683% | 24.590% | 5/5 | yes | faster |
| dhcp | dora_p50_ms | 2.49142 [2.43682, 2.96902] | 2.5665 [2.49358, 2.67002] | +3.014% | 21.362% | 4/5 | — | inconclusive |
| dhcp | dora_p95_ms | 3.11587 [2.89494, 3.44447] | 3.01066 [2.88578, 3.40935] | -3.376% | 17.636% | 2/5 | — | inconclusive |
| startup-small | p50_ms | 1.45909 [1.45009, 1.47401] | 1.44637 [1.43585, 1.48601] | -0.872% | 3.468% | 3/5 | — | inconclusive |
| startup-small | p95_ms | 1.52673 [1.49101, 1.55561] | 1.53657 [1.47365, 2.32138] | +0.645% | 55.170% | 3/5 | — | inconclusive |
| startup-small | cpu_us | 1602.95 [1591.4, 1629.95] | 1516.3 [1509.7, 1556.45] | -5.406% | 3.083% | 5/5 | no | inconclusive |
| config-small | p50_ms | 2.48522 [2.43794, 2.5097] | 2.49178 [2.4615, 2.51946] | +0.264% | 2.888% | 3/5 | — | inconclusive |
| config-small | p95_ms | 2.57138 [2.50446, 2.58698] | 2.58674 [2.50694, 2.61002] | +0.597% | 3.985% | 3/5 | — | inconclusive |
| config-small | cpu_us | 1738.25 [1701.35, 1775.3] | 1665.95 [1630.65, 1696.35] | -4.159% | 4.254% | 5/5 | no | inconclusive |
| hup-small | p50_ms | 0.302803 [0.298443, 0.309483] | 0.276523 [0.265282, 0.283922] | -8.679% | 6.741% | 5/5 | — | inconclusive |
| hup-small | p95_ms | 0.333643 [0.321083, 0.354123] | 0.305883 [0.297483, 0.315883] | -8.320% | 9.903% | 5/5 | — | inconclusive |
| hup-small | cpu_us | 338.45 [333.1, 349.7] | 308.3 [299.9, 312.7] | -8.908% | 4.905% | 5/5 | no | inconclusive |
| hup-large | p50_ms | 3.00226 [2.99415, 3.04799] | 2.63826 [2.58982, 2.7183] | -12.124% | 4.870% | 5/5 | — | inconclusive |
| hup-large | p95_ms | 3.13115 [3.09127, 3.34651] | 3.19231 [3.03039, 3.43899] | +1.953% | 12.800% | 2/5 | — | inconclusive |
| hup-large | cpu_us | 3263.6 [3225.15, 3352.2] | 2921.3 [2893.4, 3035.25] | -10.488% | 4.856% | 5/5 | no | inconclusive |

CPU is µs/operation; all CPU rounds need ≥10 ticks and the median difference must exceed 8 ticks. Lifecycle latency uses a 1 ms observation floor; lifecycle CPU includes startup, idle and shutdown for the whole round. Home6 DORA has only six samples per round and is not ranked.

| Scene | Side | RSS median KiB | RSS peak KiB | Anon peak KiB | File peak KiB | Shmem peak KiB | Tree FD peak | Parent FD peak |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | Oracle baseline | 2320 [2252, 2320] | 2320 [2252, 2320] | 516 [512, 516] | 1804 [1740, 1804] | 0 [0, 0] | 12 [12, 12] | 12 [12, 12] |
| udp-hit | Oracle candidate | 2388 [2384, 2388] | 2388 [2384, 2388] | 520 [516, 520] | 1868 [1868, 1868] | 0 [0, 0] | 12 [12, 12] | 12 [12, 12] |
| udp-miss | Oracle baseline | 2432 [2428, 2448] | 2476 [2472, 2480] | 672 [668, 676] | 1804 [1804, 1804] | 0 [0, 0] | 13 [12, 14] | 13 [12, 14] |
| udp-miss | Oracle candidate | 2438 [2434, 2442] | 2476 [2472, 2484] | 672 [668, 680] | 1804 [1804, 1804] | 0 [0, 0] | 13 [12, 13] | 13 [12, 13] |
| udp-mixed | Oracle baseline | 2408 [2404, 2410] | 2416 [2408, 2420] | 612 [604, 616] | 1804 [1804, 1804] | 0 [0, 0] | 12 [12, 12] | 12 [12, 12] |
| udp-mixed | Oracle candidate | 2470 [2464, 2480] | 2480 [2472, 2484] | 612 [604, 616] | 1868 [1868, 1868] | 0 [0, 0] | 12 [12, 12] | 12 [12, 12] |
| tcp-hit | Oracle baseline | 2520 [2516, 2520] | 2520 [2516, 2520] | 716 [712, 716] | 1804 [1804, 1804] | 0 [0, 0] | 20 [20, 20] | 20 [20, 20] |
| tcp-hit | Oracle candidate | 2584 [2580, 2584] | 2584 [2580, 2584] | 716 [712, 716] | 1868 [1868, 1868] | 0 [0, 0] | 20 [20, 20] | 20 [20, 20] |
| tcp-miss | Oracle baseline | 3540 [3516, 3550] | 3964 [3896, 3992] | 2160 [2092, 2188] | 1804 [1804, 1804] | 0 [0, 0] | 28 [28, 28] | 28 [28, 28] |
| tcp-miss | Oracle candidate | 3528 [3510, 3556] | 3928 [3884, 3968] | 2124 [2080, 2164] | 1804 [1804, 1804] | 0 [0, 0] | 28 [28, 28] | 28 [28, 28] |
| dhcp-home6 | Oracle baseline | 2292 [2288, 2292] | 2292 [2288, 2292] | 360 [356, 360] | 1932 [1932, 1932] | 0 [0, 0] | 18 [18, 18] | 18 [18, 18] |
| dhcp-home6 | Oracle candidate | 2292 [2292, 2292] | 2292 [2292, 2292] | 360 [360, 360] | 1932 [1932, 1932] | 0 [0, 0] | 18 [18, 18] | 18 [18, 18] |
| dhcp | Oracle baseline | 2800 [2800, 2804] | 2800 [2800, 2804] | 868 [868, 872] | 1932 [1932, 1932] | 0 [0, 0] | 18 [18, 18] | 18 [18, 18] |
| dhcp | Oracle candidate | 2748 [2746, 2752] | 2752 [2748, 2752] | 820 [816, 820] | 1932 [1932, 1932] | 0 [0, 0] | 18 [18, 18] | 18 [18, 18] |
| startup-small | Oracle baseline | 2212 [2210, 2212] | 2212 [2212, 2212] | 344 [344, 344] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| startup-small | Oracle candidate | 2208 [2208, 2208] | 2208 [2208, 2208] | 340 [340, 340] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| config-small | Oracle baseline | 2212 [2212, 2212] | 2212 [2212, 2212] | 344 [344, 344] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| config-small | Oracle candidate | 2208 [2208, 2208] | 2208 [2208, 2208] | 340 [340, 340] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| hup-small | Oracle baseline | 2232 [2228, 2232] | 2236 [2232, 2236] | 368 [364, 368] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| hup-small | Oracle candidate | 2280 [2276, 2280] | 2288 [2284, 2288] | 356 [352, 356] | 1932 [1932, 1932] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| hup-large | Oracle baseline | 3276 [3276, 3276] | 3300 [3300, 3300] | 1432 [1432, 1432] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| hup-large | Oracle candidate | 3100 [3096, 3100] | 3104 [3100, 3104] | 1172 [1168, 1172] | 1932 [1932, 1932] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |

Lifecycle memory/FD values are readiness snapshots, not transient peaks. RSS and RssAnon are not private memory; device PSS/USS are unavailable. ELF byte sizes are measured only when matching local files are supplied with `--elf`.
