# Frozen performance report tables

These tables report analyzer results, not final candidate acceptance. Correctness, client health and justification of memory/ELF growth remain separate gates. Summary consistency is checked here; raw-file verification is performed by the analyzer.

Separate compatibility correction: Expired-negative-CNAME correction b1136023 and startup hosts/lease reconciliation 4f869c88 are separate behavior repairs; E includes both. Tool fixes are next-version only and were not used in these windows.
It is not classified as a performance optimization; whole-artifact timing cannot attribute its individual effect.

## Primary — authorized effective paired DEVICE comparison

The user approved [the supplement rule](FROZEN_TOOL_WINDOW_SUPPLEMENT.md) after
three original tool-invalid windows, before any supplement ran. This effective
view contains **104 original windows plus six once-only supplemental windows**,
selected as complete pairs with the original odd/even order. Original 110/107
valid and all three invalid windows remain retained and are reported separately
below; no original side is paired with a supplemental side. See the
[pair mapping](candidate-e-pair-selection.json) and
[independent audit](correctness/e-device-effective-independent-audit.json).

Input: `candidate-e-effective-summary.json`; SHA256 `e3a0e556b189f35cde0a5a48abab3aab23d7c76711d03689a8bd439b3411071b`.
Complete: 11 scenes, five alternating pairs each, 110 valid verified windows.

| Side | ELF SHA256 | ELF bytes |
| --- | --- | --- |
| Deployed v0.2.0 | 8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7 | 2124571 |
| Candidate | 8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27 | 2136859 |

All intervals are median [minimum, maximum] of the five per-round statistics; individual operations and historical rounds are never pooled. Δ is right relative to left. Pairs count agreement with the median direction. “Inconclusive” is not proof of equivalence.

| Scene | Metric | Deployed v0.2.0 | Candidate | Δ | W | Pairs | CPU precision | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | p50_ms | 0.191202 [0.181661, 0.200973] | 0.189124 [0.181507, 0.194356] | -1.087% | 10.100% | 3/5 | — | inconclusive |
| udp-hit | p95_ms | 0.292458 [0.267759, 0.387173] | 0.269144 [0.266835, 0.320695] | -7.972% | 40.831% | 3/5 | — | inconclusive |
| udp-hit | cpu_us | 134 [130, 140] | 132 [130, 136] | -1.493% | 7.463% | 1/5 | no | inconclusive |
| udp-miss | p50_ms | 1.7222 [1.7185, 1.72528] | 1.61694 [1.61194, 1.62517] | -6.112% | 0.818% | 5/5 | — | faster |
| udp-miss | p95_ms | 1.95133 [1.92463, 2.12922] | 1.85362 [1.80506, 1.96911] | -5.008% | 10.485% | 4/5 | — | inconclusive |
| udp-miss | cpu_us | 514 [510, 516] | 438 [434, 444] | -14.786% | 2.283% | 5/5 | yes | faster |
| udp-mixed | p50_ms | 0.209283 [0.206667, 0.210822] | 0.20382 [0.201204, 0.21313] | -2.610% | 5.851% | 3/5 | — | inconclusive |
| udp-mixed | p95_ms | 1.79414 [1.78821, 1.8213] | 1.73789 [1.68488, 1.91125] | -3.135% | 13.025% | 4/5 | — | inconclusive |
| udp-mixed | cpu_us | 218 [214, 218] | 200 [196, 212] | -8.257% | 8.000% | 5/5 | yes | faster |
| tcp-hit | p50_ms | 0.221824 [0.211207, 0.226364] | 0.210052 [0.199511, 0.213361] | -5.307% | 6.833% | 4/5 | — | inconclusive |
| tcp-hit | p95_ms | 0.366476 [0.324157, 0.47281] | 0.32208 [0.307538, 0.506895] | -12.114% | 61.897% | 4/5 | — | inconclusive |
| tcp-hit | cpu_us | 162 [152, 164] | 156 [150, 158] | -3.704% | 7.407% | 4/5 | no | inconclusive |
| tcp-miss | p50_ms | 1.70973 [1.7055, 1.73566] | 1.56931 [1.56131, 1.58478] | -8.213% | 1.764% | 5/5 | — | faster |
| tcp-miss | p95_ms | 2.00211 [1.96095, 2.09444] | 1.84392 [1.81922, 2.1226] | -7.901% | 16.453% | 4/5 | — | inconclusive |
| tcp-miss | cpu_us | 472 [470, 478] | 378 [374, 390] | -19.915% | 4.233% | 5/5 | yes | faster |
| dhcp-home6 | p50_ms | 0.390635 [0.389558, 0.393559] | 0.397637 [0.392713, 0.427721] | +1.792% | 8.804% | 5/5 | — | inconclusive |
| dhcp-home6 | p95_ms | 0.638774 [0.635465, 0.721256] | 0.612767 [0.605381, 0.729257] | -4.071% | 20.216% | 3/5 | — | inconclusive |
| dhcp-home6 | cpu_us | 400 [396, 408] | 412 [408, 416] | +3.000% | 3.000% | 4/5 | no | inconclusive |
| dhcp-home6 | dora_p50_ms | 1.87647 [1.76652, 1.92725] | 1.79244 [1.7282, 1.88293] | — | — | — | — | descriptive only |
| dhcp-home6 | dora_p95_ms | 2.39806 [2.19162, 5.93624] | 2.2721 [2.09429, 3.23588] | — | — | — | — | descriptive only |
| dhcp | p50_ms | 3.86973 [3.85265, 4.07832] | 2.60272 [2.60111, 2.62396] | -32.741% | 5.832% | 5/5 | — | faster |
| dhcp | p95_ms | 4.43048 [4.349, 4.97531] | 2.97474 [2.96304, 3.08946] | -32.857% | 14.136% | 5/5 | — | faster |
| dhcp | cpu_us | 3868 [3844, 3944] | 2592 [2580, 2608] | -32.989% | 2.585% | 5/5 | yes | faster |
| dhcp | dora_p50_ms | 2.91149 [2.84078, 3.15763] | 2.20916 [2.158, 2.25356] | -24.123% | 10.883% | 5/5 | — | faster |
| dhcp | dora_p95_ms | 4.4888 [4.37639, 4.68747] | 3.49571 [3.37622, 3.73092] | -22.124% | 10.147% | 5/5 | — | faster |
| startup-small | p50_ms | 4.75102 [4.71501, 4.85867] | 4.56682 [4.48611, 4.62507] | -3.877% | 3.043% | 5/5 | — | inconclusive |
| startup-small | p95_ms | 5.89254 [5.02917, 8.18411] | 5.07718 [4.92507, 14.7918] | -13.837% | 194.335% | 3/5 | — | inconclusive |
| startup-small | cpu_us | 5941.5 [5852.15, 6005.75] | 5444.8 [5326.9, 5680.85] | -8.360% | 6.501% | 5/5 | no | inconclusive |
| config-small | p50_ms | 7.06991 [7.00643, 7.08329] | 5.88738 [5.80421, 5.97479] | -16.726% | 2.897% | 5/5 | — | faster |
| config-small | p95_ms | 8.06623 [7.3856, 29.6638] | 7.12607 [6.82785, 7.27965] | -11.655% | 276.191% | 5/5 | — | inconclusive |
| config-small | cpu_us | 6280.15 [6208.25, 6532] | 5718.4 [5642.25, 5899.35] | -8.945% | 5.155% | 5/5 | no | inconclusive |
| hup-small | p50_ms | 1.07542 [1.06803, 1.11335] | 1.01456 [1.01202, 1.02195] | -5.659% | 4.214% | 5/5 | — | inconclusive |
| hup-small | p95_ms | 1.23192 [1.1656, 1.34364] | 1.15583 [1.08396, 1.41743] | -6.177% | 28.851% | 4/5 | — | inconclusive |
| hup-small | cpu_us | 1338.35 [1316, 1352.3] | 1234.5 [1222.1, 1256.5] | -7.760% | 2.787% | 5/5 | no | inconclusive |
| hup-large | p50_ms | 17.423 [17.0128, 17.6784] | 14.9701 [14.8715, 15.0647] | -14.078% | 3.820% | 5/5 | — | faster |
| hup-large | p95_ms | 19.0566 [18.5693, 19.8866] | 16.8425 [16.0639, 17.2814] | -11.619% | 7.229% | 5/5 | — | faster |
| hup-large | cpu_us | 19136.3 [18925.8, 19429] | 16333.7 [16132.9, 16467.2] | -14.645% | 2.630% | 5/5 | no | inconclusive |

CPU is µs/operation; all CPU rounds need ≥10 ticks and the median difference must exceed 8 ticks. Lifecycle latency uses a 1 ms observation floor; lifecycle CPU includes startup, idle and shutdown for the whole round. Home6 DORA has only six samples per round and is not ranked.

| Scene | Side | RSS median KiB | RSS peak KiB | Anon peak KiB | File peak KiB | Shmem peak KiB | Tree FD peak | Parent FD peak |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | Deployed v0.2.0 | 2324 [2316, 2332] | 2324 [2316, 2332] | 516 [512, 516] | 4 [4, 4] | 1804 [1796, 1812] | 12 [12, 12] | 12 [12, 12] |
| udp-hit | Candidate | 2404 [2288, 2468] | 2404 [2288, 2468] | 520 [520, 552] | 4 [4, 4] | 1880 [1764, 1916] | 12 [12, 12] | 12 [12, 12] |
| udp-miss | Deployed v0.2.0 | 2408 [2336, 2468] | 2460 [2380, 2516] | 676 [664, 680] | 4 [4, 4] | 1784 [1700, 1832] | 13 [12, 13] | 13 [12, 13] |
| udp-miss | Candidate | 2440 [2394, 2514] | 2492 [2436, 2556] | 672 [668, 692] | 4 [4, 4] | 1796 [1764, 1876] | 13 [12, 13] | 13 [12, 13] |
| udp-mixed | Deployed v0.2.0 | 2408 [2300, 2444] | 2420 [2312, 2452] | 616 [608, 616] | 4 [4, 4] | 1800 [1692, 1840] | 12 [12, 12] | 12 [12, 12] |
| udp-mixed | Candidate | 2478 [2434, 2524] | 2484 [2440, 2528] | 608 [604, 616] | 4 [4, 4] | 1872 [1832, 1916] | 12 [12, 13] | 12 [12, 13] |
| tcp-hit | Deployed v0.2.0 | 2512 [2504, 2552] | 2512 [2504, 2552] | 716 [712, 716] | 4 [4, 4] | 1796 [1788, 1832] | 20 [20, 20] | 20 [20, 20] |
| tcp-hit | Candidate | 2580 [2552, 2600] | 2580 [2552, 2600] | 716 [712, 716] | 4 [4, 4] | 1864 [1832, 1880] | 20 [20, 20] | 20 [20, 20] |
| tcp-miss | Deployed v0.2.0 | 3548 [3472, 3596] | 3980 [3868, 4020] | 2152 [2084, 2180] | 4 [4, 4] | 1796 [1772, 1840] | 28 [28, 28] | 28 [28, 28] |
| tcp-miss | Candidate | 3502 [3426, 3598] | 3900 [3768, 4012] | 2104 [2052, 2156] | 4 [4, 4] | 1804 [1708, 1852] | 28 [28, 28] | 28 [28, 28] |
| dhcp-home6 | Deployed v0.2.0 | 2300 [2268, 2324] | 2300 [2268, 2324] | 356 [352, 356] | 4 [4, 4] | 1940 [1908, 1964] | 18 [18, 18] | 18 [18, 18] |
| dhcp-home6 | Candidate | 2312 [2284, 2340] | 2312 [2284, 2340] | 360 [360, 360] | 4 [4, 4] | 1948 [1920, 1976] | 18 [18, 18] | 18 [18, 18] |
| dhcp | Deployed v0.2.0 | 2804 [2776, 2888] | 2820 [2780, 2892] | 896 [892, 924] | 4 [4, 4] | 1920 [1880, 1968] | 18 [18, 18] | 18 [18, 18] |
| dhcp | Candidate | 2756 [2724, 2804] | 2764 [2732, 2820] | 860 [820, 876] | 4 [4, 4] | 1928 [1892, 1944] | 18 [18, 18] | 18 [18, 18] |
| startup-small | Deployed v0.2.0 | 2210 [2206, 2210] | 2260 [2252, 2260] | 352 [352, 352] | 4 [4, 4] | 1904 [1900, 1904] | 18 [18, 18] | 18 [18, 18] |
| startup-small | Candidate | 2270 [2268, 2284] | 2320 [2296, 2324] | 340 [340, 340] | 4 [4, 4] | 1980 [1952, 1980] | 18 [18, 18] | 18 [18, 18] |
| config-small | Deployed v0.2.0 | 2208 [2204, 2210] | 2260 [2256, 2260] | 352 [352, 352] | 4 [4, 4] | 1904 [1900, 1904] | 18 [18, 18] | 18 [18, 18] |
| config-small | Candidate | 2272 [2256, 2294] | 2320 [2316, 2324] | 340 [340, 340] | 4 [4, 4] | 1976 [1972, 1980] | 18 [18, 18] | 18 [18, 18] |
| hup-small | Deployed v0.2.0 | 2216 [2188, 2268] | 2216 [2188, 2268] | 364 [360, 364] | 4 [4, 4] | 1848 [1820, 1900] | 18 [18, 18] | 18 [18, 18] |
| hup-small | Candidate | 2288 [2276, 2328] | 2292 [2280, 2328] | 356 [352, 356] | 4 [4, 4] | 1936 [1920, 1972] | 18 [18, 18] | 18 [18, 18] |
| hup-large | Deployed v0.2.0 | 3268 [3260, 3276] | 3308 [3300, 3316] | 1436 [1436, 1436] | 4 [4, 4] | 1868 [1860, 1876] | 18 [18, 18] | 18 [18, 18] |
| hup-large | Candidate | 3120 [3072, 3148] | 3124 [3076, 3152] | 1168 [1168, 1172] | 4 [4, 4] | 1948 [1904, 1980] | 18 [18, 18] | 18 [18, 18] |

Lifecycle memory/FD values are readiness snapshots, not transient peaks. RSS and RssAnon are not private memory; device PSS/USS are unavailable. ELF byte sizes are measured only when matching local files are supplied with `--elf`.

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

Input: `oracle-e-summary-verified.json`; SHA256 `202ef36e07e8e829551a4823107d6ba7ac2137873e937877f620a353c939144a`.
Complete: 11 scenes, five alternating pairs each, 110 valid verified windows.

| Side | ELF SHA256 | ELF bytes |
| --- | --- | --- |
| Oracle baseline | 8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7 | 2124571 |
| Oracle candidate | 8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27 | 2136859 |

All intervals are median [minimum, maximum] of the five per-round statistics; individual operations and historical rounds are never pooled. Δ is right relative to left. Pairs count agreement with the median direction. “Inconclusive” is not proof of equivalence.

| Scene | Metric | Oracle baseline | Oracle candidate | Δ | W | Pairs | CPU precision | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | p50_ms | 0.035481 [0.03456, 0.03648] | 0.034 [0.03304, 0.035121] | -4.174% | 6.121% | 5/5 | — | inconclusive |
| udp-hit | p95_ms | 0.06232 [0.06212, 0.063241] | 0.060641 [0.05976, 0.061881] | -2.694% | 3.498% | 5/5 | — | inconclusive |
| udp-hit | cpu_us | 28 [26, 28] | 26 [24, 28] | -7.143% | 15.385% | 3/5 | no | inconclusive |
| udp-miss | p50_ms | 1.18149 [1.17785, 1.19921] | 1.16881 [1.16809, 1.17813] | -1.073% | 1.808% | 5/5 | — | inconclusive |
| udp-miss | p95_ms | 1.23137 [1.21389, 1.24881] | 1.20993 [1.18689, 1.22133] | -1.741% | 2.847% | 5/5 | — | inconclusive |
| udp-miss | cpu_us | 88 [82, 92] | 74 [72, 80] | -15.909% | 11.364% | 5/5 | no | inconclusive |
| udp-mixed | p50_ms | 0.039401 [0.0384, 0.04104] | 0.03784 [0.03732, 0.039441] | -3.962% | 6.700% | 4/5 | — | inconclusive |
| udp-mixed | p95_ms | 1.25165 [1.24421, 1.27049] | 1.23249 [1.22997, 1.23805] | -1.531% | 2.100% | 5/5 | — | inconclusive |
| udp-mixed | cpu_us | 44 [42, 48] | 42 [40, 42] | -4.545% | 13.636% | 4/5 | no | inconclusive |
| tcp-hit | p50_ms | 0.044681 [0.04232, 0.056761] | 0.0426 [0.04188, 0.049961] | -4.657% | 32.320% | 4/5 | — | inconclusive |
| tcp-hit | p95_ms | 0.07616 [0.073841, 0.095841] | 0.07456 [0.070201, 0.07588] | -2.101% | 28.887% | 5/5 | — | inconclusive |
| tcp-hit | cpu_us | 36 [34, 38] | 32 [32, 34] | -11.111% | 11.111% | 5/5 | no | inconclusive |
| tcp-miss | p50_ms | 1.20585 [1.19129, 1.20893] | 1.17897 [1.17513, 1.19729] | -2.229% | 1.880% | 5/5 | — | faster |
| tcp-miss | p95_ms | 1.24705 [1.23157, 1.25577] | 1.22441 [1.21345, 1.24273] | -1.815% | 2.391% | 4/5 | — | inconclusive |
| tcp-miss | cpu_us | 90 [86, 92] | 78 [74, 80] | -13.333% | 7.692% | 5/5 | no | inconclusive |
| dhcp-home6 | p50_ms | 0.062601 [0.061881, 0.086881] | 0.059601 [0.05736, 0.086681] | -4.792% | 49.195% | 3/5 | — | inconclusive |
| dhcp-home6 | p95_ms | 2.17598 [1.91106, 2.3205] | 2.02038 [1.9299, 2.30502] | -7.151% | 18.817% | 3/5 | — | inconclusive |
| dhcp-home6 | cpu_us | 80 [72, 88] | 76 [72, 92] | -5.000% | 26.316% | 2/5 | no | inconclusive |
| dhcp-home6 | dora_p50_ms | 2.41594 [2.28834, 2.68338] | 2.6121 [2.37046, 2.8077] | — | — | — | — | descriptive only |
| dhcp-home6 | dora_p95_ms | 4.7138 [2.90346, 7.57546] | 6.12873 [4.33468, 7.6607] | — | — | — | — | descriptive only |
| dhcp | p50_ms | 2.92575 [2.85426, 2.97214] | 2.63082 [2.53246, 2.74574] | -10.080% | 8.107% | 5/5 | — | faster |
| dhcp | p95_ms | 3.38915 [3.34279, 3.47475] | 3.20887 [3.04967, 3.48423] | -5.319% | 13.543% | 4/5 | — | inconclusive |
| dhcp | cpu_us | 756 [732, 764] | 548 [532, 556] | -27.513% | 4.380% | 5/5 | yes | faster |
| dhcp | dora_p50_ms | 2.56318 [2.47722, 2.71174] | 2.51694 [2.3677, 2.68218] | -1.804% | 12.495% | 3/5 | — | inconclusive |
| dhcp | dora_p95_ms | 3.12191 [2.98267, 3.18263] | 3.02671 [2.93774, 3.14331] | -3.049% | 6.792% | 3/5 | — | inconclusive |
| startup-small | p50_ms | 1.47665 [1.44121, 1.50357] | 1.42669 [1.41609, 1.46777] | -3.383% | 4.223% | 5/5 | — | inconclusive |
| startup-small | p95_ms | 1.54537 [1.50329, 2.31554] | 1.52865 [1.45917, 2.31722] | -1.082% | 56.131% | 3/5 | — | inconclusive |
| startup-small | cpu_us | 1628.85 [1568.85, 1636.05] | 1492.2 [1472.1, 1546.45] | -8.389% | 4.983% | 5/5 | no | inconclusive |
| config-small | p50_ms | 2.43762 [2.40454, 2.44474] | 2.4781 [2.44738, 2.4937] | +1.661% | 1.869% | 5/5 | — | inconclusive |
| config-small | p95_ms | 2.48898 [2.48054, 2.54506] | 2.56406 [2.53694, 2.57926] | +3.016% | 2.592% | 5/5 | — | inconclusive |
| config-small | cpu_us | 1669.85 [1664.4, 1834.55] | 1657.95 [1636.35, 1714.85] | -0.713% | 10.190% | 4/5 | no | inconclusive |
| hup-small | p50_ms | 0.303083 [0.294322, 0.317002] | 0.275082 [0.266882, 0.286203] | -9.239% | 7.483% | 5/5 | — | inconclusive |
| hup-small | p95_ms | 0.613285 [0.328763, 0.724286] | 0.319723 [0.308443, 0.619686] | -47.867% | 97.348% | 4/5 | — | inconclusive |
| hup-small | cpu_us | 391.6 [332.15, 445.15] | 304.65 [303.95, 347.4] | -22.204% | 28.856% | 5/5 | no | inconclusive |
| hup-large | p50_ms | 3.00459 [2.98678, 3.01531] | 2.65782 [2.62038, 2.72242] | -11.541% | 3.839% | 5/5 | — | inconclusive |
| hup-large | p95_ms | 3.13515 [3.11955, 3.14779] | 3.36595 [3.25179, 3.42283] | +7.362% | 5.082% | 5/5 | — | inconclusive |
| hup-large | cpu_us | 3243.55 [3227.1, 3253.85] | 2970.25 [2926.7, 3026.45] | -8.426% | 3.358% | 5/5 | no | inconclusive |

CPU is µs/operation; all CPU rounds need ≥10 ticks and the median difference must exceed 8 ticks. Lifecycle latency uses a 1 ms observation floor; lifecycle CPU includes startup, idle and shutdown for the whole round. Home6 DORA has only six samples per round and is not ranked.

| Scene | Side | RSS median KiB | RSS peak KiB | Anon peak KiB | File peak KiB | Shmem peak KiB | Tree FD peak | Parent FD peak |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | Oracle baseline | 2316 [2316, 2320] | 2316 [2316, 2320] | 512 [512, 516] | 1804 [1804, 1804] | 0 [0, 0] | 12 [12, 12] | 12 [12, 12] |
| udp-hit | Oracle candidate | 2388 [2384, 2388] | 2388 [2384, 2388] | 520 [516, 520] | 1868 [1868, 1868] | 0 [0, 0] | 12 [12, 12] | 12 [12, 12] |
| udp-miss | Oracle baseline | 2432 [2422, 2436] | 2472 [2464, 2492] | 668 [660, 688] | 1804 [1804, 1804] | 0 [0, 0] | 13 [12, 13] | 13 [12, 13] |
| udp-miss | Oracle candidate | 2428 [2424, 2432] | 2476 [2464, 2476] | 672 [660, 672] | 1804 [1804, 1804] | 0 [0, 0] | 13 [12, 13] | 13 [12, 13] |
| udp-mixed | Oracle baseline | 2406 [2404, 2416] | 2416 [2412, 2416] | 612 [608, 612] | 1804 [1804, 1804] | 0 [0, 0] | 12 [12, 12] | 12 [12, 12] |
| udp-mixed | Oracle candidate | 2468 [2468, 2476] | 2480 [2476, 2480] | 612 [608, 612] | 1868 [1868, 1868] | 0 [0, 0] | 12 [12, 12] | 12 [12, 12] |
| tcp-hit | Oracle baseline | 2520 [2516, 2520] | 2520 [2516, 2520] | 716 [712, 716] | 1804 [1804, 1804] | 0 [0, 0] | 20 [20, 20] | 20 [20, 20] |
| tcp-hit | Oracle candidate | 2584 [2580, 2584] | 2584 [2580, 2584] | 716 [712, 716] | 1868 [1868, 1868] | 0 [0, 0] | 20 [20, 20] | 20 [20, 20] |
| tcp-miss | Oracle baseline | 3542 [3492, 3554] | 3932 [3924, 3968] | 2128 [2120, 2164] | 1804 [1804, 1804] | 0 [0, 0] | 28 [28, 28] | 28 [28, 28] |
| tcp-miss | Oracle candidate | 3552 [3540, 3558] | 3948 [3920, 3956] | 2144 [2116, 2152] | 1804 [1804, 1804] | 0 [0, 0] | 28 [28, 28] | 28 [28, 28] |
| dhcp-home6 | Oracle baseline | 2292 [2288, 2292] | 2292 [2288, 2292] | 360 [356, 360] | 1932 [1932, 1932] | 0 [0, 0] | 18 [18, 18] | 18 [18, 18] |
| dhcp-home6 | Oracle candidate | 2292 [2292, 2292] | 2292 [2292, 2292] | 360 [360, 360] | 1932 [1932, 1932] | 0 [0, 0] | 18 [18, 18] | 18 [18, 18] |
| dhcp | Oracle baseline | 2804 [2800, 2804] | 2804 [2800, 2804] | 872 [868, 872] | 1932 [1932, 1932] | 0 [0, 0] | 18 [18, 18] | 18 [18, 18] |
| dhcp | Oracle candidate | 2750 [2746, 2752] | 2752 [2748, 2752] | 820 [816, 820] | 1932 [1932, 1932] | 0 [0, 0] | 18 [18, 18] | 18 [18, 18] |
| startup-small | Oracle baseline | 2212 [2212, 2212] | 2212 [2212, 2212] | 344 [344, 344] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| startup-small | Oracle candidate | 2208 [2208, 2208] | 2208 [2208, 2208] | 340 [340, 340] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| config-small | Oracle baseline | 2212 [2208, 2212] | 2212 [2212, 2212] | 344 [344, 344] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| config-small | Oracle candidate | 2208 [2208, 2208] | 2208 [2208, 2208] | 340 [340, 340] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| hup-small | Oracle baseline | 2232 [2228, 2232] | 2236 [2232, 2236] | 368 [364, 368] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| hup-small | Oracle candidate | 2280 [2276, 2280] | 2288 [2284, 2288] | 356 [352, 356] | 1932 [1932, 1932] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| hup-large | Oracle baseline | 3276 [3272, 3276] | 3300 [3296, 3300] | 1432 [1428, 1432] | 1868 [1868, 1868] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |
| hup-large | Oracle candidate | 3094 [3072, 3098] | 3104 [3104, 3104] | 1172 [1172, 1172] | 1932 [1932, 1932] | 0 [0, 0] | 19 [19, 19] | 19 [19, 19] |

Lifecycle memory/FD values are readiness snapshots, not transient peaks. RSS and RssAnon are not private memory; device PSS/USS are unavailable. ELF byte sizes are measured only when matching local files are supplied with `--elf`.

## Excluded attempt — candidate-c-summary.json

SHA256 `6cfcf047f3c7550e28780944e4431beae4aaf3909e0d84f0ab2ba60c0587a052`. Excluded regardless of any favorable individual windows.

| Window count | Valid windows | Complete marker | Parse failures |
| --- | --- | --- | --- |
| 110 | 109 | False | 0 |

- candidate-c-tcp-miss-r2-rust: ['measurement error counters', 'measurement completion count', 'upstream hit/miss count']

## Excluded attempt — candidate-e-original-summary.json

SHA256 `1da8de115310b2d87a0fb4ec0e0a217131542892b402ab52ca6d0e61da408c28`. Excluded regardless of any favorable individual windows.

| Window count | Valid windows | Complete marker | Parse failures |
| --- | --- | --- | --- |
| 110 | 107 | False | 0 |

- candidate-e-udp-miss-r4-c: ['upstream hit/miss count']
- candidate-e-tcp-miss-r3-c: ['measurement error counters', 'measurement completion count', 'upstream hit/miss count']
- candidate-e-dhcp-home6-r2-c: ['measurement error counters', 'measurement completion count', 'DORA/renew boundary']
