# E/185 A53 full 110: UDP CPU goal met, no discernible primary regression

All 110 original windows passed across 11 scenes, with no failed measurement, supplement or rerun. Author verification checked 110 archives and 3,430 files and recomputed the original window statistics. The accepted E incremental UDP-hit CPU goal is met: four of 33 primary comparisons improve and none regress under the frozen rules. Final independent audit `ed184c6b` passed all 110 archives/3,430 files, 33 primary and 77 resource comparisons, all 11 guard segments, fresh health and postflight. Immutable result JSON SHA remains `fafe943d…df2a14`. Overall candidate selection/deployment remain coordinator decisions.

| Scene | Metric | E median | 185 median | Change | W | Same direction | CPU precision | Decision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| udp-hit | CPU µs/op | 138 | 116 | -15.942% | 8.621% | 5/5 | True | faster |
| udp-hit | p50 ms | 0.198665 | 0.170427 | -14.214% | 4.454% | 5/5 | — | faster |
| udp-hit | p95 ms | 0.289149 | 0.26345 | -8.888% | 64.311% | 4/5 | — | within_variation_or_resolution |
| udp-miss | CPU µs/op | 448 | 456 | +1.786% | 5.357% | 4/5 | False | within_variation_or_resolution |
| udp-miss | p50 ms | 1.63079 | 1.63502 | +0.260% | 2.240% | 2/5 | — | within_variation_or_resolution |
| udp-miss | p95 ms | 1.88416 | 1.90309 | +1.005% | 40.891% | 3/5 | — | within_variation_or_resolution |
| udp-mixed | CPU µs/op | 208 | 186 | -10.577% | 6.731% | 5/5 | True | faster |
| udp-mixed | p50 ms | 0.212206 | 0.179353 | -15.482% | 10.660% | 5/5 | — | faster |
| udp-mixed | p95 ms | 1.71596 | 1.70935 | -0.386% | 12.308% | 4/5 | — | within_variation_or_resolution |
| tcp-hit | CPU µs/op | 164 | 152 | -7.317% | 10.526% | 5/5 | False | within_variation_or_resolution |
| tcp-hit | p50 ms | 0.224595 | 0.205205 | -8.633% | 10.986% | 5/5 | — | within_variation_or_resolution |
| tcp-hit | p95 ms | 0.39079 | 0.464885 | +18.960% | 65.111% | 3/5 | — | within_variation_or_resolution |
| tcp-miss | CPU µs/op | 390 | 390 | +0.000% | 5.641% | 0/5 | False | within_variation_or_resolution |
| tcp-miss | p50 ms | 1.5934 | 1.59109 | -0.145% | 1.828% | 3/5 | — | within_variation_or_resolution |
| tcp-miss | p95 ms | 1.92217 | 1.9441 | +1.141% | 55.076% | 3/5 | — | within_variation_or_resolution |
| dhcp-home6 | CPU µs/op | 408 | 408 | +0.000% | 1.961% | 0/5 | False | within_variation_or_resolution |
| dhcp-home6 | p50 ms | 0.394714 | 0.396252 | +0.390% | 1.482% | 3/5 | — | within_variation_or_resolution |
| dhcp-home6 | p95 ms | 0.608536 | 0.670782 | +10.229% | 23.100% | 3/5 | — | within_variation_or_resolution |
| dhcp | CPU µs/op | 2596 | 2564 | -1.233% | 1.872% | 5/5 | False | within_variation_or_resolution |
| dhcp | p50 ms | 2.62303 | 2.57325 | -1.898% | 4.582% | 5/5 | — | within_variation_or_resolution |
| dhcp | p95 ms | 3.05422 | 2.99036 | -2.091% | 90.634% | 2/5 | — | within_variation_or_resolution |
| startup-small | CPU µs/op | 5335.3 | 5381.8 | +0.872% | 1.823% | 3/5 | False | within_variation_or_resolution |
| startup-small | p50 ms | 4.54397 | 4.53435 | -0.212% | 2.150% | 3/5 | — | within_variation_or_resolution |
| startup-small | p95 ms | 4.91668 | 5.0354 | +2.415% | 99.595% | 3/5 | — | within_variation_or_resolution |
| config-small | CPU µs/op | 5610.75 | 5564.6 | -0.823% | 6.518% | 3/5 | False | within_variation_or_resolution |
| config-small | p50 ms | 5.83368 | 5.84853 | +0.255% | 5.151% | 3/5 | — | within_variation_or_resolution |
| config-small | p95 ms | 6.811 | 7.14508 | +4.905% | 133.484% | 2/5 | — | within_variation_or_resolution |
| hup-small | CPU µs/op | 1244.95 | 1249.45 | +0.361% | 4.018% | 3/5 | False | within_variation_or_resolution |
| hup-small | p50 ms | 1.01087 | 1.01487 | +0.396% | 1.713% | 5/5 | — | within_variation_or_resolution |
| hup-small | p95 ms | 1.21246 | 1.19837 | -1.161% | 44.854% | 2/5 | — | within_variation_or_resolution |
| hup-large | CPU µs/op | 16398.8 | 16193 | -1.255% | 3.287% | 3/5 | False | within_variation_or_resolution |
| hup-large | p50 ms | 14.994 | 15.0156 | +0.144% | 2.025% | 2/5 | — | within_variation_or_resolution |
| hup-large | p95 ms | 17.5121 | 16.4061 | -6.315% | 28.952% | 3/5 | — | within_variation_or_resolution |

UDP-hit CPU falls 138→116 µs/query (−15.942%, W 8.621%, 5/5, 11 ticks); mixed CPU falls 208→186 (−10.577%, W 6.731%, 5/5, 11 ticks). Their p50 comparisons also pass. TCP-hit CPU 164→152 remains indistinguishable because W and the 6-tick difference fail the gates. DHCP 150 improves descriptively from 2596→2564, but 8 ticks is not strictly greater than 8. All other rules, including lifecycle 1 ms resolution and sample-size limits, remain unchanged.

| Scene | RSS median KiB E→185 | Anon peak median KiB E→185 | Anon ranges E / 185 | Tree FD peak median E→185 |
| --- | ---: | ---: | --- | ---: |
| udp-hit | 2360 → 2392 | 516 → 520 | [516, 524] / [516, 520] | 12 → 12 |
| udp-miss | 2446 → 2480 | 672 → 668 | [664, 692] / [664, 684] | 13 → 13 |
| udp-mixed | 2470 → 2476 | 608 → 608 | [600, 652] / [600, 612] | 12 → 12 |
| tcp-hit | 2608 → 2588 | 716 → 716 | [716, 728] / [712, 716] | 20 → 20 |
| tcp-miss | 3580 → 3596 | 2140 → 2112 | [2068, 2144] / [2096, 2176] | 28 → 28 |
| dhcp-home6 | 2312 → 2308 | 360 → 356 | [356, 360] / [356, 360] | 18 → 18 |
| dhcp | 2776 → 2728 | 872 → 876 | [832, 876] / [816, 876] | 18 → 18 |
| startup-small | 2270 → 2282 | 340 → 340 | [340, 340] / [340, 340] | 18 → 18 |
| config-small | 2272 → 2296 | 340 → 340 | [340, 340] / [340, 340] | 18 → 18 |
| hup-small | 2308 → 2300 | 356 → 348 | [348, 356] / [348, 352] | 18 → 18 |
| hup-large | 3100 → 3152 | 1168 → 1168 | [1168, 1172] / [1168, 1172] | 18 → 18 |

FD medians and ranges match in every scene. RSS and RssAnon are not USS or exact private heap usage; PSS/USS remain unavailable. Lifecycle samples are readiness snapshots, not transient peaks. The JSON and private summary retain all RSS/File/Anon/Shmem/tree components and ranges. No new memory threshold or causal allocation explanation is introduced.

Exact source `185db90c` / ELF `9109e987…1d7f99` completed the original functional gates in `3c8d46e9`: 957 tests, 44 families/67 jobs, original F10/protocol/TCP/source corpora and the unchanged approved historical exceptions. ELF size is 2,145,051 B, +8,192 B over E, below the 2,200,000 B limit. APK size is 1,167,095 B, below 1,200,000 B. The size increase accompanies the measured UDP CPU improvement; runtime resource observations remain separate evidence.

Runtime used reviewed controller `d2bb00f7` and helper `8e3367d9`; fresh health used the separate original `7c93`/`0926` bundle. Guard, case, group, loadgen and resource binaries and analyzer `10added` were unchanged. Each scene retained its actual pre-stop capture and complete final log. Across 11 segments there are 3,863 qualified and 3,864 final samples, 1,504 DNS, 699 HTTP and 256 external dual-stack HTTPS checks, with no observed failure and minimum available memory 84,724 KiB. The one post-capture config-small sample had DNS/HTTP both −1 and was retained for all safety checks.

Production SHA `8472…` and PID/start `[3086, 2115]` remained unchanged. Postflight restored the original E/F task slots and found no STOP, active group or owned executable; available memory was 93,692 KiB. Valid remote window copies were reclaimed only after archive verification. A 10,779-byte read-only postflight SSH check reset twice before any restore writes. Its original script, failure and stderr remain. A short probe passed; the identical predicates then passed in four batches of at most 3,000 bytes, followed by successful atomic restoration. No measurement changed. Command-size causality was not independently proven.

The earlier pre-screen health attempt remains FAILED. Its reviewed capture-boundary repair and exact STOP recovery are recorded separately; the full 110 used a new health attempt. Oracle 110, exploratory ten, earlier E/B and F controls are not pooled. This is not a fresh direct v0.2.0 claim. The later C/185 diagnosis still requires this run’s final audit and postflight gates.

Exact identities, all 33 full comparisons, per-window values, 110 archive hashes, 11 guard segments and postflight evidence are in `A53_CACHED_ZERO_FRAME_FULL_DEVICE_RESULT.json`.
