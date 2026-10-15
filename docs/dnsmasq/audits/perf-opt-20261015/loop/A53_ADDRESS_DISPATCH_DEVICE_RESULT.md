# A53 F/address-dispatch:10/10 valid; no distinguishable gain

All10 preregistered UDP-hit attempts passed without replacement. CPU,p50 andp95 differences all fail the original W/direction/precision rules. The prototype remains exploratory and unqualified; it is not promoted.

| Metric | F median | Address-dispatch median | Change | W | Same direction | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| CPU µs/query | 126.000000 | 132.000000 | +4.762% | 6.349% | 5/5 | indistinguishable |
| p50 ms | 0.182429 | 0.191740 | +5.104% | 8.140% | 5/5 | indistinguishable |
| p95 ms | 0.327389 | 0.392251 | +19.812% | 145.335% | 3/5 | indistinguishable |

CPU median endpoints differ by3ticks, below the unchanged requirement of more than8ticks. Allfive CPU pairs have a larger prototype value, but this does not establish a regression at the frozen resolution. This round compares only contemporaneous F and address-dispatch; historical E/C or stage medians are not controls.

The original200queries/s,5-second warmup,20-second measurement,1000-query prewarm,800-name70/30 fixture, case/group/guard and analyzer were retained. Every window returned6000 correct answers with zero traffic errors; all800 upstream requests were in setup_warmup and steady requests were zero. CPU retains the5000 completed warmup+measurement-query denominator. Both ELFs use their real answer path with no stage or allocation-meter environment.

Exact prototype source `26aefa79` matched all179 SDK receipt source files. ELF `77dca9fe…e1dc40` is2,136,859bytes; map `95e7995b…680071`, build receipt `affcacb9…da6fa6`. F is ELF `b7926bcf…781fc`. Prior local/Linux screens and the1408-byte reduction in named ordinary-path frame reservation do not establish A53 CPU or dynamic stack-peak benefit. Full44 qualification was not completed.

Author verification checked10 archives and430 members against manifests and extracted bytes, then recomputed using the unchanged traffic/statistics functions. All314 resource observations and final endpoints had one daemon thread; all cases and daemons exited0. During the round,414 guard samples,162 DNS,74 HTTP and28 external dual-stack HTTPS checks passed; minimum available memory was82,884KiB.

Postflight confirmed production SHA `8472be5a…aade7` and PID/start `[3086,2115]` unchanged, exact original E/F temporary slots restored, and no STOP/active group/owned executable. Verified completed remote window copies and the three newly staged immutable sources were reclaimed; local artifacts and all evidence remain. The postflight shell and captured result are both retained. Final independent artifact audit `cfa6ceec` passed all10 archives/430 files,600 wire samples,314 thread observations, all3 primary and7 resource comparisons, health and captured postflight shell/result. It binds immutable result `2575a41c`, JSON SHA `14d87993…ff870c`.

All per-window CPU/latency/resource values, raw archive hashes and full comparisons are in `A53_ADDRESS_DISPATCH_DEVICE_RESULT.json`.
