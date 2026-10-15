# A53 UDP name-buffer:10/10 valid; no distinguishable gain

All10 preregistered F/UDP-name-buffer UDP-hit attempts passed without replacement. CPU,p50 andp95 differences all fail the original W/direction/precision rules. The prototype remains exploratory and unqualified; it is not promoted.

| Metric | F median | Name-buffer median | Change | W | Same direction | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| CPU µs/query | 130.000000 | 132.000000 | +1.538% | 10.769% | 2/5 | indistinguishable |
| p50 ms | 0.184508 | 0.186431 | +1.042% | 11.597% | 4/5 | indistinguishable |
| p95 ms | 0.345932 | 0.356550 | +3.069% | 52.028% | 3/5 | indistinguishable |

The CPU median difference is1tick, below the unchanged exclusive8tick requirement. This is neither a detected gain nor a proven regression. Only this round’s contemporaneous F values are controls; previous E/C, address-dispatch or synthetic-stage medians are not pooled.

The original200queries/s,5-second warmup,20-second measurement,1000-query prewarm,800-name70/30 fixture, case/group/guard and analyzer were retained. Each window returned6000 correct answers with zero traffic errors; all800 upstream requests were in setup_warmup and steady requests were zero. CPU retains the5000 completed warmup+measurement-query denominator. There was no allocation meter, synthetic reply or additional per-query timing/logging.

Exact source `f404ed75` matched all179 SDK receipt source files. ELF `47fe55e4…afb54f` is2,136,859bytes; map `915e7a6a…fe8f15`, build receipt `bc6cc1ff…76aeeb`. F is ELF `b7926bcf…781fc`. Related Linux934/source gates do not replace full44 qualification, which is incomplete. Source-level allocation expectations and native/Oracle observations do not establish A53 allocation-site CPU cost.

Author verification checked10 archives and430 members against manifests and extracted bytes, then recomputed using unchanged traffic/statistics functions. All314 resource observations and final endpoints had one daemon thread; all cases and daemons exited0. During the round,423 guard samples,165 DNS,77 HTTP and28 external dual-stack HTTPS checks passed; minimum available memory was85,064KiB.

Postflight confirmed production SHA `8472be5a…aade7` and PID/start `[3086,2115]` unchanged, original E/F temporary slots restored, and no STOP/active group/owned executable. Verified remote window copies and the three new immutable source copies were reclaimed; local artifacts and all evidence remain. The postflight shell and captured result are retained. Final independent audit `f083e6f5` passed all10 archives/430 files,600 wire samples,179 bound SDK source files,314 thread observations, all3 primary and7 resource comparisons, health and reconstructed postflight shell/result. It binds immutable result `dd69f54e`, JSON SHA `1aa7e5df…d7da39`.

All per-window CPU/latency/resource values, raw archive hashes and full comparisons are in `A53_UDP_NAME_BUFFER_DEVICE_RESULT.json`.
