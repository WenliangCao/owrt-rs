# A53 adaptive UDP idle-batch:10/10 valid; no distinguishable gain

All10 preregistered F/adaptive-idle-batch UDP-hit attempts passed without replacement. CPU,p50 andp95 differences all fail the unchanged W/direction/precision rules. The prototype remains exploratory and unqualified; it is not promoted.

| Metric | F median | Idle-batch median | Change | W | Same direction | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| CPU µs/query | 126.000000 | 126.000000 | +0.000% | 7.937% | 0/5 | indistinguishable |
| p50 ms | 0.181969 | 0.184661 | +1.479% | 10.750% | 3/5 | indistinguishable |
| p95 ms | 0.323004 | 0.283840 | -12.125% | 47.736% | 3/5 | indistinguishable |

CPU medians are equal at126µs/query, with zero median tick difference. This does not prove exact equivalence. The prior Oracle trace’s EAGAIN5000→1 reduction remains separate evidence: this device round did not trace syscalls, observe hint selection, use PMU or add per-query instrumentation. It establishes neither actual A53 EAGAIN counts nor high-load throughput behavior.

The original200queries/s,5-second warmup,20-second measurement,1000-query prewarm,800-name70/30 fixture, case/group/guard and analyzer were retained. Each window returned6000 correct answers with zero traffic errors; all800 upstream requests were in setup_warmup and steady requests were zero. CPU retains the5000 completed warmup+measurement-query denominator. Historical E/C or other prototype/stage medians are not pooled with these F controls.

Exact source `1b934951` matched all179 SDK receipt source files. ELF `18794b72…23e2` is2,136,859bytes; map `9067bf01…ef98a`, build receipt `c8289db9…e5948`. Related Linux83+4 gates passed in `c38108d9`; full44 qualification remains incomplete. This prototype was not combined with the name-buffer or layout patches.

Author verification checked10 archives and430 members against manifests and extracted bytes, then recomputed using unchanged traffic/statistics functions. All313 resource observations and final endpoints had one daemon thread; all cases and daemons exited0. During the round,418 guard samples,162 DNS,75 HTTP and28 external dual-stack HTTPS checks passed; minimum available memory was81,960KiB.

Postflight confirmed production SHA `8472be5a…aade7` and PID/start `[3086,2115]` unchanged, original E/F temporary slots restored, and no STOP/active group/owned executable. Verified remote window copies and the three new immutable source copies were reclaimed; local artifacts and all evidence remain. The postflight shell and captured result are retained. Final independent audit is tracked separately.

All per-window CPU/latency/resource values, raw archive hashes and full comparisons are in `A53_UDP_IDLE_BATCH_DEVICE_RESULT.json`.
