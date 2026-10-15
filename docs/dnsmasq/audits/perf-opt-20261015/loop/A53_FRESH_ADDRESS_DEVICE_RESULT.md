# A53 fresh-address:10/10 valid; favorable medians below frozen gates

All10 preregistered F/fresh-address UDP-hit attempts passed without replacement. CPU,p50 andp95 differences all fail the unchanged W/direction/precision rules. The prototype remains exploratory and unqualified; it is not promoted.

| Metric | F median | Fresh-address median | Change | W | Same direction | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| CPU µs/query | 130.000000 | 124.000000 | -4.615% | 4.615% | 5/5 | indistinguishable |
| p50 ms | 0.186893 | 0.177197 | -5.188% | 6.166% | 5/5 | indistinguishable |
| p95 ms | 0.342085 | 0.287687 | -15.902% | 195.727% | 4/5 | indistinguishable |

CPU medians are130→124µs/query with five favorable pairs, but absolute change equals W exactly; the original rule requires strictly greater. The3tick median difference also fails the unchanged requirement of more than8ticks. p50 has five favorable pairs but its5.188% change is smaller than W6.166%. The large F p95 observation remains included; no window was removed or replaced. These are favorable descriptive values, not an accepted speedup.

The original200queries/s,5-second warmup,20-second measurement,1000-query prewarm,800-name70/30 fixture, case/group/guard and analyzer were retained. Each window returned6000 correct answers with zero traffic errors; all800 upstream requests were in setup_warmup and steady requests were zero. CPU retains the5000 completed warmup+measurement-query denominator. Historical E/C or other prototype/stage medians are not pooled with these F controls.

Exact source `2a9d53b0` matched all179 SDK receipt source files. ELF `b52432a2…cce7f` is2,136,859bytes; map `950e1273…72778e`, build receipt `1463c884…c660`. Related Linux935/source gates passed in `78c25964`; full44 qualification remains incomplete. The source was not combined with name-buffer, idle-batch or other layout changes. No synthetic reply, allocation meter, additional per-query clock or logging was added.

Author verification checked10 archives and430 members against manifests and extracted bytes, then recomputed using unchanged traffic/statistics functions. All314 resource observations and final endpoints had one daemon thread; all cases and daemons exited0. During the round,424 guard samples,167 DNS,77 HTTP and28 external dual-stack HTTPS checks passed; minimum available memory was82,496KiB.

Postflight confirmed production SHA `8472be5a…aade7` and PID/start `[3086,2115]` unchanged, original E/F temporary slots restored, and no STOP/active group/owned executable. Verified remote window copies and the three new immutable source copies were reclaimed; local artifacts and all evidence remain. The postflight shell and captured result are retained. Final independent audit `6c47e5e4` passed all10 archives/430 files,600 wire samples,179 bound SDK source files, all3 primary and7 resource comparisons, health and reconstructed postflight shell/result. It binds the immutable result JSON SHA `6282570e…b2d789`.

All per-window CPU/latency/resource values, raw archive hashes and full comparisons are in `A53_FRESH_ADDRESS_DEVICE_RESULT.json`.
