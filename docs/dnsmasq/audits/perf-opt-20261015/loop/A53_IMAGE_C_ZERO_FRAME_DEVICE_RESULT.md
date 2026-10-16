# Fresh exact-image C versus 185 on A53: remaining UDP-hit gap

All 10 original windows passed without replacement. In this fresh direct comparison, 185 consumes more CPU and has higher p50 latency than exact image C under the frozen rules. This measures the current gap directly; no historical C/E or E/185 differences are subtracted or pooled.

| Metric | Exact C median | 185 median | 185/C change | W | Same direction | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| CPU µs/query | 82 | 114 | +39.024% | 8.772% | 5/5 | slower |
| p50 ms | 0.138419 | 0.168811 | +21.957% | 5.447% | 5/5 | slower |
| p95 ms | 0.324542 | 0.270606 | -16.619% | 395.780% | 4/5 | within_variation_or_resolution |

CPU medians are 41→57 ticks: the 16-tick difference exceeds the unchanged >8-tick gate, and all five pairs have higher 185 CPU. The C p95 round-4 value of 1.562003 ms is retained; W is 395.780%, so the lower 185 p95 median does not establish an improvement. No observation was trimmed, reclassified or replaced.

Exact C ELF is `097a9e21…8cab87`. Its original image musl interpreter link and four library hashes were checked again before launch. Candidate source is exact `185db90c`, ELF `9109e987…1d7f99`, with the same SDK map/build and 179-file identity as the independently audited full qualification and E/185 full 110. C is dynamically linked and 185 static PIE; ELF size alone is not their complete mapped-library or memory footprint.

Both sides used the original 800-name, 70/30 A/AAAA IPv4-loopback UDP-hit fixture, 200 requests/s, 1,000-query prewarm, 5-second warmup and 20-second measurement. Every window returned 6,000 correct responses with zero traffic errors, 800 upstream requests in setup/warmup and zero steady upstream requests. CPU uses 5,000 completed warmup+measurement queries. These are isolated service measurements, not real Wi-Fi latency or a new whole-product comparison against C.

Anon peak medians were C 228 KiB versus 185 520 KiB, ranges [228,228] and [516,524]. Tree/parent FD peaks were 11 versus 12 in every window. All RSS/File/Shmem and other resource values remain in the JSON. RSS/RssAnon are not USS or exact private heap measurements.

Author verification checked 10 archives and 430 files, all original statistics and 315 observed single-thread resource samples. Guard evidence contains 408 qualified/final samples, no tail samples, 159 DNS, 73 HTTP and 28 external dual-stack HTTPS checks; all passed, with minimum available memory 83,092 KiB. Final guard logs preserve all captured bytes.

Postflight restored exact E/F task slots, confirmed production SHA `8472…` and PID/start `[3086,2115]` unchanged, and found no STOP, active group or owned executable. All four newly staged exact C/E/F/185 source copies and valid remote windows were reclaimed only after verification; local artifacts and original evidence remain. The raw postflight scope sentence has a retained template typo (“three”), while its explicit four-file dictionary and executed shell are authoritative. Final independent audit `04684700` passed all 10 archives/430 files, 600 wire samples, 315 thread observations, the three primary and seven resource comparisons, fresh health, exact C libraries and four-source restoration. Immutable result JSON SHA remains `fbd1bcc5…f5d1d9`. All raw high values and the documented clerical wording remain.

The prior full E/185 result remains independently valid and separate. This direct C diagnostic neither reverses that incremental result nor closes the remaining C gap. It selects no new candidate and changes no production state.
