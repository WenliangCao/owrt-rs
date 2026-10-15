# Fresh physical C/E hit diagnostic

20/20 original windows valid; UDP and TCP each use five fresh alternating pairs. No supplement or historical pooling. C is exact-image `097a9e21…`; E is `8b8082b9…`. This diagnostic does not qualify a new candidate.

All values are median [min,max] across the five rounds. CPU includes parent plus waited-child user/system ticks over 5,000 warmup and measured operations.

| Scene | Metric | Exact C | E | E−C | Relative | W | Direction |
| --- | --- | --- | --- | --- | --- | --- | --- |
| udp-hit | p50_ms | 0.142343 [0.14065, 0.145036] | 0.20659 [0.202511, 0.208744] | +0.064247 | +45.135% | 3.081% | slower (5/5) |
| udp-hit | p95_ms | 0.252755 [0.234981, 0.282686] | 0.38171 [0.331543, 0.39556] | +0.128955 | +51.020% | 18.874% | slower (5/5) |
| udp-hit | cpu_us | 84 [82, 86] | 146 [142, 146] | +62 | +73.810% | 4.762% | slower (5/5) |
| tcp-hit | p50_ms | 0.185662 [0.181814, 0.191047] | 0.225364 [0.221594, 0.23829] | +0.039702 | +21.384% | 7.408% | slower (5/5) |
| tcp-hit | p95_ms | 0.331236 [0.309461, 0.389328] | 0.392482 [0.362628, 0.464807] | +0.061246 | +18.490% | 26.034% | within_variation_or_resolution (5/5) |
| tcp-hit | cpu_us | 116 [116, 118] | 168 [166, 178] | +52 | +44.828% | 7.143% | slower (5/5) |

Both CPU gaps pass the unchanged tick-precision gate. UDP p50/p95 and TCP p50 differences are discernible; TCP p95 is within its observed variation.

| Scene / side | Round | Parent user | Parent system | Waited child user | Waited child system | Total ticks |
| --- | --- | --- | --- | --- | --- | --- |
| udp-hit/c | 1 | 0 | 41 | 0 | 0 | 41 |
| udp-hit/rust | 1 | 36 | 35 | 0 | 0 | 71 |
| udp-hit/rust | 2 | 35 | 37 | 0 | 0 | 72 |
| udp-hit/c | 2 | 42 | 0 | 0 | 0 | 42 |
| udp-hit/c | 3 | 13 | 28 | 0 | 0 | 41 |
| udp-hit/rust | 3 | 36 | 37 | 0 | 0 | 73 |
| udp-hit/rust | 4 | 37 | 36 | 0 | 0 | 73 |
| udp-hit/c | 4 | 0 | 43 | 0 | 0 | 43 |
| udp-hit/c | 5 | 6 | 36 | 0 | 0 | 42 |
| udp-hit/rust | 5 | 0 | 73 | 0 | 0 | 73 |
| tcp-hit/c | 1 | 1 | 3 | 50 | 4 | 58 |
| tcp-hit/rust | 1 | 44 | 45 | 0 | 0 | 89 |
| tcp-hit/rust | 2 | 20 | 63 | 0 | 0 | 83 |
| tcp-hit/c | 2 | 0 | 4 | 55 | 0 | 59 |
| tcp-hit/c | 3 | 0 | 4 | 54 | 0 | 58 |
| tcp-hit/rust | 3 | 31 | 54 | 0 | 0 | 85 |
| tcp-hit/rust | 4 | 32 | 52 | 0 | 0 | 84 |
| tcp-hit/c | 4 | 0 | 4 | 55 | 0 | 59 |
| tcp-hit/c | 5 | 1 | 3 | 54 | 0 | 58 |
| tcp-hit/rust | 5 | 41 | 42 | 0 | 0 | 83 |

C TCP windows observe nine processes at peak, then only the same parent at both CPU endpoints; all child CPU is included through waited-child counters. No process-tree truncation or disappeared-child samples occurred. The unstable user/system split is not causal attribution.

All 20 archives and 860 files were verified. Production PID/start `[3086,2115]`, deployed SHA `8472be5a…`, four image-library hashes, routes and completed health checks stayed normal. No production service or configuration was modified.

Detailed per-round endpoints and raw hashes: [CPU accounting](c-e-hit-diagnostic-cpu-accounting.json). Full statistics: [summary](c-e-hit-diagnostic-summary.json). Identity, health and limitations: [receipt](c-e-hit-diagnostic-receipt.json).
