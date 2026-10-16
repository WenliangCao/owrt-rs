# Frozen G / 803 opt2 exact-SDK owner32

All 32 original windows completed once. High-load p95 regressed under the
original rule: +2.923%, exceeding W=2.359%, with all five pairs slower.
Every other plain comparison is inconclusive. Retain the regression and all
rounds; no promotion or full110 follows from this screen.

The [final plan](185-opt2-owner32-plan.json) binds frozen G
`185db90c9cabd26c0af09765636ef15bf6d35f79` and independent opt2 candidate
`8035114257c8706047d2038c2bb8126391331925`. SDK ELF hashes are respectively
`9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99`
and `2156c7f5f8eb22c64262e6f92939f36ec82b72e30fe2c732baed0993cc1cb3c5`.
There was no native240 for this compiler experiment. Original workloads,
windows, placements, order, normalization and statistical rules were unchanged.

| Plain metric | G median | 803 median | Change | W | Same-direction pairs | Decision |
|---|---:|---:|---:|---:|---:|---|
| low CPU, us/query | 26 | 26 | 0.000% | 23.077% | 0/5 | inconclusive |
| low throughput, query/s | 200 | 200 | 0.000% | 0.000% | 0/5 | inconclusive |
| low p50, us | 54.161 | 49.280 | -9.012% | 29.098% | 5/5 | inconclusive |
| low p95, us | 78.481 | 79.641 | +1.478% | 33.026% | 1/5 | inconclusive |
| high CPU, us/query | 4.281917 | 4.372138 | +2.107% | 2.139% | 5/5 | inconclusive |
| high throughput, query/s | 233491.30 | 228255.25 | -2.243% | 2.257% | 5/5 | inconclusive |
| high p50, us | 131.121 | 134.361 | +2.471% | 2.590% | 5/5 | inconclusive |
| high p95, us | 145.042 | 149.282 | +2.923% | 2.359% | 5/5 | slower |

Low CPU precision failed: G ticks `[14,13,13,11,14]`, 803 ticks
`[13,14,12,12,13]`. High-load CPU uses variable query counts, so its precision
field remains null. High-load sender CPU was 99.634--99.903%; its throughput
is an observed pipeline rate, not isolated server capacity. Both send-lag
percentiles are inconclusive at both loads. The
[complete derived result](185-opt2-owner32-result.json) retains all 32 rows,
full ranges, pairs, send-lag statistics and original decisions.

| PMU median per query | Low G | Low 803 | High G | High 803 |
|---|---:|---:|---:|---:|
| instructions:u | 7691.2858 | 7784.0756 | 5501.4897 | 5584.4254 |
| instructions:k | 25733.9894 | 25821.4088 | 13002.7548 | 13004.5962 |
| cycles:u | 17044.1244 | 17085.4932 | 3493.7426 | 3598.7272 |
| cycles:k | 39682.0008 | 39962.6666 | 9256.0996 | 9213.5749 |
| IPC:u | 0.451257 | 0.455596 | 1.574678 | 1.551763 |

The 12 stat and 20 plain windows ran from 07:50:39 to 08:07:20 UTC on
2026-10-16. Every window exited zero and its process group exited; no failed,
replaced or retried measured window occurred. All 48 PMU event rows were
unscaled. The original analyzer, SHA-256
`ba0aeea816976ff34a984e37adbc485017867c3376456b6e2e46b3a80de978b6`,
ran once as root on CPU0 against every latency/send-lag bin and exited zero
with empty stderr. Its result SHA-256 is
`ed6e11976297ee7692c79f5ad035bee555f201706d2ed177899377b8119db3d6`.

The [postflight](185-opt2-owner32-postflight.json), SHA-256
`b182eebf4b411d7ad5f36f9868cdb72676c1715ea69b684a0d440eed5d28d16d`,
verifies 1,264 raw files, including 3,557,698,944 bytes of bins, both 179-file
source manifests and exact SDK triples. All bins remain remote for independent
replay. The 976,781-byte smallraw archive has SHA-256
`6c2082f5fb0a674afc9bb6c0f10d0c1e9be4ca3e7ea643d502cb150bbd0da821`;
its collection SHA-256 is
`fe534fae9ceac86e8d716ecb254a0f69953c59bf970a2657c2038bc98d036725`.
All 1,172 transferred members were rehashed under
`private/perf-opt-20261015/185-opt2-owner32-results/`. Only the transfer omits
128 bins plus 64 repeated ELF/map copies; analysis and remote preservation
include them all.

The first collection attempt incorrectly asserted 192 bins instead of 192
total omitted files. It stopped before archive creation. The
[failure receipt](185-opt2-owner32-collection-failure.json) retains that error;
both script versions remain private. Correcting the collection counts to
128 bins plus 64 artifacts changed no raw file, analyzer or measured window.

The [explicit quiet release](185-opt2-owner32-release-to-correctness.json),
SHA-256 `49261583a2f2b239eaa16a48bb611d6b29c9f023a26c54d4a11f8073cc707a86`,
binds exited controller/analyzer, completed transfers, no research processes
including exact C and three free build locks. Correctness now owns the host
for unchanged full-bin replay and independent raw audit; that review is
pending. The separate physical device ten-window audit `d6d779dc` found all
three primary comparisons inconclusive. After the owner audit and its quiet
release, DNS may execute the already-authorized bare 1df original related/SDK
queue; 025 remains later.
