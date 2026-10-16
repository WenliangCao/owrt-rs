# Original G / warm6dad owner32 result

All 32 original windows completed once. The original analysis reports lower high-load CPU/query, p50 and p95 and higher throughput. High-load send lag is adverse: p50 +2.899% exceeds W=2.817%, and p95 +24.088% exceeds W=20.438%; both have five of five pairs in the same direction. All low-load decisions remain inconclusive.

This compares frozen G185 with `6dadfec2e79d0c7c858dde296f7fa0e48e91afa6`, including inherited 6ab changes. It does not isolate the warm writer. No 5c/025/1df/803/G-stage overlay or native240 is included. Original hot15 cannot reach the recycled-buffer branch; it was not changed or rerun.

| Plain metric | G median | warm median | Change | W | Same pairs | Original decision |
|---|---:|---:|---:|---:|---:|---|
| low CPU us/query | 26.000000 | 26.000000 | +0.000% | 15.385% | 0/5 | inconclusive |
| low throughput query/s | 200.000000 | 200.000000 | +0.000% | 0.000% | 0/5 | inconclusive |
| low p50 us | 56.120000 | 50.120000 | -10.691% | 11.618% | 5/5 | inconclusive |
| low p95 us | 82.441000 | 77.641000 | -5.822% | 7.035% | 5/5 | inconclusive |
| low send-lag p50 us | 70.593000 | 70.338000 | -0.361% | 5.301% | 4/5 | inconclusive |
| low send-lag p95 us | 83.153000 | 81.527000 | -1.955% | 18.918% | 5/5 | inconclusive |
| high CPU us/query | 4.302328 | 4.181078 | -2.818% | 0.786% | 5/5 | faster |
| high throughput query/s | 232131.000000 | 239121.850000 | +3.012% | 0.770% | 5/5 | higher |
| high p50 us | 131.721000 | 127.041000 | -3.553% | 1.071% | 5/5 | faster |
| high p95 us | 146.042000 | 141.762000 | -2.931% | 1.213% | 5/5 | faster |
| high send-lag p50 us | 2.760000 | 2.840000 | +2.899% | 2.817% | 5/5 | slower |
| high send-lag p95 us | 5.480000 | 6.800000 | +24.088% | 20.438% | 5/5 | slower |

Low CPU precision fails: G ticks `[13, 12, 14, 12, 14]`, warm ticks `[13, 14, 12, 13, 13]`. High CPU uses actual variable query counts; precision remains null. Its favorable decision is a saturation diagnostic, not a fixed-cohort precision pass. Throughput and send lag describe the whole pipeline. All original rounds and full ranges remain in the [author summary](warm-address-encode-owner32-author-summary.json).

| PMU median per query | Low G | Low warm | High G | High warm |
|---|---:|---:|---:|---:|
| instructions:u | 7690.828200 | 6991.791800 | 5501.325684 | 5074.446145 |
| instructions:k | 25694.642800 | 25720.938200 | 13002.902140 | 12998.068068 |
| cycles:u | 17159.811000 | 15908.340000 | 3485.616716 | 3183.248738 |
| cycles:k | 37728.565400 | 37788.776000 | 9295.704651 | 9204.943915 |
| user_ipc | 0.448207 | 0.439498 | 1.578362 | 1.594109 |

The original 12 stat and 20 plain windows ran from 11:06:11 to 11:22:52 UTC on 2026-10-16. All windows and process groups exited normally; no measurement failure, replacement or retry occurred. All 48 PMU events were unscaled. The original analyzer ran once on CPU0 with root read privileges and produced SHA-256 `bc7faa39c37de60402c362d7dbd82a6704dc42cd2317b1e75964c89a0ac141e8`.

The [postflight summary](warm-address-encode-owner32-postflight-summary.json) binds all 1,264 raw files, 3,624,051,024 bytes of bins, both 179-file source manifests and exact SDK triples. The [collection summary](warm-address-encode-owner32-collection-summary.json) records a 964,559-byte archive with 1,172 files; 128 bins and 64 repeated ELF/map copies remain remote and are included in the original analysis and independent replay.

The separate-host G-stage device50 overlapped this timing run under root coordination. Only small controls and receipts crossed the management link. All raw/archive downloads remain deferred until DHCP verifies the device archives and restores its slots. This overlap is recorded, not pooled or used to correct measurements.

The [retained local release-adapter failure](warm-address-encode-owner32-release-local-adapter-failure.json) occurred before any SSH or remote release attempt: a broad placeholder check also matched the intentional WARM status text. Checking the four exact placeholder tokens corrected this metadata-only check. The remote release ran once; measurement and analysis were not repeated.

The [fresh quiet handoff](warm-address-encode-owner32-release-to-correctness.json), SHA-256 `b660f702fc78f5067bcc60c23bef107d3b3ceafcfb1cc8909aea53406c1652bd`, records exited controller/analyzer, unchanged source/artifact/tool identities, no research processes including exact C, and three free locks. Correctness owns the original full-bin independent replay. That audit and the later local archive/download verification are pending.

These owner diagnostics establish neither physical-device gain nor complete qualification. The [frozen plan](warm-address-encode-owner32-plan.json) preserves the original workload, order, placement, counters, statistics and failure policy. No promotion or full110 follows from this result alone.
