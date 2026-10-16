# Original G / integrated9e owner32 result

All 32 original windows completed once. High-load CPU/query, throughput, p50 and p95 improve under the original rule. High-load send lag is adverse: p50 rises 2.76 to 4.60 us (+66.667%, W=1.449%), and p95 rises 5.36 to 8.72 us (+62.687%, W=21.642%); both have five of five pairs in the same direction. All low-load decisions remain inconclusive.

| Plain metric | G median | 9e median | Change | W | Same pairs | Original decision |
|---|---:|---:|---:|---:|---:|---|
| low CPU us/query | 26.000000 | 26.000000 | +0.000% | 15.385% | 0/5 | inconclusive |
| low throughput query/s | 200.000000 | 200.000000 | +0.000% | 0.000% | 0/5 | inconclusive |
| low p50 us | 53.281000 | 53.960000 | +1.274% | 12.305% | 3/5 | inconclusive |
| low p95 us | 79.240000 | 77.401000 | -2.321% | 26.306% | 4/5 | inconclusive |
| low send-lag p50 us | 70.487000 | 70.939000 | +0.641% | 2.396% | 4/5 | inconclusive |
| low send-lag p95 us | 82.020000 | 82.157000 | +0.167% | 7.410% | 3/5 | inconclusive |
| high CPU us/query | 4.294093 | 3.985395 | -7.189% | 0.578% | 5/5 | faster |
| high throughput query/s | 232635.150000 | 250489.200000 | +7.675% | 1.350% | 5/5 | higher |
| high p50 us | 131.561000 | 119.801000 | -8.939% | 0.634% | 5/5 | faster |
| high p95 us | 146.201000 | 135.001000 | -7.661% | 0.984% | 5/5 | faster |
| high send-lag p50 us | 2.760000 | 4.600000 | +66.667% | 1.449% | 5/5 | slower |
| high send-lag p95 us | 5.360000 | 8.720000 | +62.687% | 21.642% | 5/5 | slower |

This compares exact shipping SDK G185 with integrated9e, including inherited 6ab and several changes; it is not an isolated warm-writer or layout attribution. Low CPU precision fails. High CPU uses actual variable query counts and retains null precision: it is a saturation/pipeline diagnostic, not fixed-cohort precision acceptance. Throughput and send lag describe the pipeline; the complete sender CPU values, every round, percentile and full range remain in the [original result](cached-hit-9e-owner32-result.json).

| PMU median per query | Low G | Low 9e | High G | High 9e |
|---|---:|---:|---:|---:|
| instructions:u | 7690.640400 | 6634.735400 | 5501.372917 | 4728.677458 |
| instructions:k | 25695.392800 | 25639.917200 | 12991.316832 | 12998.000919 |
| cycles:u | 17146.145800 | 14710.896200 | 3493.686997 | 2868.505193 |
| cycles:k | 38937.501800 | 37223.538400 | 9264.935045 | 9010.623730 |
| user_ipc | 0.448555 | 0.451004 | 1.574661 | 1.648481 |

The original 12 stat and 20 plain windows ran from 12:40:15 to 12:56:56.135516 UTC on 2026-10-16, after native raw/postflight, a fresh process/lock/source check, and device ten restoration. Every window and process group exited normally, with no measurement failure, replacement or retry. All 48 PMU events were unscaled. The original CPU0 analyzer ran once with root read privileges against every latency/send-lag bin, producing SHA-256 `3d7e584533dd81934f4cd5d3ca151c1fbb3e6418226901b305254424fd6af399`.

The [postflight](cached-hit-9e-owner32-postflight.json) binds 1,264 raw files, 3,707,613,744 bytes of bins, both 179-file source manifests and exact SDK triples. The [transport receipt](cached-hit-9e-owner32-download-receipt.json) verifies all 1,172 transferred archive members. The 128 bins and 64 repeated ELF/map copies remain remote for the original independent replay; they were included in the author analysis and full raw hash inventory.

The [scope text note](cached-hit-9e-plan-scope-text-note.json) preserves disabled/preparation prose accidentally retained in frozen executed plans. Their actual status, flags, qualification pins, ready and launch receipts are correct. Original plan and identity bytes remain unchanged; no measurement or analysis was repeated to hide this metadata wording issue.

The [quiet handoff](cached-hit-9e-screen-release-to-correctness.json), SHA-256 `43e664dfe1792416f9ca25b86d40b50529d591ce68d952a73a15adb48185bdc2`, rechecks exited controllers/analyzer, source/artifact/tool identities, no research processes including exact C and three available locks. Correctness owns the original native raw audit and owner32 full-bin independent replay; those audits are pending.

The physical device ten and all low-load owner comparisons provide no discernible gain. These high-load diagnostics and native gains do not promote 9e or trigger full110. Both send-lag regressions and all previous adverse source-specific evidence remain.
