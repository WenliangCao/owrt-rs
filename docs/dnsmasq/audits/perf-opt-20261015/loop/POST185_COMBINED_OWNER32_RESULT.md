# G / 6ab exact-SDK owner32 screen

All 32 original windows completed once. Every plain CPU, throughput, latency
and send-lag comparison is inconclusive under the original rules. This is not
an equivalence result or a qualification of 6ab.

The [plan](post185-combined-owner32-plan.json) binds accepted G
`185db90c9cabd26c0af09765636ef15bf6d35f79` and candidate
`6ab0f064b69087add3be1cb2bf5604fbaf42dffa`. The exact SDK ELFs are respectively
`9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99`
and `feac49a01e31b7ee35dfcdaf55ac25ec8e214d986e0bfe246332b29531f31288`.
Both source trees, 179 inputs each, and their ELF/map/build triples were
reverified after the run.

| Plain metric | G median | 6ab median | Change | Original W | Same-direction pairs |
|---|---:|---:|---:|---:|---:|
| low CPU, us/query | 26 | 26 | 0.000% | 15.385% | 0/5 |
| low p50, us | 50.321 | 51.721 | +2.782% | 24.642% | 2/5 |
| low p95, us | 77.641 | 77.321 | -0.412% | 26.843% | 3/5 |
| high CPU, us/query | 4.295389 | 4.278641 | -0.390% | 0.678% | 4/5 |
| high throughput, query/s | 232726.45 | 233509.30 | +0.336% | 0.673% | 4/5 |
| high p50, us | 131.521 | 131.041 | -0.365% | 0.642% | 5/5 |
| high p95, us | 145.881 | 145.442 | -0.301% | 0.743% | 3/5 |

Low-load CPU precision failed: G ticks were `[13,13,13,13,15]` and candidate
ticks `[13,13,13,13,13]`. High-load query counts vary, so CPU precision is null
and cannot be called a fixed-cohort pass. High-load sender CPU was
99.609--99.920%; the observed rate describes the pipeline, not isolated server
capacity. The [derived result](post185-combined-owner32-result.json) retains
all rounds, both send-lag percentiles and every original decision.

| PMU median per query | Low G | Low 6ab | High G | High 6ab |
|---|---:|---:|---:|---:|
| instructions:u | 7691.2212 | 7209.9546 | 5501.5537 | 5292.5559 |
| instructions:k | 25724.7348 | 25757.2030 | 12993.3678 | 12981.5998 |
| cycles:u | 16964.0938 | 16295.8122 | 3494.3881 | 3365.0269 |
| cycles:k | 37273.3246 | 37775.9642 | 9255.3680 | 9346.9518 |
| IPC:u | 0.453393 | 0.442442 | 1.574296 | 1.572781 |

The 12 stat windows contain 48 unscaled PMU rows; the remaining 20 windows are
plain. No measured attempt failed or was replaced. A first launcher failed to
open `controller.stdout` in the root-owned staged inputs before `Popen`, with
zero windows started. Only the fresh task directory owner changed to ubuntu;
the same argv then ran. That failure remains recorded with SHA-256
`55deb194ffaa6518f0b4bf984e540e2b226f755b442c32d70c04f80a689b5e7a`.

The unchanged analyzer ran once as root on CPU0 against every latency/send-lag
bin, exited zero with empty stderr, and produced SHA-256
`6be8d83b213c03af2f81b9deb9309af99d957f28662ebc93ac1d4959fb330e09`.
The [raw postflight](post185-combined-owner32-postflight.json) verifies 1,264
files, including 3,583,345,680 bytes of bins. All bins remain remote for
independent replay. The private local collection under
`private/perf-opt-20261015/post185-combined-owner32-results/` contains 1,161
rehashed transferred members. Its 876,407-byte smallraw archive has SHA-256
`6773877146cbd50b106fb42b8a0fa800dc8638ea47557a37778ce9b586b08d61`.
The 192 bins and repeated ELF/map copies were omitted only from this transfer,
not from analysis or preservation.

The [explicit release](post185-combined-screen-release.json), SHA-256
`35dda22f7e441dc1ef2b555be2cb897ccda60e4a7c3fe5e4b0822236850513a7`,
records exited controllers, no research processes including exact C, available
build locks and completed transfers. Correctness owns the host for independent
raw replay and the original full44; independent review is pending. These
results do not authorize promotion or full110.
