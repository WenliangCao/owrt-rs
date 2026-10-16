# Frozen G / bare 1df exact-SDK owner32

All 32 original windows completed once. Under the original rules, high-load
CPU/query, throughput, p50 and p95 are discernible in the favorable direction.
All low-load and send-lag comparisons remain inconclusive. High CPU uses
variable query counts and has a null precision field; it is a saturation
diagnostic, not a fixed-cohort CPU precision pass.

The comparison is frozen G185 versus `1df135dc2401a9f0ec2f219b1e4a8f07dd637db1`,
which inherits 6ab changes. It does not isolate inline-address effects. The
[final plan](inline-address-details-owner32-plan.json) preserves the original
32 windows, workload, placement, order, counters and statistical rules.

| Plain metric | G median | 1df median | Change | W | Same pairs | Original decision |
|---|---:|---:|---:|---:|---:|---|
| low CPU, us/query | 26.000000 | 26.000000 | +0.000% | 38.462% | 0/5 | inconclusive |
| low throughput, query/s | 200.000000 | 200.000000 | +0.000% | 0.000% | 0/5 | inconclusive |
| low p50, us | 52.881000 | 51.520000 | -2.574% | 29.349% | 2/5 | inconclusive |
| low p95, us | 80.921000 | 79.961000 | -1.186% | 27.485% | 3/5 | inconclusive |
| high CPU, us/query | 4.292761 | 4.201912 | -2.116% | 1.290% | 5/5 | faster |
| high throughput, query/s | 232764.300000 | 237805.800000 | +2.166% | 1.201% | 5/5 | higher |
| high p50, us | 131.401000 | 128.081000 | -2.527% | 1.655% | 5/5 | faster |
| high p95, us | 145.881000 | 142.561000 | -2.276% | 1.375% | 5/5 | faster |

Low CPU precision fails: G ticks `[12,14,16,13,11]`, candidate ticks
`[14,13,13,12,12]`. High-load sender CPU is 99.807–99.902%; throughput is
an observed pipeline rate, not isolated server capacity. Both p50 and p95
send-lag comparisons are inconclusive at both loads. All rounds, ranges and
original decisions remain in the [full result](inline-address-details-owner32-result.json).

| PMU median per query | Low G | Low 1df | High G | High 1df |
|---|---:|---:|---:|---:|
| instructions:u | 7691.178400 | 7245.826400 | 5501.444396 | 5328.770433 |
| instructions:k | 25594.899000 | 25560.714400 | 13008.630879 | 13000.293331 |
| cycles:u | 17379.998400 | 15536.446200 | 3495.362576 | 3210.342443 |
| cycles:k | 37287.812600 | 36054.202200 | 9280.526624 | 9288.717691 |
| IPC:u | 0.442530 | 0.466376 | 1.573932 | 1.659876 |

All 12 stat and 20 plain windows ran from 08:46:28 to 09:03:08 UTC on
2026-10-16. All exited zero with exited process groups. There was no failed,
replaced or retried measured window, and no collection retry. All 48 PMU
event rows were unscaled. The unchanged adapted analyzer, SHA-256
`53856cab516bd04335f8b44937c90d8c5d50feb616f37d4df167b8023e803d96`,
read every latency/send-lag bin once as root on CPU0 and exited zero with
empty stderr. Result SHA-256:
`a67bafe3333cd3cfcc0bf54996efbaa291a33c4b7f81b552a03cbe62e8e91d6f`.

The [postflight](inline-address-details-owner32-postflight.json), SHA-256
`75b7c856e8595d3cf79b382f0dc1b567caa7cda5f6c249e1ba2f415014af5df8`,
rechecks 1,264 raw files, 3,613,555,056 bytes of bins, both 179-file source
manifests and exact SDK ELF/map/build triples. The 963,333-byte private
smallraw archive has SHA-256
`252f5aabfda6635c7c0c38819d99f8a1fcaa04a995f44d0283d9e1b1ae0a3b46`;
collection SHA-256:
`c32a65c2b3fd9a029028ad0f541d46114ff30434650c3f78816a952fbf38bdc3`.
All 1,169 transferred members were rehashed under
`private/perf-opt-20261015/inline-address-details-owner32-results/`. The 128
bins and 64 repeated ELF/map copies are omitted only from transfer, retained
remotely and included in full analysis.

The [explicit quiet handoff](inline-address-details-screen-release-to-correctness.json),
SHA-256 `6e16bb543c80b85bcfcae75f259bb866c5308c73deb75a2e7159cbfed093f163`,
binds completed native240/owner32 controllers, full raw verification and all
transfers, no research processes including exact C, and three free build
locks. Correctness now owns the original native raw/statistics audit and
owner full-bin replay; those independent audits are pending.

The separate device ten-window independent audit has SHA-256
`911deed4702fe53b9ef78274c9696ddc0cdb805411af65a161d38b01d119878e`
and found no discernible primary gain or regression. Native miss regression
is retained in [its result](INLINE_ADDRESS_DETAILS_NATIVE_RESULT.md). These
host results do not establish physical-device performance acceptance or
complete functional qualification. After independent review and quiet release,
the selected 5c queue remains original five groups/canonical SDK plus the
existing standalone signal audit, with no repeated native240.
