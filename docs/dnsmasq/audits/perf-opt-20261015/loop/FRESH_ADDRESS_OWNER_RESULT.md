# Fresh-address owner32: high-load hit gain, retained native regressions

All 32 fixed original-SDK windows completed without failed or replacement
measurements: 12 separate grouped PMU windows and 20 plain windows. The ordinary
UDP cached-hit high-load CPU/throughput/response-latency metrics improve, while
sender send lag rises and low-load CPU does not show a discernible improvement.
The eight native fallback regressions remain; this
hit-only screen does not cancel them or qualify the prototype for a candidate.

The independent sources remain F `3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`
and fresh-address `2a9d53b00fb009bfa494de4e1de9fd37d2e5c2fb`.
Exact SDK ELFs are respectively
`b7926bcf39cd7f33b4f0c110315ddc1ad719b39427bec53430ea05aeacd781fc` and
`b52432a274ab9dda36d60e568e4b618e755d34e69ffce72bc5343df485fcce7f`.
Both are 2,136,859 bytes and pass the unchanged size budget; they remain
unqualified research builds. Exact related Linux gates passed 935 tests before
screening, bound to receipt
`d63e14d8024798fa94d1486b68698e44696a2dbcfc5ad6e0df8bddea1b5fe384`.
These are not full frozen-C correctness or physical-device qualification.

## Execution and measurement scope

[Plan 9e1856a6](../dns/FRESH_ADDRESS_PLAN.md) retains three alternating PMU pairs
and five alternating plain pairs at each of low 200 queries/s and high unpaced
load. It reuses the existing driver/load generator, 800-name A/AAAA 70/30
fixture, 1,000 full prewarm queries, 5-second warmup, 20-second measurement and
1-second drain. There is no new strace matrix or pooling of prior captures.
All warmup/measurement traffic is correct and nonempty; timeout, wrong,
transport, skipped and stale-reply counts are zero. Every child tree drains.

The native480 experiment ended before the matrix gap. DHCP then downloaded and
verified both requested SDK bundles (six files) and explicitly released the
transfer gate. Only then was this owner32 launched, with an empty root-readable
research-process inventory. Oracle remained exclusive through the measured
windows. The controller and the unchanged generic raw analyzer each exited
successfully with empty stderr. There was no setup failure or analysis retry
in this fresh-address attempt; name-buffer's earlier setup failure is separate.

CPU and PMU per query divide by actual warmup plus measurement completions,
with the observation including the drain. Prewarm is excluded. Low load has
N=5,000 and a 2 µs/query CPU-tick quantum. Throughput and latency use only the
20-second measurement cohort. Measurement responses completed during the
fixed drain are retained in the same cohort, not silently discarded.

## Five plain pairs

| Metric | F median | Fresh-address median | Change | W | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Low CPU µs/query | 28.000000 | 30.000000 | +7.143% | 21.429% | within variation; tick gate fails |
| Low throughput queries/s | 200.000000 | 200.000000 | +0.000% | 0.000% | within variation |
| Low p50 µs | 56.360000 | 57.161000 | +1.421% | 26.313% | within variation |
| Low p95 µs | 81.920000 | 88.761000 | +8.351% | 20.505% | within variation |
| High CPU µs/query | 4.657719 | 4.408685 | -5.347% | 0.262% | faster; variable-N only |
| High throughput queries/s | 214467.300000 | 226619.650000 | +5.666% | 0.270% | higher |
| High p50 µs | 144.161000 | 135.481000 | -6.021% | 0.324% | faster |
| High p95 µs | 158.282000 | 150.081000 | -5.181% | 0.427% | faster |

Low CPU has only three pairs in the direction of its positive median change.
Its one-tick median difference does not clear the strict >8-tick precision
threshold and does not exceed W. Both low latency percentiles remain within
variation. No low-load CPU or latency improvement is established.

| Pair | Low CPU F → fresh, µs/query | High CPU F → fresh, µs/query | High throughput F → fresh, queries/s |
| --- | --- | --- | --- |
| 1 | 30 → 32 | 4.657719 → 4.405371 | 214554.20 → 226663.55 |
| 2 | 28 → 30 | 4.659951 → 4.416224 | 214467.30 → 226157.65 |
| 3 | 28 → 26 | 4.656782 → 4.408685 | 214090.65 → 226619.65 |
| 4 | 26 → 30 | 4.657449 → 4.411945 | 214629.20 → 226531.95 |
| 5 | 32 → 28 | 4.664558 → 4.404656 | 214454.00 → 226770.65 |

High CPU, throughput and both latency percentiles exceed W, each with five of
five favorable pairs. High plain N is 5,351,335–5,363,451
for F and 5,654,152–5,670,351 for fresh-address.
Sender CPU is 99.544%–99.883%. These are observed closed-loop
pipeline values with a saturated sender and approximately one daemon CPU,
not isolated-server capacity. High CPU explicitly retains `precision_ok: null`:
W/direction evidence on variable N is not a fixed-cohort tick-precision pass.
Every pair's counts, latency, send lag and sender CPU remain in the JSON.

Sender send lag is an adverse part of the same high-load pipeline observation,
and is not hidden by the response-latency gain:

| Send-lag metric | F median, µs | Fresh median, µs | Change | W | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Low p50 | 70.996 | 69.823 | −1.652% | 3.078% | Within variation |
| Low p95 | 82.552 | 81.624 | −1.124% | 5.359% | Within variation |
| High p50 | 2.680 | 2.760 | +2.985% | 1.449% | Slower, 5/5 |
| High p95 | 4.760 | 5.040 | +5.882% | 2.381% | Slower, 5/5 |

## Separate PMU observations

All 12 PMU windows retain inherited grouped user/kernel instructions and cycles,
positive equal enabled/running times and no scaling. The IPC values below are
medians of each window's own user-instructions/user-cycles ratio, not a ratio
assembled from different windows. These windows do not supply the plain CPU
or latency decision.

| Per-query metric | Low F | Low fresh | High F | High fresh |
| --- | ---: | ---: | ---: | ---: |
| User instructions | 8955.21 | 8296.07 | 6760.32 | 6100.82 |
| User cycles | 19853.40 | 19551.79 | 4389.83 | 3800.29 |
| Kernel instructions | 25537.34 | 25864.72 | 13007.45 | 12998.15 |
| Kernel cycles | 38977.50 | 39697.66 | 9516.77 | 9276.28 |
| Per-window user IPC | 0.45107 | 0.42431 | 1.53991 | 1.60532 |

The native and owner observations answer different questions. The hit gain is
consistent with the native cached-hit improvement, but the native miss,
miss-leases, synth-address, lease-address, RRset and three CNAME regressions
remain in [the full 15-scene native report](FRESH_ADDRESS_NATIVE_RESULT.md).
No aggregate score or favorable subset is used to accept this prototype.

## Retained evidence

The unchanged [generic analyzer](analyze_udp_owner_screen.py), SHA256
`2ca11adac3e0ed9287321c112e8babb02559ce0363282b0377533ddcbf4a1823`, processed
all original raw windows once on CPU 0. Its existing helpers handled exact
counts, child-tree drains, CPU ticks, grouped PMU data, all latency/send-lag
records and raw file hashes. The output SHA256 is
`6a3c9298f0ab59da5608e2d66b4da64f86ff9ea439982696948506af8e4c75a0`.

A subsequent small-metadata review rehashed 388 per-window files, rechecked
final ELF/map/build/controller/driver identities and all tree drains. On the
local machine, all 32 planned labels, grouped event fields, same-window IPC
and all pair summaries were checked against the unchanged comparison code.
All checks passed. Large latency/send-lag binaries were not transferred or
read a second time. No artifact was changed and no router was accessed by
this work.

Raw data remains private on Oracle `root/private/fresh-address-owner-screen1`.
[The derived result](fresh-address-owner-screen-result.json) preserves all 32
rows, raw file digest inventories, full statistics and the final review scope;
[the launch receipt](fresh-address-owner-launch.json) records the prerequisite
and transfer gates. Full correctness, full matrices, an independent E comparison
and physical qualification remain necessary for any future immutable candidate.
