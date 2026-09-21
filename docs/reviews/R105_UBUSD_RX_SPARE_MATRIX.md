# R105 shared receive buffer: exploratory matrix

Four physical-router blocks × C / R89 / accepted R103 / candidate, 10 lanes each.
Candidate `99dffae3…` is not accepted. Values below are median paired changes; negative means less CPU or latency.

| Lane | Own CPU vs C | Own CPU vs R89 | Own CPU vs R103 | p99 vs R103 |
|---|---:|---:|---:|---:|
| lookup | -25.07% | -15.11% | +1.04% | -1.99% |
| lookup_all_64 | -71.96% | -68.73% | +0.30% | +1.37% |
| invoke | -27.76% | -29.00% | +1.48% | +1.91% |
| lookup_c4 | -28.70% | -14.80% | +1.45% | -8.65% |
| lookup_all_64_c4 | -71.86% | -67.25% | -0.69% | +0.32% |
| invoke_c4 | -27.16% | -25.57% | +1.34% | -4.25% |
| lookup_prefix_64 | -72.29% | -19.00% | +1.90% | +6.68% |
| lookup_prefix_64_c4 | -72.91% | -16.01% | +0.77% | +0.09% |
| lookup_all_128 | -70.26% | -66.38% | -1.32% | +0.70% |
| lookup_all_128_c4 | -73.69% | -69.15% | +1.01% | +1.72% |

Six CPU lanes and prefix-lookup p99 trigger the frozen independent-recheck rule relative to R103. A gate flags further investigation; it is not a significance test. The independent direct-user-event recheck is separate and cannot clear these query gates.

All matrix CPU medians are lower than C/R89, but not every latency item wins: serial invoke p95 is +0.06% versus R89. Full positive and negative cells, tick counters, client/dependency CPU, throughput and per-block values are in [machine-readable results](r105-rx-spare-matrix-results.json). No confidence or equivalence claim follows from four blocks.

End-of-matrix VmRSS/RssAnon medians (KiB): C 972/144, R89 618/162, R103 624/168, candidate 628/172. This sampled state is worse than both Rust controls and C anonymous residency. It differs from the separate held-connection experiment: 64 idle connections gave R103/candidate/C/R89 RssAnon 402/100/118/82 KiB. Neither proc snapshot is precise PSS, peak, or whole-system memory.

All 16 matrix windows passed stock-production identity, same boot/configuration/host mounts and owned-process/directory cleanup. No candidate was installed. All 160 lane observations are retained.
