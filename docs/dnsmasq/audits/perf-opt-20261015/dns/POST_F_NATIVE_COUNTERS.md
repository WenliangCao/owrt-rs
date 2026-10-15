# Independent F prototype native counters

Both independent prototypes completed the fixed count-only plan under one spare Oracle correctness slot: dotted names `c627927d` and singleton lookup results `b1180f72`, each against frozen F source `3a3d8e3e`. They were not combined and did not modify F.

Both full native library suites passed 830 tests with 22 ignored. All 337 commands exited successfully. All 80 allocation controls and 240 instruction windows completed with matching checksums at each operation count and zero final live bytes. The 240 stat windows each retained raw count/time-enabled/time-running evidence, reported 100% running, and required no scaling. No failed or partial workload was retried or replaced.

The same existing 15-scene whole-answer probe and five-scene UDP-admission probe ran with 8,000 allocation-tracked operations or 200,000 uninstrumented operations under `instructions:u`. Three alternating pairs were retained for every candidate/probe/scene. PMU counts include setup, priming and output; only requested operations form the denominator. CPU0/nice10 and one build job were used while the other correctness workers continued. These data do not measure quiet CPU time, cycles, IPC or device performance.

| Probe | Scene | Dotted instruction change | Singleton instruction change |
|---|---|---:|---:|
| hot | hit | -4.3755% | -4.5099% |
| hot | hit-upper | -4.2470% | -4.3920% |
| hot | hit-leases | -3.7788% | -3.7805% |
| hot | hit-typed | -4.3784% | -4.5075% |
| hot | miss | -6.9430% | -0.0697% |
| hot | miss-leases | -5.4946% | -0.0524% |
| hot | host | -3.3284% | +0.9615% |
| hot | host-localise | -0.5237% | -0.3965% |
| hot | raw-address | -0.4228% | +0.0295% |
| hot | synth-address | -3.0972% | -0.0000% |
| hot | lease-address | -3.6904% | -0.0176% |
| hot | rrset | -1.5585% | +0.4130% |
| hot | cname | -1.9852% | -2.2213% |
| hot | cname-leases | -3.7516% | -1.8084% |
| hot | cname-config | +0.0729% | -0.0041% |
| admission | hit | -2.9275% | -4.2218% |
| admission | hit-upper | -2.8230% | -4.1211% |
| admission | miss | -4.4000% | -0.0232% |
| admission | host | -3.2461% | -0.0164% |
| admission | malformed | +0.0001% | +0.0000% |

Dotted names reduce user instructions on ordinary and lease-present paths, while configured CNAME is +0.0729%. Singleton lookup results reduce ordinary/uppercase hits; the whole-answer host control is +0.9615% and RRset is +0.4130%. Those increases remain visible and are not dismissed as timing noise or silently retested. No result here automatically admits either patch into G.

| Probe | Scene | Dotted allocations / requested bytes saved per operation | Singleton allocations / requested bytes saved per operation |
|---|---|---:|---:|
| hot | hit | 1 / 21 B | 1 / 64 B |
| hot | hit-upper | 1 / 21 B | 1 / 64 B |
| hot | hit-leases | 1 / 21 B | 1 / 64 B |
| hot | hit-typed | 1 / 21 B | 1 / 64 B |
| hot | miss | 1 / 21 B | 0 / 0 B |
| hot | miss-leases | 1 / 21 B | 0 / 0 B |
| hot | host | 1 / 21 B | 0 / 0 B |
| hot | host-localise | 1 / 30.28 B | 0 / 8.64 B |
| hot | raw-address | 1 / 21 B | 0 / 0 B |
| hot | synth-address | 1 / 23.535 B | 0 / 0 B |
| hot | lease-address | 1 / 21 B | 0 / 0 B |
| hot | rrset | 1 / 21 B | 0 / 0 B |
| hot | cname | 1 / 23 B | 1 / 64 B |
| hot | cname-leases | 2 / 44 B | 1 / 64 B |
| hot | cname-config | 0 / 0 B | 0 / 0 B |
| admission | hit | 1 / 14 B | 1 / 64 B |
| admission | hit-upper | 1 / 14 B | 1 / 64 B |
| admission | miss | 1 / 14 B | 0 / 0 B |
| admission | host | 1 / 22 B | 0 / 0 B |
| admission | malformed | 0 / 0 B | 0 / 0 B |

The host-localisation requested-byte totals include the existing process-dependent bucket/rotation allocation variability. They are not a causal byte saving estimate for the product changes. Full allocation/reallocation counts and each instruction window are retained in the derived JSON.

Oracle work has ended and the slot was released before F measurement. The STOP mechanism was available throughout but was not needed. All further layout work is local analysis; neither native timing nor SDK/device verification is claimed.

Evidence: [fixed source/fixture plan](post-f-native-count-plan.json), [replay runner](run_post_f_native_counts.py), [all results and derived summaries](post-f-native-count-results.json). Raw logs, source archives and native binaries remain in Oracle private `dns/private/post-f-native-20261015`.
