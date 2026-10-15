# A53 UDP cumulative-path diagnostic:50/50 valid

All50 fixed attempts passed with no replacement. Every window returned1000 prewarm,1000 warmup and4000 measurement replies correctly. The original case/group/guard/loadgen and100Hz CPU endpoints were unchanged; CPU uses the original5000 completed-query denominator.

| Independent comparison | CPU median µs/query | Change | W | Same direction | Median tick delta | Original CPU gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Exact C → E | 80 → 140 | +75.000% | 12.500% | 5/5 | 30 | distinguishable |
| E → stage/full | 140 → 140 | +0.000% | 7.143% | 0/5 | 0 | indistinguishable |
| Own full → receive | 136 → 70 | -48.529% | 8.571% | 5/5 | 33 | distinguishable |
| Own full → before-answer | 136 → 98 | -27.941% | 10.204% | 5/5 | 19 | distinguishable |
| Own full → skip-local | 138 → 120 | -13.043% | 5.797% | 5/5 | 9 | distinguishable |

Each group has its own five contemporaneous controls. E/full calibration was indistinguishable in CPU,p50 andp95; this does not establish zero instrumentation/layout cost. Skip-local clears the unchanged exclusive8tick CPU-resolution gate by only1tick.

| Independent comparison | p50 median ms | p50 gate | p95 median ms | p95 gate |
| --- | ---: | --- | ---: | --- |
| Exact C → E | 0.136803 → 0.199742 | distinguishable | 0.230442 → 0.408332 | indistinguishable |
| E → stage/full | 0.204820 → 0.193279 | indistinguishable | 0.394482 → 0.350702 | indistinguishable |
| Own full → receive | 0.194125 → 0.116798 | distinguishable | 0.399253 → 0.209513 | indistinguishable |
| Own full → before-answer | 0.192048 → 0.152038 | distinguishable | 0.299382 → 0.351087 | indistinguishable |
| Own full → skip-local | 0.196356 → 0.179736 | distinguishable | 0.283147 → 0.275529 | indistinguishable |

The broad receive and answer interventions identify work worth investigating. Skip-local gives a smaller distinguishable intervention in this fixture. These deltas are not additive function costs. Receive skips admission and synchronous processing; before-answer retains admission/owner/metadata and one128-byte answer allocation while replacing assembly. Skip-local retains the inspected-name hint and real cache answer. Preserved prologues, branch prediction, changed cache access and the synthetic writer remain material limitations.

All35 stage windows used one immutable SDK ELF `d72596b3…32e7e9` from `acec64f2`; the180 receipt source files matched Git. The2,140,955-byte ELF fits the unchanged2,200,000-byte size gate but remains permanently excluded from candidate acceptance. All20 full windows matched6000/cut0; all15 cut windows matched6000/selected cut5000/other cuts0. Total upstream count was800 in setup_warmup and zero in steady for every window. The fixedTTL120 synthetic replies are not exact-C wire-equivalence evidence.

Author verification checked50 tar archives and2,185 members against remote manifests and extracted bytes, then recomputed original traffic and comparisons. The1,578 observed resource samples and final endpoints showed one daemon thread; all cases and daemons exited0. The independent preflight runner review is `e396e71f`. Final independent audit `e6c1f013` passed all50 archives/2,185 files, all15 primary and35 resource comparisons, health and the captured postflight evidence. It binds the immutable `be1bb962` result JSON SHA `10fc0803…1ceab0`; the author JSON retains its pre-audit snapshot status.

Fresh health baseline lasted125.281s. During the round,2,113 guard samples,826 DNS checks,381 HTTP checks and140 external dual-stack HTTPS checks had no failures; minimum available memory was83,148KiB. Postflight confirmed production SHA `8472be5a…aade7`, PID/start `[3086,2115]`, no STOP/active group/owned executable, and exact prior staged E/F slots. Only verified completed window copies and the four newly staged immutable source copies were reclaimed; all local artifacts and evidence remain.

A local postprocessing checker initially compared JSON lists with Python tuples. Its first failure and original checker were retained, then only the recomputed mapping was JSON-normalized. No measurement, controller, statistics or raw evidence changed.

Accepted E and the frozen C oracle are unchanged. No stage mode is a product candidate. The report makes no allocation-site CPU, PMU or IPC claim; real optimizations still need their normal correctness, size and device gates.

Full per-window values, resource ranges, W/direction/precision decisions, identities and raw archive hashes are in `A53_UDP_STAGE_DEVICE_RESULT.json`.
