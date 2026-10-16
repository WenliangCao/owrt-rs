# Accepted G: original 50-window UDP stage diagnostic

All 50 fixed windows passed; archives verified and E/F restored. No measurement replacement or product promotion.

| Independent group | CPU median μs/query | Change | W | Direction pairs | Median tick difference | Original CPU decision |
|---|---:|---:|---:|---:|---:|---|
| exact-c-vs-g | 86 → 126 | +46.512% | 9.302% | 5/5 | 20 | slower |
| g-vs-stage-full | 124 → 122 | -1.613% | 13.115% | 4/5 | 1 | indistinguishable |
| stage-full-vs-receive | 124 → 74 | -40.323% | 10.811% | 5/5 | 25 | faster |
| stage-full-vs-before-answer | 122 → 94 | -22.951% | 10.638% | 5/5 | 14 | faster |
| stage-full-vs-skip-local | 116 → 110 | -5.172% | 6.897% | 4/5 | 3 | indistinguishable |

| Independent group | p50 median ms | Original decision | p95 median ms | Original decision |
|---|---:|---|---:|---|
| exact-c-vs-g | 0.145421 → 0.179352 | slower | 0.320003 → 0.392174 | indistinguishable |
| g-vs-stage-full | 0.17589 → 0.17966 | indistinguishable | 0.398176 → 0.322696 | indistinguishable |
| stage-full-vs-receive | 0.17689 → 0.12757 | faster | 0.49697 → 0.269221 | indistinguishable |
| stage-full-vs-before-answer | 0.175505 → 0.143959 | faster | 0.375094 → 0.318772 | indistinguishable |
| stage-full-vs-skip-local | 0.17112 → 0.164656 | indistinguishable | 0.257757 → 0.271375 | indistinguishable |

Each cut has its own contemporaneous full controls. Calibration does not prove zero instrumentation cost. Stage differences are not additive function costs, IPC evidence, allocation prices or product-candidate gains.

Before-answer uses G’s original cached reply buffer and send-then-recycle path. Fixed TTL120 synthetic responses remain fixture-only. No new allocation counter or zero-allocation target was introduced.

One diagnostic ELF `686ba665a7c097c5ea4555c8cecabdc22235ceadfc9b314bbdb3660fddedc8a6` from source `a34e73107bc15f29b29b83499ceb0e0bc746d915` served all four modes. Original gates: fixture 1 + bin 82 + ignored-bin 4; not full product qualification.

50 tar archives / 2185 raw files / 1575 thread observations. Every original window and range is retained in JSON; CPU uses the original 5000 denominator and strictly greater than eight ticks gate.

The original warm owner32 timing run overlapped this device50 on a separate Oracle host. Its actual launch and completion receipts, subsequent author analysis/postflight, and independent original-analyzer replay are bound in the JSON; no bulk transfer was allowed before archive verification and E/F restoration.

[Full result](A53_G_UDP_STAGE_DEVICE_RESULT.json) · [Frozen plan](A53_G_UDP_STAGE_DEVICE_PLAN.json)

Independent local raw audit PASS: [report](../correctness/g-stage-device-independent-audit.md), commit `94166598`, JSON SHA256 `8e15f20e9376104578da0bdd7285ae8a13c751932285950b40b18630e39a916d`. It recomputes all 15 primary and 35 resource comparisons and verifies the archive, counter, health and restoration evidence. The original result JSON remains unchanged at `1bb4ba246de1dc42181609bc2e4bf1c6097d89a1fad64c6e0662e90a4e4d3327`.
