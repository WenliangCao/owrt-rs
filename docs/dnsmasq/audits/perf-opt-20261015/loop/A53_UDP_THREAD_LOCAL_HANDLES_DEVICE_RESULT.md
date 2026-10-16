# G / 6ab A53 UDP-hit 对照

固定 10 窗全部有效，原始归档已核验，E/F 临时槽已恢复，生产进程身份保持不变。

| 指标 | G 中位数 | 6ab 中位数 | 变化 | W | 同向 | 原门结论 |
|---|---:|---:|---:|---:|---:|---|
| CPU μs/query | 122 | 116 | -4.918% | 6.897% | 5/5 | 不可区分 |
| p50 ms | 0.172427 | 0.169504 | -1.695% | 4.373% | 3/5 | 不可区分 |
| p95 ms | 0.319387 | 0.258679 | -19.008% | 192.026% | 2/5 | 不可区分 |

CPU 中位 tick 差为 3；门限要求严格大于 8，并同时满足 W 与同向条件。完整范围、五对值和资源观察保存在 JSON 中。

源 `6ab0f064b69087add3be1cb2bf5604fbaf42dffa`，SDK ELF `feac49a01e31b7ee35dfcdaf55ac25ec8e214d986e0bfe246332b29531f31288`。本轮是独立 UDP-hit 探索对照，完整功能和全场景验收仍由各自证据决定。

归档：10 份 tar / 430 个原始文件，314 次单线程观察。全部失败、异常与极值保留规则未改变；本轮未补跑。

[完整结果](A53_UDP_THREAD_LOCAL_HANDLES_DEVICE_RESULT.json) · [固定计划](A53_UDP_THREAD_LOCAL_HANDLES_DEVICE_PLAN.json)

独立审计通过：`5a2263a1`，[十窗、原始计数与恢复复核](../correctness/udp-thread-local-handles-device-independent-audit.json)。
