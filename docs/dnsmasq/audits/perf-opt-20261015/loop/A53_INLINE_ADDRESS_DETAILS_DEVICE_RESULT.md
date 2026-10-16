# G / 裸1df A53 UDP-hit 对照

固定 10 窗全部有效，原始归档已核验，E/F 临时槽已恢复，生产进程身份保持不变。

本轮比较 accepted G 与裸 1df；1df 继承了 6ab 的改动。CPU 中位数的 4 μs/query 差值未通过原可辨别性门限，也不能单独归因于地址内联。

| 指标 | G 中位数 | 1df 中位数 | 变化 | W | 同向 | 原门结论 |
|---|---:|---:|---:|---:|---:|---|
| CPU μs/query | 118 | 114 | -3.390% | 21.053% | 3/5 | 不可区分 |
| p50 ms | 0.171889 | 0.167965 | -2.283% | 17.865% | 3/5 | 不可区分 |
| p95 ms | 0.289457 | 0.358627 | +23.896% | 58.035% | 3/5 | 不可区分 |

CPU 中位 tick 差为 2；门限要求严格大于 8，并同时满足 W 与同向条件。完整范围、五对值和资源观察保存在 JSON 中。

源 `1df135dc2401a9f0ec2f219b1e4a8f07dd637db1`，SDK ELF `f7cde2e91c19d3aa535ef87078144acde965999163cbdd689bfff73ffa08b53d`。本轮是独立 UDP-hit 探索对照，完整功能和全场景验收仍由各自证据决定。

归档：10 份 tar / 430 个原始文件，314 次单线程观察。全部失败、异常与极值保留规则未改变；本轮未补跑。

[完整结果](A53_INLINE_ADDRESS_DETAILS_DEVICE_RESULT.json) · [固定计划](A53_INLINE_ADDRESS_DETAILS_DEVICE_PLAN.json)

独立审计通过：`a4d94373`，[十窗、原始数据与恢复复核](../correctness/inline-address-details-device-independent-audit.json)。
