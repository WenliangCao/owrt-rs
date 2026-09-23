# R138 REMOVE 正确性复核

**候选在 Oracle 的单测、wire、FD 和恢复门全部通过。** 本报告仅判断功能兼容性，性能和物理路由器验证由其他记录覆盖。

| 检查 | 结果 |
| --- | --- |
| 匹配 OpenWrt SDK 的 daemon 单测 | 55/55 |
| 八项 wire，包括新增 `remove_reply` | C、R136、候选逐字一致 |
| 六项 FD | 三项常规逐帧发送与 C 一致；三项手工帧符合既定 read-ahead 契约 |
| `ubusd_halfclose`、`ubusd_lookup_delete` | 候选全部检查通过；C 的已知失败保持原门预期 |

实际 release ELF 是 `85ea7b0ae1861001ad81360ca78d5dbbea916df788dbe4191f7cacbbbc2c83e2`。静态单测另行构建；测试 overlay 的 20 个运行时／Cargo 文件逐字匹配冻结候选。新 probe 单独编译，未替换实测 release ELF。

新增 probe 检查匿名／具名无类型对象、共享类型及最后一次类型释放的 DATA/STATUS 字节、属性顺序和请求 header；匿名监听对象删除后的 pattern 清理；同一连接上具名删除的 `DATA → INVOKE → STATUS`；监视器的 REMOVE 请求、DATA、STATUS 顺序及载荷；删除订阅对象后存活目标的 `ACTIVE=0` 通知。现有 `release` 保留 `DATA → NOTIFY → STATUS`，现有传输单测覆盖部分写和已排队回复，因此没有再复制这些测试。协议拒绝同一 owner 的 SUBSCRIBE，出向订阅检查使用两个连接，不声称验证了跨连接可观测的全局通知先后。

首轮 FD 草案失败保留在证据中：wrapper 将旧 R131 控制替换成 R136，但仍按 C-exact 接收契约检查它。R136 的三项手工帧符合 read-ahead 行为，导致控制失败，尚未执行候选。恢复原 R131 控制后，在新目录重跑原 FD 脚本，六项全部通过；运行时和 probe 均未修改。该 wrapper 同时重复了八项 C/R131/候选 wire 对比，也全部通过。

184 个归档文件已逐项校验。完整 artifact、workload、transcript、失败记录和归档 SHA-256 见 [派生结果](r138-correctness-results.json)。
