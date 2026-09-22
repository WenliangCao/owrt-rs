# R118–R120 客户端表对照计划

2026-09-22，用户要求继续研究。此次检查客户端表的分配、间接访问与索引算法，不再改动接收控制流。
这是探索性实验，任何未过正确性或资源边界的版本均不能成为生产候选。

## 假设与单变量

| 对照 | 唯一目标变量 | 固定部分 |
|---|---|---|
| R115 `b28dbc8` → R118 `3dbab41` | `Box<Client>` 改为内联 `Client` | 标准随机哈希、FD 边界、借用派发、事件逻辑 |
| R118 → R119 `4735dc5` | 随机哈希改为 SplitMix64 整数混合 | 内联 Client、协议和收发逻辑 |
| R115 → R120 `0f84cc4` | `HashMap` 改为 `BTreeMap` | Box<Client>、协议和收发逻辑 |

R119 只作成本诊断：HELLO 暴露随机 client ID，调用者可以保留或关闭连接，筛选插入集合；
STATUS/DATA 的 peer 还可选择 miss 查询。固定混合函数不能视为保留 RandomState 的抗碰撞边界。
即使普通负载胜出，也不直接合入；不得为性能擅自增加不兼容连接上限。
原 identity-hash 版本 `475cb57` 的高 7 位全零，不继续测试。

算法依据：[hashbrown 0.17.1 的 tag 提取](https://raw.githubusercontent.com/rust-lang/hashbrown/v0.17.1/src/control/tag.rs)、
[SplitMix64 作者实现](https://prng.di.unimi.it/splitmix64.c)。BTreeMap 对照保留标准库实现；精确 C 使用 libubox AVL，
这里不声称二者算法或性能相同。

## 身份和检查

四个版本均从不可变 Git 提交导出 ubusd/ubus，使用同一 Oracle 工具链、SDK、规范源码路径和 R115 release flags。
各版本使用独立 target 缓存；R115 必须逐字节复现历史 ELF `c8f3aa25…9dde`。
首次复用缓存的构建因归档时间戳导致四个 ELF 相同，已整体作废并保留；未进行设备采样。
旧 R118/R119 数据没有充分的同构建来源证据，只作探索记录，不与本轮合并。

先通过 45 条单测、六组 Oracle 功能/恢复门，再通过路由器原协议 smoke 和 FD 差分。
所有检查按精确 ELF 绑定，不沿用另一 ELF 的结果。

## 路由器采样与判定

沿用原版 libubus 调用者、固定 argv[0] 和 CPU affinity，三个 user-event 场景；
低连接和 64 个持有连接各两窗口，每段 5000 次、预热 2000 次，窗口内 ABBA/BAAB，第二窗口交换 A/B。
串行执行，记录 daemon/client/总 CPU、wall time；每窗口校验生产 C 身份、boot/config/mounts 和清理。
这不是吞吐量或完整 ubusd 矩阵，两个窗口不足以证明约 1% 的效果或等价性。

先筛 R120；若两个规模均无一致方向收益，就停止此候选，不靠变体追逐噪声。
有一致收益才追加精确 C 对照、独立确认窗口和内存/连接 churn；采用前仍须完成未覆盖的注册、查询、invoke 等场景。
R118 同构建重查和 R119 成本诊断单独记账，不能把 inline 与 hasher 的组合收益归给某一个变量。
最终权重以用户体验性能为主，CPU/内存为资源成本；不能把少用 CPU 自动称为低延迟或高吞吐胜出。

构建及原始输出保存在 ignored `private/r120-client-index/`。生产始终使用 C，本轮不部署候选。
