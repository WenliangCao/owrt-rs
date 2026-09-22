# R126：无目标回复提前退出

R126 只把 `response()` 中已有的 `clients.contains_key(peer)` 前移到属性解析之前。
缺失目标最终仍静默丢弃；有效目标、monitor、STATUS FD、DATA FD 和入站 FD 边界保持原路径。
R124 控制 ELF 逐字节复现；R126 ELF 为 `a07a9f2882e27dee14c3f538d35a4c13fe30e9abe8f8f2b2f22150b06a64eb2c`。
本地 Linux 类型检查和 49/49 单元测试通过，Oracle 六组功能/恢复门通过。

固定 lane 计数屏幕完成 48 个正式样本（三个 lane 各 16）及三个独立计量 smoke；
每 lane 都保存反序块、A/A、PMU 100%、迁核 0、完整 ACK、身份和原始哈希；匹配 lane 校验 payload，
无匹配 lane 验证零回调。[全部计数、CPU、wall 和反序比值](r126-perf-results.json)逐项保留。
八对象主 lane 的 R126/R124 instructions/op 中位数为 −16.51%（0 held）和 −16.42%（64 held）。
单对象 matched lane 为 −6.04%/−6.17%；无匹配 lane 约 0.00%。这些是 Oracle 用户态计数，
不能直接替代路由器 CPU 或耗时。

预先冻结的同 ELF A/A ±0.5% 门没有通过：八对象、64-held 的第 4 对 R126 A/A 为
`+0.9618%`，其余 A/A 对在门内。该 pair 的原始计数相差约 104 instructions/op、24 branches/op，
但该 pair CPU/wall 变化很小；现有 raw 没有随机 hash seed、对象 ID/桶布局快照，不能证明是 HashMap
探测、PMU 边界或别的原因。它也不能被事后剔除。由于主 lane 计量未校准，本轮没有启动路由器性能对照，
没有宣称 R126 性能胜出。

[路由器正确性/FD 回归](R126_UBUSD_RESPONSE_DESTINATION_ROUTER.md)和 49 条单测已完成，全部通过；
本候选仍未进入路由器性能比较，不因行为门通过而改写计量判定。
若后续重新测量，必须先提出可反证的噪声/布局假说并重新冻结工具和门；不能追加一对“好看”的 A/A。
[screen JSON](r126-perf-screen-result.json)保留每 lane 汇总和失败判定，完整逐块值在上述全部结果中。
