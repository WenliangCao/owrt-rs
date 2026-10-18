# dnsmasq K：固定 PGO 构建输入 · OpenWrt 25.12.5

本发布保存 dnsmasq K 的固定 PGO 构建输入，供 v0.2.1 固件构建使用。它不是固件，不替换路由器组件，也不是新的产品版本。

训练只执行一次，包含 11 个合成场景、50 份原始 profile，测试域名为 pgo.test；不含抓取的真实客户端流量。候选 K 的产品变化和性能见[v0.2.1 性能摘要](https://github.com/WenliangCao/owrt-control-plane-rs/blob/main/docs/reviews/V0_2_1_PERFORMANCE_20261017.json)。

| 组件 | 场景/指标 | C 原版 | 本版 Rust | 变化 | 测量依据 |
| --- | --- | --- | --- | --- | --- |
| dnsmasq | 未测（仅构建输入） | 未测 | 未测 | 未测 | 不单独测量 PGO 输入文件 |
