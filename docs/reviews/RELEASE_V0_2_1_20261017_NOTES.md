# v0.2.1 — dnsmasq K

本版交付已验收的 dnsmasq K：普通缓存命中快路径、静态 UDP 接收优化、同名 A/AAAA
缓存提示与固定 PGO。OpenWrt 25.12.5、AX3000T、十组件原生布局不变。
另九个程序、dnsmasq init/ACL、十二份 stock 恢复文件、内核与原包版本均与 v0.2.0 相同。

## 性能与边界

- 真实配置的公开七规则、200 qps 单族 UDP 命中中，v0.2.0→J 的直接五对比较为
  CPU 149.69→73.03 µs/query（−51.22%），p50 −38.80%。这是 J 的直接结果；
  K 在原简化矩阵的单族命中没有可分辨变化，未重新做 v0.2.0/K 同轮比较。
- 同名 A+AAAA 命中九对确认：J→K CPU 123.08→83.12 µs/query，配对中位 −39.47 µs，
  9/9 改善，p50 −22.65%。它与上面的不同负载收益不能相加。
- K 完成 44 组/67 项正确性、发货边界及 118 个有效完整矩阵窗口。33 项原主指标
  没有可分辨退化，也未证明等价；混合负载 CPU 配对 +4.21 µs、5/5 同向变慢的趋势保留。
- AD/CD 和 EDNS 查询继续使用完整通用路径；备用快路径没有纳入本版。
  本版不宣称所有真实查询均命中快路径，也不把查询形状比例当实际缓存命中率。
- 小 HUP 的最后 20 次诊断没有发现简单顺序缺陷，停止性能研究；未纳入租约名字复用
  或额外插桩。后续工作是实际运行观察及独立的安全性/警告清理。

以上派生数字、失败记录及限制保留在
[性能摘要](https://github.com/WenliangCao/owrt-control-plane-rs/blob/main/docs/reviews/V0_2_1_PERFORMANCE_20261017.json)。

## 精确构建

[正式 CI 39007479025](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39007479025)
从 `867c9c53d65b03d5d8266df278a03b87b5b791af` 构建。v0.2.1 标签固定指向这个提交，
后续验收文档不移动标签。程序从源码新编译，SHA256 精确等于已验收 K。

| 资产 | 字节 | SHA256 |
| --- | ---: | --- |
| sysupgrade 固件 | 13,762,848 | `d1537ba13e792f2123d32f17c9e554b02bf365114548379da7f60d37598c3d74` |
| owrt-control-plane 0.2.1-r1 APK | 5,850,699 | `54fb522ee9659ede31a1d678121bc86f54786924b3e3a54eb7ceefdfba6ad4c8` |
| 固件中的 dnsmasq | 2,296,611 | `f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08` |

固定 PGO 输入保存在独立的
[构建输入 Release](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/dnsmasq-k-pgo-inputs-20261017)。
首次构建因 Cargo 路径身份造成 2858 条 PGO missing 而失败，修正构建槽路径后最终构建为
0 missing/0 mismatch；没有改写 profile 或更换候选。生产 unsafe 新增 0，dnsmasq 的
Rust 警告 22→22；另外九组件也没有新增警告。详见
[审阅记录](https://github.com/WenliangCao/owrt-control-plane-rs/blob/main/docs/reviews/V0_2_1_UNSAFE_WARNINGS_20261017.md)。

固件和五个 APK、四份清单保持 CI 原字节；四个 LuCI 中文 APK 的附件名称将 `~` 改为 `.`，
包内版本不变。`CI-SHA256SUMS` 保持原 CI 名称与内容，外层 `SHA256SUMS` 对应公开附件名。
APK 是离线镜像装配输入，不用于在线替换 PID1 或总线。

## 实际部署

已按用户授权使用上面同一镜像保留配置刷写一次，并正常重启一次。两次均核验十组件、
45 份配置、DNS UDP/TCP A/AAAA、DHCP、双频无线、IPv4/IPv6 HTTPS、LuCI 与防火墙；
此次没有物理断电测试。当前完整状态及白天 60 分钟统计见
[部署报告](https://github.com/WenliangCao/owrt-control-plane-rs/blob/main/docs/reviews/DEPLOYMENT_V0_2_1_20261017.md)。短观察不能替代随后 24 小时运行观察。

上线前已离线保存当次配置、v0.2.0 回滚镜像与小米 TFTP 救援镜像；保留配置升级不使用
`-n`。十二份 stock 文件的 C 恢复与完整刷回 v0.2.0 是不同恢复路径，见
[救援手册](https://github.com/WenliangCao/owrt-control-plane-rs/blob/main/docs/RUNBOOK_AX3000T_RECOVERY.md)。
