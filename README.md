# owrt-control-plane-rs

逐步用 Rust 替换 OpenWrt 中能够替换的部分。当前在 Xiaomi Mi Router AX3000T 上运行，
基于 OpenWrt 25.12.5；已发布版本为 [v0.3.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.3.0)，
包含 procd、ubusd、netifd、rpcd、logd、httpd、fw4、uci、reload_config、dnsmasq、odhcpd 共 11 个 Rust 组件。

以下按时间倒序记录，日期统一使用 Europe/Berlin。链接指向当时的报告与发布记录。

## 2026-10-18

- 完成 HFO 开/关与 Mac 双网口排队定位：关闭 HFO 后 Wi-Fi 端尾延迟降低，有线 LAN
  探针约 1 ms；有线公网仍有超时。最终恢复并保持 HFO+WED，未配置 CAKE。
  [对照结果与限制](docs/reviews/QUEUE_LOCATION_20261018_RESULT.md)
- 启用硬件流卸载和 WED。Mac 下载对照中，路由器 CPU 中位数从 52.6% 降至 15.0%，
  每 GiB CPU 成本降低约 72%；吞吐差异在轮内波动内，三分钟客户端健康通过。
  上传、下载满载延迟均明显增加，CAKE 仍未配置。[测量与取舍](docs/reviews/NETWORK_OFFLOAD_20261018_RESULT.md)
- 发布并刷入 [v0.3.0：新增 odhcpd](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.3.0)。
  odhcpd-rs 接管本机 RA/SLAAC、DHCPv6 IA_NA/IA_PD、租约与 leasetrigger、ubus dhcp 对象、
  UCI 配置和 netifd 前缀订阅。[功能记录](docs/reviews/ODHCPD_PROTOTYPE_20261018.md)
- 修复 odhcpd 独立审计发现的接口错误隔离、配置更新和前缀撤销等问题，最终 SDK 程序通过
  129 项实包夹具检查。[审计修复与验收](docs/reviews/ODHCPD_FABLE_RESULT_20261018.md)
- 去掉 odhcpd 空闲轮询，改为按事件和实际到期时间唤醒；租约导出移到回复之后。
  最终程序完成路由器隔离 C/Rust 对照，10 项指标均未越过预定退步门槛。
  [完整性能结果](docs/reviews/ODHCPD_FINAL_FULL_AB_RESULT_20261018.md)
- 刷机后验证真实客户端 DHCPv6 自然续租，以及一次 20 秒 WAN6 断开/恢复；离线确认撤销报文与 C 一致。
  客户端撤销标记延迟和一次孤立 DNS 查询失败保留在[部署报告](docs/reviews/ODHCPD_V030_DEPLOYMENT_20261018.md)，
  报文对照见[C 一致性记录](docs/reviews/ODHCPD_WITHDRAWAL_C_PARITY_20261018.md)。
- 发布并刷入 [v0.2.3：减少防火墙重建和续租写入](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.2.3)。
  刷机后的 300 秒观察中，WAN6 出现 4 种地址集合，防火墙规则和 flowtable handles 保持不变。
  [部署记录](docs/reviews/DEPLOYMENT_V0_2_3_20261017.md)

## 2026-10-17

- fw4-rs 在有效规则与已加载规则可确认相同时跳过 reload 下发；有用户 include 脚本或无法确认时照常重载。
  首次 start 不建立规则比较状态；规则变化 reload 保留必要快照，较 v0.2.2 多约 14.58 ms CPU 的代价已接受。
  [实现与原版差异](docs/reviews/FW4_RELOAD_V023_20261017.md)、[定向复测](docs/reviews/V023_FW4_FOLLOWUP_20261017.md)
- netifd-rs 按 C 的 keep 逻辑处理续租，跳过未变化地址和路由的内核写入。
  [实现与验证](docs/reviews/NETIFD_KEEP_V023_20261017.md)
- 测量 v0.2.2 开机和续租事件：WAN 约 16.75 秒 up，客户端约 33 秒可联网；
  确认重复 WAN6 更新未改变有效防火墙规则。决定不重写 DHCP 脚本，改做上述两项优化。
  [测量报告](docs/reviews/DHCP_EVENT_REBOOT_20261017.md)
- 发布并刷入 [v0.2.2：十组件安全整理](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.2.2)。
  业务代码中的 unsafe 集中到系统接口封装，业务 crate 启用 `forbid(unsafe_code)`；
  路由器目标构建零编译警告，CI 将编译警告视为失败。[验收报告](docs/reviews/CORE_SAFE_20261017.md)
- 发布并刷入 [v0.2.1：dnsmasq 缓存查询优化](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.2.1)。
  纳入普通缓存命中快路径、UDP 接收优化、同名 A/AAAA 缓存提示与固定 PGO；
  完成一小时运行观察。[版本记录](docs/reviews/RELEASE_V0_2_1_20261017_NOTES.md)、[部署记录](docs/reviews/DEPLOYMENT_V0_2_1_20261017.md)

## 2026-10-14

- 发布并刷入 [v0.2.0：新增 dnsmasq](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.2.0)，
  Rust 组件从 9 个增加到 10 个；dnsmasq-rs 接管 DNS 与 DHCPv4 服务。
  完成保留配置升级、正常重启和用户物理断电复测。
  [版本记录](docs/reviews/RELEASE_V0_2_0_20261014_NOTES.md)、[部署记录](docs/reviews/DEPLOYMENT_V0_2_0_20261014.md)
- 完成 dnsmasq 候选的隔离真机性能比较；UDP 查询 CPU 和内存高于 C，TCP 未命中与 DHCPv4 续租有改善。
  此轮候选与最终发布程序不同，测量结果按报告中的对象保留。[性能报告](docs/dnsmasq/PERF_DEVICE_20261014.md)

## 2026-10-09

- 发布并刷入 [v0.1.1：修复 CLI 断管道与 IPv6 路由](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.1.1)。
  fw4、uci 等命令在输出端关闭时不再 panic；netifd 补齐 IPv6 offlink 保护路由、
  下游前缀 source rule 及 PD 自然到期清理。
  [CLI 修复](docs/reviews/health-20261008-cli.md)、[netifd 修复](docs/reviews/health-20261008-netifd.md)
- 正式产物完成离线协议、配置迁移、恢复与启动检查；九组件运行和保留配置通过真机快速验收。
  [离线验收](docs/reviews/HEALTH_20261008_FORMAL_VALIDATION.md)、[部署记录](docs/reviews/DEPLOYMENT_V0_1_1_20261009_RESULT.md)

## 2026-09-29

- 发布并刷入 [v0.1.0：九组件集成固件](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/ax3000t-rust9-v0.1.0)。
  九个 Rust 程序由统一包安装到标准路径，结束此前的独立包与覆盖挂载部署；
  保留配置升级、连续客户端验收和用户物理断电复测通过。[部署记录](docs/reviews/NATIVE_DEPLOYMENT_20260929_RESULT.md)
- 修复 netifd 在 WAN carrier 延迟到达时丢失设备 claim 的问题，完成重新部署和断电恢复检查。
  [修复记录](docs/reviews/POWER_RECOVERY_20260929_FIX.md)
- reload_config 复用规范化和基线缓冲，直接通过 ubus 顺序投递配置事件并复用连接，
  保留取消、超时与失败处理；完成九组件本轮优化收尾。
  [reload_config 报告](docs/reviews/RELOAD_CONFIG_20260929_RESEARCH.md)、[九组件记录](docs/reviews/NINE_COMPONENT_20260928_CLOSEOUT.md)

## 2026-09-28

- httpd 减少 RPC 回复复制和中间 JSON 对象，优化编码及大块写入。
  [httpd 报告](docs/reviews/HTTPD_20260928_RESEARCH.md)
- fw4 直接向输出缓冲格式化规则；rpcd 复用 UCI 模型和载荷，缩小 ACL 扫描范围。
  [fw4 报告](docs/reviews/FW4_20260928_RESEARCH.md)、[rpcd 报告](docs/reviews/RPCD_20260928_RESEARCH.md)
- procd 精确匹配 meminfo 字段；logd 单次解析 syslog 优先级；uci 减少参数与配置复制，按片段输出转义内容。
  [procd 报告](docs/reviews/PROCD_20260928_RESEARCH.md)、[logd 报告](docs/reviews/LOGD_NEXT_RESEARCH.md)、[uci 报告](docs/reviews/UCI_20260928_RESEARCH.md)
- 这些改动完成各自隔离验证，随后纳入 9 月 29 日的九组件固件；各项测量中的局部退步保留在原报告。

## 2026-09-27

- netifd 优化状态查询，复用未变化的无线配置和接口对象类型，减少 sysctl 探测。
  保留 H10 方案并结束本轮研究；事件处理、尾延迟和资源项中的未决结果一并记录。
  [工程结果](docs/reviews/NETIFD_20260927_ENGINEERING_RESULTS.md)

## 2026-09-26

- ubusd 性能研究结束，保留 R136：复用消息存储、减少注册分配与重复查找。
  18 项负载的 daemon CPU 均下降，注册及对象事件仍有 4 项尾延迟退步；当时只做隔离测试。
  [测量结果](docs/reviews/R136_UBUSD_COMPLETION_RESULT.md)、[九组件收尾记录](docs/reviews/NINE_COMPONENT_20260928_CLOSEOUT.md)

## 2026-09-20

- 修复 reload_config、uci 的正式打包输入，以及 UCI 短读丢尾等审计问题；
  候选在路由器隔离验证，生产保持 C。[修复记录](docs/reviews/R95_DEFECT_FIXES.md)

## 2026-09-15

- 九组件 R92 完成异常恢复、协议兼容和日志修复后部署；通过 68 项必需检查、
  四个冷启动和整栈对照。性能结果同时保留相对 C 与历史 Rust R89 的增减。
  [部署与验收](reports/ax3000t-stock-openwrt-25.12.5/R92_REMAINING_BATCHES.md)、[性能报告](reports/ax3000t-stock-openwrt-25.12.5/R92_PERFORMANCE.md)

## 2026-09-12

- 在九组件性能研究中，ubusd 改为处理就绪客户端，httpd 停放空闲连接，rpcd 增加 ACL 匹配快路径。
  [算法复核](reports/ax3000t-stock-openwrt-25.12.5/R87_ALGORITHM_REVIEW.md)
- 完成 R86 九组件实机对照，记录信号唤醒、HTTP 资源耗尽和子进程回收修复后的结果。
  [性能与限制](reports/ax3000t-stock-openwrt-25.12.5/R86_PERFORMANCE_REVIEW.md)

## 2026-09-10

- 修复 R81 全组件审计发现的问题，完成九组件部署和与原版 OpenWrt 的整机、单组件对照。
  [审计修复](reports/ax3000t-stock-openwrt-25.12.5/R83_R81_FIXES.md)、[首轮部署性能报告](reports/ax3000t-stock-openwrt-25.12.5/R84_DEPLOYMENT_BENCHMARK.md)

## 2026-09-09

- procd-rs 接管 PID 1、服务监管、启动与 sysupgrade 移交。
  [接管记录](reports/ax3000t-stock-openwrt-25.12.5/R75_P4_SYSUPGRADE_LIVE.md)
- ubusd-rs 经冷切换接管系统消息总线。[接管记录](reports/ax3000t-stock-openwrt-25.12.5/R76_P5_UBUSD_COLD_SWITCH.md)
- netifd-rs 接管网络管理；修复延迟出现的桥端口和上游 DNS 文件生成后，客户端联网验收通过。
  至此共 9 个组件在设备上运行 Rust 实现。[接管记录](reports/ax3000t-stock-openwrt-25.12.5/R80_P6_NETIFD_LIVE.md)

## 2026-09-02

- reload_config 接管配置变更分发，logd 接管系统日志，httpd 接管 HTTP/HTTPS 与 LuCI 访问。
  [reload_config](reports/ax3000t-stock-openwrt-25.12.5/R05_GO_LIVE.md)、[logd](reports/ax3000t-stock-openwrt-25.12.5/R15_LOGD.md)、[httpd](reports/ax3000t-stock-openwrt-25.12.5/R14_HTTPD.md)
- fw4 接管 firewall4 规则生成，uci 接管配置库与命令行。
  [fw4](reports/ax3000t-stock-openwrt-25.12.5/R09_FW4.md)、[uci](reports/ax3000t-stock-openwrt-25.12.5/R16_UCI.md)
- rpcd 先接管 file/luci 插件，再接管 session/uci/rc 与其余插件对象，停止原 rpcd。
  [插件接管](reports/ax3000t-stock-openwrt-25.12.5/R13_RPCD.md)、[核心接管](reports/ax3000t-stock-openwrt-25.12.5/R17_RPCD_CORE.md)、[完整接管](reports/ax3000t-stock-openwrt-25.12.5/R18_RPCD_PLUGINS.md)

[发布记录](https://github.com/WenliangCao/owrt-control-plane-rs/releases) ·
[组件源码](components/) · [发布与恢复说明](docs/RELEASE.md) ·
[审计及测量报告](docs/reviews/) · [早期报告](reports/ax3000t-stock-openwrt-25.12.5/)
