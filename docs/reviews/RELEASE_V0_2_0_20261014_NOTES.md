# v0.2.0 · OpenWrt 25.12.5 · 小米 AX3000T

**[v0.2.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.2.0) 已于 2026-10-14 21:12:07 UTC 发布为 prerelease、非 Latest，真机刷写与验收尚未执行。** Latest 仍为 v0.1.1。只有发布的同一镜像完成保留配置刷写、正常重启、用户手动断电重启及部署后日常采集，才转为正式 Latest。本文不能作为这些步骤已完成的证据。

## 本次变化

- 新增 **dnsmasq-rs**，与 procd、ubusd、netifd、rpcd、logd、uci、reload-config、fw4、httpd 组成十组件集成镜像。统一 APK 为 **`owrt-control-plane 0.2.0-r1`**，部署布局为 `native-ten`。
- dnsmasq 标准路径 `/usr/sbin/dnsmasq` 与已验收 init、ubus ACL 成套安装，保留原网络/Wi-Fi/DHCP 配置及成熟执行面。恢复集合扩大为十个 C 程序和 dnsmasq 原 init/ACL，共十二项。
- 原九组件各自源码相对 v0.1.1 未改变；共享 `components/ubus` 包含 dnsmasq 所需的字节对象名、通知 DATA/截止时间及有界待处理队列等已记录更新。最终 CI 产物中，**ubusd、uci 与 v0.1.1 逐字节相同；fw4、httpd、logd、netifd、procd、reload-config、rpcd 七个 ELF 不同**。七者均使用共享 ubus；这是已记录的输入变化，不是每个字节差异的完整因果证明。
- 保持 OpenWrt 25.12.5、AX3000T 固定官方 rootfs、内核、驱动、无线 handler、odhcpd、DHCP 客户端、dropbear、BusyBox、LuCI 和 sysupgrade；四个中文包沿用匹配 LuCI 修订。旧迁移 marker `native-nine-v1` 保留，防止升级时重跑首次迁移覆盖用户服务启停选择。

## dnsmasq 真机性能要点

[完整性能报告](https://github.com/WenliangCao/owrt-control-plane-rs/blob/ded73bae75f44269c93366593481d866a2e68e35/docs/dnsmasq/PERF_DEVICE_20261014.md)来自同一台 AX3000T 上的隔离实例、交错多轮测量；参考 Rust SDK ELF 为 `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c`。最终 CI 实际 dnsmasq 与已完成有限离线门的 canonical 发布参考均为 `8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7`；它与 `50e…` 不是相同 ELF，历史性能数值不转移到 `8472…`，也不是最大吞吐容量测试。

| 场景 | Rust 相对精确镜像 C dnsmasq 2.93 |
|---|---|
| UDP 缓存命中 | p50 多 0.058 ms；服务 CPU/查询多 70.0% |
| UDP 80% 命中混合 | p50 多 0.057 ms；CPU 多 46.5% |
| UDP 未命中有效稳态子集 | p50 多 0.072 ms；CPU 多 30.3%，保留下述无效窗口 |
| TCP 未命中 | p50 少 0.212 ms（−11.1%）；CPU 少 24.6% |
| 6 客户端 DHCPv4 续租 | p50 少 0.154 ms（−28.3%）；组合 CPU 少 12.9% |
| 配置停启 / 1000-host HUP 新代可见 | p50 分别多 1.883 ms / 少 5.633 ms（−24.7%） |
| 资源 | 常见场景主进程 RSS 多约 1–1.5 MiB；TCP 未命中多约 2.25 MiB；TCP 整树 FD 较少 |

TCP 命中延迟/CPU、各 DNS p95 等差异未超过波动，不能判快慢。“UDP CPU 多 70%”不等于日常上网慢 70%；常见绝对延迟差较小，用户已接受当前性能。RSS 不是私有物理内存，C 父子共享页在树 RSS 中可能重复计算。

两处未定位的尾部仍需观察：

1. UDP 未命中原第五轮 Rust 计划 4000、实际发出并正确答复 3996，漏发 4 次；最大 174.267 ms。存在工具调度/等待相关迹象，但没有确认根因，不能免责或归因 Rust。所有已发查询无错误/超时；同场景 C 最大 94.789 ms。稳态表按预先登记规则排除该轮两侧并纳入唯一补充对，原失败仍保留。
2. 6 客户端首次 DORA 的 Rust 最大 19.795 ms，C 最大 2.496 ms；样本少且原因未定位，不能宣称 DHCP 所有阶段均更快。

这些测量没有替换生产服务，期间健康检查正常。此次刷前/刷后各 600 秒采集只描述各时段的真实日常 CPU、内存、FD 等占用；不同日常请求量和缓存年龄使它不能用来判定性能输赢。

## 发布资产与身份

| 项目 | 本次状态 |
|---|---|
| Git 标签 / Release | `v0.2.0`；初始 prerelease、非 Latest；标签固定指向以下构建提交 |
| 实际构建提交 / Actions run | `ded73bae75f44269c93366593481d866a2e68e35` / [38636115402](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/38636115402)，成功 |
| 镜像文件 | `openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin` |
| 镜像大小 / SHA256 | 13,639,968 B / `2f8083e44a548802de1738ecd8ef5231f74fda950a0a69a44f0e10e2e1d30ffd` |
| 统一 APK | `owrt-control-plane 0.2.0-r1`；SHA256 `3aee6b9a40ea75f428413abc02dfce9a6d0e661bf2a82adad342c96efef581ae` |
| dnsmasq 产品输入 | 已验收产品基础，加 `5c1a2f48` 的纯测试生命周期修正；179 输入 digest `10f7c0b1ae1e5e4459a4937d3a9049b9e708ffe9d8040b6144da093ac50d9ed0` 由构建工具强制核验 |
| 最终 CI dnsmasq ELF | 2,124,571 B / `8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7` |
| dnsmasq init / ACL SHA256 | `70fb3c6bd057c6981503138b91292182f07c9a0d5aa1aaf0454c34af4ca746f0` / `8bedbcdd3018c17f272f0d3ecf9573aa6f05253806cb8812ebf92e9b87ac6020` |
| 另外九个组件 | 最终 CI 已核对：ubusd/uci 与 v0.1.1 相同，其余七个 ELF 不同；各自源码目录与 v0.1.1 相同，共享 ubus 更新如上 |
| 附件（13 个） | CI 原名 sysupgrade 镜像、统一 APK、四中文 APK、`manifest.json`、`build-inputs.json`、`binary-sha256.txt`、`dnsmasq-build-manifest.json`、`CI-SHA256SUMS`、`RELEASE_NOTES.md`、外层 `SHA256SUMS` |

本次先以 `workflow_dispatch` 完成正式 CI 构建并核对既有有限离线证据，再把同一批 CI 字节发布为 `v0.2.0` prerelease。标签指向实际构建提交；推送标签时曾短暂关闭并恢复发布 workflow，恢复后延迟触发的 [tag run 38638003434](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/38638003434)已取消，其正式整合、artifact 上传及 Release 创建均跳过，发布仍只使用 run `38636115402` 的已核验产物。公开镜像不会包含用户配置、密码、备份或采集数据。部署使用的字节必须与已发布镜像一致；后续仅补文档与晋升同一 Release，不重建、不替换镜像、不移动标签。

对应构建提交的[完整 host CI 38636080350](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/38636080350)已成功；原 ubus 测试失败与 namespace 运行环境修正记录保留。最终 image run 的原始 `SHA256SUMS` 共 35 项全部核验通过；它以 `CI-SHA256SUMS` 原样保留，其中构建日志仍在 Actions artifact，外层 `SHA256SUMS` 则覆盖本 Release 的其余 12 个附件。最终十个 ELF、dnsmasq init/ACL、stock 恢复清单及内核身份与已完成有限离线门的 `21e14a95` 候选相同；源码提交、整镜像及 APK 身份独立记录，不声称重新执行过最终整镜像的 Oracle 验证。

GitHub 将四个 LuCI 中文 APK 附件名中的 `26.180.75667~128a781` 自动改为 `26.180.75667.128a781`，下载字节与 CI 原件一致。外层 `SHA256SUMS` 使用公开附件名；`CI-SHA256SUMS` 和 canonical 清单保持原始 `~` 文件名与内容，比较时按这一名称映射核对，APK 内部版本不变。

## 部署与恢复（尚待执行）

本次经用户授权，从现役 v0.1.1 保留配置升级。刷前保存当次离线配置备份及已核验 v0.1.1 原镜像；候选上传路由器后核对哈希、完成 sysupgrade 预检，确认手动回滚材料可用，再等待用户确认断网窗口。用户本次选择手动恢复 v0.1.1，不安装自动回退守卫，不追加 Oracle 模拟或新验证；已完成的测试仅保留为历史证据。正常重启与手工断电重启都属于本次合格条件。

| 验收项 | 状态 |
|---|---|
| 当次备份、v0.1.1 手动回滚材料 | 新鲜备份 46 个成员、45 个现场文件全部匹配；v0.1.1 镜像已重新核验 SHA256，不安装守卫 |
| C 日常采集：600 秒 / 5 秒 | 已完成 121 样本，20 组 / 100 项低频健康全部成功；详见[部署记录](https://github.com/WenliangCao/owrt-control-plane-rs/blob/main/docs/reviews/DEPLOYMENT_V0_2_0_20261014.md) |
| 镜像暂存与刷前预检 | 21:13:35 UTC 已核验路由器上的公开镜像与新鲜备份 SHA256、设备型号，携带该备份的 `sysupgrade -T -f` 返回 0；尚未刷写或重启，仍须等待用户确认断网 |
| 同一发布镜像保留配置刷写 | 未执行 |
| 配置、十组件、DNS/DHCP、Wi-Fi、IPv4/IPv6、LuCI、WAN | 未执行新镜像验收 |
| 正常重启 | 未执行 |
| 用户物理断电重启 | 未执行，必须等待真实回复 |
| Rust 日常采集：相同 600 秒 / 5 秒 | 未执行 |
| 上传/采集材料清理、最终状态与部署报告 | 未完成；无自动守卫安装计划 |
| 转正 Latest | 未进行；仅全部通过后晋升同一 Release |

不能正常上网、客户端拿不到地址或管理不可达时，按已核验的手动方案刷回 v0.1.1 并记录原因，不转正；管理不可达时按救援手册进入 failsafe/TFTP。镜像内 `owrt-recover-c` 可成套恢复精确官方 C 程序及 dnsmasq init/ACL，但它与回到 v0.1.1 九组件固件不同；版本回滚使用已保存的 v0.1.1 镜像及当次配置备份。

上线后继续观察自然续租、新设备入网、DNS TCP 与 IPv6 访问、长期进程稳定性/资源趋势，以及上面两处未解释尾部是否真实重现。此次验收不保证没有未知问题，也不把短期正常当作长期稳定结论。
