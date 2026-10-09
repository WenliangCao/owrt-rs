# 正式 r3 产物离线验收与构建机基准

2026-10-09。正式 `release-image` run `37902724239`，源码 `d72928c9a7d9ed28a9aa2c8d749d31e2a9ed6d33`。26 项 SHA-256 在本地和 Oracle 均通过；九个候选程序和九个 C 原件逐一匹配清单。没有访问或修改物理路由器。

有效批次于 `08:14:43.651044Z` 检查无 `cpu-a-79e`，每个子门再次检查；`08:27:09.811512Z` 完成。9 个顶层功能/集成门首轮通过，32 轮基准均完成且内容校验首轮通过。原始取证已传回 Mac；后续汇总没有启动 Oracle 计算。

| 内容验收 | 结果 |
|---|---|
| fw4 / uci 断管道及信号条件 | 37 场景 × 6 条件 × 4 轮，888 行通过；保留原始退出状态与字节 |
| 其他一次性诊断 | 15 场景 × 6 条件 × 4 轮，360 行通过；正常内容对照正式 r2，Rust 专有选项不声称 C 文本等价 |
| 正常 CLI | fw4 上游 31 案例、defaults 12 案例；UCI 193 步字节/文件状态相同；reload 11 参考 + 17 故障案例 |
| IPv6 协议 | r56 实际 DHCPv6 交互、r62 PD 生命周期通过；r56 的 updated/ifupdate 由下述回放另行覆盖 |
| 捕获的 WAN6 输入 | 13 输入、每侧 14 快照，DAD 开启；内核状态、状态回复和 hotplug 比较均相同 |
| 无新通知的 PD 自然到期 | C / Rust source rule 都是 `0 → 1 → 0`；三份完整快照、回复与 hotplug 相同 |
| 原生镜像 | 配置迁移、后续升级、坏/挂载恢复拒绝、九项 C 幂等恢复、两类真实 APK 重装全部通过 |
| 原生启动 | PID1/五 daemon 身份、标准路径、LAN/WAN、HTTP/HTTPS 内容、日志、UCI/reload、fw4 对照与 nft check、namespace reboot 全部通过 |

基准采用 `C, Rust, Rust, C, Rust, C, C, Rust`，每侧四轮。32 轮对应 120 项负载记录、433,600 次成功测量；离线再次核验所有样本数、零错误、程序/客户端身份、reload 的完整 MD5/event 载荷，以及 netifd 的 2/32 接口集合、热插拔完成和无变化 reload 前后状态。

下表是四轮均值的中位数，单位 µs；仅表示同一 aarch64 Linux 构建机的 C / Rust 对照。没有本轮 r2 性能基线，也没有路由器性能数据，因此不能用它声称热修前后无回退。

| 负载 | C µs | Rust µs | Rust 相对 C |
|---|---:|---:|---:|
| fw4/print | 20103.81 | 993.97 | -95.1% |
| fw4/check | 32069.50 | 11991.64 | -62.6% |
| uci/export_network | 577.45 | 301.23 | -47.8% |
| uci/export_64 | 843.77 | 482.08 | -42.9% |
| uci/set_commit_get | 2847.12 | 2108.76 | -25.9% |
| reload-config/first_baseline | 6488.92 | 779.16 | -88.0% |
| reload-config/unchanged_config | 7861.58 | 808.29 | -89.7% |
| reload-config/single_change | 9632.00 | 1121.09 | -88.4% |
| reload-config/multi_change | 13294.17 | 1246.50 | -90.6% |
| reload-config/comment_only | 7894.92 | 804.64 | -89.8% |
| netifd/interface_dump | 45.63 | 38.56 | -15.5% |
| netifd/lan_status | 41.89 | 36.48 | -12.9% |
| netifd/device_status | 138.19 | 71.07 | -48.6% |
| netifd/wireless_status | 46.84 | 33.30 | -28.9% |
| netifd/reload_unchanged | 762.79 | 941.98 | +23.5% |

14/15 项负载的 Rust 中位数低于 C；`netifd/reload_unchanged` 高 23.5%，保留为明确限制，不把差值归因于本轮修复。

第一次 driver 准备误用了含 `/dev/console` 字符节点的镜像目录，Python 文件复制在被测 CLI exec 前阻塞；只终止自身两个进程后，换用九个原件哈希相同、无特殊节点的既有 `rootfs-files`。该准备失败保留，不算组件红/绿，也没有因此重复构建。

[脱敏正式验收记录](HEALTH_20261008_FORMAL_VALIDATION.json)包含 source/C 身份、全部门结果与 CPU 时间；[完整基准数据](HEALTH_20261008_BENCHMARKS.json)保留逐轮样本哈希、范围及中位数。物理无线、闪存、断电和部署恢复门仍需另行验收，本批没有部署。
