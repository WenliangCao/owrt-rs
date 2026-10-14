# inotify 修复候选：同 ELF 九组件验收补充

2026-10-14，`340ed73e83e58ba845e0a645eb21e9ead0d0f108` 的 ELF `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d`（2,089,440 B）**新增执行 Rust stack23 23/23、helper5 5/5，全部通过**。[派生收据](integrated-stack-inotify-review.json) 包含实际运行身份、每项结果、C 对照来源及原始 hash。

本轮只新增 28 个 Rust 检查。C 对照复用刚完成的[前轮相同 fixture 运行](integrated-stack-review.md)，未重跑 C，未把合计写成新增 56 项；前轮 `19bd6162` 的结果及报告保持原状。新 ELF 已独立复制到审计目录，复制前后、实际运行和收尾 SHA 一致；本专项没有重新构建候选。

与 `19bd6162` 的 Git 差异仅为 dnsmasq 的 `hosts.rs`、`main.rs`、`tests/hosts_allocations.rs`；九组件及共享 ubus 源码无变化。再次核对其 175 个文件与原 Oracle 构建树完全相同、9 个支撑 ELF 与原清单一致。458 个支撑工具文件及两个驱动与前轮 hash 全相同。驱动通过环境参数记录新候选归属并强制核对 ELF，没有沿用旧候选硬编码。

| 本轮路径 | 结果 |
| --- | --- |
| init/procd、uci/reload-config、rpcd apply、httpd/LuCI、fw4、netifd resolver 切换、odhcpd→AAAA | 全通过，配置不变 reload 保持实际 PID，SIGKILL 后服务和客户端恢复 |
| 初始、fw4 加载、apply、respawn 后客户端 | 独立 veth DHCP OFFER/ACK 和 UDP/TCP DNS 全通过 |
| 原装 dhcp-script → ubus → Rust procd hotplug | 通过；hotplug 行与 ACK 事件同 C 对照 |
| 身份与接口 | 9 个安装 ELF、6 个常驻支撑进程的实际 ELF 均匹配前轮；dnsmasq LuCI capability 和 metrics 字段名同 C |
| ubusd 重启 | 共同 F5 边界仍在：DNS 正常但管理对象消失；显式 init restart 后两个对象恢复 |

这是新 ELF 的正常九组件集成验收，inotify 低内存发布正确性由对应专项另判；没有把前轮 TCP、trial 或性能结果改签为本轮新执行。此次没有重跑 trial，没有 APK/固件构建、物理路由器操作或真实无线客户端验收。

全部新运行退出 0，收尾没有本任务所属进程或宿主可见挂载残留，原候选、审计副本及九组件 hash 不变。Oracle 原始目录为 `/dev/shm/full-audit-resume-20261014/stack-inotify/`；本地为 `private/full-audit-20261014/resume/stack/inotify/`。最终私有归档 `verified-evidence.tar.gz` SHA-256：`221be7e845a98c5b953582d8fb681f98ffa5f6590568b9fc379a45025544674a`。
