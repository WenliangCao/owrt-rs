# dnsmasq-rs 交付账本

日更：2026-10-03。本文件是唯一进度入口；每个里程碑只保留一篇报告，原始失败与产物留在 ignored/private。当前 **M4 已完成**，采用用户明确接受的方案 A；尚未完成 M5/M6，未经 M7 不能称生产验收。

## 当前状态与退出条件

| 里程碑 | 退出条件与状态 |
| --- | --- |
| M1 冲刺复核 | 权限、PID、监听来源、netlink、锁和 ethers 独立审查；问题有修复和回归，高风险有负向对照。已关闭，见 [M1_REVIEW_REPORT.md](M1_REVIEW_REPORT.md)。 |
| M2 使用场景 | 镜像 musl C 对照：20 客户端租约全流程、静态/ethers/重启、reload/UCI/odhcpd、DNS 故障恢复与 TCP/cache；三入口各 30 分钟 fuzz。已关闭，历史身份与失败见 [M2_REPORT.md](M2_REPORT.md)。旧 all-servers 夹具实际启用了 strict-order，该项由 M4 的修正工具和真正 all-servers 对照补齐。 |
| M3 长时与资源 | 混合负载实际 60 分钟，比较计数、资源走势和退出回收；ENOSPC/EMFILE 对照。已按用户修订范围收尾，见 [M3_REPORT.md](M3_REPORT.md)。到期等功能引用 M2，不强塞进 12 小时租期的长跑。旧缓存计数不能作为 live occupancy，M4 已完成双方填满后的实测，见 [M4_REPORT.md](M4_REPORT.md)。 |
| M4 可替换包 | 单线程功能和资源验证；最终源码/ELF 对应；稳定工具链 opt-level 3、static、strip、panic=abort；最终 APK 真实安装、升级、卸载、回滚。原 ELF 目标 1,000,000 字节未达成；用户已明确接受方案 A 的 1,159,280 字节，其他超标不能自行豁免。见 [M4_REPORT.md](M4_REPORT.md)。 |
| M5 完整合同 | 先覆盖 UCI/LuCI 的全部 option、tags、script/hotplug、leasequery、relay，再补 TFTP/BOOTP/PXE 等编译能力；每项 C 差分，原版缺陷单列最小复现。尚未完成。 |
| M6 性能 | 在 M4 产物上按冻结协议测缓存命中/未命中/混合/失败/TCP/DHCP/reload；报告吞吐、错误、延迟、CPU、RSS/FD 和体积，无收益写未证明。尚未启动正式性能窗口。 |
| M7 真机 | 离线 runbook、备份、自动回滚、客户端检查和约三分钟窗口；用户另行明确授权才操作物理路由器。未经 M7 不称生产验收。 |

M4 的单 poll owner 已替换六线程接线，决定见 [ADR_THREAD_MODEL.md](ADR_THREAD_MODEL.md)。非阻塞 TCP 上游和 ICMP 等待期间的 DNS/TFTP 服务、原始 DHCP interface/listen-address 并集已修复。最终产品 commit 为 `4b3fc62cea8b4d3897c3a9bca082964812e82ffc`；release ELF 为 `faa55065…24577`，全部 110 份构建归档输入与 commit 逐字匹配。该 ELF 的 DHCP 四组、DNS 七组、生命周期、TCP 停滞、ICMP/TFTP、真实 fast-retry 以及 ENOSPC/EMFILE 对镜像 C 通过；库 439 项和 main 10 项 Linux musl 单元通过，17 项 ignored 不算通过。

体积先做归因，再按用户要求保持 opt-level 3：关闭可选 unwind tables、共享启动排序和减少重复格式化。ELF 从 1,220,720 降至 1,159,280 字节，是 C 的 269,305 字节的 4.305 倍（多 330.5%），比原目标多 159,280 字节，用户随后明确接受该方案 A。format 的文件大小收益为零，共享读取器试验反而增大 24,576 字节，未采用。1.5 MB 旧预算作废；s/z 结果保留但不作为交付选项，没有引入 nightly 或 build-std。详细步骤和代价见 M4 报告。

资源结论不再以“缓存填充”单独解释 Rust RSS 增长。C 确实在启动时预分配 cache-size 个记录；Rust 也预分配槽位，但另有名称、数据和索引分配。新的满缓存测量已完成：双方各 4,096 个可证明命中的动态 A 记录，实际 300 秒试跑后实际 600 秒正式窗口；窗口期间没有其他构建或测试。正式满载 RSS 为 C 1,652、Rust 2,676 KiB，差 1,024 KiB（62.0%），后半段无增长且清理通过。每条记录附加内存成本明显更高，已列入 M6 优化项。最终 APK 为 633,984 字节（stock 的 4.087 倍）；真实升级、重装、卸载、全新安装、移除后回滚、直接降级及两种变体互斥均通过，包内仍是 FAA ELF。升级/重装/降级明确使用 init restart 激活，原版脚本的 start 不冒称自动重启。M4 已关闭；opt-level s 的 CPU 代价留到 M6 测量后决定。

## 验证与编排规则

参考永远是精确 C，期望不能由 Rust 生成。普通修复用单元加受影响 C 差分；解析器、租约、缓存、权限与资源边界保留独立复核、负向对照和回归。红色结果先复跑确认，未执行不算通过，原始失败保留。任何正式资源窗口先试跑，C/Rust 双 namespace 并行绑不同核；性能窗口不跑其他负载。

最多四个子代理，各自有明确文件所有权。证据按里程碑统一放在 `private/dnsmasq-rewrite/evidence/`；实验分支 48 小时内合入或归档后删除。当前本地仅 main 分支，旧 detached worktree 中有 ignored 证据和未提交内容，未为清理而丢弃。用户在 `docs/prompts/` 的改动保持原样。物理路由器没有操作授权，也没有执行操作。

## 北极星起点（历史摘要）

北极星曾用实际 UCI 配置完成单客户端 DORA、租约文件、DNS 查询和 UBus 注册；当时使用旧 debug Rust 与构建机 C，仅作为起点，不替代 M2–M7 验收。原始过程、二进制身份、启动/监听/锁/广播等失败与修复见 [ACTUAL_CONFIG_STAGE.md](ACTUAL_CONFIG_STAGE.md)。反向缓存 `0eaaef8` 和 TCP 流式导入 `dff7a39` 已于 2026-10-01 退休，未合入产品；后续已完成任务分支也已清理，成果由 `evidence/20261001/dnsmasq-*-retired` 与 `evidence/20261002/dnsmasq-*` 持久引用保留，旧原始证据未删除。
