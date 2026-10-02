# dnsmasq-rs 交付账本

日更：2026-10-02。此文件是唯一维护的进度入口；旧 REPORT、CONTINUATION 和细分报告保留作历史证据，不决定当前工作范围。

## 当前任务：从北极星到可交付替换

用户于 2026-10-02 给出 M1–M7 新交付顺序。当前已完成 **M2**，下一阶段是 M3；M5 与 M6 允许并行，但性能窗口期间暂停其他负载。下列退出条件在各阶段执行前成立；新增细化条件也必须先记录后测量，不能按结果放宽。

| 里程碑 | 退出条件 |
| --- | --- |
| M1 冲刺复核 | 权限/capabilities、PID、动态监听/来源限制、netlink 广播读取、事件锁、ethers 重载完成一次独立审查；确认的问题修复且每个有回归；高风险有负向对照；最终同一源码完成一次完整相关回归，报告 C/Rust 身份。已完成，报告为 [M1_REVIEW_REPORT.md](M1_REVIEW_REPORT.md)。 |
| M2 场景回归 | 在镜像 rootfs 执行精确 musl C，与 Rust 同输入比较：至少20客户端、续租/重绑/释放/DECLINE/到期/冲突与ping、静态/ethers/重启恢复、init reload/SIGHUP/UCI经LuCI或rpcd-rs/odhcpd hosts、上游故障恢复、TCP/AAAA/正负缓存及混合查询；DNS/DHCP解析定向fuzz与畸形语料完成，未解决差异不计通过。 |
| M3 长时与资源 | 同功能混合负载实际连续60分钟，保存RSS/FD/子进程/租约/缓存走势；无未解释的持续增长；磁盘写满与FD耗尽行为对照并恢复，退出后的全部资源回收可核实。趋势与故障判据在运行前定明。 |
| M4 部署候选包 | 在体积测量前设定绝对预算；匹配SDK用opt-level3静态release、strip、panic=abort构建；产生可替换stock变体的APK，正确处理provides/conflicts/init/ujail/ACL/文件归属，在镜像rootfs完成安装、升级、卸载、回滚。报告ELF/APK绝对体积与C差距；超预算不能自行豁免。 |
| M5 完整合同 | 先完成UCI/LuCI可生成的全部option/tags/script-hotplug/leasequery/relay，再完成该变体的TFTP/BOOTP/PXE等剩余能力；每项C差分，参考缺陷有最小复现并单列。全部可用合同零已知功能缺陷，能力索引不能当通过计数。 |
| M6 性能评估 | 使用M4产物，按PERFORMANCE_PROTOCOL预先冻结负载、配置、轮次和收益标准，交错C/Rust完成一次完整评估；记录吞吐/错误/p50/p95/CPU每请求/内存FD峰值/体积及全部失败。无收益写未证明，退步写绝对代价；优化另附机制及正确性/成本证据。M6达标还需满足冻结收益与退步限制。 |
| M7 真机 | 先完成离线runbook、备份、自动回滚、客户端健康检查、约3分钟探测窗口及`.c-orig`恢复命令。物理设备任何操作等待单独明确授权；未经M7不得称生产验收。 |

本轮最多四个子代理，M1按进程权限、DNS/监听并发、DHCP/ethers/netlink、整合回归分工；审查人与前一轮实现者分离。确认问题后按文件归属修复，主代理整合。一次红色结果先原样复跑确认，失败证据保留。普通修复单元+一次受影响C差分；解析器、租约状态机、缓存一致性、权限与资源边界保留独立复核、负向对照和回归集。M1 已完成，报告为 [M1_REVIEW_REPORT.md](M1_REVIEW_REPORT.md)；M2 已完成并转入 M3 计划。

M2 已关闭，剩余阻塞项为 0。DHCP 四组镜像 C/Rust 对照保持零差异（actual20、static-ethers、expiry120、ping-conflict），DNS exact-image C/Rust 的 UDP cache 11/11、expiry 6/6、TCP/cache 10/10、failure/failover 4/4、代表性混合流 1000/1000 均零差异，解析器有界差分也保持零差异。新的 exact-image 生命周期证据在 `private/dnsmasq-rewrite/evidence/M2/integration/c-lifecycle-m2-version-1790948584/` 和 `rust-lifecycle-m2-version-1790948548/`：C SHA-256 `097a9e21…cab87`，Rust 最终 release SHA-256 `8cd25e32…f851`，两边均通过启动、SIGHUP hosts、init reload、rpcd UCI staged/apply、停止回收，以及真实 DHCPv6 Solicit→Advertise→Request→Reply；固定客户端取得 `fd00:2::7ed`，odhcpd 写入 `odhcpd.hosts.lan`，dnsmasq 随后返回相同 AAAA。Rust 已逐字镜像 C 的 Compile time options 行，OpenWrt init 生成的 DHCP range 与 C 一致。M2 详情见 [M2_REPORT.md](M2_REPORT.md)。旧 jail/procfs 红、旧 Rust 启动红和本轮 DHCP runner 的 PID 文件红均原样保留；它们不被算作通过。

M3 正式 60 分钟窗口已启动，运行清单冻结在 oracle ignored `private/m3-formal-1790958418/manifest.json`：exact image `144c1283…0720`、C `097a9e…cab87`、Rust `8cd25e…f851`、20 客户端、seed `29302026`、每秒采样。计划原文仍为 `private/dnsmasq-rewrite/evidence/M3/plan-v1.json`（SHA-256 `c2587d70a2d00e1b6fe698f51607d8df9b0aab4b7e17aa0674c10eac1df8a3af`）。窗口期间不运行其他负载；压力故障门在窗口结束后执行。

DHCP M2 原始输出在 `private/dnsmasq-rewrite/evidence/M2/dhcp`：最终 release `8cd25e32…f851` 的 actual20、static-ethers、expiry120、ping-conflict 四组均完成 C/Rust 对照且零差异；修复后的 runner 记录了超时强制清理和真实 PID 文件移除。旧 release `72f70ae…c09a7` 的历史证据仍保留。DNS/DHCP 解析器有界语料已分别完成 659 和 9,797 个 exact-source cases，零差异；三项目标的 cargo-fuzz 每个运行 1,800 秒，日志在 `private/dnsmasq-rewrite/evidence/M2/fuzz-final-1790955830/`；它们是 parser primitive 证据，不替代 daemon service。

M2 lifecycle 的早期失败记录仍保留：镜像 jail 子进程缺 procfs 时打开 `/proc/self/fd` 失败，旧工具还曾把 ujail wrapper 当作 dnsmasq 身份。本次工具已递归校验 jail 内实际 ELF，并在不改变 exact init 的情况下完成 C/Rust 生命周期和 odhcpd publication；临时 `--jail-procfs` 结果仍不作为通过依据。


新证据统一在 `private/dnsmasq-rewrite/evidence/M2/`，旧证据保留来源，不往工作树内新增证据。实验分支48小时内合入或以`archive/` tag保留后删除；工作树完成后先保全证据再移除。用户`docs/prompts/`的修改保留。本账本按日更新，每里程碑只写一篇报告。

## 北极星起点（历史摘要）

北极星冒烟曾用实际 UCI 配置完成单客户端 DORA、租约文件、DNS 查询和 UBus 注册；它使用旧 debug Rust 与构建机 C，仅作为起点，不替代 M2–M7 验收。完整过程、原始身份和失败记录见 [ACTUAL_CONFIG_STAGE.md](ACTUAL_CONFIG_STAGE.md)。

## 实现与验证状态

四个大块分别由DHCP网络、DHCP tag/option、配置启动生命周期和DNS负责人交付，主代理已整合进main。相对纠偏起点，产品改动集中在实际配置加载、DHCP规则、网络接口、DNS策略和进程生命周期。没有合入原私有反向缓存或TCP快照实现。

联合源码`f099ffb`已通过native和SDK-musl的库405项、main8项及Clippy/fmt；16项ignored不计通过。之后仅解除已由监听层实现的重复guard及修复广播属性读取；最终`3cfd22e`的相关native/musl解析单元、显式隔离内核检查、Clippy/fmt及musl链接通过。复用已有完整回归，没有为最后两处改动重跑无关全套。

最终功能验证使用的原生调试ELF SHA-256为 `1b0d474ef8c147c1d925a6c7461bed07da6d1375c2dde46e6034293017ea0e3c`。原始结果与所有失败在 ignored `private/dnsmasq-rewrite/northstar-dns-20261002/`；其他模块检查路径在阶段报告中。调试产物只供功能验证，不能用于性能收益结论。

## 失败照实保留

原配置最初因PID选项不支持而不能加载。后续保留的产品失败包括PID能力/退出差异、UDP空闲持锁导致TCP超时、残留接口校验、DHCP option28错误；修复后只重跑受影响部分。fixture的编译器路径、无地址客户端UDP接收、启动身份观察race和四resolver计数假设错误也保留，未当成产品成功或删除。报文和租约等原始数据不进Git。

## 分支已经清理

2026-10-01已归档反向缓存`0eaaef8`和TCP流式导入`dff7a39`，旧分支清除，未合入产品。2026-10-02本轮已完成tag和DHCP网络分支也已清除；当前只保留main，工作树和证据未删除。

| 成果 | 持久引用 |
| --- | --- |
| 反向缓存及中断的未资格化CNAME草稿 | `evidence/20261001/dnsmasq-reverse-cache-retired` |
| TCP流式导入参考 | `evidence/20261001/dnsmasq-tcp-stream-import-retired` |
| 反向缓存工具 | `evidence/20261001/dnsmasq-reverse-cache-gate-retired` |
| 本轮tag/option | `evidence/20261002/dnsmasq-dhcp-tags-options` |
| 本轮DHCP网络/广播修复 | `evidence/20261002/dnsmasq-dhcp-network-actual-config` |
| 本轮DNS与E2E工具 | `evidence/20261002/dnsmasq-actual-config-dns` |
| 本轮启动/监听 | `evidence/20261002/dnsmasq-actual-config-startup` |

用户的`docs/prompts/`修改保持原样；当前工作以本账本开头的M1–M7顺序和验证规则为准。

## 尚未交付的范围

实际配置未启用relay/PXE或自定义DHCP option，因此这些能力没有被本次闭环资格化，也没有被从完整重写目标中删除。完整TCP缓存、其他DNS/DHCP/TFTP能力、resolver动态更新、长期运行和OpenWrt全生命周期仍是后续范围。

性能筛选未重启。下一次性能工作须沿冻结协议执行一次，在所测场景功能前置条件成立后开始；不重开旧快照筛选、不挑快窗口或豁免退步。旧SDK阶段包仍是405b7c1，不是本次源码的可替换包。物理设备部署、修改和真机测量仍需另行授权及恢复门。
