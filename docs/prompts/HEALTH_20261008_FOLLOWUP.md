# 2026-10-08 体检问题跟进：九组件 r2 是否需要修复与重发

## 背景

2026-10-08 对生产路由器（AX3000T，OpenWrt 25.12.5）做了只读体检，报告与证据：

- `/Users/USER/Documents/OpenWRT/diagnostics/2026-10-08/health-report.md`
- 同目录 `summary.json`、`wan6-observation.json`、`evidence-manifest.json`、`raw/`（含 90 份转储、日志、ubus 监视记录；不进 Git）

线上部署：`owrt-control-plane 0.1.0-r2`，布局 `native-nine`，源提交 `a4053dd5`（2026-09-29）。
`main` 比它多约 1800 个提交，但 `components/` 下除 dnsmasq 外只改了 `components/ubus/src/{conn,sys}.rs`。
dnsmasq 未上设备。

体检报告是 GPT 写的，先把它当线索，不当结论：每条判断都要自己复现后再采信，不成立的写明不成立。

## 任务

逐条判定下列问题属于哪一类：**我们的缺陷 / 原版行为 / 上游网络 / 证据不足**。只有“我们的缺陷”才修。

### 1. fw4 查询模式遇到断管道时 abort（已在源码确认）

- `components/fw4/src/main.rs:245` 等处用 `println!`，`Cargo.toml` 设置 `panic = "abort"`；stdout 写失败时 panic 并 SIGABRT，`/tmp` 里因此积累了 90 份转储。
- 注意：`components/procd/src/proc.rs:117` 起按 C `procd_signal()` 让子进程继承“忽略 SIGPIPE”，所以 odhcp6c → `dhcpv6.script` → `fw3 -q network` 整条链都忽略 SIGPIPE。shell 的 `cat: write error: Broken pipe` 就是这个继承造成的，属于原版行为，不是我们的缺陷。
- Oracle：在相同条件下（SIGPIPE 忽略、读端提前关闭）运行 `/rom` 里的原版 fw4，记录它的 stdout、stderr 和退出码，Rust fw4 必须一致。再在 SIGPIPE 为默认处理的条件下对照一次。
- 盘点九个组件里所有一次性 CLI 的输出路径（fw4 全部模式、uci、reload_config，以及其他可能被 shell 管道调用的命令），找出同类问题，修法保持一致。不要引入新的输出抽象。
- 补一个定向回归测试：调用者在写出之前关闭 stdout。
- 顺带查清读端为什么提前退出：按匹配版本的 odhcp6c 源码（`script.c`）核实，新事件到来时它是否会终止或放弃上一次脚本。这一项只需解释，不修 odhcp6c。

### 2. WAN6 每分钟约 4 次地址更新，公网地址被撤回又补回

- 体检显示 13 次 `notify_proto` 输入中有 5 次本身就不含 WAN 公网地址，说明输入来自原版 odhcp6c/脚本。
- 已有证据：2026-09-29 整栈试验（`docs/reviews/STACK_20260929_*`，原始数据在 `private/stack-20260929`）中，C2 窗口失败的原因就是 WAN IPv6 RA 抖动。先用原始数据核实“全 C 栈下也有抖动”这一点；如果成立，主因倾向上游。
- 必须排除的反馈回路：netifd-rs 撤回或添加地址、设置 sysctl（accept_ra、地址 flags、路由）时，内核侧效果是否和 C netifd 不同，并进一步影响 odhcp6c 的下一次输入。做法是用 `raw/` 里捕获的输入序列，在 netns 中运行 C netifd oracle 回放，与 Rust 比较内核侧状态（见既有 netifd oracle 方法）。
- 同一份试验评审中还有一项未关闭：netifd-rs 的 lan `ipv6-prefix-assignment` 是 ULA 优先，C 是 PD 优先（`interface-ip.c` 中 `list_add` 头插），导致 `network_get_ipaddr6 lan` 返回 ULA。先确认 `a4053dd5` 里是否已修；未修就纳入本轮。
- 不得通过屏蔽 ifupdate 或去重来掩盖问题。

### 3. 其余项只做判定，不修

- `/tmp` 转储积累：根源是问题 1，修好根源即可，不新增轮转机制。
- 上游 IPv4 TCP/53 超时、60 秒 DHCP 租期、2.4 GHz 某终端 TX failed、启动时 mt7530 探测超时：判断是否与九组件有关，无关的写一句结论即可。
- 日志保存窗口太短：只给出建议，不改设备配置。

## 修复与发布约束

- 热修复分支基于 `a4053dd5`，**不要**基于 `main`，也不带入 dnsmasq 或 `ubus/conn.rs` 的改动，除非某个修复确实依赖它们，并且要说明理由。
- 每个修复都要有 C oracle 对照证据和回归测试；构建、测试、基准一次性在 oracle 主机或路由器上批量完成，macOS 上的 `cargo test` 最多算冒烟检查。
- 红色的差分测试要重跑 3–4 次再采信；绿色的要确认真的比较了内容。
- 候选版本 r3 由 CI `release-image` 工作流产出，记录每个组件的 SHA-256，并给出与 r2 的逐组件差异。
- 每完成一项就提交一次；按路径暂存，提交前查看 `git log`，因为有其他会话在并发提交。

## 设备边界

- 允许：通过 SSH 在路由器上执行**只读**观察（logread、ubus call/monitor、读取 /proc 和 /sys、复制转储），每个观察窗口约 3 分钟，长时间任务要以 detached 方式运行。
- 禁止：安装软件、修改配置、重启服务、清理转储、部署或刷写。r3 上线需要我另行明确批准，并且要先通过恢复门（离线备份、产物身份、自动回滚、客户端健康检查）。

## 交付

提交 `docs/reviews/HEALTH_20261008_FOLLOWUP.md`，内容包括：

1. 每个问题的分类、复现证据、根因；不成立的报告条目要单独列出。
2. 每个修复对应的提交、测试和 oracle 对照结果。
3. r3 候选的 SHA-256 清单、与 r2 的差异，以及“是否值得重发”的 go/no-go 结论和理由。
4. 若结论是 go：给出部署计划和恢复门清单，但不执行。
