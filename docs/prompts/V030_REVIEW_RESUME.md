接手一轮被中断的 v0.3.0 独立审查。前一个会话因为流式输出中断而停止，你从磁盘上的状态继续，不重做已完成的部分。

先读这三份 prompt，它们是完整的规则和要求，照做：

1. `docs/prompts/V030_INDEPENDENT_REVIEW.md`：原始审查要求和硬性约束（Mac 不编译 Rust、路由器只读、不 push、每个问题一个 commit、先复现再下结论）。
2. `docs/prompts/V030_REVIEW_DEEPEN.md`：第二阶段的系统覆盖要求（覆盖账本、每文件检查清单、全仓机械扫描、到 07:00 前不收尾）。
3. 本文件：中断时的现场和接手顺序。

## 中断时的现场（2026-10-19 00:37 核对）

- **修复分支** `review/v030-independent`，工作树在 `private/review-v030/checkout`。基于 `v0.3.0`（6fb236a3），已有 8 个 commit：F01–F06 的修复（procd ×2、netifd、odhcpd、rpcd ×2）和两个补强测试。全部只在 Oracle 验证过，没有部署。
- **未提交的改动**（在该工作树里）：
  - `components/odhcpd/src/leases.rs`、`components/odhcpd/src/main.rs`，新文件 `components/odhcpd/tests/trigger_lifecycle.rs`。这看起来是 leasetrigger 子进程生命周期/数量上限的修复，还没提交，也不知道验证到哪一步。先读懂 diff，再在 Oracle 上完成先红后绿，然后单独提交；如果做不到，就把 diff 保存到证据目录，并从工作树撤掉。
  - `docs/reviews/V030_INDEPENDENT_REVIEW.md`：主报告草稿，第一阶段内容已完整。最后再更新，不要重写已核实的部分。
- **证据目录** `private/review-v030/independent-2101-evidence/`（下文称 E）：
  - `E/COVERAGE.md`：总账本骨架，已列出全部文件，绝大多数仍是“未读”。
  - `E/coverage-parts/`：分组件账本。`odhcpd.md` 已精读 9 个文件，`dhcpv6.rs` 正在补逐函数 C 对照；`dnsmasq.md`（171 个文件）和 `dnsmasq-packaging.md`（12 个文件）全部未读。
  - `E/SCAN.tsv`：全仓机械扫描结果，共 11,108 个命中，尚未分类；`E/files.json` 是文件索引。
  - `E/EXPERIMENTS.md`：实验账本；`E/oracle/`：Oracle 原始运行结果。
- **DNS/DHCP 子审查**的交付在 `private/review-v030/dns-dhcp-2101/HANDOFF.md`，第一阶段已完成，不要重做。
- Oracle 工作目录：`/home/ubuntu/review-v030-root-2101/`、`/home/ubuntu/review-v030-dns-dhcp-2101/`。

## 接手顺序

1. 核对上面的现场是否属实：`git -C private/review-v030/checkout status`、`git log v0.3.0..review/v030-independent`，确认没有其他会话还在写这个工作树。
2. 处理未提交的 odhcpd 改动（见上）。
3. 补完 odhcpd 账本，然后按以下顺序推进其余组件：procd → ubusd → ubus → netifd → rpcd → uci → reload-config → fw4 → httpd → logd → platform → dnsmasq（核心模块）→ 打包。每完成一个组件就更新分组件账本和 `E/COVERAGE.md`。
4. `SCAN.tsv` 的分类按组件和组件阅读同步做，不要最后一次性处理。测试、fuzz、诊断 probe 文件里的命中可以整批标记，但要写明依据。

## 防止再次中断

- 上下文要小：每个组件交给一个子代理（同时最多两个，组件不重叠），子代理只把结论写进对应的 `coverage-parts/<组件>.md`，主会话只读它们的摘要，不把整份源码或大日志读进自己的上下文。
- 每完成一个组件就把进度写进磁盘，并在 `E/RESUME_STATE.md` 追加一行：时间、刚完成什么、下一步做什么。这样再中断，下一个会话也能直接接上。
- 大输出（扫描结果、测试日志）只写文件，主会话用 `head`/`grep` 看摘要。

## 收尾

06:15 停止新阅读，按原 prompt 做全套测试、独立复核，再更新主报告：加入覆盖表、P2/P3 表、具体到文件名的“未覆盖”清单，然后提交报告。仍然不 push、不部署。
