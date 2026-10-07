# M6b TCP Scheme A 门禁记录

日期：2026-10-07。分支：`m6b/tcp-scheme-a`。本文只记录方案 A 的本地门禁和待在新 Oracle ELF 上执行的门禁；不引用 UDP-only 候选或其性能结果。方案实现为 `ca63c365`，COW 原语测试为 `90ce2c22`，primitive harness 适配为 `454ab2e9`。

## 本地可复核结果

| 门 | 命令/证据 | 结果 |
|---|---|---|
| 构建 | `cargo check --manifest-path components/dnsmasq/Cargo.toml --lib` | 通过；仅保留基线 unused/dead-code warnings。 |
| COW 结构隔离 | `cargo test --manifest-path components/dnsmasq/Cargo.toml --lib dns::cache::tests` | 28 passed、0 failed；含 parent/child content block/name shard 指针共享与写时分离。 |
| typed transfer | `cargo test --manifest-path components/dnsmasq/Cargo.toml --lib dns::cache::transfer_tests` | 3 passed、1 ignored（历史 exact-C probe 需要 Oracle/reference build）。 |
| cache engine | `cargo test --manifest-path components/dnsmasq/Cargo.toml --lib dns::cache_engine::tests` | 9 passed、0 failed。 |
| daemon/TCP callers | `cargo test --manifest-path components/dnsmasq/Cargo.toml --lib dns::daemon::tests` | 17 passed、0 failed。 |
| 精确 C primitive | `dns_cache_diff.py`，ASAN/UBSAN | 20 scenarios、22,571 commands、0 mismatches；summary SHA `c137b35be19ffd3396d3825122250c9243e5fdbb5623ce1b6c58b259ae1480cc`。只覆盖 dynamic forward transitions，不冒称 TCP IPC/reverse/packet extraction。 |

## S1–S8 静态审查定位

`Cache::snapshot` 复制 owner roots；`content` 为 64-slot `Arc<ContentBlock>`，`names` 为 64 个稳定 FNV shard；`Slot` 保留 owner generation/LRU/pending。所有写入口通过 `entry_mut` 或 `names_*_mut` 触发对应 COW：`start_insert`、insert/negative、CNAME/authority、commit/capture/import、lookup rotation、remove/free、lease publication、clear。`Arc<Record>` 与 `Arc<[u8]>` key 保持共享。

TCP 接线仍是 `daemon.rs::tcp_cache_view` → `main.rs::finish_tcp_accept` → `PollTcpClient.cache_view`；答案、提取、即时 transfer 和 parent import 仍调用原 `CacheContext`/`Daemon` API。`accept_clock`、100-query/150s、stale refresh、日志 drain、FD 生命周期未改。

## Oracle 服务与资源门

以下门必须在新的 Scheme A Oracle ELF 和同一 C reference 上通过，当前未运行以避免占用 UDP-only pilot 的 Oracle：

```text
dns_tcp_cache_diff.py
dns_tcp_reload_diff.py
dns_tcp_writeback_diff.py
tcp_stale_oracle.py
dns_do_cache_diff.py
dns_tcp_ingress_diff.py
dns_tcp_daemon_diff.py
dns_tcp_capacity_diff.py
dns_tcp_accept_failure_diff.py
```

`dns_tcp_cache_diff` 覆盖 accept snapshot、父 UDP 更新不可见、同连接写入可见、后连接可见和固定 TTL；reload/writeback 覆盖代际、即时导回、冲突和 counters；stale/DO/EDNS 覆盖 refresh、CD/AD/no-cache 与身份；daemon/ingress/capacity/accept-failure 覆盖 framing、100-query、队列恢复、EMFILE 和 listener survival。每次保留 C-first 原始输出、Rust 输出、命令、ELF/source SHA、错误回答和 cleanup JSON。

资源/生命周期门需新增 20/上限连接、空/半满/4096、大缓存、随机多 RR、100-query reconnect、150 秒 idle snapshot＋父 churn、冲突与 reload/lease interleave；记录 client/view/pinned-root/transaction、FD/thread/child、live requested bytes、PSS/Anonymous，以及负载结束后 0/1/5/15/60 秒。排空必须满足计数归零或确认 idle FD 集合连续稳定。

## CPU 硬门与失败规则

在同一 9 profile × C/R3/A × 5 轮交错窗口中，TCP 每个正确请求 CPU 相对 M6a opt3 不得增加超过 5%，并保持相对 C 的 CPU 优势；吞吐/p95 不得回退超过 5%，S1–S8 不得出现新增语义差异，错误和 FD 泄漏为零。方案 A 若任一硬门失败，保留全部窗口和失败原因，停止 A，不从 B/C 或不同窗口拼接结果。

历史失败：初次直接运行 primitive harness 时缺少 `local` shim 且 driver 使用旧 `Policy` 宽度，编译失败；修复仅限测试 harness 后重跑为上述 0 mismatch。`cache_transfer_rust_diff.py` 的历史 baseline 缺少要求的 `plan.json`，因此未冒称 transfer gate 已通过；应在 Oracle 新建完整 baseline 后执行。

所有性能和内存结论只代表 Oracle 构建机，不代表物理路由器。
