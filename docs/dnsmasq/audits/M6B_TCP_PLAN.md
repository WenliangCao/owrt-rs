# M6b TCP memory plan (方案 A)

日期：2026-10-07。状态：仅调用链和验收计划；没有产品代码修改、构建或 Oracle 测量。本计划补充 `M6B_TCP_MEMORY_DESIGN.md` 第 2、5 节，待主线程冻结 M6b 协议后才授权实施。

## 固定边界与调用链

被测起点是 M5 `dc1b740d7973838e2ae7f098d0726b0484e55074`（opt3 ELF `37f85d22…`），镜像 C `097a9e21…`。TCP accept 在 `main.rs::finish_tcp_accept`（4054）从 `Daemon::tcp_cache_view`（`daemon.rs:1689`）取得视图，并在 `PollTcpClient.cache_view` 持有至连接结束；accept 时钟固定在 `PendingInterfaceTcp.accept_clock`。每个 client 的读取/答案/转发/导回路径都在 `main.rs::PollTcpClient::{answer_query,run_forward,step}`：

* cache 命中：`Daemon::tcp_view_answer`/`tcp_view_local_answer` → `Cache::{lookup,lookup_question,lookup_reverse}`，并可能触发删除、LRU、轮转。
* 上游回包：`Daemon::tcp_view_extract` → `CacheContext::insert_reply_with_events` → `Cache::start_insert`, insertion/commit；capture 后 `Daemon::import_tcp_cache_transfer` → `CacheContext::import_transfer` → `Cache::import_counted`。
* debug（无私有 view）路径：`tcp_current_answer`/`tcp_current_extract` 直接操作父 cache；该路径必须保持现有 `-d` 语义，方案 A 不能把它变成 snapshot。
* client 结束：`step_tcp_clients` 在网络完成且日志已 flush 后 `swap_remove`，随后 `cache_view` Drop；父 cache 的导回已在每次成功 capture 后立即执行，不得延迟到 EOF。

方案 A 只替换 `Cache` 内部存储，不改变 `CacheContext`、wire extraction、typed transaction、TCP 状态机或上述时序：内容 `Record`/name bytes 共享；每 owner 维护私有 LRU/link/generation/pending；内容 slot 按固定 64-slot `Arc<Block>`，name index 按稳定 hash 的 64 个 `Arc` shard，具体写点先 `make_mut`。64、slot 布局和 capacity 需以第一原型实测冻结，不得从预测数字宣称收益。

## S1–S8：逐 mutator 清单

每个清单项在实现 PR 中必须给出：旧逻辑位置、A 的 detach/共享动作、一个正例和一个故意漏 detach/乱序负控；未勾完不得进入服务门。

| 合同 | 必须覆盖的 Rust mutator/读路径 | 验收要点 |
|---|---|---|
| S1 接受快照 | `Cache::snapshot`; `Cache::new`; `Daemon::tcp_cache_view`; `main.rs::finish_tcp_accept`; `LocalDnsService`/`TcpDnsService` snapshot接线 | snapshot 固定 accept 时刻的内容、name/reverse 索引、配置与 generation；父后续 UDP/reload/lease 不可见；`-d` 仍读父。覆盖 capacity 0/1/150/4096。 |
| S2 固定时钟 | `PollTcpClient.accept_clock`; `Daemon::{tcp_view_answer,tcp_view_extract,tcp_current_answer,tcp_current_extract}`；`Cache::invalid`, `lookup*`, `insert_ttl_counted`, `import_counted` | 所有 TTL/stale/expiry 使用同一 accept clock；父 import 用父 now；TTL 1 秒等待跨 2.2 秒、150 秒/100-query边界保持。 |
| S3 私有写入/副作用 | `Cache::{start_insert,insert_against_local,check_local_insert,insert,insert_counted,insert_ttl_counted,insert_at_counted,insert_negative,insert_negative_counted,set_negative_authority,set_cname_target,set_local_cname_target,commit,commit_counted,capture_commit_counted,commit_inner,import_counted,clear,clear_counted}`；私有 `remove,free,unlink,link_head`; `lookup`, `lookup_question`, `lookup_reverse`; `PublicationCache::{first_lease_entry,prepare_name,reverse_owned}` | 子 lookup 的 LRU/round-robin、expiry removal、conflict/eviction、pending、generation、referenced、long-name 和 lease generation 不能写父；每个 mutator 写前 detach 对应 content/index shard 或 owner LRU。CNAME target/negative authority 的 slot identity 不跨 owner。 |
| S4 导出集合/时机 | `Cache::capture_commit_counted`, `commit_inner`; `CacheContext::{insert_reply_with_events,insert_reply_for_transfer,insert_reply_transaction,insert_bogus_for_transfer}`; `PollTcpClient::run_forward` capture/`Daemon::import_tcp_cache_transfer` | 仅成功 commit 导出；capture 顺序与 C chain 相同，CNAME 不带 child id/target bytes，回复前即时导回；空 transaction 清 parent pending。 |
| S5 有序事务 | `commit_inner` pending pop、`import_counted` previous target reconstruction、`insert_at_counted` conflict ordering、`names` vector rotation、`reverse_chain` partition order、`CacheContext` CNAME/SOA/negative extraction | 禁止 sort/dedup/跨 owner EntryId；CNAME alias 紧邻 target、RRset/round-robin 顺序和前缀删除保持；失败后已发生移除保留，未提交尾部不可见。 |
| S6 父当前状态/失败边界 | `Cache::import_counted` local callback；`CacheContext::import_transfer`; `Daemon::import_tcp_cache_transfer`; `Cache::fail`, `check_local_insert`, `insert_at_counted`, `commit_inner` | import 在 parent 当前 hosts/lease/config 与 parent now 下串行执行；不回 poll、不全事务回滚；父 counters 只计 parent 实际操作；TTL underflow/zero 和 capacity/long-name failure 与既有 oracle 一致。 |
| S7 跨连接/EOF 顺序 | `main.rs::step_tcp_clients`; `PollTcpClient::run_forward`; `cache_view` Drop；`Daemon::tcp_cache_view/import_tcp_cache_transfer`; transaction owner | 一次消费完整 typed transaction，连接内有序、连接间按现有 poll/slot，不新增全局排序或等 EOF 队列；EOF/partial frame/RST/上游 EOF 只保留既有边界。 |
| S8 生命周期/副作用 | `PollTcpClient::{step,answer_query,run_forward}`、`TcpDnsService` pending/upstream close、`step_tcp_clients` network/log completion、`Cache::clear`/Drop、query logging/stale refresh | 100-query/150s、stale 下游关闭后刷新、upstream reuse/close、日志 drain 和 counters 不变；DNS view 仅在 DNS 工作和日志许可都结束后释放。记录 client/view/pinned-root/transaction/FD 计数。 |

## A 原语门（Primitive / isolation）

1. **结构门**：`Cache` clone 后 parent/child 根、owner LRU、pending、generation、reverse/name order 独立；`Arc<Record>`/immutable key 共享；capacity 0/1/150/4096，empty/full，single/many name，A/AAAA/CNAME/negative/SOA/generic/reverse，long-name cap 与 stale 都有 case。
2. **精确 C 原语门**：复用 `dns_cache_diff.py`、`cache_policy_transaction_diff.py`、`cache_answer_diff.py`、`cache_reverse_order_*`、`lease_cache_diff.py`；逐项比对 state/TTL/flags/counters/RR 顺序，而非只比 wire answer。
3. **负控门**：故意共享 LRU、漏 detach name shard、错用 child EntryId、CNAME 顺序交换、失败后回滚 prefix 各做一个变体；每个负控必须被对应差异器拒绝。
4. **分配门**：原型先输出 requested live bytes、Arc block/shard 版本数、alloc count 与 Drop 余额；接受成本不应复制 8194 小对象。内存数字是 Oracle AArch64/musl 页驻留测量目标，不从结构预算推导通过。

## 服务、资源和正式门

* **服务合同门**：`dns_tcp_cache_diff.py`（accept snapshot、same-client write visibility、later-client visibility、fixed TTL）、`dns_tcp_reload_diff.py`/lease publication、`dns_tcp_writeback_diff.py`、`tcp_stale_oracle.py`/`dns_stale_refresh_diff.py`、`tcp_cd_policy_oracle.py`/`dns_do_cache_diff.py`、`tcp_upstream_diff.py`/`tcp_caller_diff.py`。必须证明父/子代际、实时导回、冲突和 no-cache/EDNS/CD policy 不变。
* **资源/生命周期门**：`dns_tcp_ingress_diff.py`、`dns_tcp_daemon_diff.py`、`dns_tcp_capacity_diff.py`、`dns_tcp_accept_failure_diff.py`；100-query EOF、150s、RST/半帧/上游 EOF、最大回复、慢读写、日志 FIFO/reopen、stale refresh、TERM。每次记录 FD、线程/子进程、client/view/pinned-root/transaction 计数及 0/1/5/15/60 秒排空值。排空须等待 Rust 计数归零或已验证空闲 FD 稳定。
* **新增压力门**：20 与上限连接；空/半满/4096/大缓存；固定代际命中、随机多 RR 轮转、100-query 重连；单条 150 s idle snapshot＋父 UDP 连续替换；错峰 accept 与父/子同名冲突；reload/lease 更新与导回交错。至少 10 批重连确认 live requested 不随总连接数增长。
* **正式资格门**：M6b 协议冻结后，同一最终 ELF 做 9 profiles × C/R3/Rs × 5 交错轮；S1–S8 零新增差异。steady/saturation 每正确请求 CPU 相对当前 R3 不劣化 >5%，吞吐与 p95 不劣化 >5%，错误为零；小容量/空缓存不以大缓存收益豁免。最终还需 M5 受影响族、M2、资源、ENOSPC/EMFILE 和 APK 生命周期复测。

## 预算与风险（实施前冻结）

硬门：S1–S8 零新增差异；每正确请求 CPU 相对当前 opt3 不得变差超过 5%；steady/saturation 吞吐和 p95 不得变差超过 5%；错误、错误答、FD 泄漏均为零。TCP 20-concurrent PSS/RSS 的目标范围是设计研究预算而非承诺：cache 约 4–7 MiB、miss 约 8–16 MiB、断连约 3–6 MiB；须同时报告 requested live bytes、PSS/Anonymous 和 0/1/5/15/60 秒值。

最大风险是遗漏任何写入口而让 child 读/写父根（尤其 `prepare_name`, reverse chain、negative authority、CNAME target、failure prefix）；其次是分片 detach 破坏 C 的有序 RRset/CNAME chain，或块版本被 generation/EntryId 复用导致 ABA；再其次是随机名称 churn 令 64 index shards 全部 detach，或父长时间写入钉住旧版本，导致 PSS/CPU超过预算。A 未过 primitive 或 TCP CPU 硬门时保留完整失败证据，不拼接不同实验最优窗口，不转入 B/C。

## 实施提交顺序（未来，未授权）

1. 测量合同修正、协议冻结（独立提交）；本计划作为审查输入。
2. A 最小原型：拆 LRU/content，不改 wire/transaction；先 primitive/负控门。
3. content block + name shard/shared key；再 primitive 全量，随后服务和资源门。
4. 仅门全过后构建 final opt3/s，对 M6b 9×3×5 正式窗口；失败保持证据并回滚候选。
