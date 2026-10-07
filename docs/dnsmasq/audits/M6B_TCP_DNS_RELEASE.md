# M6b S8：DNS 工作结束后释放完整所有权

日期：2026-10-07。独立分支 `m6b/tcp-dns-work-release`，基于方案 A compact/readiness tip `85f9719b`。产品与单元测试提交 `721610ed`，FIFO 测试合同补注提交 `9a8200a0`。未改主工作树、未使用 Oracle、未执行镜像服务/资源/压力或 CPU 资格。

## 接口与完整释放边界

`PollTcpClient` 将 DNS 工作收拢到 **内联 `Option<TcpDnsWork>`**，外层只保存 `TcpLogContext`、poll slot 和 readiness。以 `dns_work.is_none()` 取代另外一份 `network_done` 布尔状态。接收时仍在原有快照点构造 `Some(work)`；所有原 `start_query/answer_query/run_forward/step` 算法移入 `TcpDnsWork`，没有改 accept clock、100-query、150s、debug 当前父路径、typed cache transaction 或导入顺序。

| 工作所有权 | DNS 工作结束时的处置 |
| --- | --- |
| `cache_view`（私有 LRU、内容块/名字索引根）、cache 参数/计数 | 整体 Drop；日志上下文没有缓存引用 |
| `LocalDnsService` 的 hosts/config、lease/interface publication roots、local query events | 整体 Drop；未直接切换成父的新代际 |
| `TcpDnsService` 的 routing/upstream/policy/pending query、持久 TCP upstream sockets | 先转出 producer events 与 connection warnings，再整体 Drop/关闭 sockets |
| 下游 stream、framer/input、phase frame、stale query、MAC、身份和 query IDs/context | 整体 Drop；不是只 `clear()` 几个 Vec 或只关闭下游 |
| `TcpLogContext` 的已接受 destination、queue/overflow 状态 | 留在 client，等待 `finish_tcp/tcp_finished` |
| client 槽位／G／`tcp_active` | 只在 logs_done 后 `swap_remove`，不提前开放新的连接许可 |

`step_tcp_clients` 的顺序固定为：执行或取消 DNS 工作 → 把已排队 query events、local/forward error/cancellation 残余事件和 connection warnings转入原日志上下文 → 取走 parent cache activity → 若 `network_alive=false`，`dns_work.take()` 完整释放 → 原日志 drain → logs_done 才释放 client 槽位。普通 poll 与 probe poll 都只为 `Some(work)` 纳入 DNS fd/timer，log-only client 仍纳入日志 fd/retry timer。

下游关闭不是 DNS 完成边界。stale 答复后原有状态机会关闭下游并开始刷新；`network_alive=true` 时仍保留整个工作集和接受时视图，直到刷新完成、失败、deadline 或取消。C 合同来源及门编号仍是 [TCP 设计第 2 节](../M6B_TCP_MEMORY_DESIGN.md)：`forward.c:2367–2790` 固定 now，`:2782–2784` stale 后台刷新；`dnsmasq.c:1632–1652`/`:1935–1958` 进程/pipe slot 生命周期；S8 的上游复用/关闭和日志延长退出。此次不改变 S1–S7 存储语义。

## 分配与布局账

没有采用 Box，因此不增加每 accept 的分配或独立堆间接层。AArch64 Linux LLVM `sizeof` globals 为旧 `PollTcpClient=2552 B`、新 `PollTcpClient=2560 B`、`TcpDnsWork=2456 B`、`Option<TcpDnsWork>=2456 B`；增加 **8 B/slot**，32 槽容器增加256 B（81,664→81,920 B）。native 64-bit 无 Linux log/poll 字段时 client/work/Option均2456 B。

内联槽位容量仍保留在 `clients` Vec 中，`take()` 释放的是字段拥有的堆对象、引用和 sockets，不承诺将 client 容器容量缩小或立即将 allocator 页归还内核。没有增加 Box 不等于 CPU 已通过：所有新 Option 分支、结束时 Drop、日志转移与整个 compact A 必须由同一个候选的 A45 CPU 门验证；不得把旧实验的最好结果拼接。

目标布局诊断从提交 source 创建 ignored copy，加 `#[used]` sizeof数组并读取真实目标 LLVM IR。两次 IR 生成后，host `cc` 无法链接 Linux musl ELF而退出101；原完整 stdout/stderr保留。此数字仅是目标类型布局，**不是交付 ELF 构建或 Linux 执行资格**。通过的 Linux 检查是 `cargo check --target aarch64-unknown-linux-musl --tests`。

## 单元回归与证据边界

最终测试提交 `9a8200a0` 上：host main **13 passed / 0 failed / 0 ignored**，AArch64 Linux `--tests` 类型检查通过。

- 扩充 `finished_tcp_log_fifo_retries_without_network_events_and_releases_slot`：配置4096条 cache view、65,535B input、partial framer、MAC/stale Vec，用生产 deadline 路径完成 DNS；FIFO 无 reader 时 client/G仍1，`dns_work=None`，lease/interface roots strong_count只余父引用；reader出现后日志排出，client/G归零。**Linux测试尚未实际运行**。
- 新 `tcp_closed_downstream_keeps_pending_stale_work_until_refresh_completes`：真实回环 TCP upstream受 channel控制；下游已EOF、upstream等待时 view/root和G仍保留；多次 step不能提前释放；放行回包后工作集销毁，持久upstream收到EOF。此非Linux路径已实际执行通过。
- 同一新测试的 Linux 分支增加 held FIFO：DNS work/upstream释放后G仍持槽，再开 reader确认 producer warning排出及overflow，最后释放槽位。file/FIFO合同是固定**单 buffer**，首warning保留，后续query/forward producer应计overflow，不能要求全部逐条输出。**此分支仅通过类型检查，未实际执行**。
- 原 TCP buffered-input 和 POLLOUT不授权read 两项 host回归继续通过。无 unsafe新增。

中央证据目录：`private/dnsmasq-rewrite/evidence/M6B/tcp-dns-work-release-721610ed/`；[收据](../../../private/dnsmasq-rewrite/evidence/M6B/tcp-dns-work-release-721610ed/receipt.json) SHA `01fecae820f65206922a4d7222449f2b6c44317521b30a0255328c05a94a6bc4`，包含产品patch、最终test-fix patch、两次实际host测试、Linux check、native/目标布局、失败与重现记录的完整逐文件SHA。

失败保留：初版本地stale测试的server线程接受非阻塞listener后，macOS accepted stream继承非阻塞，`read_exact`立即WouldBlock（exit101）。补 `set_nonblocking(false)` 后通过；初次完整stdout未单独落盘，保留原错误摘录，并在精确产品提交的ignored copy有意撤掉这一行完整重现exit101，不能把重现日志称作首次日志。Linux单buffer断言在实际运行前读码纠正，未冒称出现过Linux产品失败。目标布局两次cross-link失败也保留，不作为资格。

主线程仍须在最终整合 ELF 上实际运行 Linux main tests、S1–S8与日志/缓存受影响镜像功能族、resource/lifecycle/pressure、A45 CPU与最终统一测量。本独立提交不宣布这些门通过，不占用Oracle窗口，物理路由器未访问。
