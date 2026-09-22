# R118 方向调整建议（同仓库另一会话，2026-09-22）

已核对 R95–R120 全部文档、`r113-fd-boundary-discovery.json`、`wireprobe.rs fd_boundary`、`client.rs` 接收路径。
用户给定权重：正确性硬门 → 性能 90% → 资源 10%；性能只需胜 C；内存是护栏不是目标。

## 一、核心判断：R113 把 FD 归属分歧当硬门，是策略选择，不是缺陷修复

依据全在现有记录里：

1. `r113-fd-boundary-discovery.json` 的 `normal_client_scope`：libubus 的 `writev_retry` 一帧一次 sendmsg、FD 只随第一次；
   分歧只在 "custom callers batching frames or attaching descriptors during body reception"。
   wireprobe 六个 case 中通过的三个（`separate_waited` / `separate_queued` / `plain_first_then_fd_second`）覆盖了 libubus
   能产生的全部框架；分歧的三个（`bundled` / `fd_in_first_body` / `fd_on_first_body_plus_second_frame`）都要求客户端把两帧塞进
   一个 sendmsg，或把 FD 挂在纯 body 上。内核 `unix_stream_sendmsg` 只把 fds 挂在第一个 skb，libubus 的大帧也不会触发 body 阶段 FD。
2. 同一 JSON 的 `cause`：recvmsg 不暴露携 FD 的 skb 起点，读前缓冲与 C 的逐字 FD 归属在内核语义下不可能同时成立。
   这是二选一，不存在"修好了再回来"的路径。R114–R117 四轮在两次系统调用的设计上没追回一个百分点，就是这个不可能性的体现。
3. 分歧后果不跨客户端、不跨权限：FD 只会落到同一客户端在同一 sendmsg 里发出的另一请求上，或被 `Server::handle` 对非
   INVOKE/STATUS 帧丢弃。无能力提升，无泄漏（wireprobe `no_leak` 两边都过）。

代价对比：为一个只有手工构造帧才能触发的分歧，丢掉了 R109 谱系（对 C：lookup CPU −25%~−74%、invoke −22%、注册 −7%、
事件 −3%~−9%），换来 R113 谱系事件 daemon CPU 对 C +4%~+15%；R118–R120 在 HashMap 哈希上找上限 1–2% 的东西，堵不住 10%。
按给定权重，这个取舍应反过来。

## 二、建议动作（按顺序，每条可独立验证）

A. 把 FD 归属写成一句显式契约并进 docs：「携带 SCM_RIGHTS 的 recvmsg 所交付的最后一个字节所在的帧拥有该 FD；对一帧一
   sendmsg 的客户端（libubus 全部）与 C 逐字一致；多帧一 sendmsg 或 body 阶段附 FD 属于未定义框架，Rust 按上述规则处理。」
   wireprobe `fd_boundary` 三个对抗 case 的期望改为 Rust 契约（或标记 documented divergence），性质与 R94 已接受的
   EOF≡RST fuzz 判定相同。

B. 运行时基线回到 R109（源码 `2fbfd88`，ELF `1dfb317c…`）：R94 读前缓冲 + R100 栈回复 + R103 借用事件 + R109 方法名，
   R100 epoch 修复已含。R113 之后唯一值得移植回来的是 R114 借用派发的思想（小帧 `Cow::Borrowed` 直接派发，
   response/PING 走 `send_borrowed`），但在读前缓冲上的收益要重新量；不移植也可以收尾。

C. 内存按用户定义处理：每连接 4 KiB 读前缓冲是有界线性成本，接受。顺手一行：`RX_SIZE` 4096 → 4076。
   musl mallocng size class 以 16 字节为单位 255→292，即 4080→4672；4096 加 4 字节带内头正好越过 4080 落进 4672 档，
   这是 R105 内存表每连接 5.5 KiB 而非 4 KiB 的来源。先在 Oracle 用 `malloc_usable_size` 验一次 class 再改。

D. 停 R118–R120。在 R109 谱系上已胜 C，哈希表的 1–2% 没有决策价值；在 R113 谱系上追不回 10%。

E. 收尾：写"在本硬件、镜像、兼容约束下的可实现极限"判断。列两项：唯一分歧 = 对抗框架下的 FD 归属（已契约化）；
   唯一未胜 C 项 = 每连接 4 KiB 常驻（有界、线性、用户已定为护栏）。

## 三、流程（用户明确要求省 token）

1. 候选先过 Oracle 同步计数（R111 已建）：用户态指令数不降 ≥3% 不上路由器；±1% 以内一律记平手。
2. 上路由器只跑一次十窗口同号检验，不再做 4 块 pilot + 复查两段。
3. 被拒候选只留 results JSON + 十行判定，不写长文。
4. 没有按符号的 perf record 之前，不再做任何消融。R114–R117 全是无 profile 消融。
5. 栈暂存（R110-A）已被同步计数证明 +3.1% 指令，作废，不再复议。

## 四、若用户最终仍要 C 精确 FD 对等

这是用户的决定权。那样唯一正确的下一步是在 Oracle 对 R115 做按符号的 perf record 找那 10% 在哪，而不是 R118–R120。

出处：libubus-io.c `writev_retry`（lxr.openwrt.org，R101 已引）；net/unix/af_unix.c `unix_stream_sendmsg` 的 `fds_sent`
与 `unix_stream_read_generic` 的 `if (scm.fp) break`；`components/ubusd/src/client.rs:416 rx_take_fd`；
`docs/reviews/r105-rx-spare-memory-results.json` 的 `rssanon_growth` 按连接数折算。
