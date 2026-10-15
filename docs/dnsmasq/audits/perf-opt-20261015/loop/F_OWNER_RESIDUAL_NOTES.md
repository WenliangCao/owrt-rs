# F owner 的剩余代码路径记录

只读来源：F `3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`。
没有新增产品补丁、测试、Oracle/router 工作负载；F 本身不变。
协调者要求暂停继续研究，等待 F 的完整设备结果，再决定是否测量下述点。

## TCP 接收缓冲区的重复尾部清零

`main.rs:3068–3072` 在每次读取前执行 `input.resize(4096, 0)`，读取成功后
执行 `input.truncate(count)`。容量已复用，但 Vec 长度缩短，所以下一次
读取前重新初始化尾部。上一读为 r 字节时，下一次 resize 清零
`4096-r` 字节；32 字节 DNS 请求加两字节帧头、每次完整单帧读取的例子
是 4,062 字节。第一次分配的 4 KiB 初始化另计；合并读取、分片或
WouldBlock 的实际 r 不同，不能把此例写成每个生产请求的测量值。

最小潜在实现：保留已初始化的 4 KiB Vec 长度，用单独的有效长度表示
这次读取的内容。解析只访问 `[input_offset..valid_length]`；首次读取前
仍延迟分配，输入容量和读取上限不变，不需要 unsafe 或新抽象。

必须同时核对这些依赖 Vec 长度表达“有效数据”的位置：

- `main.rs:3052,3063,3087`：读授权、是否需要新读取、传入 framer 的切片。
- `main.rs:4257`：常规 owner 判断缓冲尾部是否可运行。
- `main.rs:5738`：TCP ready 判断。
- `main.rs:5999`：DHCP probe 期间的 owner 唤醒判断。
- `main.rs:5708`：新 TCP 工作项初始化；错误/关闭时的有效长度和偏移。

保留 8 步读/写预算、POLLIN/POLLOUT 授权、分片和流水线顺序、100 请求
上限、MAC 等待、旧查询刷新与关闭、日志阻塞时统一释放 DNS 所有权。
不能把整个已初始化尾部作为待处理数据，也不能产生忙轮询。

已有相关测试（本次未重跑）：

- `tcp_polled_write_does_not_consume_unpolled_read`
- `tcp_buffered_frame_runs_without_socket_readiness_and_sends_new_answer`
- `real_tcp_read_budget_tail_resumes_through_normal_and_probe_owner`
- `accepted_mac_wait_does_not_busy_poll_queued_dns_before_snapshot_ready`
- `tcp_idle_deadline_and_completed_client_run_without_fd_readiness`
- `finished_tcp_log_fifo_retries_without_network_events_and_releases_slot`
- service 的 `tcp_framer_all_fragment_boundaries_keep_one_frame_and_tail`、
  `bounded_tcp_framer_rejects_length_before_reading_body`、
  `one_frame_is_delivered_before_later_invalid_length`。

这些测试中直接设置 `input` 的 fixture 也必须同时设置有效长度。
实际实现时还需验证“较长读取后接较短读取”不会重新解析旧尾部。

当前只有可证的重复写入源路径，没有将 F 的 CPU/cycles 归因到这段
清零。既有 E/C 的 TCP syscall/周期结果不能换算成此候选的收益。
暂不实现，等 F 的 TCP 实测和需要时的精确路径归因。

## UDP EDNS 扫描的边界

`main.rs:5235` 的 `query_metadata(packet, ...)` 使用
`find_pseudoheader(..., true)`；未启用配置装饰时，紧接的
`client_subnet_cacheable(packet)` 再使用 `false` 扫描。普通已通过
`Admission::Continue` 的 QUERY 包，两次扫描到达相同 RR 游标，可考虑
从第一次 OPT 引用计算 ECS 缓存资格。但非 QUERY、TKEY/TSIG、坏问题、
截断 additional、多个 OPT 和严格 ECS TLV 停止条件必须分别保留。

这是小的非分配扫描重复，不是四类 EDNS 消费者可无条件合并的证明。
未提出 API 改造或补丁。无 EDNS 装饰配置时 UDP 已借用接收 scratch，
没有额外请求 Vec 复制；TCP 已采用独立帧头的 vectored 写出，不能重复
申报旧 L02/L03 的收益。

Metrics 无订阅者快照已属于旧 L07 拒绝方向，不重开。普通无上游工作
的命中路径也已在 upstream 的 `no_timer_or_socket_work()` 分支，于那组
Instant/unix clock 读取前返回；不能把活跃上游计时扫描归到纯命中路径。
