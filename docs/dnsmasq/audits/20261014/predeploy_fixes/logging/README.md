# B6：停机日志排空

匹配镜像的 patched dnsmasq 2.93 `src/log.c:457–474` 中，`flush_log()`
在队列非空且连接仍有效时持续等待；`EAGAIN` 不使连接失效，`ENOBUFS`
或重新连接失败会终止等待。该文件 SHA-256 为
`a205b9cbf9556b01f483b43e732df1ae411c82d622a0e5449f79d43b0267c47c`，
与既有 reference identity 清单一致。

Rust `Logger::finish()` 已实现这两个退出条件，但 `main.rs` 额外施加
100 ms 总截止时间。修复删除此截止时间，继续用现有单 owner、非阻塞写和
poll；没有新增日志线程、队列结构或重连策略。日志接收端永久不读且保持
连接时，停机等待也会持续，这与 C `flush_log()` 的边界一致。

[独立复现工具](../../../../../../tools/dnsmasq/predeploy_logging_shutdown.py)
在 Oracle 独立网络、挂载、PID namespace 内运行精确镜像的 C ELF 和 Rust
ELF；各自使用只读镜像上的私有 overlay 及合成 `/dev/log`，不接触路由器。

- `audit-overflow`：重跑 300 次查询，核对全部成功；两次各最多读取 11 条
  日志，TERM 后继续停读 2.1 s，随后恢复读取并验证进程正常退出。限制每次
  读取数量避免原工具“读到 EAGAIN”与服务端继续写入竞争，偶然把队列全部排空。
- `tail-drain`：先排空启动日志，再用 fixture datagram 填满内核接收队列，
  保持服务的 25 条日志队列有空间。一条 DNS 查询和 TERM 产生的 query、answer、
  SIGTERM 三条日志必须在停读 350 ms 后按顺序各读取一次，且进程正常退出。
- `peer-close`：同样建立背压，TERM 后等 350 ms 再关闭并删除接收端，验证
  连接失效后无需继续排空也能正常退出。

旧审计 ELF 的负对照在受控 `tail-drain` 中正常退出，却没有保留上述三条
已排队日志；精确镜像 C 保留三条。因此 B6 的尾日志丢失已由新实验证明，
不再只依赖 100 ms 截止时间的源码推断。该结论针对显式 `log-async=25`、
`log-queries` 合成背压配置，不代表镜像默认 logd 的真实故障频率。

原 `m5_logging.py` 的四个 `blocked-sink-*-shutdown` 用例故意永不恢复
reader，其 Rust 期望已同步修改为等待外部 SIGKILL；仍单独断言 TERM 之前
服务可用。C 在启动阶段阻塞的 FIFO/主 stderr 情形仍保留原来的 exit 5
边界，未把它改写为与 Rust 相同。测试工具的 SIGKILL 不能解释为 procd 行为。

派生结果及原始证据路径、摘要见 [summary.json](summary.json)。原始日志、
镜像 overlay 与 ELF 均仅保存在 Oracle 的 `private/`。
