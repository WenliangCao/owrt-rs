# M3 长时运行与资源报告

本报告采用 `private/dnsmasq-rewrite/evidence/M3/m3-formal-fixed-1790966385/` 的原始数据。C 和 Rust 各运行 3,600 个一秒样本，使用同一 exact image、同一 seed `29302026` 和 Rust SHA-256 `8cd25e3236b740ccb91a8d97d7c6980fd33758201e6eb9cdc5e2030a52fc85f1`。此前两个窗口的失败判定原样保留：第一个窗口的 runner 覆盖不足，第二个窗口把真实 12 小时租期错误地当作 60 分钟 expiry 门；它们没有被重写成通过。

按本次纠偏后的 M3 资源判据，C/Rust workload accounting 完全一致：DORA 20、renew 595、rebind 589、release 20、DECLINE 1、DNS UDP 1791、DNS TCP 568、failover 33、restart 1；M2 的 expiry120、static 和 ethers 证据单独承担这些功能场景。两侧均无失败，daemon、ubusd、客户端 socket 和临时租约在退出后均回收。原始 `run.json` 的 `accepted:false` 只反映旧 runner 把 expiry 当作 60 分钟窗口门；本报告按用户纠偏后的三项判据重新判定资源长跑。

| 指标 | C 后半段中位数 | Rust 后半段中位数 | 后半段范围 | 结论 |
| --- | ---: | ---: | --- | --- |
| RSS KiB | 1692 | 2084 | C 1680–1700；Rust 1960–2228 | 各自稳定；Rust 高 392 KiB 中位数 |
| PSS KiB | 1684 | 2076 | C 1672–1692；Rust 1952–2220 | 各自稳定；Rust 高 392 KiB 中位数 |
| FD | 17 | 14 | 两侧均恒定 | 无持续增长 |
| 线程 | 1 | 6 | 两侧恒定 | Rust 多 5 个线程 |
| 子进程 | 0 | 0 | 恒定 | 无泄漏 |
| 租约行 | 18 | 18 | C 13–19；Rust 13–19 | 同一工作负载下无持续增长 |
| 缓存条目估计 | 439 | 439 | 0–908 | 同一请求计数，随负载增长后稳定 |

Rust 的额外线程来自独立 DNS UDP worker、DNS TCP accept/worker、DHCP listener 以及 UBus/事件处理所需的并发执行上下文；C 将这些路径合并在单一事件循环。额外 RSS 主要是线程栈、同步对象和每个 worker 的接收/响应缓冲，表现为约 392 KiB 的中位数 PSS 差和 5 个常驻线程。M4 可评估把空闲 worker 合并为事件循环或降低线程栈保留，但在 M4 前不改变实现。

压力子门已用同一 exact image musl C/Rust runner 完成：5 分钟 smoke 通过，随后 ENOSPC 和 EMFILE 各自正式执行一次，结果均 accepted。ENOSPC 观察到满盘期间无 durable lease row，释放空间后约 60 秒重试恢复；EMFILE 观察到 FD 压力下无回复、daemon 存活，恢复 limit 后同一连接回包。原始证据在 `private/dnsmasq-rewrite/evidence/M3/m3-pressure-smoke2-1790977374/`、`m3-pressure-formal-enospc-1790977511/` 和 `m3-pressure-formal-emfile-1790977632/`，C SHA `097a9e21…cab87`，Rust SHA `8cd25e32…f851`。旧 native/glibc 工具失败记录仍保留。

M3 资源长跑和两个 exact-image 压力门均已记录，M3 收尾完成。物理路由器未操作。
