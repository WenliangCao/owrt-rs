# M3 长时运行与资源报告

本报告采用 `private/dnsmasq-rewrite/evidence/M3/m3-formal-fixed-1790966385/` 的原始数据。C 和 Rust 各运行 3,600 个一秒样本，使用同一 exact image、同一 seed `29302026` 和 Rust SHA-256 `8cd25e3236b740ccb91a8d97d7c6980fd33758201e6eb9cdc5e2030a52fc85f1`。此前两个窗口的失败判定原样保留：第一个窗口的 runner 覆盖不足，第二个窗口把真实 12 小时租期错误地当作 60 分钟 expiry 门；它们没有被重写成通过。

按本次纠偏后的 M3 判据，C/Rust workload accounting 完全一致：DORA 20、renew 595、rebind 589、release 20、DECLINE 1、DNS UDP 1791、DNS TCP 568、failover 33、restart 1；M2 的 expiry120、static 和 ethers 证据单独承担这些功能场景。两侧均无失败，daemon、ubusd、客户端 socket 和临时租约在退出后均回收。

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

压力子门尚未通过。本轮记录的 ENOSPC/EMFILE 尝试保留在 ignored `private/dnsmasq-rewrite/evidence/M3/pressure-*`：现有工具要求 native/glibc C 和预构建 ubus 依赖，无法直接执行 exact image musl C；租约工具在宿主执行 musl ELF 时得到 `FileNotFoundError`，UDP/TCP 工具的 C UBus object setup 也未建立。缺少本轮 C/Rust pressure raw evidence，因此不能把 M3 称为完整关闭，也不能进入 M4 的正式候选包门。

M3 资源长跑按上述判据通过；完整 M3 仍被 ENOSPC 和 EMFILE 两个可重复压力门阻塞。物理路由器未操作。
