# ADR: dnsmasq-rs 的线程模型

日期：2026-10-02  
状态：接受，作为 M4 的第一项重构决策  
范围：`components/dnsmasq/src/main.rs` 中的 dnsmasq-rs 服务进程；不包含
独立的 `ubusd` 进程。

## 决策

M4 回到与镜像 C dnsmasq 相同的单一事件循环。一个 owner 持有 DNS、DHCP、
TFTP 和 UBus 的可变运行状态，所有 socket 以非阻塞方式纳入同一个 poll 集，
每次迭代只在有限的工作量后回到 poll。DNS TCP 连接、DHCP relay/PXE 和
TFTP 传输都使用显式的有界状态机，不用为每个连接再建线程。

当前多线程实现先保持可回归，直到单循环候选完成 M4 的受影响验证。届时必须
用同一配置和同一输入重跑 M2 的四组 DHCP 场景以及 M3 资源对比；在这些结果
出来前，不把本 ADR 当作产品代码已经切换的声明。若要保留多线程，必须用新
的 C 差分、正确性回归和资源证据证明它有实际收益，并另写 ADR 修改本决定。

## 证据和观测边界

M3 正式窗口的 C ELF 是 `097a9e21…cab87`，Rust ELF 是
`8cd25e32…f851`。两侧各有 3,600 个一秒采样，详见
[M3_REPORT.md](M3_REPORT.md) 和 ignored 的
`private/dnsmasq-rewrite/evidence/M3/m3-formal-fixed-1790966385/`。

| 观测 | C | Rust | 解释 |
| --- | ---: | ---: | --- |
| 常驻线程计数 | 1 | 6 | C 的 poll loop；Rust 是主线程、若干 listener worker 和运行期间的 TCP client worker |
| 后半段 RSS 中位数 | 1,692 KiB | 2,084 KiB | Rust 高 392 KiB |
| 后半段 PSS 中位数 | 1,684 KiB | 2,076 KiB | Rust 高 392 KiB |
| 后半段 RSS 范围 | 1,680–1,700 KiB | 1,960–2,228 KiB | 两侧都没有持续增长 |
| 后半段 FD | 17 | 14 | 没有持续增长；数量差不是收益结论 |

M3 runner 只保存进程级 `VmRSS`、`smaps_rollup Pss` 和线程总数，没有保存
每个 TID 的 `VmStk`、栈峰值或 allocator 标记。因此本 ADR 不把 392 KiB
分摊成虚假的“每线程 KiB”。当前代码也没有给 `std::thread::Builder`
设置 `stack_size`，实际栈的保留/提交大小由目标 libc 和线程属性决定；M4
候选必须额外采集 `/proc/<pid>/task/<tid>/comm`、`statm`/`smaps` 和退出后
回收结果，才能给出逐线程栈账。

## 当前实现的线程拓扑

下面的职责和缓冲来自源码；“栈”一栏表示当前没有显式大小，“堆”一栏只列
可定位的拥有者。六线程观测包含动态的 `dns-tcp-client`；精确的六个 TID
归属没有在 M3 原始证据中保存，不能把一次采样误写成固定拓扑。

| 线程/生命周期 | 职责 | 栈和堆 | 共享状态与锁 |
| --- | --- | --- | --- |
| 主线程，常驻 | 启动、降权、信号标志、接口快照、动态 listener 增删、SIGHUP/reload、周期 metrics/UBus、join worker | 默认 libc 栈；拥有 `Runtime`、hosts/config 和 owner 引用 | `interface_snapshot`、`service`、`parent_events`、可选 `dhcp_provider`、`response_sockets` |
| `dns-udp-<address>`，每个绑定地址一个 | recv/admit、local/forward DNS、回复和跨 listener fanout | 默认 libc 栈；每个 worker 有 65,535 字节 query 缓冲，另外有当前回复/上游临时对象 | `parent_events` → 可选 `dhcp_provider` → `service`；读 `interface_snapshot`，发包时读 `response_sockets` |
| `dns-tcp-<address>`，每个绑定地址一个 | capacity 检查、accept、接口来源检查、建立本地 snapshot、回收 client handles | 默认 libc 栈；拥有 client `JoinHandle` 向量和 accept 临时对象 | `parent_events`、`interface_snapshot`、`service`；不能把锁带进 accept 等待 |
| `dns-tcp-client`，每个已接受连接一个，短寿命 | TCP framing、local/cache、上游 TCP、回复，最多 100 个 query 后结束 | 默认 libc 栈；4,096 字节输入数组、`TcpFramer`（受 packet limit 限制）、per-connection `LocalDnsService` snapshot 和 upstream 状态 | cache 访问短暂锁 `service`；`TcpPermit` 在 Drop 时锁 `parent_events` 减少 `tcp_active`；网络读写不应持有共享锁 |
| `dhcp-listener`，启用 DHCPv4 时常驻 | 维护 lease、读 DHCP 报文、冲突探测、发布租约名、写 metrics/UBus 事件 | 默认 libc 栈；16,384 字节输出缓冲和 `DhcpProvider` lease/state heap | `parent_events` → `dhcp_provider` → 必要时 `service`；DNS publisher/lookup 不能反向取得 provider 锁 |
| `tftp-listener`，启用 TFTP 时常驻（M3 配置未启用） | poll TFTP listener、维护 transfer map 和端口/重传状态 | 默认 libc 栈；transfer `BTreeMap`、每个传输的 socket 与数据缓冲 | 当前主要是本地 owner；接入单循环后与 DNS/DHCP 共用一个 poll 集 |

UBus 没有一个隐藏的 Rust 工作线程；`UbusService::process_one` 和同步
doctor/notify 都在持有 `ParentEvents` 的调用线程中执行。M3 中看到的
`ubusd` 是独立进程，不能计入 dnsmasq-rs 的线程数。

## 共享状态和已知并发缺陷

- `Arc<Mutex<ParentDns>> service` 同时保护本地 hosts/leases、DNS daemon、
  forward table 和 cache。TCP 在 accept 时复制 snapshot，UDP 和 reload
  直接改 parent；这让 generation、cache 和 lease publication 的一致性
  依赖锁边界。
- `Arc<Mutex<ParentEvents>> parent_events` 保护 UBus 连接、metrics 计数和
  `tcp_active`。所有 listener 都要经过它，因而它是多线程实现的串行瓶颈。
- `Arc<Mutex<DhcpProvider>> dhcp_provider` 保护租约状态机、租约文件维护和
  冲突探测。主线程 reload/metrics、UDP metrics 和 DHCP worker 共享它。
- `Arc<Mutex<Vec<DnsInterface>>> interface_snapshot` 由主线程刷新，UDP/TCP
  admission 读取；`response_sockets` 保护动态 listener token 到 socket 的
  映射。停止和 reload 使用 `STOP_REQUESTED`、`RELOAD_REQUESTED` 原子标志。
- 设计约定的主要锁顺序是 `parent_events -> dhcp_provider -> service`；
  UBus doctor 必须先取得真实 metrics，不能在 `service` 锁内回调 provider。
  TCP accept 还会在 event 锁内短暂读取接口和 parent snapshot。锁图随功能
  增加而变长，relay/PXE/TFTP 再沿用它会扩大死锁和饥饿面。

曾经出现过实际的并发缺陷：UDP worker 在没有输入时仍持有
`parent_events`，然后 `park_timeout(20 ms)`；TCP accept worker 需要同一把
锁，导致 UDP 空闲时 TCP 请求超时。`f099ffb`/`d3eed76` 在等待前显式
`drop(event)`，受影响的差分才恢复。该失败仍保留在账本和
[ACTUAL_CONFIG_STAGE.md](ACTUAL_CONFIG_STAGE.md)；修复它证明的是当前锁边界
可以被修正，不是多线程架构风险已经消失。

## 方案比较

| 方面 | 回到单一事件循环（选择） | 保留多线程 |
| --- | --- | --- |
| 正确性风险 | 与 C 的 owner/poll 语义一致；DHCP lease、DNS cache、reload、UBus 回调在一个顺序化状态边界内，少了 snapshot 和锁顺序差异 | 每个 listener/连接都可观察不同 snapshot；新增 relay/PXE/TFTP 必须定义更多锁顺序、取消和退出协议。已有 UDP 持锁缺陷是直接证据 |
| 内存 | 一个事件循环栈和一组有界缓冲；可去掉 `Arc`、`Mutex`、client `JoinHandle` 及每连接线程栈，目标是收敛 392 KiB PSS 差 | M3 中 Rust PSS 中位数比 C 高 392 KiB，RSS 峰值最高 2,228 KiB；线程栈、锁、每 worker 缓冲和 TCP snapshot 是可见成本 |
| 代码复杂度 | 要把 TCP upstream、TFTP transfer、relay/PXE 等等待改成显式状态机；一次重构量较大，但状态所有权直接 | 当前接线简单地分 worker，但共享 owner、锁排序、join/reap、spawn 失败和 shutdown 路径复杂；每种新协议都增加跨线程边界 |
| 对 TFTP/relay/PXE | 所有 fd 由同一 poll owner 管理，可按 C 的事件顺序接入；广播、租约更新和 DNS publication 可在一个 tick 内排序 | 需要跨 worker 队列/锁来提交 relay 和 PXE 状态，TFTP 传输退出还要与全局 stop、FD 回收协调，扩大资源泄漏面 |
| 可并行性 | 单循环不能阻塞在上游；必须保持非阻塞和每轮公平预算 | 可同时服务 TCP client 和 DHCP，但关键 parent/cache 仍由 mutex 串行，M3 没有证明吞吐收益 |

多线程的潜在收益（把慢 TCP/upstream 等待与 DHCP 隔离、利用多核）尚未在
冻结的 M6 协议下测量，不能抵销已经量化的内存和并发复杂度成本。因此在功能
替换目标上选择单循环；性能收益只有在 M4 正确性门关闭后才可重新评估。

## M4 执行门

1. 先实现单一 poll owner 和有界的 DNS UDP/TCP、DHCP、TFTP 状态机；任何
   上游、文件或 UBus 等待都不能持有跨请求锁。
2. 用与 M2 相同的最终 release、镜像 C ELF 和配置重跑 `actual20`、
   `static-ethers`、`expiry120`、`ping-conflict`，并保留旧多线程结果和
   失败记录。
3. 以同一个 workload 先做 5 分钟试跑，再做 M3 资源对比；比较线程数、
   RSS/PSS、FD、租约/cache 走势和退出回收。未执行的逐线程栈采样不算完成。
4. 重新覆盖 SIGHUP、init reload、rpcd UCI apply、上游失败恢复、TCP 和
   DHCP lease publication；任何差异先修复并重跑受影响范围。单循环候选在
   这些门通过前不能进入 M4 APK 的可替换候选结论。

