# FULL-PERF-TCP 修复的独立复核

审查对象是独立修复分支的 `936514cd` + `22fe5dd9a6539ef7381b0bab43b39786b0bceae7`，**不是把 main `e9d89b17` 的问题改写为已解决**。候选 ELF 为 `0ac4ad216c071ae708af52f5d4d4cd6e4c2130b451655033efc463888bff0834`，2,089,440 B。未修改产品、未访问路由器、未合并或推送。

**结论：原单地址 hosts 的 TCP 复制问题已实质修好，所测正常快照语义正确；整个资源问题不能完全关闭。** 新增多地址轮转用例仍会按连接复制整张轮转表，在较小内存预算下把整个 daemon 推入 OOM kill。不能以原用例通过就批准“所有 hosts 快照均只增加常量级连接开销”。

[完整派生结果](tcp-fix-review.json) 含每次新运行的身份、memory.events、逐连接内存和原始结果 hash。此报告与原报告的普通性能数据、另一 R2 修复身份分开。

## 一、尚未闭合：多地址轮转仍复制全局顺序表

**P1 资源故障残余（条件触发），已由本轮新测试复现。** 级别是共享 DNS/DHCP 进程被杀的后果，不表示家庭当前 hosts 数量会触发。不是宣称本修复比原 main 更差；原来的大规模无条件复制已经明显改善。

`22fe5dd9:components/dnsmasq/src/hosts.rs:397-411` 的 `rotate_shared` 在共享顺序表首次变为可写时，遍历 `self.rotations` 的**全部名字**并复制各自的 indices。`lookup:453-473` 即使只查询一个双地址名字，也会走这里。记录本体确实共享了，但接受时继承的全局轮转状态仍存在按连接放大的复制。

独立合成输入保持 **50,000 条 hosts 记录**，改为 25,000 个名字各有两个 A 地址。步骤：

1. 保留第一个 TCP 会话，使 records 进入共享状态。
2. 父进程通过 UDP 各查询 25,000 个名字一次，生成其轮转状态。
3. 再建立 19 个 TCP 会话，每个仅查询同一个双 A 名字一次并保持连接。
4. 检查客户端、父进程退出状态与 cgroup v2 memory.events；精确镜像 C 执行相同输入和顺序。

| 新测试 | 精确 C | 候选 `22fe5dd9` |
| --- | --- | --- |
| 64 MiB，默认轮转 | 20/20，UDP 正常；peak 15,007,744 B，OOM 0 | 20/20，UDP 正常；**peak 56,283,136 B**，OOM 0 |
| **32 MiB，默认轮转** | 20/20，UDP 正常；peak 14,602,240 B，OOM 0 | **第 9 个连接失败，daemon -9，UDP 失败；oom=1、oom_kill=1**；peak 33,554,432 B |
| 32 MiB，同输入仅加 `--no-round-robin` 定位负控 | 20/20，UDP 正常；peak 14,925,824 B，OOM 0 | 20/20，UDP 正常；peak 17,858,560 B，OOM 0 |

这不是笼统的“所有进程在 OOM 下都会死”：同输入、相同预算下 C 存活，候选在 32 MiB 下仍能完成 hosts 加载及前几个连接，查询顺序表的复制使其继续上涨到硬上限；关闭轮转后该候选也存活。64 MiB 用例把成本显式量化，没有把它误报成失败。源码和负控一致指向整表复制；没有采集 allocator 调用栈，不冒称定位了唯一具体分配指令。

实际影响：配置具有大量多地址名字且父进程已查询过这些名字时，一个新 TCP 会话的少量本地查询仍可要求与整张轮转表规模相当的额外内存；多个连接可拖掉同进程 DNS/DHCP。应保留接受时的可见顺序，同时让会话只持有自己实际改变的名字顺序，避免第一次轮转复制其它所有名字。**`--no-round-robin` 只是定位负控，不建议通过改变用户语义来规避。**

复现工具保留在电脑 `private/full-audit-20261014/tcp-fix-review/rotations_cgroup.py`、Oracle `/dev/shm/full-audit-tcp-review-20261014/rotations_cgroup.py`。必须通过 `run_isolated.sh`；参数 `--image-root /home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity/rootfs-check --rust <候选ELF> --output <新的private目录> --budget-mib 32`，加 `--no-round-robin` 运行负控。对应原始目录为 `private/rotations-cgroup`、`rotations-cgroup32`、`rotations-no-rr32`。

## 二、原反例修复成立

本轮用原审计的 `tcp_hosts_memory.py`、`tcp_hosts_cgroup.py` 重跑；只改工具 import 路径以使用隔离 rootfs helper，没有采用修复方自己写出的预期数据。

50,000 个单 A 名字时，进程树 PSS 为：

| 活跃 TCP 连接 | 精确 C | 候选 Rust |
| --- | ---: | ---: |
| 0 | 6,244 KiB | 24,048 KiB |
| 1 | 6,364 KiB | 24,064 KiB |
| 10 | 7,471 KiB | 24,280 KiB |
| 20 | 8,718 KiB | 24,512 KiB |

候选 20 个连接仅增加 **464 KiB**。基线原审计的大幅增长不再出现。相同 64 MiB cgroup 原反例中，两边都完成 20/20、UDP 正常；候选 peak **23,846,912 B**，memory.events 的 OOM 各项为 0。

另外独立重放修复方的 HUP 组合工具，事先审读其请求、旧/新答案和 cgroup 检查：保留 20 个 TCP，改写 50,000 条 hosts 后 HUP，再关闭其中 10 个、建立 10 个新连接。两边 20 条旧查询均为旧地址 `192.0.2.1`，10 条新查询均为 `192.0.2.2`；候选 peak **46,518,272 B**、OOM 0、UDP 正常。这里只证明该两代组合，不保证无限次 HUP、任意不同历史代数始终使用相同内存。

## 三、正常行为与源码审查

本轮在修复方快照工具上独立增加 IPv4/IPv6 PTR、ANY 与 hostsdir 删除路径，比较 **98 对完整 wire 和解码结果**，C/Rust 全部严格相同。覆盖：

- 两个已有 TCP 会话与 UDP 父视图的 A、AAAA、ANY 轮转各自独立。
- HUP 前接受的 TCP 保留旧正向/反向记录；HUP 后的 TCP 与 UDP 看到新记录。
- host-record 正常保留；hostsdir 原地替换及删除后，已有、新建会话与父进程分别保持正确代。
- PTR4、PTR6 与名字不存在的结果，不只是验证“返回过某个 A 地址”。

另独立执行实际 DHCP add、rename、release 三个已有调度，并在变化后新建 TCP 查询旧/新租约名，**17 对 DNS 语义严格一致**，含 flags、TTL、record 顺序和报文长度；比较仅排除测量时钟字段。每例保留 DHCP ACK/release 的 witness。该定向执行明确只有 3 个场景，未执行的全族 513 项不计为通过。

源码检查与行为结果相符：

- `Hosts::tcp_snapshot` 同时保存记录代、接受时顺序和 no-round-robin 状态；`try_clone` 会把当前 private 顺序折入新 forward indexes；结构修改通过 `writable_records` 生成独立代，PTR index 的 ID 重定位保留旧孩子的记录。
- `LocalDnsService.config` 改为 `Arc<DnsConfig>`；`publish_domain_interfaces` 只有真实地址集合改变时才 COW，避免每次 TCP accept 的接口刷新强制复制整份配置。server 源重建等真实变更仍发布新配置，旧 TCP 保持旧 Arc。
- DHCP LeaseNames、interface records 的 Arc 快照边界未被改成读取父进程最新状态；真实 add/rename/release 对照没有发现联动回归。
- **source_name**：初版 `936514cd` 确实删除了 source 0 的 `/etc/hosts` fallback，这会改变 map 没有该条目时的 source 日志/诊断契约；它不是改善共享快照所必需的变化。最终 `22fe5dd9` 已原样恢复 `or((source == 0).then_some(b"/etc/hosts"))` 并加入断言，当前候选不再包含该回归。普通成功读取仍会显式登记 source path；本项没有夸称所有 `/etc/hosts` 日志在初版都失效。

## 身份、证据与限制

冻结 `22fe5dd9` 的 dnsmasq/ubus 共 171 个源文件与修复方实际构建 source 逐项 SHA-256 匹配；候选 ELF SHA 独立校验后复制到本审计自有目录。**本轮没有独立重编译该 ELF**，采用了已核验身份的修复产物，所有本页测试结果由审计方重新执行。没有继承修复方的通过计数。

Oracle userspace 为已重新核验的精确镜像，内核 `6.17.0-1020-oracle`，不同于路由器。cgroup 是人工资源门限，不是现场可用 RAM 测量；没有全局 OOM、物理路由器、完整 APK、TLS/所有 DNS 族回归承诺。正常快照通过与残余轮转资源失败同时保留，不能互相替代。

原始数据保留于 Oracle `/dev/shm/full-audit-tcp-review-20261014/private/` 和电脑 `private/full-audit-20261014/tcp-fix-review/`；Git 中只保留派生报告/JSON。每个 cgroup 测试的 `cgroup_removed=true`；所有测试退出后再检查自有进程和挂载。后续新提交或综合修复需绑定新 ELF 重新验收，不能套用本页候选身份。
