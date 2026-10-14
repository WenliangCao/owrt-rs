# dnsmasq 全面审计：资源、失败边界与性能证据

日期：2026-10-14。基准：`e9d89b17d72a58b723cce88038ceaa1be58d7f8c`。
本分项没有修改产品代码、没有推送、没有操作物理路由器。所有新运行均在
Oracle 独立 network/mount/PID namespace；行为对照是精确镜像 C ELF。

**结论：当前 main 的主要资源问题是内存失败边界与 hosts/TCP 快照成本，
不是普通家庭负载下 CPU 不够。** 两种不同的内存压力都能使整个 Rust
daemon 消失，同条件下精确 C 仍服务。第二项已从源码疑点推进到无压力
PSS 扩展曲线和相同完整服务内存预算下的真实 OOM 对照。

## 身份与新执行范围

| 对象 | 本轮实际身份 |
| --- | --- |
| 精确镜像 C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| fresh main Rust | `e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`，2,073,056 B |
| 构建 | Rust 1.98.1，匹配 SDK linker，AArch64 musl static PIE，opt3/LTO/codegen-units=1/panic abort |
| 源码 | 对 main 做 `git archive`；产品目录与 `807db8a1` 无 diff |
| `components/dnsmasq` Git tree | `5fea0d89d5c14738e7af3db2fa4eb035dc02dd7f` |
| `components/ubus` Git tree | `dbdb549834a87e8f66d82e43bbceba36de586e23` |
| Oracle | AArch64 Neoverse-N1，Linux 6.17.0-1020-oracle；不是 Cortex-A53 真机 |

这是 fresh SDK-linker Cargo 产物，**不是新打包 APK 的包内身份**；本轮没有
重跑 SDK sstrip/APK 打包。保留的 `0d5a4769…` 包内 ELF 是另一实际文件，
不得因为源码相同就混用 SHA。为避开 Oracle 根文件系统接近满盘，独立
target 使用 `/dev/shm/full-audit-perf-20261014/target`，没有删除旧证据。

fresh test-profile 新运行：lib **784 passed / 20 ignored**，main binary
**78 passed / 3 ignored**。另明确补跑 `oracle_build.sh tests` 未包含的
`tests/hosts_allocations.rs`，**5/5 passed**。没有把 23 个 ignored 算成通过，
也没有把这些测试通过当成整 daemon 无 OOM 的证明。

构建收据、脚本散列、原始 JSON 散列及全部派生数值见
[performance-summary.json](performance-summary.json)。源码归档、ELF、stderr、
strace 与完整逐进程采样留在本地 `private/full-audit-20261014/perf/`
及 Oracle `/home/ubuntu/full-audit-20261014/private/`。

## 按严重度排列的发现

### P1：合法 hosts 重载遇到资源不足，仍中止共享 DNS/DHCP daemon

这是旧 B1/R2 的**当前 main 残余**，不是本轮新引入的回归。用 fresh ELF
重新执行已提交的 `recheck_hosts_limits.py`：初始 2,000 条正常 hosts，
分别把每侧 `RLIMIT_AS` 设为其自身 `VmSize + 1 MiB`，然后 HUP 重载
30,000 条正常 hosts。

| 项目 | 精确 C | fresh main Rust |
| --- | ---: | ---: |
| 初始 VmSize | 1,556 KiB | 3,428 KiB |
| 观测 ENOMEM 次数 | 18,036 | 23,848 |
| 测试清理前进程状态 | 存活 | **SIGABRT，exit -6** |
| 解除限制、HUP 后 UDP/TCP | 均正确解析 `recovered.test` | 进程已退出，无法恢复 |

主审此前的最终包对照在同一点已复现 3/3；本轮新增一次 fresh main 配对，
结果一致。实际后果是 DNS、DHCP 以及同进程的其他服务全部停止，必须依赖
外部重启/回退恢复；不只是忽略某条 hosts 或一次查询失败。

源码中 `Hosts::try_insert`、`Hosts::try_clone` 确实已经使用 fallible
reserve；`main.rs:3201–3211` 也尝试保留旧视图。但整个 reload 仍经过
`main.rs:3191–3194` 的 notice 转日志，以及
`logging/startup.rs:4–8` 的 `to_vec` / `extend_from_slice` / `format!`
等不可失败分配。局部 fallible 容器不等于完整错误路径已安全。本分项的
strace 没有分配调用栈，因此**不把这几行静态线索冒称本次 SIGABRT 的唯一
根因**；其他独立修复任务的定位应另行绑定其证据和修复提交。

建议修复单位是完整 reload 事务及其诊断/恢复路径：失败时保留一个可用
发布视图；处理失败和记录失败也不得再依赖可能 abort 的分配。应覆盖初始
集合大小、连续失败、发布与恢复均失败、日志目的地和 TCP 既有快照的交错。
本轮 5 个局部 allocator tests 全通过而整 daemon 仍退出，正说明需要服务级
故障注入。不能把单一 headroom 的成功当作通用安全阈值。

这是合成资源压力，不证明当前少量家庭 hosts 会达到此限制，也不估计现场
发生概率。原始结果：Oracle `private/hosts-oom-1/result.json`，本地索引和
精确 strace 散列在派生 JSON 的 `hosts_reload_enomem` / `raw_evidence`。

### P1（配置规模条件触发）：每条 TCP 连接深复制 hosts，少量正常连接即可耗尽服务预算

`main.rs:5410–5415` 在每次接受 TCP 连接时执行
`parent.local.config.clone()` 和 `parent.local.hosts.clone()`。
`hosts.rs:74–80` 的 derive Clone 会复制 entries、名称索引、每名的 Vec、
反向索引及 non-terminals，而不只是增加一个共享引用。动态 DNS cache
已采用分块共享，这项成本仍独立存在。默认 TCP 上限是 30
（`config/scalar.rs:61`），连接可存活 150 秒（`main.rs:5481`）；单纯限制
连接数未按配置规模限制快照字节数。

新测试仅使用合成 `addn-hosts`，cache-size=1000，正常 `-k` 模式。每条
TCP 连接查询一次很短的 `ready.test A` 后保持连接。C/Rust 输入相同；
C 统计整个父子进程树的 **PSS**，避免重复计算 fork 共享页。镜像 C 的
matching source `src/dnsmasq.c:2124` 使用 fork；失败会关闭该连接回到父
服务，已有 hosts 页先共享。

| hosts 条数 | 无 TCP，C / Rust PSS KiB | 20 条 TCP，C / Rust PSS KiB | Rust 连接增量 |
| ---: | ---: | ---: | ---: |
| 0 | 1,212 / 2,032 | 3,589 / 2,544 | 512 KiB |
| 1,000 | 1,324 / 2,492 | 3,625 / 8,192 | 5,700 KiB |
| 10,000 | 2,232 / 6,792 | 4,536 / 51,424 | 44,632 KiB |
| 50,000 | 6,244 / 24,060 | **8,631 / 227,632** | **203,572 KiB** |

50,000 条独立重复：C 无连接/20 连接为 6,240/8,709 KiB，Rust 为
24,024/227,596 KiB。即每条连接约新增 9.94 MiB；20 条正常连接后的
Rust PSS 约 **222.3 MiB**，已接近 AX3000T 实测 233.4 MiB 整机 RAM。
此处只是量级比较，不把 Oracle PSS 当作路由器实测值。

进一步给**整个服务进程树**相同 cgroup v2 `memory.max=64 MiB`、swap=0，
将控制器留在 cgroup 外，仍用同一份 50,000 hosts：

| 项目 | 精确 C | fresh main Rust |
| --- | --- | --- |
| 正确完成并保持 TCP | 20/20 | 前 4 条正确；第 5 条失败 |
| 完整服务 cgroup memory.peak | 10,797,056 B | 67,108,864 B（达到上限） |
| memory.events | oom=0 / oom_kill=0 | **oom=1 / oom_kill=1** |
| 清理前进程 | 存活 | **SIGKILL，exit -9** |
| 后续 UDP 查询 | 正常 | **无响应** |

这不是对 Rust 单进程加限制、放任 C 子进程不计成本：所有 C children
均在同一 cgroup 中。没有洪泛、畸形报文、超大回答或达到 TCP 连接数上限。
内核 OOM 限于任务私有 cgroup，未向 Oracle 整机或物理路由器施加内存压力。

因此大 hosts/blocklist 场景下，普通并发 TCP 就能把单连接准入成本扩大成
整个 DNS/DHCP 服务故障；增加其他九个常驻组件会进一步压缩实际可用余量。
当前家庭配置并没有 50,000 hosts，**不声称当前配置用五条 TCP 就会崩溃**。
64 MiB 是故障对照预算，不是推定路由器给 dnsmasq 的真实硬限制。

建议把不可变 hosts 数据/名称索引与每连接可变轮转状态分开，保留 C 的
accept 时快照语义，同时避免接受连接就全量深复制；准入分配失败应只拒绝
该连接。不能直接让所有连接共享可变轮转索引而破坏旧 TCP 视图，也不应把
降低全局 TCP 上限当作根治。回归应交叉覆盖 hosts 数量 × 连接数 × HUP，
同时验证 PSS、父服务 UDP/DHCP、既有快照与失败后恢复。

收尾后 Rust 在 50,000 条场景的 PSS 从 227,632 降到 28,172 KiB，FD 恢复
10 个；C 回到 6,248 KiB、9 FD、一个父进程。**这是并发峰值和存活期问题，
本实验不证明存在永久泄漏。** 一个 500 ms 排空点也不能证明长时间 allocator
驻留上限。工具：[tcp_hosts_memory.py](tcp_hosts_memory.py)、
[tcp_hosts_cgroup.py](tcp_hosts_cgroup.py)。

### P2：既定交付体积预算仍未达到；暂时替换成功不等于成本目标通过

fresh main ELF 为 **2,073,056 B**，精确镜像 C 为 **269,305 B**，约为其
7.70 倍。现有最终 SDK 包内 ELF 2,071,323 B、APK 1,126,561 B，也仍超过
既定 1,000,000 / 700,000 B 体积门，见
[最终上线前复核](../../PREDEPLOY_RECHECK.md)。当前产品与该最终包产品目录
无 diff；本轮没有生成新 APK，因此不声称 fresh APK 大小已测。

实际影响是更大的下载/存储/tmpfs 暂存及映像驻留成本；它不是立即耗尽 RAM
的证据，也不能把 ELF 文件大小与映射 RSS 再相加。普通家庭实测余量充足，
所以不应仅凭体积否定试运行；但若继续沿用原项目验收目标，就必须明确优化
或由负责人修订目标及理由，不能默默把红门当绿门。新优化不得牺牲现有
报文兼容性、static PIE/RELRO 等保护或把未支持选项静默忽略。

## 普通性能：哪些结论有证据，哪些没有

[真机资源报告](../../PREDEPLOY_AUDIT_RESOURCES.md) 的原始方法与限制基本
可信：成对单实例运行，生产健康门，正确性错误单列，CPU 包含 C children，
区分 RSS 与物理 RAM，保留发送前排队时间。它测的是 `58365e8c` / `d17a…`
ELF，不能直接改标签为本轮 fresh main 性能。

| 旧真机已测条件 | 可以用于判断量级的事实 |
| --- | --- |
| 20 DNS QPS + 0.1 DHCP 周期/s | Rust 比 C 多 1,276 KiB 主进程 RSS；额外整机 CPU 0.171 个百分点；UDP p95 增加 0.312 ms |
| 1,000 DNS QPS + 2 DHCP 周期/s | Rust 单核 CPU 27.679%，C 19.133%；只是该负载的测量，不是饱和上限 |
| 约九分钟同 PID 周转观察 | 排空后 RSS/匿名内存未持续上升；不足以证明数天或数周无泄漏 |

这些数字支持“常见家庭配置的 CPU/短期内存余量够用”，不支持“Rust 全面
更快/更省”。原始压力 REFUSED 后来已有精确 C/Rust errno 对照和设备
conntrack 事件定位为共同网络发送失败，见
[压力复核](../../PREDEPLOY_RECHECK.md)。不能继续把它列为未解释的 Rust
独有容量缺陷。约 1.056 秒发送前 TCP 长尾仍没有原时刻 connect 跟踪，不能
把其唯一原因也写成已经查清。

[旧 SDK 的 63 窗三方复核](../20261014/fix4/performance/README.md) 有完整
身份、Latin-square 顺序、cgroup CPU 和正确性计数，能支撑其限定的
“所测负载没有新增合并阻断”。但它是旧 SDK SHA、Oracle、短窗和部分场景，
不能当完整替换资格。尤其其 50,000 host-record 启动内存只是**零/少量
连接状态**，与本轮发现的 hosts × TCP 并发峰值不同。

没有发现足以否定上述原始配对方法的新证据；需要纠正的是外推范围和最终
资格的表达。原 [PERFORMANCE_PROTOCOL](../../PERFORMANCE_PROTOCOL.md)
要求 CPU/操作、私有内存、尾延迟、吞吐及较长稳定窗口；当前材料并未证明
全部目标对最新 main、实际设备和完整十组件共存均通过。

本轮没有新造一套短 CPU 窗去替代完整协议：Oracle 同时有独立修复构建，
不满足独占负载条件。本次 PSS/cgroup 测试不报告 CPU/延迟比例，因而没有
把并发编译噪声写成性能回归。需要正式性能结论时，应对最终同一 ELF
重新冻结输入、清楚排除外部负载，并保留全部失败窗。

## 排除项、覆盖限制和复现

额外检查了 UDP 多 listener 的饥饿疑点：约 130 万 UDP 包/s 持续洪泛一个
绑定地址时，Rust 优先 listener 可以挤掉另一个地址的进度；交换地址后，
精确 C 在其优先顺序下同样发生。低负载前后查询正常。故本轮把它记录为
**共同极端过载边界**，不列为 Rust 独有发现，不用成功率差声称容量排序。

已审查单 owner 的 UDP 每轮预算、TCP 有界进展、动态缓存分块共享、连接
关闭后 cache/FD 释放、helper 有界 IPC 背压、reload 发布和恢复路径。
没有把所有 `clone`、`unwrap` 或 FFI 警告直接报告成 bug；没有实证的 DHCP
普通分配失败、所有配置组合、长期运行与内核全局 OOM 边界仍属未覆盖。

重现本轮新内存结果，使用全新的输出目录；以下目录含当前源码工具和 ELF：

```sh
base=/home/ubuntu/full-audit-20261014/private
image=/home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity-final/rootfs-check
sudo -n sh "$base/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$base/tcp_hosts_memory.py" --image-root "$image" \
  --rust "$base/release/dnsmasq-rs" --output "$base/new-tcp-hosts-memory"
sudo -n sh "$base/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$base/tcp_hosts_cgroup.py" --image-root "$image" \
  --rust "$base/release/dnsmasq-rs" --output "$base/new-tcp-hosts-cgroup"
sudo -n sh "$base/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$base/source/tools/dnsmasq/recheck_hosts_limits.py" \
  --image-root "$image" --rust "$base/release/dnsmasq-rs" \
  --rust-sha256 e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0 \
  --initial-rows 2000 --headroom-kib 1024 --output "$base/new-hosts-oom"
```

两个私有内存 cgroup 均确认已删除；namespace 退出后没有宿主挂载残留。
所有本分项测试 daemon、客户端、flood generator 均已退出。源码、ELF 与
原始证据保留；可再生 build target 位于任务私有 tmpfs。没有触碰物理
路由器，设备恢复核验由主审单独报告，不能由本分项的 Oracle 清理代替。
