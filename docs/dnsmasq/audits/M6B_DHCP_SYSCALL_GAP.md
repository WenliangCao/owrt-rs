# M6b DHCP syscall 余差：只读归因

2026-10-07。结论：`6f3bed3d` 的 DHCP 余差主要来自重复接口元数据查询，不是 EAGAIN 探空。原始 trace 中 Rust 每包仍做一次新的 IPv4 dump，但对同一 `lo` 的 21 个 IPv4 地址逐条重复 `SIOCGIFNAME`＋`SIOCGIFFLAGS`；另有约 100 ms 一次的全接口 snapshot，每次对同一名字调用 22 次 `if_nametoindex`。这两类实际 syscall 合计 71,145 次，占 R3 相对 C 的 80,184 次余差的 **88.73%**。这是一次受控诊断的调用次数归因；没有修改产品、没有访问 Oracle，也没有证明消除这些调用后的 CPU 或延迟收益。

## 身份、原始来源与分母

被测产品源码 `6f3bed3de272162bf3cbbb0914de4c5367e324fb`；R3 SHA `5fe806fef0c07714f9674a7d768f4f57aab4ab6ad57a1f323177a51e429d97a7`，Rs `8ca7071cd01b5ed7914caa1d56288d3f82aba39c3653950b7ca7de3d988a1fb5`；C SHA `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。依据既有 `diag-6f3bed3d` 27 个有效诊断窗口中的 DHCP 三窗，不把它们称作正式性能窗口。

三侧原始命令相同：20 客户端、20 cycle/s、预热 2 s、负载 15 s、同 seed、`no-ping`、同 DHCP 静态地址/租期/接口/日志配置。`strace -f -C -ttt -T -s 0` 只跟踪 daemon；`-s 0` 隐藏字节载荷，但保留 fd、ioctl 码、接口名、family、flags、收发长度及返回值。scope 在启动/缓存填充以后、负载 launch 以前 attach，直到稳定排空才 detach；它包含 **40 warmup＋300 load＝340 个完整正确 cycle**、1,360 个 DHCP datagram。不能把全部 trace 次数除以正式段的 300，也不能把 `calls/cycle` 称作每秒吞吐或未插桩 CPU。

每 cycle 是 DISCOVER、REQUEST、renew REQUEST、RELEASE 四个请求，三个应答；RELEASE 不要求 ACK。三组 warmup/load 的 wrong/timeout/transport 均为 0，EAGAIN/其他 syscall errno 均为 0。配置了一个 `lo`，21 个 IPv4 地址（主地址＋20 个租约地址）和 `::1`；地址数量影响下列重复倍率，不能外推到所有部署。

本次独立从完整 plain trace 重新解析，结果逐 syscall 与原 `result.json` 和总分析表相等；selected input 的 SHA 与 archive manifest 逐一匹配，原归档的 `local_full_metadata_verified=true` 收据保留。可复现脚本和派生结果为 [analyze.py][script] / [analysis.json][analysis]，结果 SHA256 `104ad3715d843571e68f8d364ffe7a11cead56ce0b0c664afbad91afe0454ae0`。脚本还核验审查的 7 个 Rust 文件与冻结 manifest 的 SHA 一致；C 的 `dhcp.c/netlink.c/network.c` 与已应用 OpenWrt 补丁的来源逐字一致。

| 组 | 正确 cycle（warmup/load） | 完成 syscall | syscall/cycle | ioctl | ioctl/cycle | EAGAIN | 完整 trace |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| C | 340（40/300） | 27,600 | 81.176 | 5,440 | 16.000 | 0 | [C raw][c-trace] |
| R3 | 340（40/300） | 107,784 | 317.012 | 64,830 | 190.676 | 0 | [R3 raw][r3-trace] |
| Rs | 340（40/300） | 107,687 | 316.726 | 64,808 | 190.612 | 0 | [Rs raw][rs-trace] |

R3−C 是 +80,184 syscall（+235.835/cycle）；其中 ioctl +59,390（+174.676/cycle）。R3/Rs 的 packet 路径计数完全相同，余下 97 次总数差主要随全接口 snapshot 165/164 次及 allocator/租约写入边界变化；本单轮不能据此判 s 性能收益。

## 实际 ioctl 和接口查询账

| ioctl | C 次数 /cycle | R3 次数 /cycle | Rs 次数 /cycle | raw 中的来源 |
| --- | ---: | ---: | ---: | --- |
| `SIOCGSTAMP_OLD` | 1,360 /4 | 0 /0 | 0 /0 | C 每个 DHCP datagram 的接收时间；不为缩调用数引入新的时间语义差异 |
| `SIOCGIFNAME` | 1,360 /4 | 31,280 /92 | 31,280 /92 | Rust：28,560 次地址 dump 行＋1,360 ingress 名＋1,360 primary 名；全部 `lo` |
| `SIOCGIFFLAGS` | 1,360 /4 | 28,560 /84 | 28,560 /84 | C 只对 ingress 查一次；Rust每 fresh dump 的21行各查一次 |
| `SIOCGIFADDR` | 1,360 /4 | 1,360 /4 | 1,360 /4 | 每个 datagram 的当前 primary IPv4，三组相同 |
| `SIOCGIFINDEX` | 0 /0 | 3,630 /10.676 | 3,608 /10.612 | 165/164 次全接口 snapshot，各22次同 `lo` 名查询 |

Rust trace 有 **1,360 个连续 42-ioctl 块**，每块严格为 21 次 `SIOCGIFNAME`＋21 次 `SIOCGIFFLAGS`，均在 fd8（retained control socket）上，紧跟 fd9 的1596 B地址 dump datagram；首块为 R3 raw 第9–50行。三组都对每包发一次20 B `RTM_GETADDR` 请求，数据1596 B＋20 B `DONE` 各 peek/consume 两次，**C/R 都是1,360次新 dump**。没有发现 Rust 比 C 多做四倍地址 dump；余差在 dump 解析的元数据查询和异步续步开销。

Rust 另有 **165/164 个全接口 snapshot 块**。R3 首块 raw 第572–655行：新 AF_NETLINK socket →两轮 send/recv →读 `/proc/net/if_inet6` →22个 AF_UNIX socket／`SIOCGIFINDEX("lo")`／close三元组。R3这类块合计14,025 syscall（平均85/次，包含 allocator 的 mmap/munmap）；其中22次名字查询的三元组合计10,890。C同期没有此类新 socket/sweep。它是负载期间的重复工作，不是 attach 之前的启动成本。

| 可直接识别的组成 | C | R3 | Rs | R3 /cycle |
| --- | ---: | ---: | ---: | ---: |
| fresh IPv4 dump 次数 | 1,360 | 1,360 | 1,360 | 4 |
| dump 每地址 name/flags ioctl | 0 | 57,120 | 57,120 | 168 |
| 全接口 snapshot 次数 | 0 | 165 | 164 | 0.485 |
| 全接口 snapshot 内全部 syscall | 0 | 14,025 | 13,936 | 41.250 |
| snapshot 内同名 index查询的 socket/ioctl/close | 0 | 10,890 | 10,824 | 32.029 |
| `ppoll` | 1,360 | 8,160 | 8,160 | 24（C为4） |
| DHCP `getsockname` | 0 | 1,360 | 1,360 | 4 |

这里的组成有包含关系：10,890 已包含在14,025内；57,120属于总ioctl，不可再与64,830相加。71,145/80,184的88.73%仅是已识别两类 Rust-only 调用占总余差的比值，不能当 CPU 百分比。

`ppoll` 的实读形式：C为1,360次47-fd无限等待；Rust为1,360次47-fd等待＋2,720次49-fd等待＋4,080次1-fd零等待。每包3次主 wait及3次 `has_input` 检查，与“发送 fresh dump、数据、DONE 各推进一轮”的非阻塞状态机相符。该设计保留服务进展，额外20 poll/cycle不等于忙等/EAGAIN；若改为消费每个就绪 netlink datagram的有界续步，须继续保持 fair budget、TERM/reload、完整dump发布和EMFILE合同。

## 精确 C 合同与 Rust 调用链

行号按冻结 `6f3bed3d` 内容，不使用后续main变化后的行号替代。

| 边界 | 精确 C 源码 | Rust 冻结源码 | 必须保留 / 可避免的部分 |
| --- | --- | --- | --- |
| 每 DHCP 包的 ingress 名与 flags、primary 地址 | `dhcp.c:244–246,263–275,319–327`；`network.c:19–36 indextoname` | `dhcp/runtime.rs` 从 sender取得 ingress name；`net.rs:395–415 interface_name`；`dhcp/daemon.rs:1733–1742`、`interfaces.rs:65–80 primary_ipv4` | 必须保留 packet时刻的 ingress/bridge/primary/loopback语义；同一packet重复查询名称可考虑复用已捕获名字，bridge改索引时另取正确名字，不能跨packet长期缓存 |
| 为 context/relay/select_secondary获取 fresh全部地址 | `dhcp.c:352–364,591–684 complete_context` → `netlink.c:154–258 iface_enumerate(AF_INET)` | `main.rs:5527–5540` → `dhcp/daemon.rs:927–949 prepare/finish_packet_interfaces` → `interfaces_ipv4.rs:148–255 advance` | 这是每包必须刷新的合同，两侧实测均1,360次；`finish_packet_interfaces`清掉旧snapshot。不能通过延长跨packet缓存减少dump次数，也不能发布部分dump |
| 对dump行读取flags | C `netlink.c:234–258`从IFA_LOCAL/prefix/broadcast/label直接调 `complete_context`，这里不做每地址link flags/name ioctl | `interfaces_ipv4.rs:244–250 decode` → `:329–331 address_row` → `:388 flags(index)` → `:271–280 interface_flags`；每个row做一次name+flags | 21行来自同一ifindex。最小候选是在**同一次完整fresh dump**内按ifindex共享name/flags结果；不复用到下个packet/代际。不得直接删除UP/loopback检查，先核对实际down-link、删除/重建、rename等caller合同 |
| 主loop的全接口刷新 | C `dnsmasq.c:1225–1235` prime/reset、按事件按需调用；`network.c:722–747`每poll cycle latch，`:834–847`具体枚举；本窗没有全枚举 | `main.rs:1636–1638`无条件每100ms `listeners::snapshot()` → `listeners.rs:7–10` → `interfaces.rs:157–205 dns_interfaces`，每addr `if_nametoindex(:187)`＋`tentative_addresses(:210–216)` | hotplug/地址/标签/DAD/ACL/relay/listener更新必须保留；固定100ms全扫描本身不是C合同。可先在一次snapshot内按相同linkname复用index，或以route/link/address通知和实际pending timer驱动刷新，不能仅按“本窗静态”跳过所有更新 |
| 单owner非阻塞fresh dump | C `netlink.c:200–258`同步读到DONE后调用caller | Rust `interfaces_ipv4.rs:137–145`一次send或datagram、`main.rs:5530`准备后再consume DHCP | 不阻塞其他服务是既有明确差异；不要为匹配C的低poll计数恢复阻塞。可携带当前dump等待与 `has_input` 已确认状态，减少重复零poll，但要证明多listener/PXE/pending-send/信号边界 |

地址行 flags 的一次dump内 memoization，仅用当前窗口结构做算术估计：若21行仍逐行输出、每个不同ifindex的flags/name只读一次，则减少 `1360×(21−1)×2＝54,400` ioctl，即160/cycle。周期snapshot若22次同名index查询保留一次，可少 `165×(22−1)×3＝10,395` syscall。两项合计64,795＝总余差的80.81%。**这些不是已测收益**，没有实现、没有CPU或功能验收；不同interface数/别名标签/更长dump会改变规模。

## M6b报告应保留的差距与后续候选

优先次序按本次调用次数的机制证据排序，不将它写成收益已关闭：

1. **fresh dump内的同ifindex name/flags重复**：57,120次ioctl、每包42次连块。候选按dump代际memoize接口元数据，保留全部地址顺序、当前packet上下文与完整发布；须过精确C DHCP网络/alias/bridge/shared/leasequery/relay、down/rename/hotplug/EMFILE及公平性回归。
2. **100ms全接口snapshot的同名if_nametoindex**：3,630次AF_UNIX socket、同数ioctl、同数close，加固定snapshot其余开销。先消除一次snapshot内重复name→index，不引入跨代际cache；进一步事件驱动替代periodic需证明route错误/丢事件恢复、DAD、bind-dynamic、local-service/ACL和DNS/TFTP共享owner，不因静态负载省略这些语义。
3. **fresh dump续步的has_input/poll重复**：8,160 vs1,360 poll，EAGAIN=0。可以有界推进当前就绪datagram或保留readiness见证，仍要每轮让出其他服务；调用数优化不等于应删除非阻塞合同。
4. **小项**：每包 `getsockname`来自 `dhcp/service.rs:662–668 OwnerSender.dump_source`，本窗dump关闭仍有1,360次；可像DNS路径按dump真正启用gating。broadcast回复的680次`setsockopt(SO_BROADCAST)`也在startup已配置后重复；`dhcp/runtime.rs:69–83`对应发送准备，未来单独核对socket状态/失败合同。它们只占余差的小部分，不能掩盖前两项。

无需为了本次报告修改产品或补新正式窗口。M6b最终CPU、延迟和s选择只看新的无ptrace正式冻结；本派生报告作为“仍未解决差距/下轮候选”引用。单轮C/R3/Rs顺序、17秒warmup+load scope和21个IPv4地址样本无法提供组内波动阈值，也没有路由器数据。

[script]: ../../../private/dnsmasq-rewrite/evidence/M6B/dhcp-syscall-attribution-6f3bed3d/analyze.py
[analysis]: ../../../private/dnsmasq-rewrite/evidence/M6B/dhcp-syscall-attribution-6f3bed3d/analysis.json
[c-trace]: ../../../private/dnsmasq-rewrite/evidence/M6B/diag-6f3bed3d/archives/r01-dhcp-lease-c/attempt-1/plain/formal/strace-syscalls.log
[r3-trace]: ../../../private/dnsmasq-rewrite/evidence/M6B/diag-6f3bed3d/archives/r01-dhcp-lease-r3/attempt-1/plain/formal/strace-syscalls.log
[rs-trace]: ../../../private/dnsmasq-rewrite/evidence/M6B/diag-6f3bed3d/archives/r01-dhcp-lease-rs/attempt-1/plain/formal/strace-syscalls.log
