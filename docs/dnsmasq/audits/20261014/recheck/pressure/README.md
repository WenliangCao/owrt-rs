# 1,000 QPS REFUSED 独立复核

**结论：已复现的是路由器连接跟踪容量压力导致上游发送失败，C 与 Rust 的
REFUSED 回退行为一致。不是 Rust 的 1,000 QPS 限速，也不是本轮发现的
Rust 特有协议错误。** 这不等于 1,000 QPS 零错误容量验收通过。

## 无跟踪的同负载、同配置对照

先用审计 C 原 Rust ELF `d17a392c…470e` 与镜像 C 重跑，再用最终 SDK ELF
`0d5a4769…dc728` 反向配对。原 `predeploy_resources.py`、window 脚本和
capture-helpers 未改：UDP 990/s、TCP 10/s、DHCP 完整周期 2/s；UDP 20 客户端、
TCP 2 客户端、bank=800、初始 128 条合成租约。每窗 20 秒 idle、20 秒 warmup、
120 秒 measurement、20 秒 post。每窗重启独立实例，不并行运行 C/Rust。

保留 cache=1000、EDNS max=1232、domain-needed、local/rebind 等全部审计 C
策略和相同的回环映射。仅独占目录、租约绝对到期时间和随机内核状态随运行
变化。[身份](identity.json) 包含原/最终产品与工具 SHA。

| 顺序 | UDP 发出 | 正确 | REFUSED | 计划槽跳过 | TCP 正确/发出 | DHCP 正确周期 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 原 ELF 配对 1：C | 118,789 | 118,788 | 1 | 11 | 1,200/1,200 | 240 |
| 原 ELF 配对 2：Rust | 118,798 | 118,772 | 26 | 2 | 1,200/1,200 | 240 |
| 最终 ELF 配对 1：Rust | 118,800 | 118,799 | 1 | 0 | 1,200/1,200 | 240 |
| 最终 ELF 配对 2：C | 118,794 | 118,773 | 21 | 6 | 1,200/1,200 | 240 |

四窗所有已发请求均无 timeout 或 transport_error；错误包全部是保持原 ID /
question 的 REFUSED。不是以验证器的 `wrong` 计数直接当作 RCODE。独立工具
重新解析全部错误包并核对二进制 latency 记录和计数，见
[原 ELF 配对](original-pair.json)、[最终 ELF 配对](final-pair.json)。

同配置不代表连接跟踪表的初始内容相同。没有清空生产共享的 conntrack，也
没有改其上限或超时；两个配对交换 C/Rust 顺序。两组中后跑的一侧错误更多，
不能从这四个小样本判断谁的拒答率更高。最终配对只读采样达到
`nf_conntrack_count=15360`，恰为 `nf_conntrack_max`，全窗 `drop` 增加 23、
`early_drop` 增加 6,085。共享计数不是单 daemon 私有计数，不把额外的一次
drop 强行分配给某个 DNS 包。

## 实际因果链，而不只是资源相关性

另做两窗诊断，配置与计划速率不变，仅客户端增加空 EDNS0 OPT，使 REFUSED
能携带 EDE；在完成原 socket 隔离检查后，将只读观察器附着到**指定测试 PID**。
不修改报文、不注入错误、不跟踪生产进程或 C 子进程。ptrace 改变调度，
诊断窗的延迟/吞吐不得当作性能对比。

| 诊断对象 | UDP 发出/正确 | REFUSED | 实际 syscall | 逐请求对应 |
| --- | ---: | ---: | --- | --- |
| 最终 Rust | 118,535/118,529 | 6 | 6 次 `sendto(127.0.0.1:15354) = -1 EPERM` | 6/6 为同问题、同发送至完成窗口内的 EDE23 REFUSED |
| 精确 C | 117,014/116,999 | 15 | 15 次相同上游 `sendto = -1 EPERM` | 15/15 为相同的 EDE23 REFUSED |

观察到的 socket/bind/sendto/sendmsg 失败全部是这 21 次上游 sendto EPERM，
没有混入 ENOMEM、EMFILE、bind 失败、转发表满或来自上游的 REFUSED。两侧
DHCP 240/240、TCP 1,200/1,200；UDP 无超时。诊断 UDP 跳过 265/1,786 个计划
槽，明确保留，不用实际较低发出数冒充无扰动的 1,000 QPS 性能数据。
见 [逐包派生结果](diagnostic-pair.json)。

相应内核记录为 `nf_conntrack: table full, dropping packet`。新 trace 同时
记录 MONOTONIC / MONOTONIC_RAW / BOOTTIME / REALTIME：不能直接把 DNS 客户端
的 MONOTONIC 与 dmesg 时间相减，它们在本次设备上相差约 108 秒。新 syscall
事件与内核 full 事件的 RAW 时间也存在约 4 ms 固定偏移；时钟分析单独说明，
不用错误的绝对时钟假设制造“同一瞬间”。

此外，在 Oracle 新 namespace 对**精确 C 与最终 Rust**的首个上游 sendto
分别注入 EPERM、ENOBUFS、ECONNREFUSED，每种各无 OPT/有 OPT，共 12 个故障
用例。两者错误响应逐字节相同：无 OPT 是 REFUSED；有 OPT 是 EDE23；后续
不注入的查询正常。每个用例有无注入发送序号校准。见
[发送故障对照](../refused_source/send-error-controls.json) 和
[源码解释](../refused_source/README.md)。因此，内核拒绝新的上游流后走本地
REFUSED，属于本次精确 C 已执行证明的相同行为。

## 原审计那批包的解释范围

旧 Rust 的 13 个压力错误和连续观察的 38 个错误，已保留完整 REFUSED 包。
本轮读取仍留在设备环形缓冲中的旧 conntrack full 记录，用新诊断时钟校准
作独立外推，并做事件顺序、一对一匹配和时间平移负控。51 个 Rust 旧错误
全部有强时间关联；旧 C 的 17 个 `wrong` 完成事件也有对应关联，但其错误包
没有保存，**不事后补判那 17 包的 RCODE**。

时钟外推、一个近邻事件歧义和原记录缺少 errno 的边界见
[独立时钟关联](../refused_source/historical-clock.md)。它支持旧 Rust 那批
REFUSED 与新复现同因；旧 51 包没有被追溯变成“当时逐包抓到了 EPERM”。
原因判断由新真机 syscall→具体请求→EDE23、内核 full、原事件关联及精确
C 故障对照共同支持。

## 对试运行和其他服务的意义

这项 REFUSED 本身不再作为 Rust 独有的试运行阻断；也不能改写成“压力测试
无错误”。连接跟踪表是全路由器共享资源，测试只使用回环并不使这项资源
私有。达到上限可能影响其他新连接；不能把生产健康检查通过写成全部业务
零干扰，更不能通过清空 conntrack 或调高生产限制掩盖错误。

原审计的 1.056 秒 TCP 计划发送长尾主要发生在发送前。本轮四个无跟踪窗
4,800 个 TCP 查询全部正确、无计划槽跳过，但没有专门记录原时刻的 connect
syscall，故不把那个历史长尾的唯一原因也宣布已定位。

三次正式运行共六窗、66 次生产健康检查均通过；生产 PID/starttime、ELF /
配置 hash 保持不变；最低 MemAvailable 103,876 KiB。每次回收均验证独占
目录已删除、测试进程为零、测试端口监听为零。没有停止或信号通知生产
dnsmasq，没有装包、写闪存、改防火墙/sysctl 或清空 conntrack。

首次新 watcher 因本机 Python 3.9 不支持 `zip(strict=True)` 在基线阶段退出，
尚未创建远端测试目录；修正复核工具后重跑，保留该尝试目录，不计为产品
失败或正式窗口。原始本地根为 `private/dnsmasq-predeploy-recheck-20261014/`。

复跑入口：原 `predeploy_resources.py` 执行无跟踪配对；
`recheck_resource_watch.py` 增加只读 conntrack 采样；
`recheck_resource_edns.py` 生成诊断客户端；watcher 的 `--observer` 只用于
诊断窗口。`recheck_pressure_analyze.py RUN --output JSON` 从私有原件重算
上述计数和逐包 syscall 对应；工具和构建输入 hash 见 identity。

[最终收尾](closeout.json) 重读 70 项本地私有证据身份，hash 零差异。最后只读
检查时，测试端口相关的回环 conntrack 条目也已自然回收为 0，全局条目 98；
没有执行网络状态清空。产品及部署文件对复核起点的 diff 为空。
