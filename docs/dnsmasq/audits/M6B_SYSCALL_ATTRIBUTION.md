# M6b 系统调用归因（进行中）

2026-10-07。所有数字仅代表 Oracle 构建机。TCP方案A尚未进入主线；本次比较用于第1b事件分派修复。

## 第1b初版的有限收益

`d52d5cac`只做UBus请求gate、poll数组backing复用和logger pending gate。feature-off opt3 `2ef2360a…`、1,933,352B的单轮短基线保留全部稳态和饱和区间，不能把两区间CPU加总后除以正确数解释稳态：

| 稳态 | 镜像C µs/正确请求 | UDP-only386fa821 | d52d5cac |
| --- | ---: | ---: | ---: |
| TCP local | 27.434 | 45.722 | 45.679 |
| UDP hit | 11.955 | 24.533 | 23.639 |
| reload DNS | 20.610 | 51.022 | 48.261 |
| DHCP cycle | 456.072 | 1,754.624 | 1,550.191 |

这是单轮解释性结果，没有五轮W/4-of-5资格，不能称显著收益。两次C基线的DHCP差异也不可忽略。perf debug companion能解析`SinglePoll::step*`、`wait_for_files`和logger调用栈，但没有证明Metrics/UBus是主要成本。初版固定开销假设据此收窄。

## 首批strace观测

在精确镜像rootfs中串行运行C/Rust，daemon CPU0、上游CPU1、负载器CPU2、controller CPU3，`strace -f -c`覆盖C父子。每窗2s预热、15s负载、固定seed、20客户端，保留回答校验、退出与排空结果。跟踪显著扰动时延和CPU，这里的计数不作为性能窗口。

| 场景 | C calls/成功请求 | d52 Rust calls/成功请求 | C失败调用 | Rust失败调用 |
| --- | ---: | ---: | ---: | ---: |
| UDP hit | 3.000 | 4.394 | 0 | 51,296 |
| TCP local | 3.508 | 4.153 | 297 | 333,701 |
| reload | 3.336 | 13.779 | 2 | 137,684 |
| DHCP cycle | 81.000 | 869.447 | 0 | 187,680 |

分母是`warmup.correct + measurement.correct`，包括跨窗正确完成，不能只用15s窗口内正确数。旧hook在idle前attach、固定排空采样后detach，分子还包括idle/drain；因此这张表只表示诊断范围内摊销计数，不是精确formal每请求计数。`-c`的errors不保留errno，不能把每个错误直接称EAGAIN。后续hook将确认attach、限定scope、保留原始errno和unfinished/resumed，重新核实EAGAIN。

主要多余调用具有明确代码位置：

* TCP：`recvfrom`438,379次，其中270,231失败；`accept4`26,060次，24,380失败；无UDP业务仍`recvmsg`26,060次全部失败。
* reload：`recvmsg`85,913次，68,742失败；`accept4`34,456次全部失败。
* DHCP：`accept4`89,760次全部失败；`recvmsg`91,120次，89,760失败。还存在64,874次ioctl，需要单独归因，不由readiness错误解释全部DHCP成本。
* UDP hit：`getsockname`335,158次，恰为167,579个成功请求的两倍。关闭dump仍在QUERY/REPLY路径读取local_addr；精确C `dump.c:101–123`先检查fd/mask，Rust已以独立提交修正。

`main.rs::wait_for_files`原来只保存network/file/signal三类布尔值，随后`step`扫全部listener/TCP client。这支持按具体fd的revents分派，保留读写事件、error/hangup、时间到期、内部缓冲及尚未完成的文件工作。

## 中间实现与未通过门

`211ab618`增加UDP/TCP listener和TCP client的fd gate；诊断失败调用下降到UDP21,301、TCP256,282、reload85,750、DHCP8,160，全部原始结果保留。`12cbadce`进一步gate upstream completion，单窗改善仍有限。它们都未作最终资格。

静态审查发现新gate漏掉upstream retry/timeout deadline、TCP150s deadline和network_done日志回收、DHCP probe内部poll、TFTP pending MAC（active=0）以及DHCP地址dump续步。因此这些候选不得冻结，不得用它们作为方案A基线。另一次`856fee48`仅通过lib检查但Linux bin构建失败；`7396663d`修正编译，不冒称原构建成功。

下一步先完成完整readiness/runnable/timer合同，精确C功能/生命周期回归，再重测syscall和不插桩CPU。方案A以此后新freeze的R3/C作为对照，原M6a约20µs不再作为当前门槛。

原始证据：`private/dnsmasq-rewrite/evidence/M6B/oneb-baseline-d52d5cac`、`syscall-1b2-d52d5cac`、`syscall-1b2-211ab618`、`syscall-1b2b-12cbadce`；机械汇总`syscall-first-pass-analysis.json` SHA `53950eb692a1bbdeaf3bd85bb057214ee0f01af93cde67d405fc9d2e54756605`。失败、scope限制和后续结果在最终M6B报告一并保留。
