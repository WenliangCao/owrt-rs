# 受监护机制独立复核

结论：当前机制不能作为“监护进程中断后仍可靠回到 C”的试运行保障。存在一次普通监护 SIGKILL 就会留下无 DNS/DHCP daemon 的可复现窗口。其余正常故障路径能恢复 C，不抵消这个窗口。

本组仅在 Oracle 的独立 network/mount/PID namespace 中运行，未操作物理路由器、未修改产品或部署脚本。候选为最终 SDK ELF `0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`，控制器为 `83e8f1a3312e7583b319fc179af6795efae7354ffad5093ad881bd4639f6aef1`；ROM C、ujail、procd、ubusd、init、ACL、helper 均来自指定镜像。内核仍是 Oracle 6.17，不代表 AX3000T 的 6.12.94 内核或硬件。

## 发现

所有定向结果及原始文件 SHA-256 见 [independent-summary.json](independent-summary.json)。`failure_reproduced=true` 表示成功复现所查缺陷，不表示测试工具运行失败。

| 级别 | 发现与证据 | 实际影响及代码位置 |
| --- | --- | --- |
| P1，试运行阻断 | `c-attempt-crash`：正常手动 rollback 中，真实 `openat(/run/dnsmasq-deploy/c_attempted, O_CREAT…)` 返回后，单次 SIGKILL 终止监护。procd 的新监护进入 `recovery-failed`，`live_pid`/`live_sha256` 为空，daemon 列表为空；15 秒后仍如此。同一 syscall 执行前终止的负控 `c-attempt-before-crash` 正常恢复 C。 | C 启动尚未发生便被“已经尝试过 C”锁永久拒绝。`dnsmasq-deploy:130–133,145–146`。故障不要求 C、ubus、文件系统或第二个进程同时失效；这是回退事务自己的崩溃窗口。监护存活也不会再启动 C，必须人工恢复或重启。 |
| P2 | `c-tcp-connection`：健康 fallback C 接受正常 DNS TCP 查询并保持连接，`daemons()` 同时发现 C 主进程与其 TCP fork 子进程；两个 ELF hash 都是 ROM C。监护进入 `recovery-failed / c-identity-failed`；关闭 TCP 后仍为终态。独立客户端 DHCP OFFER/ACK、UDP/TCP DNS 均正常。 | 正常 C 协议行为被当成身份错误，停止正常监护，并使正常 `release` 被阶段门拒绝。`dnsmasq-deploy:32–50,336–339,470`。主进程身份验收须区分 C 的合法 worker，不能要求所有匹配 argv 的进程总数恰为一。 |
| P2，监护自身卡住的边界 | `guard-stopped`：只对监护 SIGSTOP，超过原始 180 秒期限 10.17 秒时仍是 `trial`，候选真实 ELF 仍运行，监护状态为 `T`。SIGCONT 后才因 `confirmation-timeout` 回 C，外部客户端恢复通过。 | procd 的 respawn 只处理退出，不检测存活但不前进的监护。`dnsmasq-deploy:228,264–381`。不能把 daemon SIGSTOP 测试等同于监护自身挂住也受保护；这个实验不推导所有 watchdog 必须无限递归监控。 |
| P2，状态表达 | `c-bus-repeat`：C 第一次 ubusd 重启可修复；第二次后两个 dnsmasq 对象均缺失，但 `phase=fallback`，只更新 `reason=bus-repair-exhausted`。C PID 稳定，客户端 DNS/DHCP仍好。 | 限制重启次数合理；但 fallback 阶段名不再表示完整的管理对象健康。`dnsmasq-deploy:373–376`。读 status 的流程必须识别降级；不能仅依据 fallback/ELF 宣称完整恢复。 |

### 其他服务

`services` 使用真实镜像 odhcpd，且它在 prepare/start 前已经运行。Rust 运行和 C 回退后均完成外部 DHCPv6 Solicit/Request、收到 Advertise/Reply，并通过 odhcpd 生成 hosts 的正常回调解析对应 AAAA。odhcpd PID 不变；初始 ubusd、logd、procd、netifd 进程仍存活。另一接口 `guard-wan0` 的独占 UDP/68 socket 在整个过程保持绑定，LAN 的 prepare/monitor 探针成功。这证实探针的 SO_BINDTODEVICE 不会仅因另一接口占用 UDP/68 就发生端口冲突；没有把这个 socket 实验宣称为真实 WAN 租约续租或 Wi-Fi 验证。

本轮未运行真实物理重启。磁盘上 stock C 保留、bind mount 与状态处于临时文件系统、没有持久 Rust 开机授权，支持“正常重新启动后回 stock C”的静态判断；它不是硬件断电/重启实测。

## 方法与复跑

复核工具为 `tools/dnsmasq/recheck_deploy_oracle.py`，复用现有隔离 rootfs/客户端 fixture。崩溃窗口通过 ptrace 在真实 guardian 的 syscall 入口/返回处投递 SIGKILL，没有替换 mount、ujail、procd 或修改脚本逻辑。前后 syscall 负控排除了“只要使用 ptrace 就失败”的解释。

工具经 `run_isolated.sh` 和 `actual_config_network.py` 调用，参数与原部署矩阵相同，追加 `--case`。本轮远端工具目录为 `/home/ubuntu/dnsmasq-recheck-guard-20261014/tools`，输出为同级 `private/<case>`。`c-attempt-crash` 的最终采样为 `private/c-attempt-crash-v2`，其他服务最终采样为 `private/services-v3`。结果中的 `raw_evidence` 给出精确路径与 hash。

校准过程透明保留：首次 tracer 在 SIGKILL 后多调用 PTRACE_CONT，内核返回 ESRCH，删去这个多余调用后重跑；首次 DHCPv6 客户端缺少 fixture 的 link-local 地址，改用已有完整客户端初始化后重跑。另一次 binary mount 日志窗口实验确实命中崩溃点，但 C 到达 `recovery-failed` 而非预期的 fallback，未完成原计划的 release 验证，故没有把“隐藏 mount 导致 release 失败”的假设列作发现。原始证据保留在 private，未将其冒充成功测试。
