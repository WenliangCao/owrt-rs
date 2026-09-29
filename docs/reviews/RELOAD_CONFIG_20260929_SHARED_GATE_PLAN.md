# reload-config：共享 ubus 消费者正式功能门结果

最终状态为 `COMPLETE_WITH_INTERRUPTION`：本轮重新构建的 7 个 canonical 消费者共 11 门全部通过。原采集在前 4 门通过后发生原因未明的控制中断；保留原始记录，核验身份和清理状态后只执行剩余 7 门。`functional_gates_passed=true`，原集合的 `passed=false` 与 `uninterrupted_collection=false` 保留，不能将其描述成一次连续通过。

脱敏逐门身份、日志 SHA、源码 SHA、恢复及清理结果见 [SHARED_GATES.json](RELOAD_CONFIG_20260929_SHARED_GATES.json)。该结果仅补本轮共享库变更的必要功能回归；未重开前七组件性能矩阵，也不代表整栈部署验收。

## Canonical 与隔离范围

`owrt-ubus` 新增显式取消和绝对 deadline 接口。已有消费者继续使用默认 `None` 回调；底层收发及连续可读时的截止检查共同编译，因此使用本轮实际重建的 ELF 验证，没有沿用旧 ELF 的通过记录。UCI 自身不依赖 ubus。

构建源码为 `43b98a138bea2b37713634c012a37a9d7186a20b`；[正式构建 36491554447](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36491554447) 成功。运行源码冻结于 `e106123`，逐文件身份写入私有记录。HTTPD、LOGD、FW4、RPCD ELF 与实际 APK、镜像中的文件一致；UBUSD、PROCD、NETIFD 使用同次 canonical 直接构建产物。无代码变化而 SHA 相同的产物也经过本次构建和实际功能门。

所有门在 Oracle Linux 主机串行运行，每门使用冻结 `ns-exec` 建立私有 namespace 和 loopback；未操作路由器。原镜像仍为 OpenWrt 25.12.5 `r33051-f5dae5ece4`，精确 C 依赖保留。RPCD apply/rollback 使用单独 rootfs 副本，仅将 `/sbin/reload_config` 替换为 marker；初始化和恢复时验证仅此路径不同，其他 helper 未替换。marker 只证明请求发生；真实事件投递由 reload-config 专项门验证。

## 实际通过项

| 消费者 | 门 | 结果与覆盖 | 边界 |
|---|---|---|---|
| UBUSD | `ubusd-r36`、`ubusd-r36-user` | 两种 daemon 身份下，真实 C CLI 对象、调用、通知、ACL/raw protocol transcript 一致 | 未重跑全性能矩阵或全部恶意协议模糊门 |
| PROCD | `procd-r65` | 非 PID1 服务生命周期、顺序事件、notifier 订阅差分通过 | 不涉及 PID1、watchdog、重启/升级验收 |
| HTTPD | `httpd-r14` | 61/61 请求一致，含 HTTP 与真实 C ubusd/rpcd JSON-RPC 回复/错误路径 | 未重测吞吐或 TLS 资源模型 |
| LOGD | `logd-r15`、`logd-reconnect` | 10/10 输出一致；ubusd 中断后重新注册，保留中断前、中、后记录 | 沿用门中的 kmsg 禁用策略；未重测性能 |
| FW4 | `fw4-upstream`、`fw4-image` | 31/31 上游规则用例；真实镜像 `print` 与 `check` 各成功一次，0 错误 | nft check 仅在私有网络 namespace；附带计时不作性能证据 |
| RPCD | `rpcd-r17` | session/ACL、UCI apply/confirm/rollback 等 283/283 步一致 | 独立 marker rootfs；不宣称实际服务已重载 |
| NETIFD | `netifd-r83-config`、`netifd-restart` | `r83_config_diff.sh` 的 baseline/dns/metric/route/rule/hotplug/rc 输出一致；C 与候选 restart 均验证延迟 reexec、同 PID/argv、对象恢复及服务可用 | 内核网络操作只在私有 namespace，非物理 Wi-Fi 验收 |

11 门均 `exit=0`，没有组件门失败或超时。HTTPD、LOGD 和 FW4 的数字分别表示请求、输出和上游用例数，不能相加成统一测试数。门执行时长只用于预算与故障诊断，不作组件性能对比。

## 控制中断与证据衔接

初始采集于 `2026-09-28T22:27:00Z` 开始，在 UBUSD 两门、PROCD、HTTPD 完成后控制连接停止推进。恢复审计证实原 runner 已消失，下一门 LOGD 尚未开始，无本轮遗留进程或挂载；原因没有确定，不能归因于 SSH/NAT，也不据此判定组件失败。

恢复前保留 `interruption-1.original-results.json`，SHA 为 `6862b155c535c3fb59e4bd62402c1bc5d6776f0a253afb21b684066551991719`；核对前四门命令、退出码、日志 SHA 与 canonical ELF 身份。镜像、源码、FW4 源码、输入和复制 ELF、输入和复制 helpers、manifest、namespace 源码及宿主 namespace 等 12 类身份检查全部一致。随后由独立 durable runner 于 `22:47:31Z` 接续尚未执行的七门，`22:49:09Z` 完成。

恢复结束的同 12 类身份检查全部通过。归档后再次校验全部 11 份顶层日志 SHA、每门实际/结束后 ELF SHA 和 namespace launcher SHA；与正式构建期望身份一致。最终 `results.json` SHA 为 `1fe5e59b2dbd76132e4618422d9df3621fad283fd95b0145ad98750452036f55`。原始记录、输出和日志保存在 ignored 私有目录 `private/reload-next-20260928/shared-functional-archive/`。

以 root 权限执行的结束后进程/挂载清查及再次只读复核均为 `owned_processes=[]`、`owned_mounts=[]`，原 runner 与恢复 runner 已退出。整个共享门过程未运行构建或正式性能测量；清理确认后已释放主机，供后续增量性能使用。

本轮共享库所需的限定范围功能回归已完成。原中断记录仍是结果的一部分；整栈部署、生产防火墙、物理 Wi-Fi 和设备生命周期验收均未由这些门覆盖。
