# odhcpd-rs：真机隔离测量与有限试运行准备

当前仍运行 v0.2.3 与 C odhcpd。本文是待执行方案，不是设备验收结果。
本阶段不发布新版本或修改 v0.2.3 镜像。物理操作须在材料齐备后取得独立批准，
依据 `AGENTS.md` 的 “Never modify or flash physical router state without a
separate explicit user request and a verified recovery gate.”

候选源代码 `d0ef9f04d8533c174c5177301b3f479e11d6e4d0`；
[SDK CI 39078678256](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39078678256)
host/target 均通过，编译及未分类警告为零。SDK ELF 是静态 AArch64、790,640 字节，
SHA256 `79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`。
原型功能结果不能替代此精确 ELF 的功能、延时和内存门。

## 只读恢复材料核对

新导出的配置备份与 v0.2.3 完工备份逐字节相同：46 项、9,662 字节，SHA256
`b8702654472e3aec26c233e30f1ad2192e351d4d572965768c880c945562b650`。
备份中的 dhcp/network/system 内容与当前文件哈希一致，无试运行或 guard 成员。
现役与 ROM 的 C odhcpd 均为精确基线
`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
原 init、odhcpd-update 和 C ELF 已只读取回。私有材料位于
`private/odhcpd-20261018/pretrial-01/`；不会提交配置、客户端标识或原始报文。

## 隔离性能门

使用路由器上真实 C/SDK Rust ELF，私有 mount/net/PID namespace、只读根、
私有配置/ubus 和无物理端口的空 bridge。禁止把真实 WAN/LAN/Wi-Fi 设备移入
namespace，禁止安装模块、清全机 cache、改调频或 PGO。

路由器没有 Python，使用静态 C 仪器与 shell 驱动。先在 Oracle 证明同一工具的
隔离和收发成立；两份 ELF 的输入、进程启动顺序和静默间隔相同。
三对 C/C 校准后固定三对 C/R，交替先后；每指标噪声取 C/C 配对绝对差最大值
与两倍单调时钟量化的较大者。保留全部样本，任一明确变慢先停止后续试运行并
报告，不追加样本挑选结果。

记录首主动 RA、首 RS 回复、首 Solicit/Advertise、首 Request/Reply 和三 IA_NA
状态的 RSS。本机实际为三 NA；三 NA 加一 PD、前缀变更和 ubus 重连的四阶段
内存另有 Oracle 对照，均按 Rust 不超过 C 两倍判断。

两份 daemon 都关闭 multicast loop；空 bridge 内首主动 RA 用 AF_PACKET 读取
出站包。这测得实际发包到隔离内核捕获的时间，不能称为真实 Wi-Fi 客户端接收
时间。后续客户端健康检查另验证现网可用性。工具故障不算产品通过。

## 有限试运行

使用原 init 管理 odhcpd，tmpfs 文件 bind 到 `/usr/sbin/odhcpd`，只重启该服务。
原始 UCI、init 和触发脚本保留。试运行前校验候选、原 C、脚本、备份、当前 boot
和配置身份，并排除其他活动试验。先证明私有 namespace 中的真实 bind/unmount、
原 procd/init 启停和自动恢复，不用模拟成功输出替代。

独立 setsid guard 自己执行覆盖与启停，先设定 300 秒期限。SSH 断开不取消 guard；
超时、候选退出、显式恢复或验收完成均撤销 bind 并启动 C。确认表示本次有限
试验成功，随后立即恢复 C，不留下临时覆盖等待下一次操作。

客户端健康证据必须来自管理客户端，包括路由/地址、TCP DNS、绑定接口的
IPv4/IPv6 HTTPS、LuCI 及连续稳定窗口；沿用已记录的客户端 UDP DNS 限制，
不能把它写成通过。确认收据绑定 trial token、boot、候选 SHA 与外部证据摘要。
恢复后再次校验 C 的实际受管 PID/ELF、dhcp 对象、原配置及客户端健康。

固件、完整十一组件镜像集成和永久部署另有资格门；有限试运行通过不自动发布。
