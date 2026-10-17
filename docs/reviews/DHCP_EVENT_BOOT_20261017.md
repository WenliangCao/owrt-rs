# DHCP 事件层：v0.2.2 现有开机日志测量

后续已获准一次重启，使用 `logread -t` 取得原始毫秒时间戳；新结果见
[一次重启测量](DHCP_EVENT_REBOOT_20261017.md)。以下保留首次不重启采集的证据边界。

**开机日志已不在保留窗口，无法裁决 `<2 s && <100 ms`。本轮不启动替换实现。**
现存 50 分 33 秒运行期日志有 168 条防火墙重载触发记录、101 条 WAN 租约取得记录；
这些不是开机统计，不能用来判断 DHCP 事件层是否值得优化。

## 测量前约定

仅采集当前启动的 `logread`，不重启、不触发 DHCP/接口/防火墙重载、不改设备。
先核验现有离线配置、完整设备备份、现役镜像和 v0.2.1 回滚镜像；
原始日志留在 Git 忽略的 `private/dhcp-event-boot-20261017/`，只提交派生结果。
本轮测完先汇报，不开始 DHCP 脚本替换或 odhcpd-rs 实现。

成本模型：开机到联网的关键路径由内核/驱动、服务初始化、链路与租约等待、
DHCP 事件脚本及 netifd 通知、后续防火墙/DNS 配置组成；并发工作不能直接相加。
现有部署记录中 netifd 在开机 22.82 s 启动、最终 dnsmasq 在 29.26 s 启动，
不能从这两个进程起点推出脚本耗时。其余分项是本轮未知数。
待推翻的预测：WAN lease→up 日志落在同一个秒桶；若跨秒或出现多秒脚本起止证据，
则需要改变“事件层可能很小”的判断。该预测不等于预先认定小于 100 ms。

最小决策效应为脚本合计 2 s、WAN 单次事件 100 ms。按研究指引，后者需要
不大于约 33 ms 的有效分辨率，且必须有正确的起止边界。先检查日志完整性、
时间戳精度和开机校时，未记录的耗时标作未知，不记为零。
现有开机日志最接近真实目标且只需一次只读采集；离线重放不能代替开机路径，
加探针重启超出本轮范围，所以不做这些实验。不存在候选叠加或性能筛选。

放弃条件严格为 `脚本合计 <2 s && WAN 单次事件 <100 ms`；缺失测量不算通过，
也不算达到优化门槛。不单独替换 jshn/jsonfilter/ubus CLI/logread。

## 结果

2026-10-17 19:02:24 UTC 通过现有 `openwrt` SSH 别名执行一次完整 `logread`，
另取一次 `logread` 用法输出。设备上未执行其他采集命令、写文件、重载、重启或刷写。
日志共 **1,101 行、136,785 B**，SHA256：
`a67d178a19f01b4a047fe895a09b48c38cf56c3335d39228fbe18fa2dd59fc27`。
原件：`private/dhcp-event-boot-20261017/logread.txt`，0600；未提交原始日志或客户端标识。

日志显示时间为 **2026-10-17 20:11:51–21:02:24**，跨度 **3,033 s**。
没有内核记录、开机标记、WAN/WAN6 的 `is now up` 或 dnsmasq `started, version`。
首尾均为运行中的 SSH 记录。该窗口晚于已有 v0.2.2 部署/启动阶段；
现有环形日志不含所需开机过程。已检查永久部署目录及 preflash 日志，未找到开机
`logread` 转储；`guard-evidence.tar.gz` 为离线资格收据，不能当作这次真机开机记录。
本次未额外读取 boot ID 或安装文件身份，版本背景来自已验收的
[v0.2.2 部署记录](DEPLOYMENT_V0_2_2_20261017.md)。

| 请求指标 | 本轮结果 | 原因 |
| --- | --- | --- |
| 开机防火墙重载次数及耗时 | **未知** | 开机窗口缺失；现存 168 条均为 `Reloading firewall due to ifupdate of wan6 (wan)`，没有配对结束记录，不能计成功次数或耗时。 |
| 开机 dnsmasq 重载次数 | **未知** | 现存日志启动、退出、显式 HUP 记录均为 0；仅有一次 DHCPDISCOVER/OFFER/REQUEST/ACK 的 4 条记录。不能把“未保留”写成“重载 0 次”。 |
| WAN 首次获得租约→接口 up | **未知** | 有 101 条运行期 `lease ... obtained`，没有对应首次 up，无法配对。 |
| 脚本耗时/开机到联网总时长 | **未知** | 脚本执行起止、开机起点和首次客户端联网边界均缺失，分子分母都不能还原。 |

默认 `logread` 显示到秒，分辨率也不满足 100 ms 的判定。logd 底层保存
CLOCK_REALTIME 毫秒（[实现](../../components/logd/src/main.rs)），但这不等于本次
文本有毫秒，更不能补回已覆盖记录。没有用额外 ubus 调用、当前运行期续租或离线
计时替代指定的开机测量。相邻防火墙触发间隔不是重载耗时；lease→up 即使可配对，
也包含 netifd 配置/调度，并非纯脚本耗时；接口 up 不等于客户端已联网。

## 备份与回滚准备

在 SSH 前重新逐 SHA256 验证 **14 个离线原件全部通过**：历史完整备份 10 个文件
（含 Factory 校准）、v0.2.2 干净配置、现役镜像、v0.2.1 回滚镜像、TFTP 救援镜像。
将已有干净配置复制到本次私有目录并再次核验；**没有声称重新取得了当前设备配置**。
校验清单及结果分别为该目录的 `recovery.sha256`、`recovery-check.txt`。

| 材料 | SHA256 |
| --- | --- |
| 干净配置 `config-backup-20261017T182052Z.tar.gz` | `3e19b84765b5276cdc35a2d178627d527a9999a73d63f9f6a97d7a0bc34d6666` |
| 现役 v0.2.2 镜像 | `af05e9325e43b4961bb332aa8d004f9141a040d88ee87c7f77515e628406693d` |
| 回滚 v0.2.1 镜像 | `d1537ba13e792f2123d32f17c9e554b02bf365114548379da7f60d37598c3d74` |
| 小米 TFTP 救援镜像 | `77bf35b27b6ec29fbfe2c3f4280618cd70bade5e9998d407b634ce8a12825cc6` |

现役与回滚镜像分别保存在 `private/backup/release-v0.2.2/installed-v022/`、
`private/backup/release-v0.2.2/v021-rollback/`。后续真机变更仍须使用当次恢复门和
自动回退；本轮只读，没有安装守卫、触发恢复或改变设备状态。

## 决定与下一项未知数

当前模型仍缺少脚本执行成本，无法把 168 条运行期触发推断为性能瓶颈。
本轮预测不可检验，两个放弃条件均为 **unknown**，不是 true，也不是 false。
没有依据批准 DHCP 脚本重写，也不能声称已满足转向 odhcpd-rs 的数值条件。
按“测完先汇报”停止在此；三天实现期限尚未启动，未开始 odhcpd-rs。

若继续这项评估，首先需要保住下一次正常启动的日志，且确认有足够精度的脚本起止
证据；仅补全相同格式的 `logread` 仍不能量出全部脚本时间。应先裁决如何取得缺失的
计时边界，不为此单独重启，也不开始候选实现。

复算本次保留窗口中的计数（原件仅在私有目录）：

```sh
wc -lc private/dhcp-event-boot-20261017/logread.txt
shasum -a 256 private/dhcp-event-boot-20261017/logread.txt
rg -c 'firewall: Reloading firewall' private/dhcp-event-boot-20261017/logread.txt
rg -c 'netifd: wan \([0-9]+\): udhcpc: lease of ' private/dhcp-event-boot-20261017/logread.txt
rg -c 'Interface .wan6?. is now up|dnsmasq.*(started, version|exiting|SIGHUP)|Booting Linux|Linux version ' private/dhcp-event-boot-20261017/logread.txt
```

最后一条应无输出、退出码 1，表示匹配记录不存在，**不表示开机事件没有发生**。
