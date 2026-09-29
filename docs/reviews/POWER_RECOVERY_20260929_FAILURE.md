# 供电先于 WAN 恢复：本次故障已定位到 netifd 启动清理

2026-09-29。本次九组件断电试验失败，持久保护在开机 614 秒触发回退。当前九组件已恢复为 C，客户端和路由器联网检查通过，19 份配置文件与部署前逐字节一致。失败现场已完整下载并核验，回退保留了采集目录。

**根因是当前 netifd-rs 在启动时错误释放了仍在等待 carrier 的 WAN 设备。** 协议尚未启动时的 `State::Down` 被当成“无人使用设备”，启动清理随后清除了 WAN 的 `IFF_UP`。端口被管理性关闭后，稍晚插入的网线无法让 DHCP 正常启动。

这个结论同时得到真机事件、镜像对应 C 源码、正式 ELF 的隔离复现和单一改动对照支持。修复方向已验证；诊断版本只在隔离构建机运行，尚未完成正式修复回归或新一轮真机断电验收。

**本次身份与证据边界。** [冻结试验计划](POWER_RECOVERY_20260929_PLAN.md)固定九组件源码为 `d7bfcf831ca5c73447cb638fdb7253d44ebd32ed`、正式构建为 `36558448787`。故障前软件重启及客户端连续健康检查通过。此次按用户授权测试“供电先恢复、WAN 后恢复”，没有更换内核、驱动或持久网络配置。

| 对象 | SHA256 |
|---|---|
| 真机部署及隔离复现使用的正式 netifd-rs | `3dffc7f8af52b433830b9bf76dafbeaf77c75303088b9d2232e1e52fe79f7f8d` |
| 精确镜像的 C netifd | `8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90` |
| 同环境重建、未修改源码的 Rust 对照 | `2e319a2329981992e3a267c1cba4d2da9626294eaa39c5b0247ca664970c2910` |
| 仅删除错误清理循环的 Rust 诊断版 | `316b679bccf796c25989cbf85a5a1cafd896b4ec08bf967d19f201a5db1feba1` |

故障 boot 的设备墙上时间滞后约 73 分钟。下文使用同一 boot 的单调启动秒数；跨重启时间由采集电脑的 UTC 记录对齐。设备断电期间无法记录，WAN 管理性关闭也妨碍 carrier 观测，因此不从缺少链路事件倒推出用户实际插线时刻。

**真机故障链。**

| 故障 boot 启动秒数 | 观测 |
|---|---|
| 11.438 | 独立采集器已绑定 `wan`，设备 ifindex 为 3；WAN 设备存在 |
| 17.541963 | 内核 `RTM_NEWLINK`：WAN `0x1003`，管理性开启，尚无 carrier |
| 17.549472 | 仅 7.509 毫秒后，WAN 变为 `0x1002`，管理性关闭；之后直到回退没有再开启 |
| 24.94—608.84 | 58 份协议状态快照均为 WAN/WAN6 `up=false, pending=false, available=true, autostart=true`；没有 DHCP 客户端进程、WAN 地址或默认路由 |
| 614 | guard 判定 600 秒健康期限已过，先保存恢复前快照，再恢复 C 启动路径 |
| 615 | C 恢复已写入，配置和证据保留，随后重启 |

完整采样共 59 份，覆盖 11.48—608.84 秒，全部采样正常结束；首份早于 netifd 注册接口。原始日志对应出现 WAN/WAN6 `enabled` 后立即 `disabled`。WAN 抓包只有 24 字节 pcap 文件头，没有捕获到报文；抓包 socket 的 received/dropped 都为 0，失败 boot 没有采集配额溢出或接收错误。它与协议进程、接口和路由记录共同证明：故障已经发生在 DHCP 请求之前。

快照里的 `carrier=missing` 是脚本读 sysfs 失败时的占位文字。WAN 已存在，只是管理性关闭，不能解释成驱动没有创建端口。LAN 静态地址和两个 AP 已起来；电脑从本次 Rust boot 的 uptime 25.89 秒起可持续经 SSH 读取状态，直到回退重启。故障范围是 WAN 联网，没有证据显示整机启动失败。

恢复后的 C boot 提供同机对照：17.401957 秒开启 WAN，在无 carrier 时保持开启，21.521350 秒获得 carrier；22.031810 秒安装 WAN IPv4 地址，22.032212 秒安装默认 IPv4 路由。随后九组件 C 身份、WAN/WAN6、客户端 DHCP、双频 AP、HTTP/HTTPS、DNS IPv4/IPv6、路由器外网 HTTPS 和 watchdog 检查均通过。

**对应的代码错误。** 发布源码的 [setup_interfaces](../../components/netifd/src/main.rs) 第 1424—1461 行，在逐个调用 `iface_up()` 后增加了清理循环：

```rust
let in_use = self.interfaces[i].state != State::Down;
// 同设备的其他接口也都 Down，且不是 bridge member 时：
self.device_release(dev);
```

这段判断混淆了两件事：协议是否开始运行，以及设备是否仍被接口持有。无网线启动时，WAN/WAN6 已通过 `iface_claim()` 持有设备，并开启端口，但协议必须等待 carrier，合法状态正是 `Down`。清理循环又为这两个接口分别调用原始 `device_release()`，把共享 WAN 的引用数减到零；后者清除 `IFF_UP` 并禁用使用这个设备的接口。

该调用还绕过 `iface_unclaim()`，没有同步清理 `claimed_main` 中的持有记录；这是源码中可见的记账不一致。本次没有额外测试手工 `ifup` 等恢复行为，不以它们补充事故结论。

镜像对应上游 revision 为 `cbb83a1857407a28a63dc09412a1f209195914ef`（[源码映射](../../reports/ax3000t-stock-openwrt-25.12.5/SOURCE_MAP.md)）。C 的 `interface_set_up()`（`interface.c:1356`）先 claim 设备，再检查协议状态；`interface_start_pending()`（`:1435`）只逐个启动 autostart 接口，没有按协议 `Down` 释放设备的循环。等待 carrier 时继续持有并开启设备，正是本次 C 真机记录中的行为。

**因果对照已经完成。** [复现工具](../../tools/netifd_delayed_wan_probe.py)只在 Linux 构建机的独立 PID、网络和挂载 namespace 中运行。使用精确镜像的 C ubusd、logd、协议脚本及 DHCP 客户端，只有 netifd 可变；测试 DHCP 服务器为构建机 BusyBox。WAN 的 veth peer 放在另一个网络 namespace，避免 netifd 将同 namespace 的 peer 当父设备顺带拉起。

每个二进制分别测试网络在 netifd 启动前就绪、以及启动 3 秒后才就绪。以下“成功”要求接口 up、DHCP helpers 存在并安装默认路由；“失败”表示观察满 12 秒仍然全部缺失。

| netifd | 网络预先就绪 | 网络延后就绪 | 等待期间 WAN 管理状态 |
|---|---|---|---|
| 精确镜像 C | 成功 | 成功，约 3 秒获得地址和路由 | 开启 |
| 真机部署的正式 Rust ELF | 成功 | 失败 | 被关闭 |
| 同环境重建的未修改 Rust | 成功 | 失败 | 被关闭 |
| 仅删除启动清理循环的 Rust | 成功 | 成功，约 3 秒获得地址和路由 | 开启 |

正式 ELF 实验保留一组 C 对照；未修改重建和诊断构建各自也运行完整 C 对照，共 12 个完整观测。后两份 ELF 使用同一源包、SDK、编译参数和源码目录，唯一源码差异是删除该循环、保留随后 `rescan_devices()`；避免将构建环境差异错当作修复效果。结果与真机“开启后立即关闭 WAN”的事件链一致。

隔离实验验证的是 IPv4 获租和默认路由；DHCPv6 helper 的存在证明共享端口恢复后客户端得以启动，不等于完成了 IPv6 获租、PD 和公网连通验收。

首次复现尝试因工具假定“无 IPv4 地址时 `ip -j -4 addr` 仍返回一个对象”而中止。修正为接受空列表后重新运行，首次失败目录原样保留，没有将其计入上述 12 次观测。工具退出成功仅表示观测完成，不代表待测组件通过；候选成败必须读取结果字段。

**之前为什么没拦住。** 既有 [R52 DHCP 对照](../../tools/r52_dhcp_diff.sh)先开启 veth 两端和 DHCP server，再启动 netifd；它验证了已有 carrier 后的 DHCP 路径。[R64 晚出现端口对照](../../tools/r64_lateport_diff.sh)测试的是 static LAN 的 bridge member 晚出现。两者均未覆盖“设备已经存在，但 DHCP WAN 在 netifd 启动清理结束后才获得 carrier”。本次成功的软件重启中，carrier 在 WAN 开启约 1.238 毫秒后出现，也没有进入失败分支。

因此，本次真实断电暴露的是启动时序缺陷。隔离复现不需要切断供电，足以触发同一行为。观察到的持久配置未变，失败时 DHCP 尚未运行，无需引入 DNS、IPv6 前缀顺序或防火墙故障来解释这条链。内核中的 `mt7530` 探测报错在正常 C boot 中也出现，单独那条日志没有归因价值。本结论定位本次版本，不将缺少现场的历史事故直接视为同一根因。

**下一步的发布条件。** 将设备持有关系与协议状态分开处理，移除错误清理；把这次 WAN 延迟恢复场景纳入会明确失败的回归门，并覆盖共享 WAN/WAN6、`auto=0`、显式 down、正常拔插恢复和配置 reload 的设备释放行为。既有 netifd 对照通过后，再安排真机断电验收。当前诊断版本还没有这些验收，继续保留生产 C。

本次约十分钟的等待来自 guard 预设的 600 秒健康窗口及 15 秒检查间隔，实际在开机 614 秒触发。自动回退完成了恢复和保全证据的职责；九组件仍未通过本次稳定性验收。下一次试验应结合人为保持 WAN 断开的时长重新收紧回退窗口，避免重复等待这么久。

**证据留存。** 原始配置、地址、MAC、boot 标识、抓包和二进制仅在 ignored `private/power-recovery-20260929/failure-review-01/`，Git 只收录本报告、脱敏派生数据与复现工具。

| 文件/目录 | 用途 |
|---|---|
| `raw.tar.gz`、`files.sha256`、`verified.json` | 路由器证据归档及 71 个文件的完整性核验；归档 SHA256 为 `b1fea8ab34cc6879b7ed781244bec00443ca487fa49c0554d59550f8f03a96d4` |
| `raw/owrt-power-test/boots/` | 分 boot 的 netlink、WAN pcap、启动日志、快照、恢复前快照；由角色区分成功 Rust、故障 Rust、恢复 C |
| `client-timeline.jsonl`、`current-health.json`、`raw/config.sha256` | 电脑 UTC/SSH 观测、恢复后健康、与部署前 19 文件哈希的逐字节比较 |
| `causal-evidence.tar.gz`、`causal-files.sha256.json` | 隔离复现、诊断补丁、构建日志及 ELF；归档 SHA256 为 `5f109c53166a966b731f528352658d55ef99244676407a13c66a6003477342b8`，下载后核对远端哈希，并生成 196 个文件的本地哈希清单 |
| `causal/delayed-wan-{canonical-02,control-01,diagnostic-01}/` | 三组完整的前后状态、进程、路由、日志和结果；`canonical-01` 保留工具首次中止现场 |
| [脱敏派生数据](../../reports/ax3000t-stock-openwrt-25.12.5/POWER_RECOVERY_20260929.json) | WAN 事件时间线、二进制身份、完整对照矩阵及恢复状态 |
