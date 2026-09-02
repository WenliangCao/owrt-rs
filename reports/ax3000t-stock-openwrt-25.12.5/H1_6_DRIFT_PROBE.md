# AX3000T stock / OpenWrt 25.12.5：baseline `network` drift 只读探针

> 日期：2026-09-02
> 设备操作：仅现有 SSH，三批只读命令（`uci show`、`ubus call … dump/status`、`ls`、`grep`、`cat`）；
> 无写入、无 ubus 事件、无 reload、无 mount。原始输出留在 Git 外的 `private/b*-probe-20260902/`。

## 结论

H1.4 观察到的 drift 只有一项：`/etc/config/network` 在 `globals` 段多了
`option packet_steering '1'`。文件 mtime 为 2026-09-01 22:00:58 CEST，早于 H1.4 首次实机运行
（20:17:59Z，即 22:17 CEST）17 分钟。其余 18 个 baseline 条目全部与当前规范化结果一致。

drift 的成因是 OpenWrt 自身的设计：`/sbin/reload_config` 的调用方只有 `/etc/init.d/boot`
（启动时一次）和手工 CLI。rpcd/LuCI 的 `uci apply` 直接向 procd 发 `config.change`，不经过
`reload_config`，因此不会更新 `/var/run/config.md5`。任何经 LuCI 保存的配置变更都会留下这种
drift，这不是候选或设备的异常。

该变更已经生效：`/etc/init.d/packet_steering`（S25，独立 procd 服务）已把 `eth0` rx 队列的
`rps_cpus` 设为 `2`。netifd 自启动后未重启，且 `uci changes` 为空、`/tmp/.uci` 为空目录。
现在若任何 `reload_config` 实现投递一次 `network` 事件，效果是 netifd 空差分 reload 与
packet_steering 幂等重写，不会改变接口状态。

## 观察值

| 项目 | 值 |
|---|---|
| baseline `/var/run/config.md5` | 19 条，mtime 2026-07-29 21:29 CEST（启动早于 NTP 校时，时间戳不可靠） |
| drift 条目 | `network` 1 条；其余 18 条 same |
| `network` 与 4 月备份的差异 | 仅 `packet_steering '1'`（705 vs 677 bytes） |
| `reload_config` 调用方 | `/etc/init.d/boot`、`owrt-reload-config-switch`；rpcd/LuCI 不调用 |
| netifd / rpcd / uhttpd 启动 | 均在开机后 12–15 s，此后未重启 |
| `eth0` rx-0 `rps_cpus` | `2`（packet steering 已应用） |
| 候选状态 | package installed，switch `disabled`，mount count 0，原 dispatcher SHA-256 不变 |

## 对 H1.6 的含义

H1.6 之前先用**原始**实现执行一次 `/sbin/reload_config` 收口 baseline，这是设备管理员的常规
操作，预期恰好一个 `network` 事件、零接口变化。收口后再单独授权 canary。两步都尚未授权。

## 2026-09-02 10:29Z：用原始实现收口 drift（已授权，已执行）

在 switch 仍为 `disabled`、mount count 0、`/sbin/reload_config` 为原始 SHA-256 的状态下执行一次
`/sbin/reload_config`，退出码 0。

| 项目 | 前 | 后 |
|---|---|---|
| baseline SHA-256 | `b77e0e99…c163` | `da010536…39d0c` |
| baseline 条目 | 19 | 19 |
| `network` 条目 md5 | `01940b21…` | `7bde7b1d…`，等于当前 `uci show network` |
| drift 复核 | 1 项 | 0 项 |
| netifd / odhcpd / dnsmasq pid 与启动时间 | 1764/1369、1882/1414、3148/2090 | 完全相同，无重启 |
| 接口 uptime | 连续 | 连续，lan/wan/wan6 均未重启 |
| `eth0` rps_cpus | 2 | 2 |

响应 `network` config.change 的 procd 服务实测为 network、odhcpd、packet_steering、ucitrack。
日志中可见的效果只有 hostapd "Reload all interfaces / Reloaded settings for phy0, phy1"（netifd
reload 连带重读 wireless 配置，无 station 断连记录）和 dnsmasq 重读 hosts 文件（SIGHUP，pid
不变）。SSH 会话全程保持。
