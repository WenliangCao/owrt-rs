# 0015：阶段 9（ubusd 替换）不执行——前置条件未满足

> 日期：2026-09-02。阶段 9（计划 §11.4，"有条件"）。状态：采纳（不做）。

## 前置条件与检验

§11.4 要求先在精确 rootfs 沙箱验证每个 libubus 客户端在 ubusd 消失后确实重连并重新注册对象。
`tools/r22_ubus_clients_reconnect.sh`（rootfs 副本 + 私有 net/mount namespace，仅 lo）启动 ubusd、
netifd、dnsmasq 2.93（`--enable-ubus`）、odhcpd、logd-rs，kill ubusd，2 秒后重启 ubusd，观察 60 秒：

| 客户端（设备版本） | 源码中的处理 | 沙箱观察（60 秒） |
|---|---|---|
| netifd 2026.02.26 | `connection_lost` → 2 秒定时 `ubus_reconnect`；libubus `ubus_refresh_state` 重注册全部对象 | `network`、`network.device`、`network.interface` 2 秒内恢复；**`network.wireless` 未恢复** |
| dnsmasq 2.93 | `connection_lost` 立即 `ubus_reconnect`（ubusd 尚未回来则失败并销毁上下文），之后只在主循环迭代时 `ubus_init()` 重试 | **`dnsmasq`、`dnsmasq.dns` 未恢复**（空闲进程不迭代；设备上取决于 DNS/DHCP 流量，未证明） |
| odhcpd 2026.06.29 | 只有 `ubus_connect`，未设置 `connection_lost`，libubus 默认 `uloop_end` 未导致退出 | **`dhcp` 未恢复**，进程继续运行但已脱离总线（两次运行一致） |
| logd-rs（本项目） | 每秒重连、重注册（§11.6 新增） | 2 秒内恢复 |
| procd 2026.03.13 | 50 ms→1 s 退避重连（`procd/ubus.c`） | 沙箱无法运行（须为 PID 1），仅源码 |
| hostapd/wpa_supplicant 2025.08.26、odhcp6c | 1 秒 eloop 定时重连 | 沙箱无无线硬件，仅源码 |
| rpcd-rs、C rpcd | 断连即退出，procd respawn | 与 C 一致 |
| httpd-rs、uhttpd-mod-ubus、libiwinfo、ubus CLI、ujail | 每次调用新建连接 | 不受影响 |

原始输出：`private/stage9/r22-run.log`、`r22-run60.log`。

## 结论

一次在线的 ubusd 替换（bind mount `/sbin/ubusd` 后 kill，由 procd 的早期服务 `ubus` 用新二进制 respawn）
会让 odhcpd 永久脱离总线、dnsmasq 在空闲时脱离、netifd 丢失 `network.wireless`；补救只能重启 netifd
（网络与无线重配置）、dnsmasq、odhcpd——这正是决策 0006 与 §11.5 在这台唯一生产设备上禁止触碰的
netifd/无线栈。只在开机时切换也不可行：ubusd 在 procd `STATE_UBUS` 阶段、任何 rc.d 脚本之前启动，
现有"Sxx init + bind mount"模式够不着，须改 preinit；且不重启无法验证（0006 禁止重启）。

因此**阶段 9 不执行，不写 ubusd-rs 代码**（没有上线路径的代码只会增加维护面）。

## 解除条件

- 有第二台设备或台架机允许重启与网络中断，可在其上做在线切换与开机切换的验证；或
- 设备上的 odhcpd 具备 `connection_lost` 处理、netifd 在重连后恢复 `network.wireless`、dnsmasq 有
  定时重试——三者在上游落地并随包更新到本设备后，重跑 r22 全绿。

## 本阶段留下的东西

- `tools/r22_ubus_clients_reconnect.sh`：可重复的客户端重连检验。
- logd-rs 的 ubus 重连（§11.6 前置，已上线于沙箱验证；设备上的 logd-rs r1 尚未升级，见 R19 回合报告）。
- 客户端清单与各自的重连语义（上表），供将来任何总线层改动参考。

## 2026-09-09 附记：冷切换已执行（R76）

本决策封死的热切换禁令**继续有效**（r22 于 2026-09-09 对 C 与 ubusd-rs 两种总线重跑，
故障面同形、未改善）。但"开机切换不可行"的两个前提已消解：procd-rs 自 R74/R75 起是设备
PID 1（早期 ubus 服务由我们控制），重启窗口已获授权。P5 以冷切换（替换 /sbin/ubusd +
重启）上线 ubusd-rs，任何客户端都未经历总线重启。证据与终态见 R76_P5_UBUSD_COLD_SWITCH.md。
