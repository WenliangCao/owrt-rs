# R63：procd 在这台机器上的实际职责范围

日期：2026-09-07。来源：设备只读采集（`ubus call service list`、`/proc/1/exe`），
未做任何写操作。这是 P3 开始前计划要求的枚举，之前一直没做。

## 现状

- `/proc/1/exe` → `/sbin/procd`。PID 1 是原版 procd。
- `/etc/init.d/` 下 31 个脚本。
- `ubus call service list`：**19 个服务，15 个运行中的实例**。

## 实例实际用到的字段

只列设备上真实出现的，不是 procd 支持的全集：

```
capabilities  command  data  exit_code  group  jail  limits
mount  no_new_privs  pid  respawn  running  term_timeout  user
```

这就是 P3.1 监管核心必须覆盖的面：spawn 与 argv、uid/gid、limits、
respawn 策略、term_timeout 的停止超时、退出码、以及 jail / capabilities /
no_new_privs / mount 这组隔离参数（后者按计划走现有 ujail 契约，不自己实现沙箱）。

**注意 `data`**：实例携带的自定义数据，`service list` 会回显，触发器和
`reload_config` 依赖它。不能只做 spawn/respawn 就宣称监管核心完成。

## 还没枚举的

- trigger 的实际使用情况（哪些服务注册了什么 trigger）。
- inittab 内容与 procd 内建 rcS 的实际脚本顺序。
- watchdog 设备与喂狗间隔。
- hotplug/coldplug 规则。

这些都要在 P3.1 动工前补上，否则又会出现"实现了一部分就以为覆盖了"的情况。

## 边界（不变）

P3 的完成标准是设备 PID 1 换成 Rust，而计划写死：只在启动边界切换、
禁止用杀 PID 1 的方式；并且**旧救援报告"failsafe 不加载 overlay 改动"的结论
不能外推到 procd**，必须重新逐步追踪 failsafe 下会不会误选 Rust PID 1。
这一步需要真实重启窗口和明确授权，不在离线范围内。

---

## 补齐：上面那四项（2026-09-08，全部离线，来源是解包 rootfs）

### inittab 与启动顺序

`/etc/inittab` 只有三行，没有任何设备定制：

```
::sysinit:/etc/init.d/rcS S boot
::shutdown:/etc/init.d/rcS K shutdown
::askconsole:/usr/libexec/login.sh
```

所以 procd 作为 PID 1 要做的是：解析 inittab、按 `sysinit` 跑 `rcS S boot`、
按 `askconsole` 在控制台起 `login.sh`（procd 二进制里有 `/sbin/askfirst`），
关机时跑 `rcS K shutdown`。`rcS` 遍历 `/etc/rc.d`，本机 32 个链接：

```
S00sysfixtime S00urngd S10boot S10system S11sysctl S12log S12rpcd
S19dnsmasq S19dropbear S19firewall S19wpad S20network S25packet_steering
S35odhcpd S50cron S50uhttpd S80ucitrack S94gpio_switch S95done S96led
S98sysntpd S99bootcount S99ubihealthd S99urandom_seed
K10gpio_switch K21wpad K50dropbear K85odhcpd K89log K90boot K90network
K90sysfixtime K90umount
```

`S12rpcd` 是 rpcd-rs，`S20network` 会拉起 netifd —— 也就是 P1/P2 的产物都在这条
链上，PID 1 换人时它们跟着一起换启动者。

### watchdog

设备上没有任何 shell 脚本喂狗；`/lib/functions/procd.sh` 里的 `watchdog` 只是
实例属性名。喂狗的是 procd 自己。二进制里的相关字符串：

```
/dev/watchdog
Opened watchdog with timeout %ds
Set watchdog frequency: %ds        Set watchdog timeout: %ds
Watchdog GETSUPPORT failed         Watchdog does not have CARDRESET support
Watchdog GETBOOTSTATUS failed      Watchdog has previously reset the system
instance %s::%s watchdog timer expired
WDTFD                              Watchdog handover: fd=%s
```

两层，不要混：

1. **系统 watchdog**：procd 打开 `/dev/watchdog`，用 `WDIOC_SETTIMEOUT` 设超时
   （默认 30s），按 frequency 周期喂。
2. **每实例 watchdog timer**：实例属性里的 `watchdog`，超时只影响那一个实例。

`WDTFD` 是 P3 的关键约束：procd 把已打开的 `/dev/watchdog` fd 号放进环境变量
交给下一个 procd，`Watchdog handover: fd=%s` 就是接手方的日志。这意味着
**watchdog 是可以跨 exec 传递而不复位的**——但反过来，任何"换掉 PID 1"的做法
如果没接手这个 fd 且没有正确关闭（写 `V` 再 close 才是 magic close），硬件
可能在超时后直接复位整机。这是 P3 必须先验证的东西，不是实现完再说。

### 触发器：只有一套规则引擎

`/etc/hotplug.json` 和 procd 的 trigger 用的是同一种 JSON 数组 DSL
（`case` / `if` / `and` / `eq` / `regex` / `has` / `makedev` / `exec` /
`run_script` / `return`）。`_procd_add_*_trigger` 只是往实例的 `triggers`
数组里拼这套规则。

本机实际注册的三类事件源：

| 事件            | 谁发                 | 本机注册者 |
|-----------------|----------------------|-----------|
| `config.change` | uci 提交             | `ucitrack`（转发给各服务）、`uhttpd`、`system`、`dnsmasq`、`gpio_switch`、`log`、`firewall`、`network`、`packet_steering`、`odhcpd` |
| `interface.*`   | netifd 的接口事件    | `sysntpd` |
| `service.data.update` | procd 自己的 data | `firewall`（`procd_add_reload_data_trigger`）|

第二行说明 **P2 的 netifd 和 P3 的 procd 是有接口的**：netifd 发的接口事件要
能被 procd 的 trigger 规则匹配上，否则 sysntpd 不会在链路起来时重同步。

### hotplug / coldplug

- procd 自己 bind netlink hotplug socket（`Failed to bind hotplug socket`），
  规则来自 `/etc/hotplug.json`，脚本目录 `/etc/hotplug.d/`，本机 9 个子目录：
  `dhcp firmware ieee80211 iface leds neigh net ntp tftp`。
- coldplug 是 fork 出一个实例跑 `udevtrigger`（`Launched coldplug instance`），
  完成后发 `event.trigger`。
- `procd -h <path>` 可以只做 hotplug daemon，不当 PID 1。**这给了 P3 一个
  低风险的分阶段验证点**：先用 Rust 实现替掉 hotplug daemon 这个角色单独验证
  规则引擎，再谈 PID 1。

## 这四项对 P3.1 的直接影响

原来的字段清单（spawn/respawn/limits/jail/data）只覆盖了"监管一个实例"。
补齐后多出三块必须一起做的：

1. **inittab + rc.d 序列**：PID 1 的职责不止 supervise，还有 sysinit/shutdown。
2. **规则引擎**：hotplug 和 trigger 共用，是一个独立可测的部件，可以先于 PID 1
   落地并单独验证。
3. **watchdog（含 WDTFD 交接和 magic close）**：这是唯一一个"写错了会复位整机"
   的部分，必须在任何设备侧动作之前离线验证清楚。
