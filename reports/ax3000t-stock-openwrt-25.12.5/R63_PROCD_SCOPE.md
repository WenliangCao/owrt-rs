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
