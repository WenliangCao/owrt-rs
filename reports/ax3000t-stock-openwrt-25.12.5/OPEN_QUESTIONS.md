# AX3000T stock / OpenWrt 25.12.5：未解问题

> I0.8 状态：完成；I0 follow-up 已关闭 OQ-01、OQ-07
> 日期：2026-08-31

当前仍有七个开放问题。每条写明**为什么开放**、**由什么关闭**、**阻塞哪项职责**、
**属于哪个阶段**。机器记录见
[replacement-boundary.json](../../manifests/ax3000t-stock-openwrt-25.12.5/replacement-boundary.json)
的 `open_questions`；已关闭问题在同一文件的 `closed_questions`。

## 1. 阻塞具体职责的问题（5 条）

| ID | 问题 | 为什么开放 | 由什么关闭 | 阻塞 | 阶段 |
|---|---|---|---|---|---|
| OQ-02 | 替换实现能否从相同配置产出等价的 nftables ruleset | firewall4 的兼容合同是它的输出，尚无差分比较 | 在相同输入上比较 fw4 与候选实现输出的差分工装 | R09 | C1 oracle + V1 |
| OQ-03 | LuCI 对 uhttpd 的 `lua_prefix` 与 `ubus_prefix` handler 具体要求什么 | 耦合已登记但从未被执行，没有请求级 trace | 对参考设备录制一次 LuCI 会话 | R14 | C1 |
| OQ-04 | 读-改-写是否保留实现未建模的 UCI option | 未建模字段的保留是任何 UCI 替换的约束条件，无法被动观察 | 对设备自身配置做 byte 与 AST round-trip 测试 | R04 | C1 |
| OQ-05 | shell、ucode、C 三类写入方并发写同一 config 时会发生什么 | 没有跨进程写锁；该窗口不制造就观察不到 | 在非生产设备上做受控并发实验 | R04 | V1（实验设备） |
| OQ-06 | 本部署实际走到哪些 netifd proto handler 与 wireless notify 路径 | 这里只配置了 dhcp、dhcpv6、static；handler 契约比实际运行的更宽 | 按配置枚举 handler，或把合同范围收缩到已观察集合 | R07 | C1 |

## 2. 不阻塞职责但限制结论外推的问题（2 条）

| ID | 问题 | 为什么开放 | 由什么关闭 | 阶段 |
|---|---|---|---|---|
| OQ-08 | 在不同配置下 ubus 目录是否仍然完整 | 完整性是针对**一种配置**验证的；`wpa_supplicant.<ifname>` 在本设备上没有实例 | 配置变更后重跑核对，或把完整性主张限定在本配置 | V1 |
| OQ-09 | 一次真实启动中每个 rcS step 的精确 wall-clock 耗时是多少 | 启动记录已被覆盖；默认 procd debug 0 又不输出 `DEBUG(2)` 的 monotonic duration | 经单独授权的串口或 instrumented lab boot；普通 `logread` 不足 | H1 性能基线 |

OQ-09 不阻塞 R07，也不阻塞 I0 gate。顺序与失败传播已由 OQ-01 的关闭证据确定；剩余的
只是具体设备、具体启动的性能基线。

## 3. 本次 follow-up 关闭的问题

| ID | 关闭证据 | 结论 |
|---|---|---|
| OQ-01 | `boot-chain.json.rcS_scheduling`；[I0_FOLLOWUP_REVIEW.md](I0_FOLLOWUP_REVIEW.md) | rcS 全队列严格串行；普通非零退出继续；pipe/fork 在登记前失败会卡住。精确耗时拆为 OQ-09 |
| OQ-07 | 独立只读采集与脱敏 UCI AST 比较；`i0-followup-review.json` | DHCP 等价于镜像加预期首启变换；旧 DNS override 不再生效；firewall 软件 flow offloading 正在生效；设备可用作以当前配置为输入的 C1 oracle |

OQ-07 的“是谁做的”无法从现存元数据完全重建，但操作者身份不是 oracle 合同的一部分。
C1 必须固定的是经审查的当前输入、文件集合和参考行为。

## 4. I0 期间更早关闭的问题

| 曾经的问题 | 关闭方式 |
|---|---|
| kernel command line 未知，影响 rootfs 挂载选项 | Q01 实测：不含 `rootfs_mount_options.*`，确认无影响 |
| `hotplug.<subsystem>` 的实例集合 | Q05 实测：完整 10 个 |
| `udebug` 对象由谁提供 | Q10 实测：不存在，ACL 授权了无提供方的对象 |
| dnsmasq 是否以默认名注册 | Q09 实测：是，且只有 `metrics` |
| 声明的 jail 是否生效 | Q11 实测：分化——ntpd/dnsmasq 有 namespace，wpad 没有 |
| 用户是否增删改过 package | Q14 实测：+4 纯翻译包，无删除、无版本变更 |
| `uhttpd.main.ubus_prefix` 实际值 | Q13 实测：`/ubus`，`no_ubusauth` 与 `ubus_cors` 均未设置 |
| ucitrack 实际注册了哪些 trigger | Q06 实测：10 条，四条静态预测全部命中 |

## 5. 明确不会用只读观察回答的问题

- `reload` 的实际中断行为（需要主动触发 reload）；
- 服务故障注入后的传播；
- R17 的升级/恢复出厂路径（终止性操作，属 H1 的 recovery gate）。
