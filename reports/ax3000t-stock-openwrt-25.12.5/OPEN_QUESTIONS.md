# AX3000T stock / OpenWrt 25.12.5：未解问题

> I0.8 状态：完成
> 日期：2026-08-31

八个问题在 I0 结束时仍然开放。每条写明**为什么开放**、**由什么关闭**、
**阻塞哪项职责**、**属于哪个阶段**。

机器记录见
[replacement-boundary.json](../../manifests/ax3000t-stock-openwrt-25.12.5/replacement-boundary.json)
的 `open_questions`。

## 1. 阻塞具体职责的问题（6 条）

| ID | 问题 | 为什么开放 | 由什么关闭 | 阻塞 | 阶段 |
|---|---|---|---|---|---|
| OQ-01 | 可观察的启动顺序、时序与失败传播 | 日志环形缓冲区只覆盖约 93 分钟，启动记录已被覆盖，加大行数无法取回 | 观察一次真实启动——**不是只读观察** | R07 | H1 或单独授权的实验 |
| OQ-02 | 替换实现能否从相同配置产出等价的 nftables ruleset | firewall4 的兼容合同是它的输出，尚无差分比较 | 在相同输入上比较 fw4 与候选实现输出的差分工装 | R09 | C1 oracle + V1 |
| OQ-03 | LuCI 对 uhttpd 的 `lua_prefix` 与 `ubus_prefix` handler 具体要求什么 | 耦合已登记但从未被执行，没有请求级 trace | 对参考设备录制一次 LuCI 会话 | R14 | C1 |
| OQ-04 | 读-改-写是否保留实现未建模的 UCI option | 未建模字段的保留是任何 UCI 替换的约束条件，无法被动观察 | 对设备自身配置做 byte 与 AST round-trip 测试 | R04 | C1 |
| OQ-05 | shell、ucode、C 三类写入方并发写同一 config 时会发生什么 | 没有跨进程写锁；该窗口不制造就观察不到 | 在非生产设备上做受控并发实验 | R04 | V1（实验设备） |
| OQ-06 | 本部署实际走到哪些 netifd proto handler 与 wireless notify 路径 | 这里只配置了 dhcp、dhcpv6、static；handler 契约比实际运行的更宽 | 按配置枚举 handler，或把合同范围收缩到已观察集合 | R07 | C1 |

**OQ-01 不阻塞 I0 gate。** 它只阻塞 R07，而 R07 已被分类为`延后评估`——没有任何
依赖它的职责进入替换范围。这一点是 gate 能通过的前提，不是被忽略的例外。

## 2. 不阻塞职责但影响后续用法的问题（2 条）

| ID | 问题 | 为什么开放 | 由什么关闭 | 阶段 |
|---|---|---|---|---|
| OQ-07 | 是什么改动了 `/etc/config/dhcp` 与 `/etc/config/firewall`，其中是否仍有生效内容 | `config.md5` 显示存在更早工具留下的备份；两个文件都已偏离镜像。内容含地址与策略，本阶段刻意未读入报告 | 对这两个文件做单独的脱敏审查 | C1 使用本设备作为 oracle 之前 |
| OQ-08 | 在不同配置下 ubus 目录是否仍然完整 | 完整性是针对**一种配置**验证的；`wpa_supplicant.<ifname>` 在本设备上已经没有实例 | 配置变更后重跑核对，或把完整性主张限定在本配置 | V1 |

OQ-07 是使用本设备做参考 oracle 的前置条件：设备当前配置已偏离镜像，
任何差分测试必须以**设备当前配置**为输入，而不是以镜像里的配置为输入。

## 3. 已在 I0 期间关闭的问题

以下问题曾是开放项，现已由 I0.7 关闭，此处记录以免重复提出：

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

## 4. 明确不会用只读观察回答的问题

以下问题需要主动触发或注入故障，**不属于只读观察**，也不应被包装成只读采集：

- `reload` 的实际中断行为（需要主动触发 reload）；
- 服务失败传播（需要注入故障）；
- R17 的升级/恢复出厂路径（终止性操作，属 H1 的 recovery gate）。
