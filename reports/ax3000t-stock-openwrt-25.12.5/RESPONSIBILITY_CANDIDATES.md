# AX3000T stock / OpenWrt 25.12.5：控制面职责候选表

> I0.6 状态：完成
> 日期：2026-08-31
> 范围：17 项控制面职责的证据完整度与风险评估
> 本阶段**不排名**"最想用 Rust 重写的组件"，也不选定替换候选。

## 1. 本表的用途和不做的事

这张表只回答两个问题：

1. 每项职责的 DEP/SRC 证据是否已经完整到可以谈兼容合同；
2. 缺失的 RUN 证据是什么，由哪个运行态问题去关闭。

它**不**回答"哪个先重写"。排序需要失败边界、爆炸半径和恢复路径三者都有运行态证据，
这些要等 I0.7 之后在 I0.8 里做。

完整机器记录见
[responsibility-candidates.json](../../manifests/ax3000t-stock-openwrt-25.12.5/responsibility-candidates.json)。
该文件由 [i0_6_candidates.py](../../tools/i0_6_candidates.py) 生成，工具会把每条声明
（artifact 路径、init 服务名、config 名、ubus 对象名）与 I0.5 manifest 交叉校验，
声明与证据不一致时直接失败而不是产出报告。

## 2. 总表

| ID | 职责 | 当前实现 | 提供的 ubus 对象 | 运行时命名 | 已知调用方（init/ACL） | 待关闭问题 |
|---|---|---|---|---:|---:|---|
| R01 | 服务监管与进程生命周期 | procd | `service`、`system` | 2 | 1 / 4 | Q06、Q11 |
| R02 | init 框架与服务定义 | rc.common + procd.sh | — | 0 | 0 / 0 | Q06 |
| R03 | 启动编排与早期 rootfs | procd initd + preinit | — | 0 | 0 / 0 | Q01、Q02、Q03 |
| R04 | 配置存储与事务 | uci / libuci | — | 0 | 0 / 0 | Q04、Q12、Q13 |
| R05 | 配置变更检测与分发 | reload_config + 触发器 | — | 0 | 0 / 0 | Q06、Q12 |
| R06 | 首启配置生成 | board_detect + config_generate | — | 0 | 11 / 0 | Q03、Q04 |
| R07 | 网络接口与设备管理 | netifd | `network`、`network.device`、`network.interface` | 1 | 5 / 1 | Q04、Q05、Q07 |
| R08 | 无线配置与 AP/STA | wifi-scripts + wireless.uc + wpad | `network.wireless`、`hostapd`、`hostapd-auth`、`wpa_supplicant` | 1 | 1 / 0 | Q04、Q05、Q10、Q11 |
| R09 | 防火墙规则生成 | firewall4 (fw4) | — | 0 | 2 / 0 | Q08 |
| R10 | DNS 与 DHCPv4 | dnsmasq | — | 1 | 2 / 0 | Q09、Q11 |
| R11 | IPv6 RA / DHCPv6 / PD | odhcpd + odhcp6c | `dhcp` | 1 | 5 / 0 | Q05、Q07、Q09 |
| R12 | IPC 总线 | ubusd | — | 0 | 0 / 0 | Q05、Q10 |
| R13 | RPC 网关、会话与授权 | rpcd + 插件 + uhttpd_ubus | `session`、`uci`、`rc`、`file`、`iwinfo`、`rpc-sys`、`luci-rpc`、`network.rrdns`、`luci` | 0 | 0 / 9 | Q13 |
| R14 | HTTP 服务与 ubus 桥 | uhttpd + uhttpd_ubus | — | 0 | 4 / 0 | Q13 |
| R15 | 系统日志 | logd / logread | `log` | 0 | 8 / 1 | Q02、Q11 |
| R16 | hotplug 事件分发 | procd hotplug + /etc/hotplug.d | — | 1 | 0 / 0 | Q05 |
| R17 | 系统信息、升级与重启 | procd system + rpcsys | `system`、`rpc-sys` | 0 | 0 / 3 | 无（见 §5） |

"已知调用方"是从 I0.5 manifest 反查出来的：init 脚本里对该对象的 `ubus call`、
对该 config 的引用，以及 rpcd ACL 中授权该对象的文件数。它是**下界**，不是完整调用方
集合——LuCI 前端、外部脚本和运行时订阅者都不在静态可见范围内。

## 3. 证据完整度分档

### 3.1 DEP + SRC 已足够进入兼容合同讨论（需求仍待 RUN 确认）

R01、R02、R04、R05、R12、R15。

这几项的共同点：接口面基本是编译期常量或镜像内文本，I0.5 已经把方法集、参数来源、
生命周期语义和失败路径固定下来。它们缺的是"设备上实际怎么用"，不是"接口是什么"。

R12（ubusd）是其中风险最高的：它没有持久状态，但**每个控制面交互都经过它**，
重启即丢失全部注册对象。任何替换都必须先证明重连语义。

### 3.2 接口面确定，但行为高度依赖运行时配置

R07、R08、R10、R11、R13、R14。

这些职责的对象名、实例数或方法可达性都由运行时配置决定：

- R07：`network.interface.<name>` 的实例集合来自 `/etc/config/network`，而该文件不随
  镜像发布；
- R08：`wpa_supplicant.<ifname>` 同理，且 wireless 配置由硬件探测生成；
- R10：dnsmasq 的 ubus 对象名本身是运行时赋值（`ubus_object.name = daemon->ubus_name`）；
- R11：`odhcp6c.<interface>` 每个 WAN 接口一个；
- R13/R14：`uhttpd.main.ubus_prefix` 由 uci-default 在首启写入，镜像里的
  `/etc/config/uhttpd` 中该项是注释状态。

**在 RUN 证据到位前，不能为这几项写兼容合同。**

### 3.3 一次性执行，状态全在外部

R06、R09、R16。

它们没有常驻进程，效果全部落在别处：R06 落在 `/etc/board.json` 和首套 UCI，
R09 落在 nftables ruleset，R16 落在设备节点和下游 handler 的副作用。

这一类的"兼容"不能用接口比对来定义，只能用**产出物比对**来定义。R09 尤其明确：
`fw4` 的兼容合同必须是生成的 ruleset，而不是它的命令行。

### 3.4 无法只读观察

R17。见 §5。

## 4. 风险维度（不排序，只登记）

| ID | 失败边界 | 爆炸半径 | 恢复路径 |
|---|---|---|---|
| R01 | PID 1 | 整机重启 | 无带内恢复 |
| R03 | 整机 | 不可启动或只能 failsafe | failsafe / TFTP / bootloader |
| R06 | 无网络配置 | 需 failsafe 才能恢复 | 删 board.json 重生成，会毁掉用户配置 |
| R09 | 整条包路径 | flush 后设备门户大开或失联 | `fw4 restart`，中间态无回滚 |
| R12 | 全部控制面交互 | 所有 daemon 需重连 | 重启即丢失全部注册 |
| R13 | 远程管理；经 `file.exec` 与 `rc.init` 可达整机 | 等价远程执行 | procd 重启；apply/confirm 窗口内可回滚 |
| R17 | 设备本身 | 刷写失败可变砖 | 仅 bootloader 恢复 |
| R07 | 全部连通性 | 所有客户端 | procd respawn，无配置回滚 |
| R08 | 全部无线客户端 | 无线中断 | `wifi reload`，respawn 3600 1 0 |
| R10 | 名称解析与 IPv4 分配 | 所有客户端 | procd respawn，租约在文件中保留 |
| R11 | 全部 IPv6 连通性 | IPv6 客户端 | procd respawn |
| R04 | 单个 config package | 掉电可能写坏 | commit 前可 revert；commit 后仅 rpcd 窗口内 |
| R05 | 事件漏发 | 服务静默使用旧配置 | 下次 reload_config 重新检测 |
| R14 | Web 管理面（以 root 运行） | 管理面失效 | procd respawn |
| R15 | 仅可观测性 | 静默丢日志 | procd respawn，缓冲丢失 |
| R02 | 单次调用 | 单个服务 | 重跑脚本，无自动回滚 |
| R16 | 设备节点与下游 handler | 取决于 handler | 无重试机制 |

两条要点：

1. **R05 的失败是静默的。** 事件漏发不会报错，服务会继续用旧配置运行。任何替换实现
   必须先解决"如何证明变更已送达"，这比复刻 md5 比较逻辑重要得多。
2. **R16 没有重试。** hotplug 事件丢失即永久丢失。

## 5. R17：没有安全的只读观察

R17（`system.reboot`、`rpc-sys.upgrade_start`、`rpc-sys.factory`、`sysupgrade`）的
每个方法都是终止性操作。除了 Q05 已经采集的方法列表以外，**不存在**对它的只读观察。

真正行使它属于 H1，必须在独立的 recovery gate 之后，不属于本阶段的只读采集。
这条已作为 `no_run_question_justification` 记入 JSON，生成器要求任何"没有运行态问题"
的职责必须给出这样的理由，否则直接失败。

## 6. 与 I0.7 的关系

16 项职责各自的缺失 RUN 证据都指向 [RUNTIME_QUESTIONS.md](RUNTIME_QUESTIONS.md) 的
具体问题编号。I0.7 只允许执行那份清单里已批准的命令；本表不授权任何设备操作。
