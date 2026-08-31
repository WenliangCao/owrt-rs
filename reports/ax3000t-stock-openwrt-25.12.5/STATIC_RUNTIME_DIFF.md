# AX3000T stock / OpenWrt 25.12.5：静态预测与运行态实测差异

> I0.7 状态：完成
> 日期：2026-08-31
> 用途：逐条裁决 I0.5 的静态结论；差异按"方法缺陷"还是"设备状态"分类。

## 1. 总体结果

| 类别 | 数量 | 说明 |
|---|---:|---|
| 静态预测被证实 | 14 | 见 §2 |
| 静态**漏报** | 2 | `dnsmasq.dns` 对象、`ubus` 伪服务，见 §3 |
| 静态**误判** | 0 | 没有"源码里有但设备上不存在"的对象或方法 |
| 静态无法判定、运行态给出答案 | 5 | 见 §4 |
| 被动运行态未回答、后续源码审查关闭 | 1 | rcS 顺序与失败传播，见 §5 |

没有出现需要标记 `contradicted` 的冲突。两处漏报都指向同一类**方法缺陷**，
不是个别笔误。

## 2. 被证实的静态结论（14 条）

| # | I0.5 结论 | 实测 |
|---:|---|---|
| 1 | `dhcp` 对象无 `ipv4leases`（`#ifdef DHCPV4_SUPPORT`，本镜像装 `odhcpd-ipv6only`） | 证实：只有 `ipv6leases`、`ipv6ra`、`add_lease` |
| 2 | `network.device` 无 `hotplug_event`（`#ifdef DUMMY_MODE` 仅非 Linux 定义） | 证实：只有 `status`、`set_alias`、`set_state`、`stp_init` |
| 3 | `dnsmasq` 对象无 `set_connmark_allowlist`（`#ifdef HAVE_CONNTRACK`，基础变体） | 证实：只有 `metrics` |
| 4 | 5 个"一次性 procd 服务"无 instance | 证实：`firewall`、`gpio_switch`、`packet_steering`、`system`、`ucitrack` 运行实例均为 0 |
| 5 | ucitrack 不为 procd 服务的 `init` 字段注册 trigger | 证实：`firewall`/`dnsmasq`/`network`/`odhcpd`/`dropbear` 均未出现在 10 条 trigger 中 |
| 6 | ucitrack 会为非 procd 的 `init: led` 注册 | 证实：`run_script /etc/init.d/led reload` 已注册 |
| 7 | `exec: /sbin/block mount` 会注册但悬空 | 证实：已注册；`/sbin/block`、`block-mount` 均不存在 |
| 8 | `affects` 指向未安装包仍注册且无订阅者 | 证实：`luci-splash`、`qos`、`miniupnpd`、`luci_statistics` 四条事件已注册 |
| 9 | `wpa_supplicant.<ifname>` 只在配置 STA 时出现 | 证实：本设备无 STA，无该实例；`wpa_supplicant` 基对象存在 |
| 10 | `hostapd.<iface>`、`odhcp6c.<interface>`、`network.interface.<name>`、`hotplug.<subsystem>` 四条命名规则 | 证实：分别得到 2、1、4、10 个实例 |
| 11 | `dnsmasq` 使用运行时对象名，默认为 `DNSMASQ_UBUS_NAME` | 证实：注册名就是 `dnsmasq`，未被 `--ubus` 覆盖 |
| 12 | ubusd ACL 授权的对象不等于存在提供方 | 证实：`udebug` 被 `wpad_acl.json` 授权，设备上 `Not found` |
| 13 | `logd` 靠进程内 `getpwnam("logd")` 降权 | 证实：uid/gid 均为 514 |
| 14 | `dnsmasq` 靠自身 `--user=` 降权，不走 procd `user` 参数 | 证实：`NoNewPrivs=0`，而走 procd 参数的 wpad/ntpd 均为 1 |

第 1–3 条尤其值得记下：它们是 I0.5 之后为 I0.6 做命令审查时才发现并修正的
build gating 结论，**三条全部经运行态证实**。当时依据的是 recipe 的 build 条件，
而不是二进制里方法名的字节缺失——后者被同期证伪（见 §3.3）。

## 3. 静态漏报（2 条）——两处方法缺陷

### 3.1 `dnsmasq.dns`：补丁引入的 ubus 对象对上游解析器不可见

设备上存在 `dnsmasq.dns`，I0.5 的 IPC 目录没有它。

| 位置 | `dnsmasq.dns` 出现次数 |
|---|---:|
| OpenWrt `200-ubus_dns.patch` | 1（第 176 行 `{ .name = "dnsmasq.dns" }`） |
| 上游 `dnsmasq-2.93/src/ubus.c` | **0** |

`i0_5_controlplane.py` 只解析固定 revision 的**未打补丁**上游 checkout，
因此结构上不可能看到补丁新增的注册点。

**影响范围不止这一个对象。** I0.4 已登记 313 个 recipe patch 资产
（其中 hostapd 63 个、dnsmasq 2 个、ucode 5 个），IPC 目录从未消费它们。
要得到完整的 ubus 注册面，源码解析必须同时覆盖 patch stack。

本次只漏了 1 个对象（40 分之 1），但这是运气而非方法保证：本镜像里向 ubus 注册的
补丁很少。hostapd 的 ubus 支持整个来自 `600-ubus_support.patch`，I0.5 之所以没漏，
是因为改从**部署的 ucode 文件**和二进制字符串取证，绕开了补丁问题。

### 3.2 `ubus` 伪服务：procd 内部注册的服务没有 init 脚本

设备上 procd 管理 19 个服务，镜像只有 18 个 init 脚本声明 `USE_PROCD=1`。

多出的 `ubus` 由 procd 在 `STATE_UBUS` 通过
`service_start_early("ubus", "/sbin/ubusd", "ubus", "ubus")` 直接注册
（`procd/state.c:155`）。任何以 `/etc/init.d/*` 为枚举起点的服务图都必然漏掉它。

I0.5 的 BOOT_CHAIN 正确记录了这行调用，但 SERVICE_GRAPH 的服务集合是从 init 脚本
构建的，两份报告之间没有交叉核对。**服务图的枚举起点应当是"procd 会注册什么"，
而不是"有哪些 init 脚本"。**

### 3.3 一处被及时废弃的错误判据

I0.5 的一个中间版本用"方法名字面量是否出现在部署二进制的字节里"来判定方法缺失，
产出 12 条"缺失"。运行态证明这 12 条**全部是假阳性**：`iwinfo.info`、`file.stat`、
`uci.{add,set,state,reload_config}`、`network.interface.{up,down,status,dump}`、
`service.{add,set,watchdog}`、`session.set`、`system.{info,validate_firmware_image,watchdog}`
在设备上均存在。

原因是链接器会合并字符串常量，短名通常作为更长字符串的尾部存放，没有独立的
`\0name\0`。该判据在 I0.5 阶段就已被废弃并改为**只报正向证据**，最终 build gating
结论改为依据 recipe 条件——这个选择被运行态证明是正确的。

## 4. 静态无法判定、运行态给出答案（5 条）

| # | I0.5 标记为未知 | 运行态答案 |
|---:|---|---|
| 1 | kernel command line（DTS `chosen` 无 `bootargs`） | `console=ttyS0,115200n1 loglevel=8 swiotlb=512 rootfstype=squashfs firmware=0 mtd=ubi uart_en=1`；**无 `rootfs_mount_options.*`**，故 `80_mount_root` 不附加挂载选项 |
| 2 | `hotplug.<subsystem>` 的实例集合（静态只能从 ACL 推出 4 个） | 完整 10 个：`button`、`dhcp`、`firmware`、`ieee80211`、`iface`、`leds`、`neigh`、`net`、`ntp`、`tftp` |
| 3 | 声明实例数 ≠ 运行实例数 | `log` 声明 3 实际 1（未配 `log_file`/`log_ip`）；`dnsmasq` 实例名为匿名 section 名 `cfg01411c` |
| 4 | `uhttpd.main.ubus_prefix` 实际值（镜像中该行是注释） | `/ubus`，由 `00_uhttpd_ubus` 首启写入；`no_ubusauth` 与 `ubus_cors` 均未设置（默认关） |
| 5 | 声明的 jail 是否生效 | **分化**：`ntpd`、`dnsmasq` 获得独立 ipc/mnt/pid namespace；`wpad` **没有任何 namespace 隔离** |

第 5 条的机制可以完全用静态证据解释，只是此前没有推到底：
`_procd_add_jail`（`/lib/functions/procd.sh`）只在有 flag 或 mount 时才产生隔离内容，
而 `/etc/init.d/wpad` 写的是 `procd_add_jail hostapd`——只有名字。
**"声明了 jail"和"获得了 namespace 隔离"是两件事**，I0.5 的特权表把两者并列为
"jail=是"，这一列现已按运行态修正理解。

## 5. 被动运行态未回答、后续源码审查关闭（1 条）

**启动记录与时序。** `logread` 的环形缓冲区只覆盖采集前约 93 分钟，最早一条记录晚于
本次启动。缓冲区容量（`log_buffer_size` 默认 64 KiB）不足以保留启动记录，
**加大 `-l` 行数无法取回已被覆盖的内容**。

后续对精确 procd/libubox 源码的组合审查关闭了 OQ-01：rcS 设置
`max_running_tasks = 1`，所以按 glob 顺序严格串行；普通子进程退出状态不传播，下一项
继续；pipe/fork 在登记子进程前失败会卡住队列。原报告把“同编号可能并发”列为未知，
这是静态分析没有读完 runqueue 调用方与实现的遗漏，现已更正。

真实逐项耗时仍未观察。procd 虽用 `CLOCK_MONOTONIC_RAW` 计算耗时，但日志受 `DEBUG(2)`
保护；本设备 PID 1 无 `-d`/`DBGLVL`，默认 debug 0。该性能基线改列非阻塞 OQ-09，
只能由串口或经授权的 instrumented boot 关闭，普通重启后 `logread` 仍不足够。

## 6. 两处方法缺陷已在 I0.8 前修复

两处漏报都不是笔误，因此都按方法修复，而不是补一条记录：

| 缺陷 | 修复 | 验证 |
|---|---|---|
| IPC 目录不消费 patch stack | `i0_5_controlplane.py` 增加 patch 扫描：1075 个 patch 文件中**恰好 1 个**含 `ubus_add_object` 新增行，即 `200-ubus_dns.patch` | `dnsmasq.dns` 现已在目录中，且记录为无方法的通知对象，与运行态一致 |
| 服务图以 init 脚本为枚举起点 | 增加 `service_start_early` 扫描，识别 procd 内部注册的服务 | `ubus` 现已在目录中，含 `user=ubus`、`respawn` 参数 |

同时给每条动态命名规则加了显式 `name_pattern` 正则，使 I0.7 的核对脚本按目录声明的规则
匹配，而不是按脚本里硬编码的前缀——上游新增规则会自动进入比较。

修复后重新核对：

```text
运行态对象 40
  静态字面量预测命中  21
  动态规则预测命中    20   （container 同时命中两类）
  未被预测             0
  字面量声明但未注册    0
  规则无实例           1   （wpa_supplicant.<ifname>，本设备未配置 STA）
```

**目录与运行态现在双向闭合**，这是本项目在只读约束下能取得的最强验证。

## 7. 对后续阶段的影响

1. ~~补齐 patch stack 解析~~、~~改服务图枚举起点~~：均已在 §6 完成。
2. **特权面必须区分"声明"与"生效"。** 替换设计若假设 wpad 在 namespace 内运行，
   会在本设备上失配。
3. **本设备可作为 C1 的参考 oracle。** 后续 OQ-07 脱敏审查确认 DHCP 当前语义等于镜像
   加预期 `15_odhcpd` 首启结果，旧 DNS override 已失效；firewall 的软件 flow offloading
   正在生效。任何差分测试仍必须使用经审查的设备当前配置与完整文件集，不能换成镜像默认值。
