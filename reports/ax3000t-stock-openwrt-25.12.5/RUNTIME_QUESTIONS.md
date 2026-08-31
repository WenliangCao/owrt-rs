# AX3000T stock / OpenWrt 25.12.5：运行态问题单

> I0.6 状态：完成
> 日期：2026-08-31
> 授权状态：**未授权执行**。设备访问未授权，collector 未批准。
> 本文件是一份数据清单，不是可执行 collector。

## 1. 授权边界（先读这一节）

**取得设备 shell 或 ubus 访问本身就是一次状态变更，不是"只读采集"的一部分。**

出厂 OpenWrt 需要先设置 root 口令才能用 dropbear 登录；启用 SSH、设置口令、
改变 dropbear 配置都会修改设备。这些属于**单独的授权项**，必须由用户明确批准，
不能被包装进"只读观察"。

因此 I0.7 的前置授权分成两件独立的事：

1. **接入授权**：允许以何种方式接触设备（既有 SSH 会话 / 串口 / LuCI），以及为此
   需要做的任何前置改动；
2. **采集授权**：允许执行本文件 §3 的哪些命令。

在两者都获得明确批准之前，不执行任何一条。

## 2. 命令分级与排除清单

每条候选命令都经过源码审查并归入四类之一。**只有 `read-only` 类可以进入采集清单。**

| 类别 | 含义 |
|---|---|
| `read-only` | 只读取已有状态，不 fork、不写文件、不改内核或服务状态 |
| `executes-code` | 会执行程序或脚本 |
| `mutates-state` | 会写配置、改系统状态或创建会话 |
| `disrupts-service` | 会中断或扰动正在提供的服务 |

### 2.1 明确排除的命令（11 条）

这些命令看起来像"读"，源码审查后确认不是：

| 命令 | 类别 | 审查结论 | 依据 |
|---|---|---|---|
| `ubus call rc list` | executes-code | `rc_list` 对**每个** `/etc/init.d` 脚本 `fork()` + `execl(path, path, "running")` | `rpcd/rc.c:122-172,251-255` |
| `ubus call iwinfo scan` | disrupts-service | 调用 `iw->scanlist`，触发 nl80211 主动扫描，扰动射频 | `rpcd/iwinfo.c:377-396` |
| `ubus call luci getFeatures` | executes-code | 运行 `hostapd -v`、`wpa_supplicant -v`、`dnsmasq --version`、`odhcpd -h`、`ipset --help` | `/usr/share/rpcd/ucode/luci:268,275,278,294,315` |
| `ubus call luci setBlockDetect` | mutates-state | `system('/sbin/block detect > /etc/config/fstab')` 覆写配置文件 | 同上 `:532` |
| `ubus call luci setLocaltime` | mutates-state | 改系统时钟并重启 `sysfixtime` | 同上 `:111-112` |
| `ubus call luci setPassword` | mutates-state | 通过 `busybox passwd` 改口令 | 同上 `:474` |
| `ubus call luci setInitAction` | executes-code | `init_action` 执行 `env -i /etc/init.d/<name> <action>` | `/usr/share/ucode/luci/sys.uc:153-159` |
| `ubus call network.interface.<n> up\|down\|renew` | disrupts-service | 改接口状态，`renew` 重启协议处理器 | `netifd/ubus.c:1096-1101` |
| `ubus call uci get\|configs\|changes` | mutates-state | 所有 uci 方法都要求 `ubus_rpc_session`，调用意味着先建会话 | `rpcd/uci.c:52,612-615` |
| `ubus call file read\|exec` | executes-code | `file.exec` 执行任意程序；两者都需要会话 | `rpcd/file.c:1115-1126` |
| `ubus call system reboot` / `rpc-sys upgrade_start` / `rpc-sys factory` | mutates-state | 终止性操作 | `procd/system.c:855-862`；`rpcd/sys.c:486-497` |

两个对照值得记住：

- `ubus call rc list` 被排除，但 `ubus call service list` 被批准。差别在源码：
  前者 fork+exec 每个 init 脚本，后者只遍历 avl 树做序列化
  （`procd/service/service.c:515-543`）。
- `luci.getInitList` 是安全的（`init_list`/`init_enabled` 只做 glob 和 stat），
  而 `luci.setInitAction` 不是。同一个 ubus 对象内部安全性并不一致，
  **必须按方法而不是按对象授权**。

### 2.2 生成器强制的规则

[i0_6_candidates.py](../../tools/i0_6_candidates.py) 在生成清单时强制：

- 任何 `class != "read-only"` 的命令出现在已批准问题里 → 直接失败；
- 每条命令必须同时有 `review`、`source`、`expected_status`、`timeout_s`；
- 每个问题必须写明 `closes`、`why_static_is_insufficient`、`fields`、`redaction`；
- 任何"没有运行态问题"的职责必须给出书面理由，否则失败。

## 3. 问题清单（15 项，23 条已批准命令）

完整机器记录见
[runtime-questions.json](../../manifests/ax3000t-stock-openwrt-25.12.5/runtime-questions.json)。
下表给出每项的核心内容；`why_static_is_insufficient`、逐命令审查依据、超时和期望状态码
以 JSON 为准。

| ID | 问题 | 关闭的静态边界 | 已批准命令 | 脱敏 |
|---|---|---|---|---|
| Q00 | 设备运行的是否正是本项目基线镜像 | I0.7 前置门 | `cat /etc/openwrt_release /etc/os-release`；`cat /tmp/sysinfo/{board_name,model}`；`ubus call system board` | 主机名可能是用户自定义，提交前检查 |
| Q14 | 安装包集合是否已偏离发布镜像 | PROVENANCE_GAPS 未验证项 | `cat /lib/apk/db/installed` | 提交派生 diff，不提交原始数据库 |
| Q01 | 实际 kernel command line | BOOT_CHAIN §8 | `cat /proc/cmdline` | 提交前检查厂商序列号 |
| Q02 | 实际走过的启动分支，failsafe 是否触发 | BOOT_CHAIN §8 | `logread -l 400`；`test -e /tmp/.failsafe` | **必须**：日志含 MAC、主机名、SSID |
| Q03 | 是否已过首启，剩余 uci-defaults | CONFIG_FLOW §7、BOOT_CHAIN §8 | `ls -la /etc/uci-defaults/ /etc/board.json /etc/rc.local` | 无 |
| Q04 | 生成后的 network/system/wireless 与 board.json | CONFIG_FLOW §7 | `cat /etc/board.json`；`cat /etc/config/{network,system,wireless}` | **必须**：无线密钥、MAC、ULA、DUID、WAN 凭据 |
| Q05 | 实际注册的 ubus 对象与方法签名 | IPC_CATALOG §10 | `ubus list`；`ubus -v list` | 检查 `wpa_supplicant.*` 名中的 SSID |
| Q06 | procd 实际监管的服务与实例、触发器 | SERVICE_GRAPH §7 | `ubus call service list "{\"verbose\":true}"` | 检查命令行中的凭据 |
| Q07 | netifd 实际接口与设备状态 | SERVICE_GRAPH §7、IPC_CATALOG §10 | `ubus call network.interface dump`；`ubus call network.device status` | **必须**：地址、前缀、DNS、MAC、WAN 对端 |
| Q08 | fw4 实际生成的 nftables ruleset | SERVICE_GRAPH §7 | `nft -a list ruleset` | **必须**：地址与前缀 |
| Q09 | dnsmasq 是否用默认对象名；odhcpd 是否 ipv6only | IPC_CATALOG §10 与 build gating 结论 | `ubus -v list dnsmasq`；`ubus -v list dhcp` | 无 |
| Q10 | `udebug` 对象由谁提供 | IPC_CATALOG §10 | `ubus -v list udebug` | 无 |
| Q11 | 声明的 jail 与降权是否真的生效 | SERVICE_GRAPH §7 | 对 hostapd/wpa_supplicant/ntpd/dnsmasq/logd 的 pid 读 `/proc/<pid>/status` 与 `/proc/<pid>/ns` | 检查进程参数中的路径 |
| Q12 | 当前配置变更基线与未提交 delta | CONFIG_FLOW §7 | `ls -la /tmp/.uci /var/run/uci`；打印固定分隔行；`cut -c35- /var/run/config.md5` | 丢弃 `/tmp/.uci` 下的会话标识 |
| Q13 | 六个随镜像发布的配置是否已漂移；uhttpd/rpcd 实际设置 | CONFIG_FLOW §7、IPC_CATALOG §7 | `sha256sum` 六个 config；`cat /etc/config/{uhttpd,rpcd}` | **必须**：丢弃 rpcd login 段的 password 字段，即使仍是 `$p$root` 占位符也不记录 |

### 3.1 几处刻意的取舍

- **Q04 用 `cat` 而不是 `uci show`。** `uci show` 会合并 `/tmp/.uci` 会话 delta，
  回答的是另一个问题；而经 ubus 的 `uci.get` 需要先建 rpcd 会话（见 §2.1）。
  要看持久态就直接读文件。
- **Q08 用 `nft list ruleset` 而不是 `fw4 print`。** `fw4 print` 会**重新生成**规则，
  回答的是"现在的配置会生成什么"，而问题问的是"当前加载的是什么"。两者可能不同，
  混用会把不一致掩盖掉。
- **Q12 只取 `/var/run/config.md5` 的文件名列，不取哈希。** 问题是"哪些包在基线里被
  跟踪"，不需要哈希值本身。
- **Q10 允许退出 0 或 4。** 0 表示对象存在并可列出，4 是 ubus 对不存在对象的
  `Not found`；两者都是该问题要区分的有效观察，不应把 4 当成采集失败。
- **Q13 六个配置只取 sha256，只有 uhttpd 和 rpcd 取全文。** 这两个决定 HTTP→ubus 和
  RPC 的暴露面，需要内容；其余用哈希就能回答漂移问题，不必导出内容。
- **Q14 用 `cat /lib/apk/db/installed` 而不是 `apk list`。** 后者是包管理器调用，可能触碰
  索引或网络；前者是纯文件读，且格式与 I0.4 解析的一致。
- **Q11 不用 `ps w`。** 早期草稿里有一条全量 `ps w`，那正是退出门禁止的"顺便把所有
  状态 dump 一遍"。改为只读取五个目标进程的 `/proc/<pid>/status` 与 ns 链接。

### 3.2 没有出现在清单里的东西

以下静态未知项**故意不设采集项**，因为只读观察无法回答：

| 未知项 | 为什么不采集 |
|---|---|
| `reload` 的实际中断行为 | 需要主动触发 reload，属于实验不是观察 |
| 服务失败传播 | 需要注入故障 |
| 并发写入 UCI 的行为 | 需要制造并发窗口 |
| R17 的升级/恢复路径 | 全部是终止性操作，属于 H1 的 recovery gate |
| 方法级 blobmsg policy 完整字段 | Q05 的 `ubus -v list` 给出签名；更完整的字段/类型约束应在 C1 冻结合同时从源码逐方法提取，不靠设备猜 |

## 4. I0.7 执行前置

执行时必须按 EXECUTION_PLAN §15 的清单逐条满足，此处只强调三点：

1. 先证明设备身份与镜像身份一致，再执行任何采集；
2. 原始输出只进入 Git 之外的 evidence 目录，脱敏结果经人工复核后才进仓库；
3. 一次观察不能外推到未观察的时序或故障状态——每条结论都要带采集时间和范围。

`runtime-questions.json` 中 `authorization.collector_approved` 与
`authorization.device_access_approved` 目前均为 `false`。
