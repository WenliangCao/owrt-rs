# proto-shell 合同（本机需要的部分）

来源：`netifd cbb83a18` 的 `proto-shell.c`、`proto.c`、`netifd-process.c`，
以及设备上的 `/lib/netifd/netifd-proto.sh`（484 行）与
`/lib/netifd/proto/{dhcp,dhcpv6,ppp}.sh`。

本文是**实现前的合同记录**，不是已实现的说明。当前状态：

- **已实现**：受监管子进程子系统（`components/netifd/src/process.rs`，
  7 个单元测试）——§1 说的那个前提。
- **已实现但**未接入 daemon（`components/netifd/src/proto.rs`，12 个单元测试）：
  §1c 的 handler 发现（含"以 proto 目录为 cwd"和"空 dump 视为失败"）、
  §3 的状态机（`plan()`，含 setup 只在 IDLE 接受、setup 中 teardown 走 abort、
  teardown 幂等、renew 记住而不排队、`ERROR=` 的传递）、以及 §2 的 argv 构造。
- **未实现**：§4 的 8 个 `notify_proto` action。
  没有 action 0，接口即使脚本成功也永远到不了 `IFS_UP`。因此 daemon **故意还没有
  接线**：`get_proto_handlers` 仍只报 `static`，遇到 `dhcp`/`dhcpv6` 的接口发
  `ifup-failed` 并**保持 down**。报一个 handler 却让接口卡在 SETUP，比明确拒绝更糟
  （见 R45 §"两个已知缺口"）。

## 1. 最关键的一点：netifd 是协议 helper 的进程监管者

`dhcp.sh` **不自己**拉起 `udhcpc`。它通过 `notify_proto` 的 **action 1
（`run_command`）** 把 argv 和 env 交给 netifd，由 netifd `fork`+`exec` 并登记为
`state->proto_task`。action 2（`kill_command`）再让 netifd 发信号。

也就是说：实现 proto-shell **必须**先实现一个受监管子进程子系统
（启动、SIGTERM/SIGKILL、退出回调、pid 记账），不能把 helper 交给 shell 自己去
`&` 后台化——那样 netifd 就不知道 helper 死了。

## 1b. 脚本必须以 proto 目录为工作目录执行

`/lib/netifd/proto/dhcp.sh` 第 7 行是 `. ../netifd-proto.sh`——**相对路径**。
直接 `chroot ... /lib/netifd/proto/dhcp.sh dhcp dump` 会立刻失败：

```
/lib/netifd/proto/dhcp.sh: .: line 7: can't open '../netifd-proto.sh'
```

而且失败时**退出码仍是 0**，所以"脚本跑过了"不能当成"脚本成功了"。
`netifd_start_process` 里的 `fchdir(proc->dir_fd)` 就是为此存在的：
必须先 `chdir` 到 `/lib/netifd/proto`，再以 `./dhcp.sh` 执行。

## 1c. `dump` 的输出格式

```json
{ "name": "dhcp",
  "config": [ ["ipaddr:ipaddr", 3], ["broadcast:bool", 7], ["mtu_dslite", 5],
              ["sendopts:list(string)", 1] ],
  "no-device": false, "no-device-config": false, "no-proto-task": false,
  "available": false, "renew-handler": true, "lasterror": false,
  "teardown-on-l3-link-down": false }
```

`config` 每项是 `["名字[:校验式]", blobmsg 类型]`。`get_proto_handlers` 的
`validate` 表取冒号后的校验式；**没有冒号时按类型给默认名**——实测
3 → `string`、5 → `uinteger`、7 → `bool`（例如 `clientid` 是 3 报 `string`，
`delegate` 是 7 报 `bool`，`skpriority` 是 5 报 `uinteger`）。

八个布尔的对应关系（`static` 的值见 R45 §2，shell handler 的 `immediate` 与
`force_link_default` 都是 false）：

| `get_proto_handlers` | `dump` |
|---|---|
| `no_device` | `no-device` |
| `init_available` | `available` |
| `renew_available` | `renew-handler` |
| `last_error` | `lasterror` |
| `teardown_on_l3_link_down` | `teardown-on-l3-link-down` |
| `no_task` | `no-proto-task` |
| `immediate` / `force_link_default` | 不在 dump 里，shell handler 均为 false |

## 2. 脚本调用形式

```
<script> <proto-name> <action> <interface-name> <config-json> [<main-device>]
```

- `action` ∈ `setup` | `renew` | `teardown`；启动时另有一次 `dump` 用于注册。
- `<config-json>` 是该接口整段配置的 `blobmsg_format_json(..., true)`。
- `<main-device>` 只在 `iface->main_dev.dev` 存在时作为**第 5 个参数**出现。
- `teardown` 时，如果 `state->last_error >= 0`，环境里多一条 `ERROR=<n>`。

## 3. 状态机（`state->sm`）

`S_IDLE` → `S_SETUP` → `S_IDLE`；teardown 走 `S_TEARDOWN`；
setup 期间收到 teardown 则进 `S_SETUP_ABORT`：

- `PROTO_CMD_SETUP` 只在 `S_IDLE` 接受，否则返回 -1。
- `PROTO_CMD_RENEW` 在 `PROTO_FLAG_RENEW_AVAILABLE` 未置位时直接返回 0；
  脚本任务还在跑时置 `renew_pending` 并返回 0（**不排队第二个进程**）。
- `PROTO_CMD_TEARDOWN` 在 `S_SETUP` 且脚本仍在跑时：设 1000 ms 的
  `teardown_timeout`、给脚本和 proto_task 各发 `SIGTERM`、进 `S_SETUP_ABORT`、
  返回 0——**不立即跑 teardown 脚本**。
- 正常 teardown 设 5000 ms 的 `teardown_timeout`。
- `S_TEARDOWN` 期间再来 teardown 返回 0（幂等）。

`checkup_timeout`：接口在 `checkup_interval` 秒后仍不是 `IFS_UP` 且 `autostart`
仍为真，就自己发一次 teardown。

## 4. `notify_proto` 的 8 个 action

| action | 含义 | 关键约束 |
|---:|---|---|
| 0 | `update_link`：报告链路状态与地址/路由/DNS | `S_TEARDOWN`/`S_SETUP_ABORT` 期间返回 `PERMISSION_DENIED` |
| 1 | `run_command`：让 netifd 启动 helper | 同上；argv 上限 64、env 上限 32 |
| 2 | `kill_command`：给 helper 发信号 | `signal > 31` 一律当 `SIGTERM`；`SIGTERM`/`SIGKILL` 会置 `proto_task_killed` |
| 3 | `notify_error` | 记 `last_error`，teardown 时经 `ERROR=` 传给脚本 |
| 4 | `block_restart` | |
| 5 | `set_available` | |
| 6 | `add_host_dependency` | 让本接口依赖另一个接口到某主机的可达性 |
| 7 | `setup_failed` | |

`action` 缺失返回 `INVALID_ARGUMENT`；未知 action 同样。

### action 0 的细节

- 属性名是 **`link-up`（连字符）**，不是 `link_up`。名字写错的后果不是报错而是
  「什么都没发生」：脚本每次上报都拿到 `INVALID_ARGUMENT`，接口一直不 up。
  r52 第一次跑出来就是这个（见 §7）。
- 没有 `link-up` 返回 `INVALID_ARGUMENT`；`link-up=false` 触发
  `IFPEV_LINK_LOST` 并返回 0（**不碰地址**）。
- `IFPEV_LINK_LOST` 的语义容易看反：**接口不是 `IFS_UP` 时它直接 return**，
  什么都不做。`dhcp.script` 的 `deconfig` 分支在拿到 lease 之前就会发一次
  `link-up:false`，把它当 ifdown 处理会在启动时就把接口拆掉。真的触发时接口回到
  `IFS_SETUP`（不是 `IFS_DOWN`），因为 helper 还在跑，还可能拿到地址。
- `keep=true` 表示保留现有 L3 设备与地址；但如果接口不是 `IFS_UP` 或没有
  `l3_dev`，`keep` 被强制为 false。
- `ifname` 存在时 `keep` 也被强制为 false，并按 `ifname` 取/建设备
  （`addr_ext` 时 `dev_create` 从 1 变 2）；`tunnel` 存在时改为建隧道。
- 随后 `interface_set_l3_dev` + `device_claim` + `device_set_present(true)`，
  再 `interface_update_start(iface, keep)` 走地址/路由/DNS 的增量更新。

19 个属性（`notify_attr`，proto-ext.c；名字照抄，注意混用连字符和下划线）：

```
action error command env signal available link-up ifname address-external
routes routes6 tunnel data keep host dns dns_search neighbor neighbor6
```

### action 0 的载荷形状（**不是** proto-static 读的那套扁平 UCI 形状）

地址和路由都不在 `notify_attr` 里，而是由另外两张策略表解析同一个顶层 blob：

- `ipaddr` / `ip6addr` 是**表的数组**，每个表自带掩码
  （`proto_ip_addr`：`ipaddr mask broadcast ptp preferred valid offlink class`）。
  缺 `ipaddr` 或掩码超出族上限就丢弃这一条。
- `gateway` / `ip6gw` 是字符串，且**只有该族拿到过地址才会被应用**。
- `routes` / `routes6` 是表的数组，走 `interface_ip_add_route`
  （`route_attr`：`interface target netmask gateway metric mtu table valid
  source onlink type proto disabled`）。`target` 里的 `/len` 会覆盖 `netmask`；
  IPv4 且掩码 < 32 时主机位被清零。`source` 无掩码时按主机路由（v4 走
  `RTA_PREFSRC`）。
- `data` 是一个表，每个成员按名字存进一棵 avl 树 —— 所以 status 里 `data`
  是**按名字排序**的，不是到达顺序。
- `metric`/`mtu`/`table`/`type`/`proto` 只有显式给了才置对应的 `DEVROUTE_*` 标志，
  也只有置了标志才会打印出来。主表（`main`）不置 `DEVROUTE_TABLE`。

`parse_netmask_string` 的两个细节都是可观测的：不含 `.` 时走
`strtoul(str, &err, 0)`（**基数 0**，所以 `0x18` 是 24；只有尾部有垃圾才算错，
空串是 0）；含 `.` 时 v6 直接报错，v4 用 `32 - fls(~mask)`——**没有连续性检查**，
`255.0.255.0` 会得到 8 而不是被拒绝。改成"更正确"的写法就是偏离。

## 4b. 设备的 claim 计数与 `system_if_clear_state`

链路状态跟的是 `dev->active` 这个**计数**，不是某个接口的状态：

- `device_claim` 只在计数 0→1 时真的把设备拉起来，`device_release` 只在归零时
  拉下去。
- `simple_device_set_state(dev, true)` 会先 claim 设备的**父设备**——
  `system_if_get_parent` 读 `/sys/class/net/<dev>/iflink`，对 DSA user port 是
  conduit，对 veth 是对端。这就是 conduit 被自动拉起来的机制。
- 一个接口持**两个** claim：ifup 时的 `main_dev`（`interface_set_up` 里
  `device_claim(&iface->main_dev)`）和协议上报时的 `l3_dev`。`IFPEV_DOWN` 只在
  `!(config_state 正常 && autostart && available)` 时释放 `main_dev`——所以
  「清掉 autostart」才是让设备真的落下去的那一步，链路丢失则不会。
- `device_init` 对**每个**新建的 device 对象跑一次 `system_if_clear_state`：
  拉下链路、退出网桥（同名网桥直接删掉）、清掉两个族的地址/路由/永久邻居、
  再把 `disable_ipv6` 写回 0。这不只发生在配置里出现的设备上：只作为别人的父设备
  被创建也算。别人放在这种设备上的地址会在 netifd 启动时消失。
- 清理是「dump 一遍，把命中的报文改成 DEL 再发回去」，而且**必须等 dump 结束再发**
  ——带着 dump 序列号的错误应答会中断 dump。过滤条件：地址比 `ifa_index`；路由要求
  `RTA_OIF` 命中且**跳过内核自己的 IPv6 路由**；邻居只删 `NUD_PERMANENT` 或
  `NTF_PROXY` 的，而且代理项要**单独发第二次 dump** 才会被内核列出来。

## 4c. hotplug.d 的排队规则

`interface_queue_event` 每次都发 ubus 广播和通知，**只有 hotplug.d 调用会被合并**。
一个接口最多有一个"排队中"事件和一个"正在处理"事件：

- 正在处理这个接口时：队列里已有一条就覆盖它（`IFEV_UPDATE` 除外）；队列里没有，
  则只有 `ev != current_ev` 或 `ev == IFEV_UPDATE` 才入队。
- 处理别的接口（或空闲）时：队列里已有一条就覆盖（除了「排队的是 ifup、来的是
  ifupdate」），没有就入队。

后果：**static 拆接口的两次 `IFEV_DOWN` 只有一次 hotplug 调用**（第二次紧跟第一次，
落在"正在处理且事件相同"上被丢掉），而**shell 协议的两次是两次**——中间隔着
teardown 脚本和 helper 退出的时间，第一次调用早就结束了。这不是可以用一个
"这次要不要调 hotplug" 的布尔量表达的，用布尔量在 static 上碰巧对、在 shell 上错。

## 5. 本机实际用到的 handler

`dhcp`（拉 `udhcpc`）、`dhcpv6`（拉 `odhcp6c`）。`ppp`/`pppoe` 已注册但本机没有
接口使用。三个脚本都保留不重写（计划 §1）。

`get_proto_handlers` 每个 handler 报一张 `validate` 表加 8 个布尔
（`immediate no_device init_available renew_available force_link_default
last_error teardown_on_l3_link_down no_task`）。`static` 的值已在 R45 §2 记录。

## 7. r52 的教训：沉默不等于成功

r52 用 `busybox udhcpd` 在 veth 对端起一台真的 DHCP 服务器，跟设备自己的 C netifd
比整条 proto-shell 路径。前三次跑，候选侧的 daemon 日志里**只有一行** handler 发现
信息——看起来像"脚本根本没跑"，其实脚本一直在报错。

原因：helper 的输出只在它退出时才被读。`udhcpc -f -t 0` 永远不退出，所以
`dhcp.script` 打的每一行——包括那句 `notify_proto ... (Invalid argument)`——都躺在
一个没人读的管道里。C 是从 uloop 逐行读的（`netifd_process_cb`），改成逐行读之后，
真正的错误第一时间就出来了。管道写满还会把 helper 卡住。

同一条教训的第二次：`ifdown` 之后 helper 还活着、hotplug 少一次调用，两个现象都指向
teardown 命令从来没跑过——门槛条件要求状态机不在 `S_IDLE`，而协议跑通之后正好停在
`S_IDLE`，也就是 teardown 命令**应该**从那里出发的状态。

第三次：子进程退出原来只靠轮询发现，最多晚一个 poll 超时。这是能看见的——`ifdown`
之后 lease 还在设备上待那么久，而 C 已经删掉了。现在用 SIGCHLD self-pipe 唤醒循环,
超时只当兜底。
