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

- 没有 `link_up` 返回 `INVALID_ARGUMENT`；`link_up=false` 触发
  `IFPEV_LINK_LOST` 并返回 0（**不碰地址**）。
- `keep=true` 表示保留现有 L3 设备与地址；但如果接口不是 `IFS_UP` 或没有
  `l3_dev`，`keep` 被强制为 false。
- `ifname` 存在时 `keep` 也被强制为 false，并按 `ifname` 取/建设备
  （`addr_ext` 时 `dev_create` 从 1 变 2）；`tunnel` 存在时改为建隧道。
- 随后 `interface_set_l3_dev` + `device_claim` + `device_set_present(true)`，
  再 `interface_update_start(iface, keep)` 走地址/路由/DNS 的增量更新。

19 个属性：`action error command env signal available link_up ifname address_ext
routes routes6 tunnel data keep host dns dns_search neighbors neighbors6`。

## 5. 本机实际用到的 handler

`dhcp`（拉 `udhcpc`）、`dhcpv6`（拉 `odhcp6c`）。`ppp`/`pppoe` 已注册但本机没有
接口使用。三个脚本都保留不重写（计划 §1）。

`get_proto_handlers` 每个 handler 报一张 `validate` 表加 8 个布尔
（`immediate no_device init_available renew_available force_link_default
last_error teardown_on_l3_link_down no_task`）。`static` 的值已在 R45 §2 记录。
