# procd 行为合同（本机范围）

对象：`procd 58eb263d`（OpenWrt 25.12.5）。范围见
[R63_PROCD_SCOPE.md](../../reports/ax3000t-stock-openwrt-25.12.5/R63_PROCD_SCOPE.md)。
这里只记**读源码不会一眼看到、但调用方能观察到**的行为，不重复源码结构。
差分是 [r65_procd_diff.sh](../../tools/r65_procd_diff.sh)。

本阶段（P3.1）只覆盖 `getpid() != 1` 那一半。`procd.c:main()` 是

```c
if (getpid() != 1)
	procd_connect_ubus();
else
	procd_state_next();
```

所以发货的 `/sbin/procd` 在 PID 1 之外跑就**正好是**一个总线上的服务监管器，
可以和候选逐字节比对。inittab、rcS、hotplug、watchdog 属于 P3.2，不在这里。

## 1. 一个实例什么时候"有效"

`instance_config_parse_command()` 是最容易搞反的地方：

| `command` | 结果 |
|---|---|
| **完全没有这个字段** | 有效。会被 `list` 列出，但永远不启动，日志写 `command not set` |
| 有，但是空数组 | **无效** |
| 有，但含非字符串元素 | **无效**（`blobmsg_check_attr_list`） |
| 有 `bundle` | 跳过整个 command 解析 |

而 `instance_dump()` 开头就是 `if (!in->valid) return;`——**无效实例根本不出现**，
不是出现一个空表。所以"列出但不启动"和"不列出"是两种不同的状态，
把它们合并会让一个纯声明式实例从 `service list` 里消失。

`instance_start()` 的三个早退（errors 非空 / 没有 command 也没有 bundle /
已经有子进程）都**发生在碰 `exit_code` 之前**，所以一个从没启动过的实例
`exit_code` 是 0，不是某个 spawn 失败码。

## 2. respawn 的 retry=0 是"永不放弃"

崩溃循环判定是

```c
if (in->respawn_count > in->respawn_retry && in->respawn_retry > 0)
```

**严格大于，而且要求 retry > 0**。所以 `retry = 0` 关掉的是**放弃分支**，
不是 respawn 本身——它意味着无限重启。默认值来自
`uint32_t vals[3] = { 3600, 5, 5 }`，即 threshold/timeout/retry，
数组给几个就覆盖几个，其余保留默认。

`term_timeout` 的默认值 5 在 `instance_init` 里，不在解析里。

> **2026-09-08 修订。** [R68](../reviews/R68_ASTRA_P31_REVIEW.md) 推翻了原第 3
> 和第 10 条，其余多条条件写宽了。第 3、10 条已按反例改写，并补了第 12 节
> 记录 R68 复现出来、原文完全没写的行为。仍未逐条收窄的是第 1、4、5、6、
> 8、9 条的边界条件——它们的主体结论有源码依据，但**不要把它们当成完整定义**。

## 3. reload_signal 让 restart 不再是 restart（**这一条是错的**）

`instance_restart()`：

```c
if (in->reload_signal) {
	kill(in->proc.pid, in->reload_signal);
	return;
}
```

发完信号**直接返回**。

**但"所以 pid 不变"是错的**，而且 r65 第 10 例并不证明它——那一例只发了两次
完全相同的 `set`，根本没有配置 `reload_signal`。R68/F07 的实测是：C 在一次更新里
**先按旧配置处理旧进程、再搬新配置**；被信号通知的进程本身也可能因此退出。
（本实现顺序反了，用新的 `reload_signal` 去打旧进程，实测把进程打死了。）

`instance_stop()` 里 `uloop_timeout_set(&in->timeout, ...)` 被
`if (!in->has_jail)` 包着——**jail 实例不会收到 SIGKILL**，ujail 自己负责收尾。

## 4. instance_update 的三条路

`instance_update()`：

- **没在跑，或正在停** → 搬配置然后 `instance_start()`，**无条件**，
  哪怕配置一个字段都没变。
- 在跑且配置变了 → `instance_restart()`（见上，可能只是发个信号）。
- 在跑且只有 `data` 变了 → 触发新旧两轮 `service.data.update`，**不重启**。

`instance_config_changed()` 比较的字段里**没有 `data`**，这就是第三条路的来源。

## 5. `list` 的字段顺序是接口

`service_dump()`：`autostart`（**只在 false 时出现**）→ `data` → `instances`
→ verbose 才有的 `triggers`、`validate`。

`instance_dump()`：`running` → running 才有的 `pid` → `command` → `bundle`
→ `term_timeout` → **不 running 才有的** `exit_code` → `errors` → `env`
→ `data` → `limits` → `netdev` → `reload_signal`（非 0 才有）→ `respawn`
（有策略才有）→ `trace`/`no_new_privs`（true 才有）→ `seccomp`
→ `capabilities` → `pidfile` → `user` → `group`。

## 6. validate 有两个不同的顺序

同一批 validator，两个方法按**不同顺序**打印，而且都不是字母序：

- `service list verbose` 走 `s->validators`，那是 `list_add` 建的，
  所以是**声明顺序的倒序**。
- `service validate` 走全局 `validators` avl（键是 package，**允许重复**），
  于是 package 按 strcmp 排序，同一个 package 内的 type 按**插入顺序**。
  option 是自己的 avl，所以按字母序。

`service_validate_add()` 缺 package、type、data 任一个就整条丢弃。
`service_handle_validate()` 只要看到 `service` 参数就**立刻返回空**，
在看 package/type 之前。

## 7. 触发器：一个规则引擎，一个命令名

`trigger_match()` 不是 glob：

```c
char *wildcard = strstr(match, ".*");
if (wildcard)
	return !strncmp(event, match, wildcard - match);
```

`.*` 把 pattern 截断，**点跟着星一起没了**。`interface.*` 的前缀是
`interface` 九个字符，所以 `interfaceX` 也匹配。r65 用事件 `mytrigX`
对着 `mytrig.*` 验过，两边都会触发。

`rule_handle_command()` 只认 `run_script` 一个名字，规则产出的其他命令
**静默丢弃**。

`trigger_command_add()` 按**整条 argv** 去重：已排队的同名命令只**延长**
定时器（`remaining < t->timeout` 才改），从不缩短；正在跑的标记一次
`requeue`。runqueue 宽度是 1。timeout 为 0 时实际延迟是 1 ms。

### `%` 展开（libubox `eval_string`）

- `%VAR%` 取值；**变量不存在就展开成空**，不是错误。
- `%%` 是字面量 `%`。
- `%` 的个数是奇数 → 整条命令报
  `Unterminated variable reference in string` 并作废。

`eq` / `regex` 里变量不存在返回**假**，不是错误——这就是
`["eq","ACTION","add"]` 在没有 ACTION 的消息上安全的原因。
`regex` 是 POSIX ERE（`REG_EXTENDED | REG_NOSUB`），**编译失败算假**。

## 8. update_start / update_complete 是跨调用的 vlist

`service_handle_update()` 把 `vlist_update`（标记全部）和 `vlist_flush`
（清掉仍被标记的）拆成两个 ubus 方法。中间的 `add` 会清掉它点名的那些标记。
这是调用方在不发一整个 `set` 的前提下表达"这些实例留下"的方式。

## 9. get_data 把服务级数据放在 `*` 下

`service_get_data()` 对服务自己的 data 用实例名 `"*"` 开表，实例 data 用
实例名。没有匹配项的服务或实例**整个表都不出现**。

`set_data` 带 `instance` 时**不触发任何 trigger**；不带时走
`service_update_data()`，先为**旧键**触发一轮，再为新键触发一轮。

## 10. 每实例 watchdog 的两个默认值和一个"自管理"位

`instance_config_parse` 里 `uint32_t vals[2] = { 0, 30 }`，只读前两个元素：

- mode 超出 `[0, __INSTANCE_WATCHDOG_MODE_MAX)` 就**回落到 0**（disabled）；
- freq **只有 atoi 之后为 0 才回落到 30**。写"不大于 0 就回落"是错的：
  值先经 `atoi` 再存进 `uint32_t`，`"-1"` 变成 `0xffffffff`，`> 0` 成立，
  不回落。R68/F16 实测 C 的 getter 显示 `timeout:-1`（CLI 对该 32 位值的表示）。

`service watchdog` 方法：`name` 和 `instance` 缺任一个都是 **NOT_FOUND**
（不是 INVALID_ARGUMENT），而且在查服务之前就判。传了 `mode` 或 `timeout`
任一个，就把实例标成 `self_managed`——之后 `instance_config_changed()`
**不再比较** mode/freq，所以再来一次带原始值的 `set` 不会重启它。
r65 用两次 `service list` 取 pid 比过这条。

`instance_dump()` 的 `watchdog` 表在**最后**，而且只在 mode 非 disabled 时出现。

## 12. R68 复现出来、原文没写的行为

这些是外部审查用实测反例确立的，不是从一次运行反推的：

- **`instance_update` 的顺序**：运行中的实例先按**旧配置**处理旧进程
  （`instance_restart`），再搬新配置。所以一次"加上 `reload_signal`"的更新，
  发的是旧配置的信号——也就是没有信号，走正常重启。
- **exec 失败是子进程的事**：C 先 fork，`execvp` 失败由子进程 `exit(127)`，
  因此走完整的 `instance_exit`，**respawn 预算生效**，一个稍后才出现的命令
  会被重试成功。父进程记个 127 就停下，在 `list` 里看起来一样，行为完全不同。
- **崩溃预算耗尽后实例保留**：`running=false`、带最后的 `exit_code`、
  **不再输出 `respawn`**（因为 dump 看的是当前预算，不是存下来的策略）。
- **`running` 是 `proc.pending`**：SIGTERM 宽限期内进程还活着，
  `running` 仍是 true、`pid` 仍在。用"打算停了"代替"进程还在"会让调用方
  以为进程已经没了。
- **没有显式 `group` 时主 GID 来自 passwd**，不是 UID。
- **`file`/`netdev` 比的是内容和身份**：`file` 存 MD5、`netdev` 存 ifindex，
  都是在**解析新配置时取快照**再和旧快照比。同路径文件被重新生成、
  同名接口被重建，都算变化。这不是持续监视器。
- **trigger 的 requeue 条件是 `!delay.pending`**，包含"延迟已到、
  已入队但还没拿到运行槽位"。只看"正在跑"会丢掉一次执行。
- **规则按对象归属**：服务的规则和它每个实例的规则是分开释放的；
  实例的 `triggers` 也要注册，不注册就永远不触发。
- **`service.data.update` 走内部规则引擎**，不是往 ubus 对象发通知；
  并且按**旧键、新键**两轮触发。
- **jail 的三个前置条件**：`trace` 会取消 jail；`/sbin/ujail` 不存在时，
  声明了 `require` 的实例**整个无效**，没声明的**静默失去沙箱照常运行**。
- **每实例 watchdog 是软件定时器**，`getpid() != 1` 时同样会动：超时后
  有 respawn 的重启、没有的直接停掉。配置值经 `atoi` 存进 `uint32_t`，
  `"-1"` 变成 `0xffffffff` 并**不会**回落到 30。
- **validate 合并不重排**：多个 validator 合进同一个 package/type 时，
  各自的 rules 按自己的 avl 顺序加入，先加的在前。

## 11. 本实现与原版的已知差异

- **子进程回收**用事件循环里的 `waitpid(WNOHANG)` 轮询，不是 SIGCHLD 处理器，
  所以退出会在一轮循环内被发现而不是立刻。netifd-rs 也是这样。
- ~~`rc(name, "running")` 这里没有~~ **已实现**：`service_update()` 的 glob +
  宽度 8 的 `r` 队列（r65 第 20 例、F17）；脚本输出按 `pipe_cb` 的形状
  以 `<file>: <line>` 记进日志。`rcS()` 的宽度 1 串行队列（`rcs::RunQueue::serial`
  + `queue_all`）也已实现并有单测，但**没有调用方**——它属于 PID 1（P3.2）。
- ~~实例日志 FD 指向 /dev/null~~ **已实现**：`stdout`/`stderr` 接到 procd 读的
  管道，逐行以 `basename(argv0)[pid]` 为 ident 进 syslog（r65 第 23 例）。
- **ubusd 重连后 watch 是否恢复**：**有意偏离**，见第 13 节。这是本合同里
  唯一一处候选故意不等于 C 的行为。
- ~~每实例 watchdog 定时器不会触发~~ **已实现**（软件定时器，超时后
  按 respawn 决定重启还是停止）。系统 `/dev/watchdog`、`WDTFD` 继承和
  magic close 仍属于 P3.2，
  所以 mode=active 的实例不会因为超时被重启。
- **container 对象**只为签名对齐而注册，容器方法一律拒绝；本机
  `ubus call service list` 没有任何容器。
- **`sysupgrade` / `validate_firmware_image`** 按真实签名注册并**拒绝**。
  本项目不刷设备，而一个静默成功的 sysupgrade 是能想到的最坏失败模式。

## 13. ubusd 断线与重连（R70 坐实）

发货 procd 丢失总线后以 50 ms→1 s 退避重连（`ubus.c`：`ubus_reconnect_cb`
只做 `ubus_reconnect()` + `ubus_add_uloop()`），重连时重新注册
`service`/`system`/`container` 与 `hotplug.*` 对象，实例监管不中断
（实测重连前后子进程 pid 不变）。

**但 watch 订阅链在重连后永久失效**：重启前声明的 watch 不再重新附着，
重启后新声明的 watch 也永不附着。根因在两层：libubus 的 `ubus_reconnect()`
→ `ubus_refresh_state()` 只重放对象注册和 libubus 自己 auto-subscribe 的
`register`，**不重放** `ubus_register_event_handler()` 那次对 `ubus.event` 的
`register`；而 procd 的 `watch_ubus()` 只在首次连接的 `ubus_connect_cb()` 里
调用。对照实验里直接 `service event` 仍能触发，所以失效的只是订阅链。
证据：[R70 §一](../reviews/R70_FABLE_P31_REVIEW.md)，探针
`tools/r70/reconnect_probe.sh`（重启后新建 watch 指向新对象，C 30 s 不触发，
`ubus monitor` 可见 `ubus.object.add` 已投递而没有 `lookup`/`subscribe` 跟进）。

**procd-rs 有意偏离**：重连时重新注册事件处理并重订阅所有 watch
（`reconnect()` → `register_event_handler` + `resubscribe()`）。理由：
(a) 设备上 ubusd 从不重启（决策 0015），偏离在设备上不可观测；
(b) C 的行为是一次性注册的遗漏而非设计——复刻它意味着一次总线重启后
netifd→procd 的接口触发器全部静默。决定于 2026-09-08 由项目负责人作出。
r65 不比较这一条（F06 只断言监管器回到总线），证据是上述独立探针。

**watch 释放的精确形状（不是偏离）**：C 的 `watch_del()` 只从链表删条目，
**不 `ubus_unsubscribe`**。所以实例释放后：(1) 被 watch 的对象**重建**
（新 id）→ 不再重订阅 → 不触发；(2) 同一对象**仍活着**继续 notify → 旧订阅
还挂在 ubusd 上 → `watch_notify_cb` 照样 `trigger_event`，别的服务对该通知
类型的规则照触发。候选在 `f473c23` 起与此一致：`resubscribe()` 不再对
"没人要的路径"退订。r65 的 F04b 用 notifier 重建对象，落在 (1)。

## 14. `list` 回显数组字段的顺序，和 `service` 对象的通知（R70 后续实测）

**列表顺序。** procd 用自己的 `blobmsg_list_fill(list, data, len, array)` 存
`env`/`data`/`limits`/`jail.mount`（表）和 `netdev`/`file`/`error`/`jail.setns`
（数组）：avl 树、`avl_strcmp`、**不允许重复**。表元素的键是名字；数组元素的键是
`blobmsg_data()` **当作 C 字符串**——字符串数组就是值本身，而 `setns` 这种表数组
就是原始负载到第一个 NUL 为止的那几个字节。可观测后果（都在发货 procd 上量过，
r65 第 25b 例）：

- `netdev: ["zeth","aeth","meth","aeth"]` 回显为 `["aeth","meth","zeth"]`；
  同名重复丢弃；换个顺序再 `set` **不算配置变化**（`blobmsg_list_equal` 按 avl 序比）。
- `env`/`limits`/`data` 按名字排序；同名重复**第一个赢**。
- `setns: [{pid:3,…},{pid:1,…},{pid:2,…},{namespaces:[..]}]` 回显为
  `[{namespaces:[..]},{pid:3,…}]`：三个以 `pid` 属性开头的表负载前几个字节相同，
  被当成重复只留第一个；没有 `pid` 的那个首字节不同，排在前面。ujail 的 `-j`
  参数也只来自留下的那些。
- `file` 不出现在 `list` 里，但同样排序去重，所以换序不重启。

**通知。** `service` 对象上 `ubus_notify` 的全部形状（`ubus subscribe service`
可见，r65 第 28 例按排序后的多重集比较）：

| 何时 | 通知 | 负载 |
|---|---|---|
| 新建服务的 `set`/`add` 返回后 | `service.start` | `{"service"}` —— 更新已有服务**不**发 |
| 服务被释放（`deleted` 且无实例） | `service.stop` | `{"service"}` |
| 实例 fork 成功 | `instance.start` | `{"service","instance"}` |
| 实例被回收 | `instance.stop` | 同上 |
| 崩溃预算内/外 | `instance.respawn` / `instance.fail` | 同上（设备 `58eb263` 是三字段；上游 HEAD 已加 pid/exit_code，见 R70 基线） |
| `service event` | `event.trigger` | 请求原样：`{"type","data"}` |
| `service event` 且 type 为 `config.change`、data 有 `package` | 另发 `config.change` | `{"config": package}` |
| `set_data` / data 变化 | **没有**通知 | `service_data_trigger()` 只走内部规则引擎 |
