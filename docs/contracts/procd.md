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

> **2026-09-08：以下第 3 条和第 10 条已被 [R68](../reviews/R68_ASTRA_P31_REVIEW.md)
> 的反例推翻，第 1、4、5、6、7、8、9 条条件写宽了。逐条修订前不要引用本文件
> 作为合同依据。**

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

## 11. 本实现与原版的已知差异

- **子进程回收**用事件循环里的 `waitpid(WNOHANG)` 轮询，不是 SIGCHLD 处理器，
  所以退出会在一轮循环内被发现而不是立刻。netifd-rs 也是这样。
- **`rc(name, "running")`**：`service_update()` 会 glob `/etc/init.d/<name>`
  并用 `running` 参数排队执行。这里没有——runqueue 属于 P3.2。
- **实例日志 FD**：原版在实例声明 `stdout`/`stderr` 时把它们接到自己读的管道。
  这里两个都指向 `/dev/null`。没人消费的管道正是被监管进程死锁的方式，
  所以在日志通路落地前不接管道。
- **每实例 watchdog 定时器不会触发。** 取值、`self_managed` 位和 `list` 输出
  对齐了，但定时器没做。**把它整个归到 P3.2 是错的**——R68/F16 实测 C 在
  `getpid() != 1` 下同样会在超时时停掉实例，所以这是 P3.1 的范围，
  所以 mode=active 的实例不会因为超时被重启。
- **container 对象**只为签名对齐而注册，容器方法一律拒绝；本机
  `ubus call service list` 没有任何容器。
- **`sysupgrade` / `validate_firmware_image`** 按真实签名注册并**拒绝**。
  本项目不刷设备，而一个静默成功的 sysupgrade 是能想到的最坏失败模式。
