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

`service state {spawn:false}` 以 `halt=false` 停止实例。对忽略 SIGTERM 的
子进程，期限到达后**不升级为 SIGKILL**，实例继续以原 pid 报告 running。
`service delete` 的 `halt=true` 仍会在期限到达后强杀。R90 用钉死镜像的
原版确认了两条路径，并修正 Rust 把 `Run::Halting` 当成 halt 标志的错误；
维护节拍、只读查询快路径和 respawn 调度保持原有实现。

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
- **ubusd 重连后 watch 是否恢复**：**有意偏离**，见第 13 节。
- **ubus 用户 home 的创建**（R73 审计发现的"治愈型"偏离）：STATE_UBUS 里
  C 对 pw_dir（/var/run/ubus）做**单层 mkdir**，父目录不存在就失败——设备
  上被 preinit 预建的 /var/run 掩盖，从不出错；procd-rs 用 create_dir_all
  建出整条链，所以在 C 起不来的环境（如无 /tmp/run 的命名空间 fixture）里
  也能走通。方向是候选更能自愈，无回归风险，保留不改。
- **PID 1 状态机与 inittab 已实现**（R71，隔离命名空间内完整启动+关机已验）：
  EARLY→UBUS→INIT→RUNNING、早期 ubus 服务、rcS 串行、respawn/askfirst/
  askconsole、SHUTDOWN/HALT。**hotplug/coldplug 已实现**（uevent 监听 +
  hotplug.json 规则 + makedev/rm/exec/button/load-firmware 队列 +
  udevtrigger 冷插；start-console 在父进程跑 inittab 处理器，注释里标了
  与 C 的差异）；**watchdog 完整面已实现**；**`hotplug.*` 对象已实现**
  （监管模式同样注册，r65 26c 例比对含 inotify 动态注册）；**`-h` hotplug
  daemon 模式已实现**（r72a 真 uevent 差分）；**askfirst 真 tty 交互已验**
  （r72b，pty 横幅→回车→激活）。**P3.2 无余量。** inittab id 字段不含斜杠
  （C 正则同形，r72b 实测）。设备上的 PID 1 启动验证属 P3.3 设备窗口
  （切换/回退：tools/p33_switch.sh，运行手册 R72）。
- ~~每实例 watchdog 定时器不会触发~~ **已实现**（软件定时器，超时后
  按 respawn 决定重启还是停止）。系统 `/dev/watchdog`、`WDTFD` 继承和
  magic close 仍属于 P3.2，
  所以 mode=active 的实例不会因为超时被重启。
- **container 对象**只为签名对齐而注册，容器方法一律拒绝；本机
  `ubus call service list` 没有任何容器。
- ~~system 对象方法全部拒绝~~ **board/info/watchdog/signal 已实现**并进 r65
  差分（26b 例）：board 逐字节比、info 比形状、watchdog 的钳制算术
  （frequency ≤ timeout/2，timeout ≤ frequency 时翻倍）、signal 的
  INVALID_ARGUMENT 与忽略 kill() 结果，都与发货 procd 一致。
- ~~`sysupgrade` / `validate_firmware_image` 拒绝~~ **已实现**（P4，
  sysupgrade.rs）：validate 是 fork/exec 校验脚本 + "首个完整 JSON 对象
  获胜、尾随忽略"的 vjson 语义（脚本缺失/exec 失败 = "no JSON input"，
  与 C 的空管道一致）；sysupgrade 走三布尔门（valid/forceable/
  allow_backup 必须齐且为 bool 型）→ 与 C 逐字节相同的错误应答表 →
  service_stop_all（term_timeout 上限睡眠 + inittab kill）→ chroot(prefix)
  + WDTFD 移交 + UPGRADE_BACKUP/UPGRADE_OPT_*（名字大写、非 [A-Za-z0-9_]
  整项丢弃、仅整数值）→ execvp /sbin/upgraded 替换本进程。exec 失败按 C
  清理（unsetenv/cloexec/chroot(".")）并回 UNKNOWN_ERROR 无错误表。
  差分：r65 F21（安全错误路径，含 validate 全 JSON 回显字节比）+
  r75（双侧 ns 内真 exec 移交：argv/PID1/环境逐字节比）。**已知文本偏离**：
  JSON 解析器的错误消息细节（"failed to parse JSON: ..."）来自各自解析器，
  仅在校验脚本输出损坏 JSON 时可见。

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

**R93：按新增对象的 path 重订阅。** 精确 C 的 `watch_subscribe_cb` 只在事件的
`path` 与某条 watch 相同时才 lookup。候选曾对任意 `ubus.object.add` 扫描所有
watch 并逐条同步 lookup，每条最多等待 1 秒；无关对象变化也可能长时间阻塞实例期限
和硬件看门狗维护。现在无关或缺失 path 不发总线调用，匹配 path 只 lookup 一次，
同 id 不重复订阅、重建后的新 id 重新订阅；带同一 id 的重复事件不再触发 lookup。
显式配置更新和重连仍恢复全部 watch，但分批进入主循环，既有不退订的合同不变。`watch_tests` 用真实 Unix socket 记录 LOOKUP/SUBSCRIBE 报文，
覆盖无关/缺失 path、同 id、新 id 和重连采用的全量重放路径。

**R93：总线 I/O 不得无限阻塞监管。** 初始连接和重连均启用 1 秒对象服务 I/O
预算，覆盖一帧完整接收、reply 和 notify。半帧或发送背压超时会关闭损坏的传输，
主循环继续监管并重连；新连接的 admission/HELLO 同样受共享连接层 1 秒预算约束。
纯同步请求在帧边界超时保留连接，半帧超时关闭。相比 C 的无界补帧/发送等待，这是
有意收紧的故障边界。Linux 单测让假总线保持连接 2.2 秒但只发一个字节或不读大回复，
候选 1 秒后恢复实例期限处理并 SIGKILL 测试自己启动的子进程；不操作硬件看门狗。

**R93：批量恢复必须让出监管维护。** watch 使用去重待办队列，每个主循环最多处理一条
path（lookup ≤1 s，再 subscribe ≤1 s）；配置删除过滤过时待办，新增不重置已有顺序/重试时间，
重连清空连接所属 id 后重建全量队列。传输、timeout 或非永久错误按 1 s 延后轮转，无需新的
object.add 才能恢复；NOT_FOUND 等明确拒绝等待下次对象事件或配置更新。
**保留 R89 的返回时点：** service.set/add 携带 instances 时，成功 STATUS 等到该服务本次
每条 watch 已尝试后才返回，已有对象的首次通知不会被提前回复丢掉。每条之间继续监管维护；
NOT_FOUND 或失败也结束本次尝试，后续异步重试不无限阻塞回复。期间不分派后来的业务请求，
避免另一次 set/delete 先完成并替代本次配置；只保存一份拥有 Request 的待回复状态，断连
丢弃旧连接代际的请求及 fd，no_reply 仍不发送 STATUS。rc running 入队和新服务的
service.start 同样在初始 watch 尝试后完成，set 产生的 trigger 命令等待该边界再启动；
既有运行中命令及其回收继续进行。断连已应用的配置仍运行本地 running hook，旧连接的
service.start/reply 不跨代重放。其它服务的全量刷新和重连仍异步。
最初提前回复的队列版本确实退化：预先存在六对象、set 后立即通知最后对象，R89 12/12 送达，
提前回复版本 0/12 送达；不能以 C 的 watch_add 只存链表、不保证返回前订阅来接受该回退。
service.start 驱动立即通知的对照也曾复现 R89 12/12、仅延迟 STATUS 版 2/12；最终候选
恢复两种时序各 12/12。维护不在 lookup 与 subscribe 之间重入，避免 reap→collect_stopped→refresh_watches 的递归及服务生命周期交错。

hotplug 子系统同样使用去重登记队列：先推进 script jobs、读取最多一块 inotify 事件，再最多
执行一次 add/remove（≤1 s）；失败保留待办并延后，删除 button 仍无效。ADD_OBJECT 超时可能
已经成功但丢失对象 id，因而主动关闭传输后重连重建，避免盲重试永远撞上自己的同名对象。
队列截止时间参与 poll 以及纯读取洪流下的维护判断。最坏批次成本由 N×请求预算变为每轮
watch ≤2 s + hotplug 登记 ≤1 s；这是批量总线工作的边界，不把其它文件系统、子进程或
handler 成本称为硬实时上限，也不保证能满足用户自设小于该值的 watchdog timeout。

正常初始启动仍在 rcS 前尝试登记所有初始 hotplug 对象；每次尝试之间专门执行日志排空、
回收、实例期限和 watchdog，失败待办保留给主循环。不会在登记中递归推进 dispatch。
Linux 回归用真实 Unix socket 和自有子进程：六条 watch 每条两次 300 ms 响应，旧代码把
50 ms halt deadline 推迟到 3.61 s；六个临时目录每次登记 350 ms，旧代码推迟到 2.11 s。
候选均在批次完成前处理期限且最后全部登记成功；还覆盖重试、配置取消、button 保留、
重复事件、id 重建及维护调度截止时间。测试不触碰真实 `/etc/hotplug.d` 或硬件 watchdog。

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

## 15. R92 恢复与启动边界

总线断连和重连等待期间继续排空实例 stdout/stderr、处理退出与监管定时器，避免管道写满后
堵住服务子进程。非 PID 1 监管模式也维护 watchdog 节拍；精确 C 在该模式只喂一次，属于
共有缺陷的有意修复。`r92_recovery_probe.py` 使用匿名 socketpair 注入 WDTFD，测试不打开
主机或物理 watchdog；watchdog 响应能力不会由“进程仍在”代替验证。

jail 中的 bundle 不要求 command；同时给两者时只把 bundle 交给 ujail，与原版 argv 一致。
watchdog 初始化保留 WDIOC_GETSUPPORT、CARDRESET、GETBOOTSTATUS 的分支与原版诊断；
`watchdog_status` example 通过 mock ioctl 验证 ABI、调用顺序与五种结果，不接触硬件。

R90 的启动期 hotplug 队列存活断言和生命周期回归继续必需；不把本次恢复修复替代它们。
