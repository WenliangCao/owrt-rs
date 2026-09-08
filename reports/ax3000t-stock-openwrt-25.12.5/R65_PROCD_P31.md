# R65：P3.1 服务监管核心 —— **未通过验收**

> **2026-09-08 撤回原标题。** 外部审查 [R68](../../docs/reviews/R68_ASTRA_P31_REVIEW.md)
> 把两边的监管器启动命令都换成 `/bin/false`，r65 仍然输出 `r65: ok`、
> diff 0 字节、退出码 0。**这个 harness 允许整套调用没有到达任何监管器**，
> 所以下面写的"1050 行 0 diff"不构成验收证据。
> 审查另列 F01–F18 共 18 项实现差异，其中 F03/F05/F06/F07/F08/F09 属于
> 监管核心的行为损坏，且都有复现记录。
>
> 本文以下内容保留为**当时的过程记录**，不是结论。真正的状态是：
> **P3.1 开发中，验收门槛需重建。**

日期：2026-09-08。对象 `procd 58eb263d`（`manifests/.../sources.json` 里钉住的
那个 revision）。全部在 oracle 上离线完成，**没有碰设备**。

## 为什么能做逐字节差分

`procd.c:main()`：

```c
if (getpid() != 1)
	procd_connect_ubus();
else
	procd_state_next();
```

所以发货 rootfs 里的 `/sbin/procd` 在 PID 1 之外启动时，**就是**一个总线上的
服务监管器——正好是 P3.1 的范围。两边在同一个 netns 里对着各自的 ubusd 跑，
比同一串 ubus 调用的回复。这和 netifd 的做法是同一套路子
（见 [netifd-oracle-is-c-netifd-in-a-netns] 那条经验）。

harness：[tools/r65_procd_diff.sh](../../tools/r65_procd_diff.sh)。

## 结果

```
r65: ok        1050 行对比，0 行 diff
候选二进制 md5 a68748ea21a75b84d4fce6fd7b83bdae，构建于运行前 2 分钟
```

26 个用例，覆盖：签名（三个对象全部方法的 policy）、退出码、无效实例、
`set` 与 `add` 的差别、delete、signal、state、update_start/complete、
get_data/set_data、autostart=false、触发器实际执行了什么、validate 的两种顺序。

`service` 的 **13 个方法全部实现**，另外 `watch`（ubus 订阅）、
`rc(name, "running")`、实例 stdout/stderr 进 syslog、jail 的 ujail argv、
以及带类型的 `data` 都已对齐。`watchdog` 的取值、`self_managed` 位和
`list` 输出都对齐了；**定时器本身**属于 P3.2，所以 mode=active 的实例
现在不会因为超时被重启——这是已知缺口，不是差异。`container` 和 `system` 按真实签名注册，
方法拒绝——`sysupgrade` 尤其：本项目不刷设备，静默成功是最坏的失败模式。

## 差分抓到的东西

第一次运行就红了三处，全是我写错：

1. **`command` 字段缺席 ≠ 空数组。** `instance_config_parse_command()` 在
   完全没有 `command` 时返回 **true**：实例有效、会被列出、只是永远不启动
   （日志 `command not set`）。只有"有但为空"或"有但含非字符串"才无效，
   而无效实例被 `instance_dump()` 开头的 `if (!in->valid) return;` 整个跳过。
   我把两者合并了，结果一个纯声明式实例从 `service list` 里消失。
2. **从没启动过的实例 `exit_code` 是 0。** `instance_start()` 的早退发生在碰
   `exit_code` 之前。我报了 127，等于凭空造了一次没发生过的 spawn 失败。
3. **`watchdog` 的 policy 顺序是 `{mode, timeout, name, instance}`。**
   指定初始化器不决定数组顺序，enum 才决定；初始化器里 name 写在第二位，
   enum 里它在第三位。`ubus -v list` 打印的是 enum 顺序。

后续又抓到三处：

4. `service_dump()` 的顺序是 `autostart`（**只在 false 时打印**）→ `data`
   → `instances`。我把 data 放在 instances 后面，而且完全漏了 autostart。
5. `eval_string` 的 `%` 展开我写反了——先读开关再翻转，于是 `%A%` 变成
   `"A%"`。段号为奇数才是变量；n 段意味着 n-1 个分隔符，偶数段数就是
   "未终止的变量引用"错误。
6. validator 的两个顺序（见合同第 6 节）。而且**存 validator 的那行赋值
   根本没被插进去**——我的编辑没匹配上，我也没检查。r65 以空回复的形式
   抓到了它。之后每一处编辑都自己断言是否生效。

## 一次假绿：三轮跑的其实是旧二进制

比假红更该记的是这个。为了让 harness 能带上 `notifier`，我给构建加了
`--examples`——**`cargo build --examples` 只构建 examples，不构建 bin**。
它照样打印 `Compiling owrt-procd` 和 `Finished`（因为要为 example 编译这个
crate），所以从命令输出看不出任何异常。

结果是接下来三轮 r65 跑的都是加 `--examples` 之前那个二进制。我据此
"发现" watch 不触发、日志不落盘，然后去调试——调的是根本不在二进制里的代码。
正确的写法是 `--bins --examples`。

harness 现在把候选的路径、mtime 和 md5 记到 `candidate.txt`，和运行时间放在一起。
绿不绿是一回事，**跑的到底是不是你以为的那个东西**是另一回事，而后者原来
完全没有证据。

## 一次假红

有一轮 diff 934 行、pid 断言也翻了，看着像大回归。实际是 harness 的竞态：
rootfs 副本被两次运行共用，**上一轮的 ubus socket 文件还在**，而就绪循环等的是
"路径存在"，于是立刻返回，procd-rs 连到一个死 socket（`Connection refused`），
整个 rs 侧为空。build host 一忙起来才暴露。

改成等一次真实的 `ubus list` 往返、先删旧 socket、并把"总线起不来"报成独立错误
而不是 diff。这正是 [[flaky-assertion-worse-than-none]] 那条：红了先重跑，
而且要能说清楚绿的时候到底比了什么。

## 已知缺口（不是决定，是还没做）

- 每实例 watchdog **定时器**（取值和 `list` 输出已对齐）。
- ~~实例日志 FD~~、~~`watch.c`~~、~~jail argv~~、~~带类型的 data~~ 已补上，
  见下面"已经补上的"。原来这一段对 `watch.c` 的描述是错的————这条我一开始写错了，它不是"文件/netdev 监视"，
  而是**ubus 对象订阅**：实例的 `watch` 数组列的是 ubus 路径，procd 订阅它们，
  被订阅对象发来的每条 notification 都进 `trigger_event(method, msg)`。
  它不是"文件/netdev 监视"而是 ubus 对象订阅。
  本机只有一个使用者，但很关键：`/etc/init.d/network:21` 的
  `procd_set_param watch network.interface`——**这是 netifd 的接口事件进入
  procd 触发器的那条线**。实现它需要给 `owrt-ubus` 加订阅者支持
  （`ubus_register_subscriber` / `ubus_subscribe`），目前那个 crate 没有。
- `rcS()` 的串行队列（`rc()` 已经做了，见下）。
- 实例的 `netdev` / `file` 属性只参与配置比较，没有做 ifindex 解析和 md5 检查。

## 已经补上的

- **`rc(name, "running")`**：`service_update()` 结尾的
  `if (init || tb[SERVICE_SET_INSTANCES]) rc(s->name, "running")`。
  这条从普通 `ubus call service set` 就能走到，不必是 PID 1，所以属于 P3.1。
  r65 用一个真实 init 脚本验过：带 instances 的 `set` 会跑它，
  名字不匹配的服务什么都不跑。
- **`service watchdog`**：`name`/`instance` 缺任一个是 NOT_FOUND；
  传 mode 或 timeout 会置 `self_managed`，之后带原始值的 `set` **不重启**实例。
  r65 用两次 `service list` 取 pid 比过这条。

- **`watch`**：实例的 `watch` 数组列 ubus 路径，被订阅对象的每条 notification
  都进 `trigger_event`。r65 在**声明 watch 之后**才发布被订阅对象——这就是设备上
  的真实顺序（netifd 比 procd 起得晚），所以只在配置时订阅一次的实现会永远挂不上。
  用一个新的 `notifier` example 驱动，因为 `ubus` 命令行只能 invoke 和 listen，
  不能"成为一个会发 notification 的对象"。
- **实例 stdout/stderr**：接到 procd-rs 自己读的管道，逐行按 C 的 ident
  （`basename(argv0)[pid]`）和实例自己的 facility 写 syslog。读有预算、
  半行有上限——没人消费的管道正是被监管进程死锁的方式；而且**排空发生在收尸之前**，
  否则子进程最后几行会跟着管道一起丢掉。
- **jail**：`jail_run()` 的 ujail argv 逐个开关转写。原来的实现直接 exec 了
  实例自己的命令——**既没有沙箱，又因为 jail 实例本来就跳过降权而仍然是 root**，
  比两种选择都糟。
- **带类型的 `data`**：原来压成了字符串表，整数和布尔字段被整个丢掉。

## 单元测试

23 个，跑在 `cargo test`；全仓库 `make test` 13 个测试二进制、267 个用例全绿。值得点名的是 `exit_code_of` 对着 C 的宏顺序、
`%` 展开的全部边界、以及 `regex` 走平台自己的 `regcomp/regexec`——
和 C 调用的是同一份实现，没有第二套正则方言要同步。

`tools/check_rlimit_consts.sh` 把 14 个 `RLIMIT_*` 号对着 `<sys/resource.h>` 校验
（在 Linux 上跑，因为这些号是每平台不同的：`NOFILE` 在 Linux 是 7、Darwin 是 8）。
