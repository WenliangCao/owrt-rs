# R65：P3.1 服务监管核心，离线通过

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
r65: ok        762 行对比，0 行 diff       连跑 3 次全绿
```

20 个用例，覆盖：签名（三个对象全部方法的 policy）、退出码、无效实例、
`set` 与 `add` 的差别、delete、signal、state、update_start/complete、
get_data/set_data、autostart=false、触发器实际执行了什么、validate 的两种顺序。

`service` 的 13 个方法实现了 12 个。没实现的是 `watchdog`（每实例看门狗定时器），
它要和 P3.2 的真实 watchdog 一起做。`container` 和 `system` 按真实签名注册，
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

## 一次假红

有一轮 diff 934 行、pid 断言也翻了，看着像大回归。实际是 harness 的竞态：
rootfs 副本被两次运行共用，**上一轮的 ubus socket 文件还在**，而就绪循环等的是
"路径存在"，于是立刻返回，procd-rs 连到一个死 socket（`Connection refused`），
整个 rs 侧为空。build host 一忙起来才暴露。

改成等一次真实的 `ubus list` 往返、先删旧 socket、并把"总线起不来"报成独立错误
而不是 diff。这正是 [[flaky-assertion-worse-than-none]] 那条：红了先重跑，
而且要能说清楚绿的时候到底比了什么。

## 已知缺口（不是决定，是还没做）

- `rc(name, "running")`：`service_update()` 会 glob `/etc/init.d/<name>` 并用
  `running` 参数排队执行。runqueue 属于 P3.2。
- 实例日志 FD 两个都指向 `/dev/null`。没人消费的管道正是被监管进程死锁的方式。
- 每实例 `watchdog` 方法。
- `watch.c` 的文件/netdev 监视。

## 单元测试

17 个，跑在 `cargo test`。值得点名的是 `exit_code_of` 对着 C 的宏顺序、
`%` 展开的全部边界、以及 `regex` 走平台自己的 `regcomp/regexec`——
和 C 调用的是同一份实现，没有第二套正则方言要同步。

`tools/check_rlimit_consts.sh` 把 14 个 `RLIMIT_*` 号对着 `<sys/resource.h>` 校验
（在 Linux 上跑，因为这些号是每平台不同的：`NOFILE` 在 Linux 是 7、Darwin 是 8）。
