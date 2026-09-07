你的主路径理解基本正确，但 **“按 local 地址判断撤回”不等价于 C 的按前缀归属处理**。我已在 oracle 的隔离 PID/net/mount namespace 中，用发货 rootfs 的原版 netifd 复现了反例，也验证了无线进程死亡路径。[实验结果](/tmp/ask2-evidence/summary.json)和[复现脚本](/tmp/ask2_probe.py)已保存。

下面 C 文件的行号指 `/tmp/nfd`；`wireless-device.uc` 指你指定的发货 rootfs 文件。

第一个问题，**只改变父前缀长度，就能让父前缀不同而 local 完全相同**。无需双 WAN：

```text
LAN：ip6assign=64，ip6hint=0，ip6ifaceid=::1

旧委派：2001:db8:100::/56,300,600
新委派：2001:db8:100::/60,1200,2400

两次分配均为：2001:db8:100::1/64
```

`prefix_cmp()`（`interface-ip.c:588`）比较的是父前缀的地址和长度，所以 `/56` 与 `/60` 是两个不同的 vlist 节点。

因此实际顺序是：

1. 新 `/60` 创建自己的 assignment，把同一个地址刷新为新生命周期。
2. flush 旧 `/56`，撤回旧前缀拥有的 assignment。
3. 旧 assignment 仍是 enabled，撤回会作用于同一个内核地址：删除显式路由、设置 preferred=0，并使用**旧前缀**的 valid deadline。

我读到的原版结果如下，地址始终是 `2001:db8:100::1/64`：

| 阶段 | 内核 preferred / valid，秒 | 地址与 `/64` 路由 |
|---|---:|---|
| 首次 `/56` | 300 / 600 | `noprefixroute`；`proto static metric 1024` |
| 换成 `/60` | 0 / 约599 | `deprecated`；`proto kernel metric 256` |

而此时 LAN 的 ubus `ipv6-prefix-assignment` 仍显示**新 assignment**，preferred/valid 约为 1199/2399。这说明仅比较 ubus 分配列表，还会漏掉内核状态的差异。[事件轨迹](/tmp/ask2-evidence/monitor.log:78)也记录了先刷新、再撤回的顺序。

你当前的地址存在性检查会发现 local 仍在，跳过撤回，因而保留新生命周期和显式路由。**即使把 local 的 `/64` 长度也加入比较，这个反例仍然成立。**

同类情形还包括：两个上行分别提供相同或重叠的前缀，随后其中一个撤回。每个上行有自己的 prefix vlist，C 不会跨这些列表按 local 去重或转移所有权；这是源码推导，上面的单上行反例则已经实测。

最小的结构修正是保留类似这样的父前缀身份：

```text
PrefixId =（来源上行或 ULA，规范化父前缀地址，父前缀长度）
```

续租沿用该父前缀的 assignment；父前缀消失时撤回它拥有的 assignment。另一父前缀恰好产出同一个 local，不能成为跳过撤回的理由。你可以选择有意改善这个边界行为，但那就应记录为与参考实现的差异。

另外，你对三个分支的概括需要两个限定：同 key 分支在 `new_valid=false` 时也会撤回；“先 add 后 flush”适用于这里的协议更新流程，不能推广到 ULA 直接替换或 `interface_refresh_assignments()` 的全部路径。

第二个问题，**发货版 PROCESS_ADD 登记的是每个 radio 的进程监控列表**。

实际调用者已经接上这条路径：

- `wifi/hostapd.uc:598` 调用 `hostapd.config_set`，随后登记返回的 `ret.pid`。
- `wifi/supplicant.uc:298` 调用 `wpa_supplicant.config_set`，随后登记返回的 `ret.pid`。
- `wifi/netifd.uc:27` 将 executable 经 `fs.realpath()` 解析，再发送 `{pid, exe, required, keep}`。

这些进程可以由其他服务启动，所以实现不能只依赖回收 netifd 自己的子进程。

`wireless-device.uc:287` 和 `:519` 的具体行为是：

| 条件或字段 | 发货版处理 |
|---|---|
| radio 在 `setup` 或 `up` | 可以登记 |
| 其他状态 | 返回成功，忽略登记 |
| `pid` 或 `exe` 为假值 | 忽略登记，仍返回成功 |
| 有效登记 | 整个 `data` 追加到 `wdev.procs`，没有去重 |
| 首次登记 | 创建每 1000 ms 执行一次的 interval |
| `required`、`keep` | 保存在 data 中，但这份实现**不读取它们** |

登记时不立即检查进程。定时检查通过 `netifd.process_check(pid, exe)`，进入 `ucode.c:490`、`utils.c:178`，读取 Linux 的 `/proc/<pid>/exe`。因此进程消失、读取失败或 executable 不匹配，都能触发失败。

这里还有个精确兼容边界：这版 Linux 代码给 `readlink()` 的缓冲区长度是 `strlen(exe)`，短路径前缀也可能被判为匹配；它没有保存进程启动时间。正常桩应填写完整的实际 executable 路径。

**检查失败直接调用 `wdev.teardown()`**，见 `wireless-device.uc:270`。正常已 UP 的路径是：

```text
进程检查失败
→ 取消 proc_timer，清空 procs
→ state=teardown，排队运行 teardown handler
→ handler 完成后撤下链接、清空 handler_data、state=down
→ 调用 setup()
→ autostart=true 且没有 retry_setup_failed 时重新 setup
```

清空 procs **不会发送任何 kill 信号**。PROCESS_ADD 也没有保存重新启动该进程所需的 argv；恢复交给 radio 的 handler。`keep=false` 不会使这里自动杀进程，`required=false` 也不会使死亡被忽略。

**这条死亡路径本身不扣 retry。** 扣 retry 的位置是 `wdev_setup_cb()`（`:143`）：setup handler 完成时，radio 如果仍停留在 `setup`，才扣预算或设置 `retry_setup_failed`。已经报 UP 的 handler 完成后直接返回。因此每一轮都成功 UP、随后注册进程死亡，可以反复 teardown/setup。

如果死亡发生在 setup handler 尚未完成时，teardown 会进入串行队列，实际执行可能需要等当前 handler 完成或超时，不能把“一秒检查周期”理解成“一秒内完成恢复”。

还有一个容易沿用旧行为的地方：shell helper 虽然保留 `PROCESS_KILL_ALL=3`，这份 `wireless-device.uc` 没有对应分支，会返回 `INVALID_ARGUMENT`。

你提出的受控子进程办法可以直接扩展 r60。setup 桩中的核心登记可以写成：

```sh
/bin/busybox sleep 300 </dev/null >/dev/null 2>&1 &
pid=$!
exe=$(readlink "/proc/$pid/exe")

ubus call network.wireless notify \
  "{\"command\":2,\"device\":\"radio0\",\"data\":{\"pid\":$pid,\"exe\":\"$exe\",\"required\":false,\"keep\":true}}"
```

随后设置 `retry=0`，正常发送 UP，让 handler 退出。背景进程的标准流要像上面那样重定向，避免它继续占着 handler 的输出管道。PID 与 executable 必须从 netifd 所在的 PID namespace/chroot 视角取得；BusyBox 的 `sleep` 对应 executable 是 `/bin/busybox`。

验证步骤建议固定为：

1. 等到 UP 且 setup handler 已完成，再经过两个检查周期，确认没有自行重启。
2. 保存当前代 PID，在同一 PID namespace 中定点杀它。
3. 断言出现一次 teardown 和下一代 setup，注册 PID 更新，最终 UP 且 `retry_setup_failed=false`。同时检查 teardown 收到旧 token，下一次 setup 的设备 data 已清空。

我实际运行得到：

| 实验 | 原版结果 |
|---|---|
| `retry=0`，连续杀四代已 UP 的注册进程 | 每次约一秒后完成恢复，失败标志始终 false |
| 存活 PID 配错误 executable | 同样触发 teardown/setup，那个 PID 仍存活 |
| 保留另一个 `keep=false` 注册进程 | 清空登记表后它仍存活 |
| down 状态发送 PROCESS_ADD | 返回成功，忽略 |
| `retry=0`，setup 退出但不报 UP | teardown 后停在 down，失败标志 true |

最后补一处证据问题：我读取的 [r62_pd_diff.sh](/Users/USER/Developer/owrt-control-plane-rs/tools/r62_pd_diff.sh:72) 仍是 `r=$(...) || true` 后打印 `$?`，这样显示的返回码始终为 0。应先设 `rc=0`，使用 `r=$(...) || rc=$?`，再打印 `$rc`。另外，当前只查看 `dev veth2` 的路由，会漏掉父前缀的 unreachable route；撤回验证也应覆盖它。
