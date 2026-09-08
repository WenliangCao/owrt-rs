# R70：P3.1 独立复审（第二轮外部审查）

来源：Claude Fable 5.1，2026-09-08，接替 Astra（R68）。结论：**不通过**，但性质与 R68 不同——
门槛不再对「没有监管器」失明，实现的主体路径逐函数能对上 C；剩下的是一族同根的
状态判断缺陷（五处，三例跑实）、一条尚未修完的 F04 生命周期、一条新的门槛假绿
路径（五处注入全部漏过），以及一条需要写进合同的 C 真实行为（重连后 watch 永久失效）。

## 基线（全部核过 md5）

| 项 | 值 |
|---|---|
| 仓库基线 | `73ef160`（harness `tools/r65_procd_diff.sh` md5 `73c2a10a6f2b396ff1488137be04fb92`） |
| 候选 | `procd-rs` md5 `845b7b43c2d85a82c95e82f3457e6360`，快照 oracle:/tmp/rv/cand-845b7b43/procd-rs |
| notifier | md5 `95e70b7dbcdba8118fa434a87dd7601e` |
| rootfs | oracle:/home/ubuntu/h1-4-extract.JK5fNS/rootfs（发货 25.12.5，procd `2026.03.13~58eb263d`，libubus `2026.06.28~24864e78`） |
| C 源 | oracle:/home/ubuntu/stage9/procd（HEAD `2c1834a`）、/home/ubuntu/stage9/ubus（HEAD `24864e7` = 设备 libubus） |

stage9/procd 比设备的 `58eb263` 多 26 个提交。`git diff 58eb263 HEAD -- service/ watch.c ubus.c`
只有三处：console 日志级别、`watch_add` 的 `int→size_t`、以及 **HEAD 给
`instance.fail`/`instance.respawn` 换成了带 pid/exit_code/respawn_count/command 的
`service_event_instance_exit()`，而设备上的 `58eb263` 仍是三字段的 `service_event()`**。
下文引用的 C 行为都对过这份 diff；候选的三字段事件与设备一致。拿 HEAD 源码当参照
的人会在这一条上写错合同，特此记下。

「可重现构建」的条件：73ef160 从干净 `git archive` 在 /tmp/rv/src-73ef160 重建得到
md5 `5cb1455b…`，大小同为 725064，差异只是二进制里嵌的两条源码路径
（`strings` 可见 `/home/ubuntu/netifd-r59/components/ubus/src/blob.rs`）。
**同一 checkout 路径**才能复现 `845b7b43`。R65 写可重现时要带这个条件。

所有实验在 oracle 上复制出来的 rootfs 内，以私有 mount/net/pid namespace 跑普通
procd 进程。没有碰物理路由器。探针脚本在 `tools/r70/`，产物在 oracle:/tmp/rv/。

## 一、第三条：C 重连后不恢复 watch，是 C 的真实行为

### 实验（`tools/r70/reconnect_probe.sh`，产物 /tmp/rv/reconnect2）

两侧各一份 rootfs，同一脚本：声明带 `watch` 的实例 → notifier 发布对象并通知
（step1）→ `kill -9 ubusd`、起新 ubusd → 等 `service` 回到总线（step2）→
**对照**：直接 `service event` 打同一条规则（step3）→ 同一路径重新发布并通知，
等 30 s（step4）→ **重启后新声明**一个 watch 指向**全新**对象，通知，等 30 s
（step5）。全程 `ubus monitor` 记录。

| 步骤 | C（发货 procd） | Rust（845b7b43） |
|---|---|---|
| step1 重启前 | 触发 `before` | 触发 `before` |
| step2 回到总线 | 1 s，全部对象（含 hotplug.*）重新注册，子进程 pid 不变 | 1 s |
| step3 对照：直接 event | 触发 `direct-after` —— trigger 机制活着 | 触发 |
| step4 同路径重发布，30 s | **不触发** | 触发 `republished` |
| step5 重启后新 watch + 新对象，30 s | **不触发** | 触发 `fresh` |

step5 是判别式：它排除了「等待不够」和「旧订阅没续上」两种解释——重启后
新建的 watch 从未附着。

### 根因（源码与监视器两边对上）

- `procd/ubus.c`：`ubus_reconnect_cb()` 只做 `ubus_reconnect(ctx) + ubus_add_uloop(ctx)`；
  `watch_ubus(ctx)`（注册 subscriber 对象 + `ubus.object.add` 事件处理）只在
  首次的 `ubus_connect_cb()` 里调一次。
- `libubus-io.c`：`ubus_reconnect()` → `ubus_refresh_state()` 把 objects 树里的
  对象逐个 `ubus_add_object` 重放，然后 `ubus_refresh_auto_subscribe()` **只**为
  libubus 自己的 `auto_subscribe_event_handler` 重做一次 `register`。procd 的
  `watch_event` 对象被重新 add 了，但 `ubus_register_event_handler()` 里那次对
  `ubus.event` 的 `invoke register` 是一次性的，**永不重放**。
- 监视器（/tmp/rv/reconnect2/c-monitor.txt）：重连后 C 的连接发了一串 `add_object`，
  **只有一次** `register`（objid 1，pattern `ubus.object.add`），紧跟一个 `lookup: {}`
  ——正是 `ubus_refresh_auto_subscribe` 的形状。之后 `fake.iface` 和 `fresh.obj` 的
  `ubus.object.add` 都投递到了那个对象（第 149、166 行），**没有任何**
  `lookup {"objpath":...}` 或 `subscribe` 跟进。`watch_subscribe_cb` 从未被叫到。

所以 Astra 的观察成立，且不是探针时序：发货 procd 在任何一次 ubusd 重启之后，
既有 watch 不再重新附着，新声明的 watch 也永不附着。设备上 `/etc/init.d/network`
的 `procd_add_reload_interface_trigger` / watch `network.interface` 就是这条线。

### 合同该怎么写

> **11. ubusd 断线与重连。** 发货 procd 丢失总线后以 50 ms→1 s 退避重连
> （`ubus.c`），重连时重新注册 `service`/`system`/`container` 与 `hotplug.*`
> 对象，实例监管不中断（实测重连前后 pid 不变）。**但 watch 订阅链在重连后
> 永久失效**：重启前声明的 watch 不再重新附着，重启后新声明的 watch 也永不
> 附着。根因是 libubus `ubus_reconnect()` 只重放对象注册，不重放
> `ubus_register_event_handler()` 那次 `ubus.event register`，而 procd 的
> `watch_ubus()` 只在首次连接时调用。对照实验里直接 `service event` 仍能触发，
> 所以失效的只是订阅链。（R70 §一）
>
> **procd-rs 有意偏离**：重连时重新注册事件处理并重订阅所有 watch。理由：
> (a) 设备上 ubusd 从不重启（决策 0015），偏离在设备上不可观测；(b) C 的行为是
> 一次性注册的遗漏而非设计——复刻它意味着一次总线重启后 netifd→procd 的
> 接口触发器全部静默。这是合同里唯一一条候选故意不等于 C 的地方；r65 不比较
> 它（F06 只断言监管器回到总线），证据是独立探针 `tools/r70/reconnect_probe.sh`。

如果决定改成复刻 C，把第二段换成「候选同样不恢复」，并去掉 Rust `reconnect()`
里的 `register_event_handler` + `resubscribe()`。我不建议。

## 二、实现：一族同根缺陷——用 `state == Running` 代替 C 的 `proc.pending`

C 里「有活着的子进程」是 `in->proc.pending`，**包括已发 SIGTERM、等 term_timeout
的那段**；「正在被停」是 `in->halt`。候选多处用 `state == Run::Running` 同时替代了
这两个概念，Halting 被当成「没跑」。五个位置（73ef160 的 main.rs）：

| 位置 | C | 候选 |
|---|---|---|
| `instance_stop` | `if (!pending) {if halt delete; return}`；否则**无条件** `halt=halt; restart=respawn=false; SIGTERM; 重置 timer` | `state != Running` 时只置 `halt`（若 halt）就返回，**`restart` 原样保留**，不重发 TERM |
| `instance_restart` | `if (!pending) return`；否则 reload_signal 或 `halt=restart=true; SIGTERM` | `state != Running` 直接返回 |
| `instance_update` | `running = pending; stopping = halt` | `running = (state==Running); stopping = (state==Halting)` —— 合起来就是 `state != Running`，丢了 `halt=false` 的 Halting |
| `handle_state` | 按 `!!pending == !!spawn` 跳过 | 按 `state == Running` 过滤，Halting 实例在 `spawn=true` 时被 `instance_start` → `if halt {restart=true}` |
| `handle_signal` | 默认 `sig = SIGHUP`；`kill(in->proc.pid, sig)`，按 errno 返回（ESRCH→NOT_FOUND） | 默认 `SIGKILL`；只对 Running 发；其余静默 OK |

### 验证 A：Halting 窗口（`tools/r70/halting_probe.sh`，产物 /tmp/rv/halting，子进程 `trap "" TERM` 撑满 5 s）

| 用例 | C | Rust（845b7b43） |
|---|---|---|
| A. 实例正在为一次配置变更重启（halt=true, restart=true），窗口内 `delete` 整个服务 | 9 s 后 `{}` | **`ta` 以新 pid 38 跑起来了**——被删除的服务复活 |
| B. `delete` 后窗口内 `state spawn=true` | `{}` | **`tb` 以 pid 60 复活** |
| C. `state spawn=false`（halt=false）后窗口内改配置 `set` | 以新配置重启，pid 82 | **停死**：`running:false, exit_code 137`，新配置没起 |

A 是 `/etc/init.d/x restart` 撞上 `stop`/`disable` 的真实形状；B/C 是 `state`
方法的用户（`procd_send_signal`/容器）。

### 验证 B：signal（`tools/r70/signal_probe.sh`，产物 /tmp/rv/signal2）

| 用例 | C | Rust（845b7b43） |
|---|---|---|
| `signal` 不带 `signal` 字段 | 子进程 `exit_code 129`（SIGHUP） | `exit_code 137`（SIGKILL） |
| `signal` 打已退出的实例 | `Command failed: Not found` | 成功，空回复 |
| `signal 9` 打 Halting 实例（TERM 被忽略） | 立即死，2 s 后 `{"sc":{}}` | 不发送，2 s 后仍 running，等 term_timeout 才被杀 |

（第一次 signal 运行 /tmp/rv/signal 里 C 的 HUP 没生效——我用 `nohup` 起的探针
把 SIG_IGN 一路继承给了子进程。改成 `setsid` 重跑得到上表。记在这里，因为
「HUP 没反应」差点被我当成 C 的行为。）

修法是机械的：五处判定换回 C 的两个布尔量；`instance_stop` 对 Halting 实例也要走
完整路径（尤其 `restart=false`）；`handle_signal` 默认 `SIGHUP`、对任何有 pid 的实例
`kill()` 并按 errno 映射状态。

## 三、F04：删除路径确实没做；对 Astra 数据的构造说明

Astra 的 r2 watch 探针对 845b7b43 快照复跑（oracle:/tmp/astra-p31-r2-watch-kq8495ov，
两侧 rootfs 内 procd-rs md5 核过）：C `all_events` = appears/recreated/before-reconnect；
Rust 多出 `deleted-service`、`deleted-instance`、`after-reconnect`、`deleted-reconnect`。
机制：`refresh_watches` 只在 set 路径被调；`handle_delete` 与 `handle_update`
（update_complete 的 flush）都不碰 `watches`。C 的 `instance_free()` → `watch_del(in)`。

探针构造（probe.py 76–82 行）：**规则挂在一个从不删除的服务 `watch_observer` 上**
（`r2.notice → echo %phase%`），watch 挂在别的服务的实例上，每次 publish 都注册
**新**对象。所以「删整个服务」这一路的泄漏是可观察的——只要任何别的服务对同一
通知类型有规则；设备上就是别的服务的 `procd_add_interface_trigger`。

精确度：C 的 `watch_del()` 只删链表条目，**不 `ubus_unsubscribe`**。所以 C 实测形状是
(1) 对象重建（新 id）→ 不再重订阅 → 不触发；(2) 同一对象仍活着继续 notify →
旧订阅还在 ubusd 上 → `watch_notify_cb` 照样 `trigger_event`。修法若在 stale 分支
`unsubscribe`，则在 (2) 上比 C 少触发。合同写哪种都行，但要写 C 实测的形状。

## 四、门槛：确认一条新的假绿路径

注入脚本 = 73ef160 的 harness 改 **5 行**（`tools/r70/r65_inj_stale.diff`，
注入版 md5 `fb59dc9d777c19a6cdda68425110e0dc`）：

1. 369 行 `mytrigX` → `zzX`（"fourth" 必须触发的用例，改成永不匹配）
2. 374 行 未设变量用例的事件类型 → `zz.now`（不触发）
3. 385 行 `ev2` caseA → `zz2`（不触发）
4. 412 行 第二次 `hasinit` set → `noinit0`（rc running 不再跑第二次）
5. 658 行 F06 的实例 `sleep 300` → `sleep 3`（重连时实例已死）

结果：**`r65: ok`，EXIT=0，diff 0 行，coverage 31/31 pid 行、11/11 失败调用，
两侧都没有 expect.err**（oracle:/tmp/rv/inj-stale/）。c-calls.txt 第 456–461 行
"fourth"/未设变量两个用例下面都只有第一个用例留下的 `first`，第 584 行第二次
rc running 打的是第一次的 `hasinit ran with: running`，第 888–889 行 F06 的 `back`
抓到的是 `"running": false`。五处注入一处都没被抓到。

（这次注入运行时的候选是 `2b5af00a…`——一个中间构建正好覆盖了那个路径。
对本结论无影响：注入两侧对称、门槛判定与候选无关，但引用时要写清。）

机制：`must_have` 断言的是「文件非空」，文件跨用例累积，第一个子用例之后永远
非空；`back=` 抓 `"running"` 不区分 true/false。

### 修法

- `must_have` 改成「读完即删」，每次断言都必须是**新**产出；六处 fired.txt、三处
  initd.txt、watched.txt、dataev.txt 都受益。
- F06：`grep -E '"running": true'`。
- **通知从未被比较**：`instance.start/stop/respawn/fail`、`service.start/stop`、
  `service.data.update` 这些 `service` 对象的 notify 没有任何一侧被记录。drive
  开头 `ubus subscribe service > /tmp/out/notify.txt &`，结尾 kill，scrub pid 后进
  diff（`ubus` CLI 有 `subscribe`，已确认）。这是现在完全看不见的一个面。
- selftest 补「drive 中途 exit 但先写 drive.done」注入。
- 新差分用例：§二 A/B/C 三例、signal 三例、verbose list 带实例级 `triggers`（§五）。

## 五、读码发现，未跑实验

1. `instance.rs::dump` 忽略 `verbose`：C `instance_dump` 在 verbose 时输出实例自己的
   `triggers` blob（tmpoverlaysize 之后、watchdog 之前）。候选任何情况下不输出。
2. `dump` 的 jail 块缺 `setns` 数组：C 在 `mount` 之后输出 `"setns": [...]`。候选解析了
   `jail.setns`（`config_changed` 用它）但不打印。
3. 事件负载：设备的 `58eb263` 用三字段 `service_event`，候选一致；stage9 HEAD 不一致。

## 六、Rust 主体路径核对（对 C 源逐函数）

`instance_exited` 对 `instance_exit`、`take_config` 对 `instance_config_move`、
`config_changed` 对 `instance_config_changed`、`reconnect`/`resubscribe` 对
`ubus.c`+`watch.c`、`instance_update` 的 data-only 分支（`service_data_trigger` 旧后新）、
`collect_stopped` 对 `instance_delete`/`instance_free`（data trigger、trigger_del）、
`handle_set_data` 实例路径不触发 / 服务路径先旧后新、`service_update` 的
`deleted=false`、restart 后的 `rc(name,"running")`、`instance_watchdog` 的
`instance_stop(in, true)`：**都对得上**，除 §二五处判定和 §三的 watch_del。
`config_changed` 比 C 少 `uid/pw_gid/gr_gid` 的直接比较，它们由 `user/group` 派生，
只有 passwd 在两次 set 之间变了才可见，忽略。

## 七、对 R65/R69 叙述的两条更正

- 「注入下 `calls.diff` 仍为 0 行」不是新门槛的证据：注入让两侧按构造相同，diff=0
  是必然。新门槛的证据只有一条——它红在 `ready.err`。
- 引用运行时写明**路径 + md5**。今天同一路径上至少出现过六个 md5
  （a68748ea、17083602、6f37819d、61b1c996、845b7b43、2b5af00a）。

## 复现

```sh
R=/home/ubuntu/h1-4-extract.JK5fNS/rootfs; C=/tmp/rv/cand-845b7b43
ssh oracle "md5sum $C/procd-rs"                                            # 845b7b43…
ssh oracle "sudo -n sh /tmp/rv/reconnect_probe2.sh $R $C/procd-rs $C /tmp/rv/reconnect2"   # §一
ssh oracle "sudo -n sh /tmp/rv/halting_probe.sh $R $C/procd-rs /tmp/rv/halting"            # §二 A
ssh oracle "setsid sh -c 'sudo -n sh /tmp/rv/signal_probe.sh $R $C/procd-rs /tmp/rv/signal2'"  # §二 B，不要用 nohup
ssh oracle 'sudo -n python3 /tmp/rv/probe_watch_r2.py'                                      # §三
ssh oracle "sudo -n sh /tmp/rv/r65_inj_stale.sh $R $C/procd-rs /tmp/rv/inj-stale $C"      # §四
```
