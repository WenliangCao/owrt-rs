# R83 · procd：R81-F01（P0）、F21、F22

日期 2026-09-10。实现参照为 procd `58eb263d`，运行参照为精确 OpenWrt 25.12.5
rootfs 的 `/sbin/procd`。早期草稿使用的 `stage9/procd` checkout 为较新的 `2c1834a`，
本轮已读取固定修订，尤其不采用新版 `instance.fail/respawn` 通知格式。
日志参照为镜像对应 libubox `7dd12784` 的 `ulog.c`。
验证在 `oracle:/home/ubuntu/r83-complete` 和一次性 namespace 中进行，未接触实体路由器。
最终产物摘要和验证命令见 [validation.md](validation.md)；下文标记的红证 hash 仅识别历史构建。

## 0. 结论一览

| 发现 | 判定 | 修法（一句话） | 证明 |
|---|---|---|---|
| F01 PID 1 `eprintln!` 到 O_NONBLOCK 的 stderr → abort → 内核 panic | **成立** | 全 crate 50 处 `eprintln!` 归一到 `sys::ulog`（永不 panic，按 C ulog 走 kmsg→syslog）；panic hook 作 `do_reboot()`；SIGABRT 进 crash 集 | 单测 `sys::tests::a_full_nonblocking_stderr_drops_the_line_instead_of_panicking`；门 r83-C（stderr 满管道下两侧 PID 1 都要启动到底并应答） |
| F21 `service set`（含原样 reload）关掉运行实例的 stdout/stderr 管道 | **成立** | `take_config` 保留 `log_out/log_err`（C `instance_config_move` 不碰 `_stdout/_stderr`） | 单测 `take_config_keeps_the_running_childs_log_pipes`（审计给的补丁文本原样纳入）；门 r83-A `pid_same=yes log_grew=yes` |
| F21 子进程 SIGPIPE 被 std 复位成 SIG_DFL（C 子进程继承 SIG_IGN） | **成立** | `proc::inherit_ignored_sigpipe()` 挂到全部 8 条 spawn 路径 | 单测 `a_child_inherits_sigpipe_ignored_like_the_c_child`（读 `/proc/self/status` SigIgn）；门 r83-A `sigpipe_ignored=yes` |
| F22 `service delete '{}'` 回 INVALID_ARGUMENT | **成立** | 改 NOT_FOUND（`service.c:560`） | 门 r83-A |
| F22 stdout 管道实例缺 `LD_PRELOAD=/lib/libsetlbf.so` | **成立** | `instance_run` 的 `setlbf = _stdout >= 0`，照抄 | 单测 `a_piped_stdout_gets_libsetlbf_preloaded`；门 r83-A `ld_preload=1` |
| F22 `service.data.update` 不再对每个解析实例触发 | **成立** | `handle_set` 对消息里每个实例先 `data_trigger_keys`（`instance_init` 末尾） | 读码；无独立门（见 §5） |
| F22 无 cgroup 归置 | **成立（本构建 C 确实做）** | `proc::start` 子进程内 `mkdir_p 0700` + 写 `cgroup.procs` | 门 r83-A `cgroup_member=yes cgroup_mode=700` |
| F22 makedev `umask(0)` 下 `create_dir_all` → 0777 | **成立** | `DirBuilder.mode(0o755)`（C `mkdir_p(d, 0755)`） | 门 r83-B `755 755` |
| F22 inittab exec 失败不按 500 ms 重试 | **成立** | `fork_action` 失败分支照 `child_exit()` 布 `respawn_at` | 读码；无独立门（见 §5） |
| F22 未知 `facility` 以 -1 进 openlog | **成立** | `pump_logs` 过滤 -1 → LOG_DAEMON（`instance.c:1431`） | 读码 |
| F22 合成 DEVNAME/DEVICENAME 泄入 hotplug 环境与通知 | **成立** | 回退移进 json_script 的变量查找（`rule_handle_var` 本来就是查找回调，不进表） | 单测 ×3；门 r83-B（exec 环境里 DEVNAME 行数两侧都是 1） |
| F22 主循环 200 ms 只 poll ubus fd | **部分** | poll 集加 SIGCHLD 自管道、uevent socket、inotify、全部日志管道；200 ms 只剩定时器用途 | r65/r71/r72 行为门；未测延迟数值（见 §5） |

## 1. F01（P0）——成立

### 1.1 证据

- Rust（修前）：`sys.rs:561-566` `set_stdio` 给 fd 2 加 `O_NONBLOCK`；`sys.rs:273` `klog` 与全 crate
  共 **50 处** `eprintln!`（`grep -c` 按文件：main 21、hotplug 11、sysupgrade 5、sys 3、rcs 3、
  dispatch 2、inittab 2、instance/trigger/watchdog 各 1）；`Cargo.toml` `panic = "abort"`。
  std 对 stderr 写失败除 EBADF 外 `panic!`；审计的演示测试（填满 O_NONBLOCK 管道后
  `catch_unwind(eprintln!)`）机制成立 —— 但它依赖 unwind，在 `cargo test --release`
  （`panic=abort`）下会把测试进程整个 abort，所以**没有原样保留**，改成不需要 unwind 的
  fixture（见 1.3）。
- C：`procd.c:97,121,128` `ulog_open(ULOG_KMSG)`（`-S` → `ULOG_STDIO`）；`state.c:169`
  STATE_INIT 末尾 `ulog_open(ULOG_SYSLOG, LOG_DAEMON, "procd")`；`state.c:54` 同样把 stderr
  设成非阻塞；`signal.c:22-31` `do_reboot()`：`LOG("reboot")`、`fflush`、`sync`、`sleep(2)`、
  `reboot(RB_AUTOBOOT)`、`while(1)`；`signal.c:90` `procd_signal()` 先 `signal(SIGPIPE, SIG_IGN)`，
  PID 1 再装 SEGV/BUS → `signal_crash` → `do_reboot`。
- libubox `ulog.c:92-105`：`ulog_kmsg` 写 `<%u>` 用的是**裸 priority**（`LOG()`=ULOG_INFO → `<6>`，
  `ERROR()` → `<3>`），facility 由内核补（`devkmsg_write` 默认 LOG_USER）。Rust 原来写的 `<29>`
  （LOG_DAEMON|LOG_NOTICE，注释称"ulog 的默认"）**与 C 不符**。早期修复草稿要求保留 `<29>`，与 C 不符，故改成 C 的 `<prio>`：设备 dmesg 里文本不变，
  logread 的 facility 列会从 daemon.notice 变成 user.info —— 与 C procd 的设备一致。

### 1.2 修法

`components/procd/src/sys.rs`（新增 ~150 行，替换 `klog`）：

- `LogChannel { Stdio, Kmsg, Syslog }` + `ulog_open()` / `ulog(prio, line)`：Stdio 走
  `let _ = writeln!(io::stderr().lock(), "procd: {line}")`；Kmsg 每条 `open("/dev/kmsg")` 写
  `<prio>procd: line\n` 再关（ulog 的 fopen/fclose）；Syslog 走 `syslog(3)`（`openlog("procd", 0,
  LOG_DAEMON)` 在 `ulog_open(Syslog)` 时做）。三条路都不检查写结果。
- `main.rs` 顶部两个宏：`log!(prio, ..)` = `LOG()/ERROR()/ULOG_WARN()`，`debug!(level, ..)` =
  `DEBUG(level, ..)`（LOG_NOTICE，仅 `debug >= level`）。`-d <n>` 与 `DBGLVL` 现在被解析
  （`sys::set_debug_level`）；修前 Rust 把 C 的 `DEBUG(4, "Launched new %s action")` 这类行
  **无条件**打出来，现在与 C 一样默认沉默。
- 50 处逐一按 C 对应宏映射优先级（如 `LOG("Not starting instance ...")` → LOG_INFO；
  `ERROR("WDT failed to write")` → LOG_ERR；`P_DEBUG(3, "watchdog timer expired")` →
  `debug!(3, ..)`）。`sysupgrade.c` 的 5 处 `fprintf(stderr, ...)` 保持裸 stderr，走
  `sys::stderr_line()`（同样不 panic）。三处 Rust 独有诊断（"failed to start ubusd"、
  "{svc}::{name} failed to start: {e}"、"hotplug disabled"）保留为 LOG_ERR，C 没有对应行
  （C 子进程 execvp 失败时静默 exit 127）。
- 通道时序照 C：`run()` 起点 `ulog_open(Kmsg)`（PID 1 且无 `-S`）或 `Stdio`；`Boot::Init` 末尾
  `ulog_open(Syslog)`。**一处有意偏差**：非 PID 1（supervisor 模式，OpenWrt 上只有测试用）默认
  Stdio 而非 C 的 kmsg —— 否则 r65 这类命名空间探针会把候选的日志写进 oracle 的内核日志。
- panic hook（`sys::install_panic_hook`，两种模式都装）：`ulog(LOG_ERR, "panic: {info}")`；
  `getpid()==1` 时再直接写 kmsg（通道可能已是 syslog 而 logd 已死）、`"Rebooting as procd has
  crashed"`、`crash_reboot()`（`sync`、`sleep 2`、`reboot(RB_AUTOBOOT)`、自旋 —— 即原
  `crash_signal` 的函数体，现在两者共用）。pid 在 panic 时读，不缓存：fork 出去的子进程继承 hook
  但 pid≠1，只记日志让 abort 发生。
- `procd_signal_pid1` 的 crash 集从 `[SIGSEGV, SIGBUS]` 扩到 `[.., SIGABRT]`：Rust 的 abort
  （分配失败、或 hook 来不及）也走 `do_reboot` 而不是 init 退出 → 内核 panic。C 不装 SIGABRT，
  因为 C 没有 abort 路径；这是 F01 爆炸半径内的一行加固，写明。

### 1.3 测试与门

- `sys::tests::a_full_nonblocking_stderr_drops_the_line_instead_of_panicking`：建 pipe、写端
  `O_NONBLOCK`、写满、断言裸 `write` 回 EAGAIN（fixture 就是发现本身）、`dup2` 到 fd 2、调
  `ulog_stdio()` 与 `stderr_line()`、恢复 fd 2。在 `panic=abort` 下同样可跑。
- 门 `tools/r83_procd_r81.sh` 第 C 部分（照 r71 的 PID 1 启动块）：python3 把 fd 2 换成**已写满
  的 O_NONBLOCK 管道**再 exec `unshare ... chroot /sbin/procd -S`（rs 侧 `procd-rs -S`），命名空间里
  不放 `/dev/console`（两侧 `set_stdio` 都失败、stderr 保持满管道），inittab 只跑两个 rc 脚本
  和一个 respawn 项，驱动脚本做 10 次失败 `set` + 10 次 respawn 杀，最后 `system reboot`。
  注入 = R83 前的二进制：第一行 `- early -` 的 `eprintln!` 即 abort，drive.txt 不会出现。

## 2. F21 —— 成立

### 2.1 管道

- Rust `instance.rs:284-325` `take_config`：`*self = new` 后只回填 state/pid/respawn/deadline/
  watchdog，`log_out/log_err` 随旧值 drop → 读端关闭；子进程下一次写 → EPIPE/SIGPIPE。
- C `instance.c:1514-1570` `instance_config_move` 逐字段搬，**不碰** `in->_stdout/_stderr`。
- 修：`take()` 两个管道再 `*self = new` 再放回（4 行）。审计的测试补丁原样进 `instance.rs`
  `mod tests`（多加一条 fd 相同的断言）。

### 2.2 SIGPIPE

- C：`signal.c:90` `signal(SIGPIPE, SIG_IGN)` 在 `procd_signal()` 第一行，**两种模式都做、
  fork 之前**；被忽略的处置跨 `execve` 保留，所以实例、inittab 项、hotplug exec、rc 脚本、
  trigger `run_script`、sysupgrade validate 全部带 SIG_IGN 起跑。`instance_run()` 不再改信号。
- Rust std `Command`：exec 前 `sigemptyset`+`signal(SIGPIPE, SIG_DFL)`，在 `pre_exec` 闭包**之前**。
- 修：`proc::inherit_ignored_sigpipe(&mut Command)`（一个 `pre_exec` 里 `signal(SIGPIPE, SIG_IGN)`）
  挂到 `proc::start`、`proc::spawn_tty`、`dispatch.rs`（hotplug.<subsys> call）、`hotplug.rs`
  （udevtrigger、exec/button）、`rcs.rs`、`main.rs` trigger run_script、`sysupgrade.rs` validate ——
  即 crate 里全部 `Command::new`。`spawn_firmware` 是裸 fork 不 exec，天然继承。

## 3. F22 —— 逐项

| 项 | C 证据 | 判定 | 修 |
|---|---|---|---|
| `service delete '{}'` | `service.c:558-560` `if (!cur) return UBUS_STATUS_NOT_FOUND` | 成立 | `handle_delete` 缺 name → NOT_FOUND |
| LD_PRELOAD | `instance.c:477` `bool setlbf = _stdout >= 0`；`:491` `setenv("LD_PRELOAD", "/lib/libsetlbf.so", 1)`，在实例 env 之后（覆盖实例自带的）；rootfs 有 `/lib/libsetlbf.so`（4098 B） | 成立 | `stdout_to_log` 时 `cmd.env("LD_PRELOAD", SETLBF)`，位置同 C |
| `service.data.update` | `instance.c:1664-1665` `instance_init()` 末尾 `service_data_trigger(&in->data)`，`service.c:41-53` 每个实例 attr 都先 `instance_init` 再 `vlist_add` | 成立 | `handle_set` 在算 plan 前对 `fresh` 每个实例的 data 键 `data_trigger_keys` |
| cgroup | `instance.c:564-596` `instance_add_cgroup` **无 ifdef**，只在 `stat("/sys/fs/cgroup/cgroup.subtree_control")` 失败时跳过；`:677` 在 fork 出的子进程里、`instance_run` 之前调用；`mkdir_p(..., 0700)`、写 pid 到 `cgroup.procs`；设备 `/sbin/init`（58eb263d `initd/early.c:64`）挂 `cgroup2` 到 `/sys/fs/cgroup`；rootfs `strings /sbin/init` 有 `cgroup2 /sys/fs/cgroup nsdelegate`，`strings /sbin/procd` 有 `/sys/fs/cgroup/services`、`/cgroup.procs`、`failed adding instance cgroup for %s: %s` | 成立，本构建 C 确实做 | `proc::cgroup_dir()`（父进程：stat + 拼路径 + C 的 256 字节上限）→ `pre_exec` 里 `cgroup_add_self()`（逐级 `mkdir 0700`、`open/write/close`，栈缓冲无堆）；失败 `ULOG_WARN` 同文 |
| makedev 目录 0777 | `plug/hotplug.c:138` `umask(0)`，`:155` `mkdir_p(d, 0755)` | 成立 | `DirBuilder::new().recursive(true).mode(0o755)` |
| inittab exec 失败 | `inittab.c:92-141`：fork 后子进程 execvp 失败 `exit(-1)` → `child_exit` → `respawn >= 0 && dev_exist(id)` → `uloop_timeout_set(&a->tout, 500)` | 成立 | `fork_action` 的 `Err` 分支布 `respawn_at = now + respawn_ms`（条件同 `child_exit`） |
| facility -1 | `instance.c:1430-1435`：`syslog_facility_str_to_int` 回 -1 时 **不赋值**，保持 LOG_DAEMON | 成立 | `pump_logs` `.filter(\|f\| *f != -1)`；`sys.rs` 那句"C 原样存 -1"的注释是错的，已改 |
| DEVNAME/DEVICENAME | `plug/hotplug.c:476-491` `rule_handle_var` 是 json_script 的 `handle_var` 回调（表里查不到才调，返回值不进表）；`handle_exec` 的 envp 与 `hotplug_ubus_event` 的通知都来自原始 uevent 变量表；`service/trigger.c:62-65` 的 `rule_handle_var` 返回 NULL | 成立 | `jsonscript::run_hotplug_rule()`（`Ctx.devname_fallback`，`find_var` 表里没有时取 `basename(DEVPATH)`）；`parse_uevent` 不再往表里塞；trigger 路径不受影响 |
| 200 ms poll | C `uloop_run()` 对每个 fd 就绪即醒 | 部分（延迟成立；空闲唤醒次数不在爆炸半径内） | `Procd::wait_activity()`：poll 集 = ubus fd + SIGCHLD 自管道（`sys::install_sigchld_wakeup`，两种模式都装，uloop 也这样）+ uevent socket + `/etc/hotplug.d` inotify + 所有实例/rc/serial 日志管道；`next_incoming(200)` → `wait_activity(200); next_incoming(0)`。200 ms 只剩定时器粒度 |

## 4. 构建机验证（oracle，工具链 1.98.1）

```
cargo test                                   → 71 passed; 0 failed（MD5 测试已移至共享 ubus 库）
cargo clippy --all-targets -- -D warnings    → 无输出（干净）
cargo fmt --check                            → HEAD 基线 128 个 hunk（crate 从未 fmt 干净：一行 let-else、
                                               一行结构体字面量是全 crate 风格）；修后 137，多出的 9 个
                                               全是测试里与邻行同风格的一行 `Field { .. }`/`vec![..]`。
                                               新增的所有 >100 列行都已按 rustfmt 折行。
```

新增单测（10）：`sys::tests::a_full_nonblocking_stderr_drops_the_line_instead_of_panicking`、
`instance::tests::take_config_keeps_the_running_childs_log_pipes`、
`proc::tests::{a_child_inherits_sigpipe_ignored_like_the_c_child, a_piped_stdout_gets_libsetlbf_preloaded, an_unpiped_stdout_gets_no_preload}`、
`jsonscript::tests::the_hotplug_context_derives_devname_from_devpath_without_storing_it`、
`hotplug::tests::{a_uevent_datagram_becomes_exactly_the_kernels_variables, an_explicit_devname_wins_over_the_fallback}`（两条改写）+
`the_device_rules_parse_and_route_a_tty_add` 改走 DEVPATH 回退。`tools/audit/r81_procd_findings.rs` 已删除。

### 4.1 差分门

第一次 r65 用了本机 glibc 构建的候选（`cargo build --release` 不带 target），rootfs 是 musl，
`/sbin/procd-rs: not found`，rs 侧 0 个 pid —— 这一轮是**环境错误**不是行为差异，记在这里防止重演：
门要吃 `--target aarch64-unknown-linux-musl` 的静态产物（`examples/notifier` 同理）。

```
r65_procd_diff.sh
r65: ok；两侧各 272 个 case marker、49 条 pid 记录、20 次预期失败调用；calls.diff 为空
r65_selftest.sh：双侧 supervisor 死亡及中途截断均被门禁判红

r71_pid1_probe.sh
r71: ok（PID 1 启动时间线与状态行两侧一致，/tmp/procd-r71）

r72_hotplug_daemon_probe.sh / r72_tty_probe.sh
r72a: ok（hotplug 守护）；r72b: ok（tty）；r75: ok（PID 1 sysupgrade exec 交接）

r83_procd_r81.sh（新门；A 监督模式 / B hotplug 守护 / C PID 1 满 stderr）
r83: ok（A/B/C 三部分效果日志两侧相同且每条自带预期均满足，/tmp/procd-r83p）
```

红证（注入 = R83 前的二进制 `procd-rs`）：
```
r83: FAIL: A(rs): service delete '{}' is not NOT_FOUND
r83: FAIL: A(rs): child has no LD_PRELOAD=/lib/libsetlbf.so
r83: FAIL: A(rs): child does not have SIGPIPE ignored
r83: FAIL: A(rs): child not in /sys/fs/cgroup/services/lg/i
r83: FAIL: A(rs): instance cgroup is not 0700
r83: FAIL: A(rs): identical set changed the pid (F21)
r83: FAIL: A(rs): stdout log stopped after the identical set (F21)
r83: FAIL: B(rs): exec env carries a synthesized DEVICENAME (or lost DEVNAME)
r83: FAIL: B(rs): makedev parent dirs are not 0755
r83: FAIL: C(rs): PID 1 never reached the driver with stderr full (F01)
r83: FAIL: C(rs): namespace ended early: ns exit 139        <- 满 stderr 下 PID 1 abort，即 P0
（基线 = 3c46782 树的 musl 构建，md5 0b8d47d20238382ae2a39dc71c429760）
```

## 5. 验证边界

- `service.data.update` 每实例触发、inittab exec 失败重试、facility -1 过滤由固定修订读码和
  现有行为门间接覆盖，没有为这三项单独制作故障注入红证。
- r65 在私有 proc 下运行，并将 `/proc/kmsg` 绑定到 `/dev/null`，防止宿主消息挤掉实例日志。
  tty 夹具改用 `[ -t 0 ]` 和 `readlink /proc/self/fd/0`：镜像 BusyBox 没有 `tty` applet，
  原先的失败来自夹具命令缺失。
- r75 的成功交接会使测试 PID 1 退出，namespace 因而终止；成功由 `upgraded` 的 PID 1、
  argv/env 及没有旧 supervisor 继续运行的标记判定。前四个失败调用仍逐字节比较回复。
- 200 ms 项没有量化延迟（`kill` 实例到 `instance.stop` 事件的间隔）；行为门全绿说明 poll 集
  没有引入 POLLHUP 忙等（日志管道 EOF 当轮即被 `pump_logs` 丢掉）。
- 有意偏差两处，均写在代码注释里：supervisor 模式默认 stderr（C 默认 kmsg）；kmsg 前缀由
  `<29>` 改为 C 的裸 `<prio>`（以 C 源码为准）。
- C HEAD（2c1834a）把 `instance.fail/respawn` 通知改成带 service/instance/pid/exit_code 的表，
  设备的 58eb263d 没有；Rust 跟设备，不跟 HEAD。
- `syslog(3)` 在 `/dev/log` 接收队列满时会阻塞 —— 与同一 musl 下的 C 一致，未改。
- Rust 独有的三行 LOG_ERR 诊断（§1.2）保留。

## 6. 最终验证

`make test`、严格 clippy、musl release 构建通过；r65、r65 自检、r71、r72 hotplug/tty、
r75 与 r83 A/B/C 均通过。14 个 RLIMIT 常量由目标 SDK C 编译器作静态断言验证，
避免把 syslog facility 表误收为常量，也无需执行目标动态加载器。
最终构建身份和日志索引见 [validation.md](validation.md)。未构建 APK 或部署固件。
