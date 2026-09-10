# R83 · rpcd：R81-F23（`file exec` 阻塞请求循环）与 F24（其余偏差）

日期 2026-09-09。参照 C：`oracle:/home/ubuntu/stage5/rpcd`（`file.c` / `exec.c` /
`sys.c` / `ucode.c` / `plugin.c`）、`oracle:~/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/luci/libs/rpcd-mod-{luci,rrdns}/src/*.c`、
设备 rootfs `oracle:~/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`
（内含 `/usr/share/rpcd/ucode/luci`）。构建/测试目录 `oracle:~/r81-rpcd`（本机只编辑，
不在 oracle 上改代码）。未接触路由器。

## 1. 逐条结论

| 项 | 结论 | 说明 |
|---|---|---|
| F23 `file exec` | **成立**（P1） | C `ubus_defer_request`；Rust 在循环上等到子进程结束。实测 4 s vs C 0 s |
| F23 luci shell 帮助函数 | **不成立** | C 的 `luci` 对象是 rpcd 进程内的 ucode 脚本，`popen`/`system` 同样堵住 uloop |
| F24 `file write` 的 `umask(0)` 窗口 | **成立** | 已改为 `O_EXCL` + `fchmod`，进程 umask 不再被动过 |
| F24 exec ACL 命令行长度差一 | **成立** | C 的阈值是 1023 字节（含 NUL），Rust 是 1024 |
| F24 延迟动作用线程而非 fork | **成立** | `upgrade_start` 后 SIGHUP，C 仍升级，Rust 丢掉 |
| F24 rrdns 截断输出部分 PTR | **成立** | C 的 `ns_initparse` 先整包校验，Rust 边解析边发 |
| F24 非 UTF-8（rpcd 自己的 Json 路径） | **成立**，未修 | `file.rs` 自带 `from_utf8_lossy`，与 `owrt-ubus/convert.rs` 无关；修它要改 `Json`/`BlobBuf`（他人 crate） |
| F24 rrdns `server` 为主机名 → UNKNOWN_ERROR | **成立**，未修 | 不在本次指派的修复清单内 |
| H02 “r13 掩掉 `file_exec_sh` 的 code” | **部分不成立** | 差分里确实掩了，但候选侧另有硬断言 `code == 3` |

## 2. F23：`file exec` 阻塞（P1）

C 里 `rpc_file_exec_run`（`file.c:1064`）fork 出子进程、把两个管道挂进 ustream、
用 `uloop_timeout_set(&c->timeout, *ops->exec_timeout)` 起超时，然后
`ubus_defer_request(ctx, req, &c->request)` 就返回；回复走
`rpc_file_exec_reply()` → `ubus_complete_deferred_request()`。因此 C 保证：

- 回复顺序**没有**保证（deferred 回复相对同步回复可以后到），
- 每个请求一个独立的 exec 超时，
- 没有 `cancel_cb`：客户端先走掉，回复只是发不出去，不会有别的动作。

Rust 原来在 `dispatch()` 里同步跑完 `run_command()`。同一 rootfs 沙箱（自带 ubusd，
无 C rpcd）里发 `file exec /bin/sh -c "sleep 5"`，1 s 后第二个客户端量
`session list`：

```
##### C rpcd (/sbin/rpcd + file.so)
session_list_s=0        exec reply: { "code": 0 }
##### rpcd-rs（修复前）
session_list_s=4        exec reply: { "code": 0 }
##### rpcd-rs（修复后）
session_list_s=0        exec reply: {"code":0}
```

修法（`components/rpcd/src/file.rs`）：把 C 在 fork 之前做的事（参数解码、
`sid`+`env` 拒绝、`rpc_file_exec_lookup` 的 PATH 查找、两次 `session access`）
留在请求循环上 —— 这些都是有界操作，C 也在循环上做 —— 只把子进程的看护交给
worker 线程，回复经既有的 `Deferrer`（channel + 唤醒管道）回到事件循环。
`run_command()` 一个字节没改，所以超时/64 KiB 上限/`WEXITSTATUS` 语义原样保留；
`params.len() > 253`（C 子进程 `arglen==255` 后 `_exit(127)`）也移进线程，
因为 C 那条路径同样是**延迟**回复的。`file` 的其余方法仍在循环上。

`luci` 对象不动：设备上 `luci` 来自 `/usr/share/rpcd/ucode/luci`，由 `ucode.so`
加载。`rpc_ucode_script_call`（`ucode.c:441`）虽然先 `ubus_defer_request`，紧接着
就用 `uc_vm_call()` **同步**执行处理函数，而该脚本里是
`popen('dnsmasq --version')`、`popen('luci-bwc ...')`、
`system('(echo p; sleep 1; echo p) | busybox passwd ...')` 这类调用 —— C 自己
就把 uloop 堵住同样长的时间。C 为准，报告里记为不成立。（`luci-rpc` 走
`libs/rpcd-mod-luci`，纯嵌套 ubus + defer，Rust 侧早就有 `Deferrer`。）

## 3. F24 各项

### 3.1 `file write` 的 `umask(0)` 窗口

C：`prev = umask(0); open(path, O_CREAT|O_WRONLY|flag, mode); umask(prev)`
（`file.c:411-413`），单线程 uloop 里没有别人能 fork。Rust 的 `rc`/`rc init`/
`rpc-sys upgrade_test`/`uciobj` 的 `reload_config` 都在 worker 线程里
`Command::spawn`，`util.rs` 那句“请求循环是单线程”的断言在 stage 7 之后已不成立，
子进程可能带着 umask 0 起来。

改为不碰进程 umask：先 `O_CREAT|O_EXCL` 建文件再 `fchmod(mode & 07777)`；
`EEXIST` 时退回普通 `open` 且**不** chmod —— 文件已存在时 C 的 `mode` 参数本来就
被 open(2) 忽略。悬空符号链接会让 `O_EXCL` 报 `EEXIST` 而普通 open 仍然创建目标，
所以退回前用 `fs::metadata()` 再判一次是否由我们创建。`util::umask_zero/​umask_restore`
连同 `util.rs` 的 `umask` extern 一起删掉，crate 里只剩 `main()` 启动时那次
`umask(0o077)`。

### 3.2 exec ACL 命令行长度差一

C（`file.c:950-951`）：

```c
if (arglen == 255 || p + blobmsg_data_len(cur) >= cmdstr + sizeof(cmdstr))
        return UBUS_STATUS_PERMISSION_DENIED;
```

blobmsg 字符串的 `data_len` **含 NUL**，所以条件等价于
`已用长度 + 参数长度 + 1 >= 1024`：能进第二次 ACL 检查的命令行最长 1023 字节。
Rust 原来写 `cmdstr.len() + p.len() >= CMDLINE_MAX`，正好放宽一个字节 ——
一条 1024 字节的命令行会绕过 C 会拒绝的那次 `PERMISSION_DENIED`。
现在这段逻辑提成 `acl_cmdline()`（同时也把 `arglen` 计数改成 `i + 2`，
避免 clippy 的 `explicit_counter_loop`），单测钉住 1023/1024 与 253/254 两个边界。

### 3.3 延迟动作：必须是 fork 出来的子进程

C `sys.c:419/446/460`：`if (!fork()) { sleep(2); execv(...); }`（`reboot` 是
`sync(); sleep(2); reboot(RB_AUTOBOOT); while (1);`）。子进程和 rpcd 的生死无关。
Rust 用 `std::thread::spawn` + `thread::sleep(2s)`：rpcd-rs 收到 SIGHUP 会
`exec_self()` 重新起自己、收到 SIGUSR1 会 `exit(0)`，两种情况下线程连同待办的
sysupgrade / jffs2reset / reboot 一起消失。可观测，已修：`delayed_exec()` 和
`reboot` 改成真 `fork()`，argv 的 `CString` 在 fork 之前构造好，子进程里只调
`sleep`/`execv`/`_exit`。

留一个已知差异：C 的 uloop 用 `waitpid(-1, …, WNOHANG)` 顺手收了这个子进程，
rpcd-rs 不做全局回收（会抢掉 worker 线程 `Child::wait` 的状态），所以理论上会留一个
僵尸。三个动作都会让系统消失（`sysupgrade`/`jffs2reset -r`/`reboot` 都不返回），
所以不影响行为。

### 3.4 rrdns 截断响应

C `rrdns_parse_response()` 先 `ns_initparse(res, len, &handle)`，glibc/musl 的实现
会把四个 section 的每条记录都走一遍（`ns_skiprr`）做长度校验，失败直接 `-EINVAL`，
一条 PTR 都不会进 blob。Rust 是边走 answer 边 `msg_string()`，被截断时把已经读出来的
PTR 发了出去；而且截断发生在 authority/additional 里时它根本不看，照样成功。
补了一个等价的 `initparse()` 前置校验（并给 `skip_name()` 的压缩指针加上越界检查）。
`ns_parserr` 成功后 `ns_name_uncompress` 才失败那条路径 C 确实会留下之前的记录，
所以答案段的增量写入保持不变。

### 3.5 非 UTF-8（rpcd 自己的 Json 路径）—— 成立，未修

报告点到 `owrt-ubus/convert.rs:404` 之外还有一处，确实有：`file.rs` 的
`read()` 用 `String::from_utf8_lossy`（非 base64 分支），`run_command()` 的
stdout/stderr 也是。C 侧 `rpc_file_read` / `rpc_ustream_to_blobmsg` 是
`blobmsg_alloc_string_buffer` + `memcpy` 原样搬字节。同一 rootfs 两个沙箱里
`printf 'a\377b' > /tmp/bin.txt` 后 `ubus -S call file read`：

```
original :  7b 22 64 61 74 61 22 3a 22 61 ff 62 22 7d          {"data":"a.b"}
candidate:  7b 22 64 61 74 61 22 3a 22 61 ef bf bd 62 22 7d    {"data":"a...b"}
```

未修：`Json::Str(String)` 和 `BlobBuf::msg_string(&str)` 都在 `components/ubus`，
不属于本次可改范围；`file` 的回复要带原始字节必须先让那两个 API 收字节串。
建议和 `convert.rs` 的同一根因一起改。

### 3.6 rrdns `server` 为主机名 —— 成立，未修

C `rrdns.c:336` 是 `usock(USOCK_UDP, server, usock_port(port))`，走 getaddrinfo，
主机名能解析；Rust `server.parse::<IpAddr>()` 失败即 `UNKNOWN_ERROR`。不在本次
指派的修复清单里，只记录。

### 3.7 H02：r13 对 `file_exec_sh` 的掩码

`tools/r13_rpcd_check.py:126` 的 `EXPECT_CODE = {"file_exec_sh": 3}` 在差分比较里
把两侧的 `code` 都换成 `<masked>`（C 的 `rpc_file_exec_process_cb` 与管道 EOF 有真
竞争，先 EOF 时 `c->stat` 还是 0），但紧接着第 207-211 行另有一条硬断言
`json.loads(c[1]).get("code") == EXPECT_CODE[rid]`，候选侧的 code 必须正好是 3。
即“掩掉了”只对 C 一侧成立，候选的退出码并没有失去保护，因此没有改 r13。

## 4. 测试与门

新增单测（`components/rpcd/src/{file,rrdns}.rs`）与新门
`tools/r83_rpcd_defer.sh <rootfs-files> <rpcd-rs-binary>`（一次性 rootfs 沙箱，
自带 ubusd，不跑 C rpcd；把 `/sbin/sysupgrade` 换成只 `touch` 的桩）。

红证 —— 把三处改动分别退回原状后 `cargo test`：

```
test file::tests::the_acl_command_line_stops_one_byte_before_the_c_buffer ... FAILED
  panicked at src/file.rs:552: 1024 bytes must be denied
test file::tests::write_creates_with_the_exact_mode_and_leaves_the_umask_alone ... FAILED
  assertion `left == right` failed: a new file must get the requested mode, not mode & ~umask
    left: 384   right: 438
test rrdns::tests::a_truncated_response_yields_no_ptr_at_all ... FAILED
  panicked at src/rrdns.rs:438: cut 1 leaked a partial answer
test result: FAILED. 35 passed; 3 failed
```

红证 —— 把 `file exec` 退回同步执行、`delayed_exec` 退回线程后重新编译并跑新门：

```
defer_session_list_s=4      FAIL session list waited 4 s behind file exec (C: 0)
parallel_two_execs_s=8      FAIL two 4 s execs took 8 s, they must overlap
respawn_upgrade_ran=0       FAIL upgrade_start did not survive the SIGHUP respawn
r83 rpcd defer gate: FAIL
```

修复后（最终二进制）：

```
defer_session_list_s=0   defer_exec_reply={"code":0}
parallel_two_execs_s=4   respawn_upgrade_ran=1
r83 rpcd defer gate: PASS
```

既有门（同一最终二进制、同一 rootfs）：

```
r13_rpcd_check.py       63 requests: 63 identical, 0 differ      rc=0
r17_rpcd_core_check.py  272 steps:  272 identical, 0 differ      rc=0
r18_rpcd_plugins_check.py 74 steps:  74 identical, 0 differ      rc=0
r19_lucirpc_check.py    11 pairs:    11 identical, 0 differ      rc=0
```

`cargo test`：38 passed / 0 failed。
`cargo clippy --all-targets -- -D warnings`：本次引入的三条已清（`explicit_counter_loop`、
`type_complexity`、`cloned_ref_to_slice_refs`）；仍红的 5 条在本次未触碰的文件/行上，
即 R81 §6 记的那批风格提示：`iwinfo/netlink.rs:76`、`iwinfo/nl80211.rs:1477`、
`iwinfo/nl80211.rs:1511`、`lucirpc.rs:644`、`util.rs:106`（`is_multiple_of` /
`map_or` / `collapsible_match`，新版 clippy 才有），按“只动指派的发现”未改。
`cargo fmt --check`：仓库没有 `rustfmt.toml`、CI（`.github/workflows/ci.yml` 只跑
`make test`）也不跑 fmt，默认配置下 20 个源文件全部有 diff（改动前后一样），
故按 crate 现有风格书写，未做全仓格式化。

## 5. 发布产物

```
oracle:~/r81-rpcd/components/rpcd/target/aarch64-unknown-linux-musl/release/rpcd-rs
md5  43b1da26617b4a0445f7857d65b1a19e
cargo +1.98.1 build --release --bins --examples --target aarch64-unknown-linux-musl
```

注意：`~/r81-rpcd` 是整仓 rsync，编译时把并发会话对 `components/ubus`、
`components/uci` 的未提交改动一起带上了，所以这个 md5 只对当次树状态可复现。

## 6. 遗留

1. 非 UTF-8 字节（`file read` / `file exec` 输出）仍被换成 U+FFFD，需要
   `owrt-ubus` 的 `Json`/`BlobBuf` 先支持字节串（与 `convert.rs:404` 同一根因）。
2. rrdns `server` 为主机名时返回 UNKNOWN_ERROR，C 会 getaddrinfo。
3. `umask(0)` 竞争窗口的永久测试只钉住了“新文件拿到确切 mode、已存在文件保持原
   mode、进程 umask 不变”这三条行为；窗口本身靠“crate 内除启动外不再调用 umask(2)”
   在结构上排除，没有加并发 fork 的抽样断言（会是概率性红）。
4. 延迟动作的 fork 子进程无人回收（见 3.3），行为上无影响。
5. clippy 的 5 条历史风格提示未动。
