# R83 — ubusd-rs / owrt-ubus: R81 findings F02, F27, F24(ubus 部分)

日期 2026-09-09。范围：`components/ubusd`（ubusd-rs）与 `components/ubus`（owrt-ubus）。
参照 C：`oracle:/home/ubuntu/stage9/ubus`（ubusd_acl.c / ubusd_event.c / ubusd_monitor.c / ubusd_obj.c / ubusd_proto.c）与
libubox 2026.06.19~7dd12784（blobmsg_json.c、blob.h、blobmsg.c）。
差分沙箱：exact rootfs `~/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`，
C `/sbin/ubusd` + 设备自带 `/bin/ubus` CLI，每侧独立 mount+net namespace（与 r36 同一 harness）。

新增门：`tools/r83_ubusd_acl.sh` + `tools/r83_ubusd_inner.sh` + 线级探针 `components/ubusd/examples/wireprobe.rs`
（用 `--examples` 随发布版一起交叉编译，不进包：packaging 只拷 `src/*.rs`）。
R81 演示测试 `tools/audit/r81_ubusd_acl_pathless.rs`、`tools/audit/r81_ubus_lib_fidelity.rs` 已并入各 crate 的单元测试并删除。

## 结论一览

| 项 | 判定 | 修在 |
|---|---|---|
| F02 无 path 系统对象一律拒绝非 root | **成立** | `acl.rs` `Acl::check(obj: Option<&[u8]>)`，`server.rs invoke()` 传 `o.path.as_deref()` |
| F27.1 释放仍有订阅者的对象，owner 收不到 NOTIFY(ACTIVE=0) | **成立** | `server.rs free_object()` |
| F27.2a MONITOR 属性顺序 | **成立** | `server.rs mirror()` |
| F27.2b 事件 seq 每次派发一个而非每条投递 `++event_seq` | **成立** | `server.rs dispatch_event()` |
| F27.3a HUP 时 acl.d 空/缺失清空 ACL 表并 seq++ | **成立** | `acl.rs load()` 提前返回；`server.rs load_acl()` 不发事件 |
| F27.3b `.x.json` 点文件被当 ACL 加载 | **成立** | `acl.rs acl_files()` |
| F27.4 `blob::iter` 接受末尾未填充属性 | **成立** | `ubus/blob.rs attr_at()`；`server.rs attrs_of()` 去掉冗余补丁 |
| F27.5 `append_json` 整数全 INT64（C INT32） | **成立** | `server.rs acl_query()` 改用 `convert::json_to_fields`，删除 `append_json` |
| F27.6 浮点最短往返 vs `%.17g` | **成立** | `ubus/json.rs write_double()` |
| F27.7 每个 INVOKE 克隆凭据 / 每个 STATUS 新建 BlobBuf | **成立（低影响）** | `server.rs invoke()` 借用、`send_status()` 复用 scratch；未测墙钟 |
| F24 非 UTF-8 STRING 变 `""`（owrt-ubus） | **成立** | `ubus/convert.rs field_to_json()` 改 lossy（U+FFFD）；残余见 §F24 |

r83 门：C vs 修后 rs **3/3 identical（35 行）**；C vs R81 基线 rs（md5 `f3940b6c…`）**红**，§1/§2 与 events/monitor/release/aclquery 全部行不同（下文贴出）。
r36 门修后 identical（85 行）。r42 fuzz 修后 3 次：identical、identical、1 次 `final objects unchanged: no`——基线二进制同样出现该行，是 r42 自身在 rpcd 就位前 `ubus list` 的既有抖动，非本轮回归。

发布二进制：`~/r81-ubusd/components/ubusd/target/aarch64-unknown-linux-musl/release/ubusd-rs`
md5 **`5ae1a0a193357fd68adc3977f445477d`**（`cargo +1.98.1 build --release --bins --examples --target aarch64-unknown-linux-musl`，
构建路径 `/home/ubuntu/r81-ubusd`；两次构建同 md5）。探针 `…/release/examples/wireprobe` md5 `f4f8a39e841fd284a9dcc15ed95fcb49`。

---

## F02 — 无 path 的系统对象（event/acl/monitor）对非 root 一律 PERMISSION_DENIED

**判定：成立。**

C（ubusd_acl.c:108）：
```c
if (!cl || !cl->uid || !obj)
    return 0;
```
`ubusd_handle_invoke` 传 `obj->path.key`，三个系统对象和匿名对象的 key 为 NULL → 直接放行，再由对象自己的 `recv_msg` 判定
（event `send` 对 id 做 `UBUS_ACL_SEND`，`register` 对 pattern 做 `UBUS_ACL_LISTEN`，monitor 只认 uid/gid 0）。
Rust 原 `invoke()`：`o.path.clone().unwrap_or_default()` → `b""` 进 `Acl::check` → 非 root 遍历表无匹配 → 6。

**复现（沙箱，用户 `network` uid 101，rootfs 自带 `wpad_acl.json` 授 `send: ["bss.*","wps_credentials"]`）**——C vs 基线 rs：
```
-network_send_bss: rc=0
-network_send_wps: rc=0
+network_send_bss: rc=6
+network_send_wps: rc=6
-nobody_pathless: … acl.query=0 acl.bogus=1 event.bogus=1 event.register(no-such-object)=4 event.send(unlisted id)=6 monitor.add=6 monitor.bogus=6
+nobody_pathless: … acl.query=6 acl.bogus=6 event.bogus=6 event.register(no-such-object)=6 event.send(unlisted id)=6 monitor.add=6 monitor.bogus=6
-network_send_while_root_listens: rc=0
-root_listen_got: [{"bss.add":{"k":1}}]
+network_send_while_root_listens: rc=6
+root_listen_got: []
```
即基线上 hostapd 的每条 `ubus_send_event("bss.*")` 都被拒，root 侧 `ubus listen bss.*` 收不到；`acl query`、未知方法的 INVALID_COMMAND(1)、
`register` 的 NOT_FOUND(4) 全部塌成 6。两侧一致的行证明对象自身检查仍在：`network_send_unlisted rc=6`、`nobody_send_bss rc=6`、`monitor.add=6`。

为什么 r36 没看见：`ubus call acl query` 先按 path LOOKUP，acl 对象无 path → 两侧都是 4（`cli_call_acl_query: rc=4`），
r36 §2 那几行从未触到 ACL 判定；§9 的非 root 只调有 path 的对象。探针直接 INVOKE objid 1/2/3。

**修法**：`Acl::check(&self, cred, obj: Option<&[u8]>, method, ty)`，`None` → 放行（注释引 C 行）；`invoke()` 传 `o.path.as_deref()`，
其余六个调用点传 `Some(..)`。空串 `""` 仍是真实 path（C 里 `"\0"` 通过 STRING 策略后 `obj` 非 NULL），单测覆盖 `Some(b"")` 不放行。

**测试**：`acl::tests::pathless_object_bypasses_the_table_like_c`（原 r81_f1，改为 `None`）；r83 门 §1（10 行）。

## F27 — 其余偏差

### F27.1 释放仍有订阅者的对象时 owner 收不到 NOTIFY(ACTIVE=0) — 成立
C `ubusd_free_object` → `ubus_notify_unsubscribe(s)`：先给订阅者 UNSUBSCRIBE，再 `ubus_unsubscribe(s)`，
其中 `if (list_empty(&obj->subscribers)) ubus_notify_subscription(obj)` → owner 收到 NOTIFY(ACTIVE=0, seq=++invoke_seq)。
Rust `free_object` 丢弃了 `reg.unsubscribe()` 的返回值。
```
-release: … release_sequence=DATA NOTIFY(active=0,seq=2) STATUS(0) subscriber_got=UNSUBSCRIBE …
+release: … release_sequence=DATA STATUS(0) subscriber_got=UNSUBSCRIBE …
```
修：`if self.reg.unsubscribe(s, id) { self.notify_subscription(id); }`。owner 若正在断连，消息入队后随 client 一起丢，与 C 相同。

### F27.2a MONITOR 属性顺序 — 成立
`ubusd_monitor_message`：CLIENT, PEER, SEQ, TYPE, SEND, DATA。Rust 原为 CLIENT, PEER, SEND, SEQ, TYPE, DATA。`ubus monitor` 按策略解析所以看不出；探针看到：
```
-monitor: … m0: type=MONITOR seq=1 attr_ids=0,1,3,4,2,5 mirrored_type=STATUS send=1 …
+monitor: … m0: type=MONITOR seq=1 attr_ids=0,1,2,3,4,5 mirrored_type=STATUS send=1 …
```

### F27.2b 事件 seq — 成立
`ubusd_send_event_msg`：`(*ub)->hdr.seq = ++event_seq` 每投递一份加一。Rust 每次 dispatch 加一，同一事件的所有接收者同 seq：
```
-events: … round0: … seq_delta=1 objids=o1,o2 … round1: … seq_delta=1 …
+events: … round0: … seq_delta=0 objids=o1,o2 … round1: … seq_delta=0 …
```
修：在 `dispatch_event` 的每次 `send` 前 `event_seq += 1`。

### F27.3a HUP 时 acl.d 空/缺失 — 成立
C `ubusd_acl_load`：`if (glob(path, …)) return;`——无 `*.json` 匹配（空目录、只有非 json、目录不存在）即返回，不 `vlist_update`、不 `seq++`、不发 `ubus.acl.sequence`。
Rust 原 `load()` 无条件替换表并 seq++。沙箱里 root 监听 `ubus.acl.sequence` 计数：
```
-empty_dir_hup_network_send_bss: rc=0        +… rc=6
-empty_dir_hup_seq_events: 0                 +… 1
-missing_dir_hup_seq_events: 0               +… 3
-restored_hup_seq_events: 1                  +… 4
-acl_seq_events_seen: [2 3 ]                 +acl_seq_events_seen: [2 3 4 5 6 ]
```
修：`acl_files()` 为空 → `load()` 返回 `false` 不动表；`Server::load_acl` 仅在 `true` 时发事件。
目录里 json 全部因属主/权限被跳过的情形与 C 一样清空表（glob 成功、vlist_flush）。
测试 `acl::tests::load_with_no_files_keeps_the_previous_table`（原 r81_f5）。

### F27.3b 点文件 — 成立
`glob("*.json")` 无 GLOB_PERIOD，`*` 不匹配前导点；`read_dir + ends_with(".json")` 匹配。基线里这一项被 F02 遮住（非 root 走不到 SEND 检查），
所以单独做了红证：在修后代码上仅去掉 `!name.starts_with('.')` 重建（md5 `f1def38f…`）跑 r83：
```
RESULT: transcripts differ
-dotfile_hup_nobody_send: rc=6
+dotfile_hup_nobody_send: rc=0
```
测试 `acl::tests::dotfiles_are_not_acl_files`（原 r81_f6，改为直接测 `acl_files()`，不再依赖以 root 运行）。

### F27.4 `blob::iter` 接受末尾未填充属性 — 成立
libubox `__blob_for_each_attr`（blob.h:254-256）要求 `blob_pad_len(pos) <= rem`；Rust `attr_at` 只要求 raw_len 放得下。
`attrs_of` 顶层已补丁，但 SIGNATURE 方法列表和 blobmsg 字段走 `blob::iter`：手工报文可让 Rust 注册一个 C 丢弃的方法。
修在 `owrt_ubus::blob::attr_at`（`buf.len() >= offset + pad4(raw_len)`），`attrs_of` 冗余检查删除。
测试 `blob::tests::iter_requires_the_padded_length_to_fit`（原 r81_f7：10 字节未填充 INT16 字段 → C 0 个，补齐 2 字节 → 1 个）。
r42 fuzz 修后 identical（见上）。libubox 产生的 blob 的子属性总在父的 raw_len 内完整填充（`blob_new` 用 `blob_pad_len` 累加），正常报文不受影响。

### F27.5 `append_json` 整数全 INT64 — 成立
C 把 ACL 文件按 `blobmsg_add_json_element` 存 blob（int 在 int32 范围内 → `blobmsg_add_u32`，否则 u64），`acl query` 原样回吐。
沙箱注入 `/usr/share/acl.d/r83_probe.json`（user root，`access.r83.priv.acl = {n:1,neg:-5,big:3000000000,s,b,f,z,arr,t}`）：
```
-aclquery: … acl=[n:INT32,neg:INT32,big:INT64,s:STRING,b:INT8,f:DOUBLE,z:UNSPEC,arr:ARRAY[:INT32,:STRING],t:TABLE[k:INT32]]
+aclquery: … acl=[n:INT64,neg:INT64,big:INT64,s:STRING,b:INT8,f:DOUBLE,z:UNSPEC,arr:ARRAY[:INT64,:STRING],t:TABLE[k:INT64]]
```
修：`acl_query` 改用 `owrt_ubus::convert::json_to_fields`（已有 i32 范围分流和单测 `json_int_uses_signed_i32_range`），删除 `append_json`（35 行重复代码）。

### F27.6 浮点格式 — 成立
blobmsg_json.c：`snprintf(buf, sizeof(buf), "%.17g", blobmsg_get_double(attr))`。Rust 用 `{f}` 最短往返。
在 oracle 上用 gcc 编了 `printf("%.17g")` 参照表（含 0.1、1e21、1e16/1e17 边界、次正规数、`2^-25` 这类第 18 位恰为 5 的 ties），
实现 `json::write_double`：`{:.16e}` 取十进制指数 X，`X < -4 || X >= 17` 走 e 格式（指数带符号补两位），否则 `{:.(16-X)}`，再去尾零。
Rust 精确格式化与 glibc/musl 同为 round-half-even，ties 一致（`2^-25 → 2.9802322387695312e-08`，`3·2^-25 → 8.9406967163085938e-08`，两者均经 C 核对）。
非有限值照 C 输出 `inf`/`-inf`/`nan`/`-nan`（原来输出 `null`；C 从不输出 null，这里以 C 为准）。
测试 `json::tests::double_formatting_matches_printf_17g`（含原 r81_f9 的五个值，共 27 个值 + 4 个非有限）。
影响面：`Json::Float` 序列化的所有使用者（httpd bridge、rpcd、fw4、netifd）——它们此前对 DOUBLE 字段输出的字节与 C 不同。

### F27.7 每个 INVOKE 的克隆 — 成立，低影响
`invoke()` 改为借用 `clients[client]` 的 uid/gid/extra_gid 与 user/group（`Cred<'_>` + `forward_blob(who: Option<(&str,&str)>)`，`forward_blob` 改自由函数），
`send_status()` 复用 `self.scratch` 走 `send_blob`。其他非热路径（notify/add_watch/event_*）保留 `cred_of()` 拷贝。未做基准（R82 已说明墙钟不可见）。

## F24（ubus 部分）— 非 UTF-8 STRING 经 `field_to_json` 变 `""`

**判定：成立。** libubox `blobmsg_format_string` 对字节逐个只转义 `\b\n\t\r"\\` 和 <0x20，其余原样拷贝，不做 UTF-8 校验；`ubus` CLI 也原样打印。沙箱实测（两侧相同）：
```
utf8: register=0 send=0 got=INVOKE s_hex=636166e9 s_is_utf8=false
cli_listen_utf8_hex: [… 22 3a 22 63 61 66 e9 22 7d 20 7d 0a |":"caf."} }.|…]
```
即 `{"s":"caf\xe9"}` 的 0xe9 原字节被 C 库直接写到输出。owrt-ubus 原 `Field::as_str().unwrap_or("")` 让整个值消失。

修：`Field::as_bytes()`（到 NUL 的原字节）；`field_to_json` 用 `String::from_utf8_lossy` → `"caf\u{fffd}"`。
测试 `convert::tests::non_utf8_string_is_not_silently_emptied`（原 r81_f10）、`blob::tests::string_field_bytes_are_not_validated`。

**残余差距（未做，按指示不启动 Vec<u8> 重构）**：
1. 值仍是有损的 U+FFFD，不是 C 的原字节；rpcd `file read` 等经 Json 的路径依旧不是字节精确（R81 F24 的 rpcd 部分不在本轮范围）。
2. 字段**名**非 UTF-8 时 `Attr::field()` 返回 None，整个字段被跳过（C 原样打印名字）；`Field.name: &str` 改类型会波及所有 crate。
3. `event_register` 的 pattern、`event_send` 的 id 用 `as_str()`，非 UTF-8 时回 INVALID_ARGUMENT（C 接受）。极端边缘，未改。

## 未复现 / 未改的

- F27 报告称 `server.rs:1037-1071 append_json` 与 `convert::json_to_fields` 重复：成立且已删；**没有**发现两者在 null/bool/string/double/嵌套上的其他差异。
- 顺带核对但**未改**（不在清单内）：SIGNATURE 中 raw_len 为 1..3 的属性，C `blobmsg_check_attr` 判失败使整个类型作废（对象无类型），Rust `attr_at` 在此停止、保留之前的方法。仅手工报文可触发，记录备查。
- `cargo fmt --check`：两个 crate 在 HEAD 基线上就不干净（默认 rustfmt：owrt-ubus 6 处、ubusd 82 处；试 max_width 100/110/120 都不为 0，仓库无 rustfmt.toml，CI 也不跑 fmt）。本轮按现有风格写，改后为 7/85 处（多出的都是与现有测试同形的单行 `Cred {..}`），未对未触及代码重排。

## 测试与门（oracle，toolchain 1.98.1）

```
components/ubus : cargo test → 10 passed；cargo clippy --all-targets -- -D warnings → 通过
components/ubusd: cargo test → 21 passed；cargo clippy --all-targets -- -D warnings → 通过（含 examples/wireprobe.rs）
tools/r83_ubusd_acl.sh  C vs rs(5ae1a0a1) ×3 → RESULT: identical transcripts (35 lines)
tools/r83_ubusd_acl.sh  C vs rs(f3940b6c 基线)  → RESULT: transcripts differ（上文各段引文）
tools/r83_ubusd_acl.sh  C vs rs(f1def38f 去点文件过滤) → 仅 dotfile_hup_nobody_send 一行不同
tools/r36_ubusd_diff.sh C vs rs(5ae1a0a1) → RESULT: identical transcripts（85 行）
tools/r42_ubusd_fuzz.sh C vs rs(5ae1a0a1) ×3 → identical ×2，1 次 "final objects unchanged: no"（基线同现，r42 既有抖动）
```
门的完整性：r83 门要求两侧都到达 `daemon_alive: yes` 才比较，避免半截 transcript 假绿。

## 改动文件

- `components/ubus/src/blob.rs`：`attr_at` 填充长度检查；`Field::as_bytes`；2 个单测
- `components/ubus/src/convert.rs`：STRING lossy；1 个单测
- `components/ubus/src/json.rs`：`write_double`/`trim_fraction`（`%.17g`）；1 个单测
- `components/ubusd/src/acl.rs`：`check(obj: Option)`、`load() -> bool`、`acl_files()`；3 个新单测，旧单测改签名
- `components/ubusd/src/server.rs`：`load_acl`、`send_status`、`free_object`、`invoke`、`forward_blob`（自由函数）、`notify`、`dispatch_event`、`acl_query`、`mirror`、`attrs_of`；删 `append_json`
- `components/ubusd/examples/wireprobe.rs`（新，382 行）
- `tools/r83_ubusd_acl.sh`、`tools/r83_ubusd_inner.sh`（新）
- 删除 `tools/audit/r81_ubusd_acl_pathless.rs`、`tools/audit/r81_ubus_lib_fidelity.rs`

未提交（按本轮规则不做 git 操作）。设备上线前请用 R80 的窗口流程替换 `/sbin/ubusd`（回滚 = mv `.c-orig` 回来）；本轮未碰 `openwrt`。
