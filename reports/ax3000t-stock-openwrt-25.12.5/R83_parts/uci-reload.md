# R83 — uci-rs / reload-config-rs：R81 发现 F25、F26

日期 2026-09-10。范围：`components/uci`（libuci + `/sbin/uci`）、`components/reload-config`。**未触碰路由器。**

参照实现（唯一裁判）：
* **libuci C**：`oracle:/home/ubuntu/stage6/uci`，读 `list.c`、`file.c`、`delta.c`、`util.c`、`cli.c`、`libuci.c`。
* **exact rootfs**：`oracle:~/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`
  （镜像自带 `/sbin/uci` 16395 B md5 `f380835af26ec17550fa7f31c6452abc` + `libuci.so`，以及 17 行
  shell 版 `/sbin/reload_config`）。

新增门：`tools/r83_uci_findings.sh`（F25 全项 C-vs-Rust 差分，两份一次性 rootfs 副本 + bind-mount
`/sbin/uci`，每步 stdout/stderr/rc 及整棵 scratch 树逐字节比对；每步都带 `-c <dir> -t <dir>/save`，
因为 C 的 `uci -c <dir>` 仍用 `/tmp/.uci` 作 savedir，不给 `-t` 两侧会互相污染）。
R81 演示测试 `tools/audit/r81_uci_findings.rs` 已删除，改为 crate 集成测试
`components/uci/tests/libuci_fidelity.rs`（15 例）。F26 的三项断言加进既有门
`tools/r1_candidate_check.py`（f07/f08/f09，并把 f03/f05 改写成“继续本轮”/“等锁”）。

历史验证二进制（非最终产物；`cargo +1.98.1 build --release --bins --examples --target aarch64-unknown-linux-musl`，
构建路径 `/home/ubuntu/r81-uci2`）：

| 二进制 | 字节 | md5 | sha256 |
|---|---|---|---|
| `uci-rs` | 528496 | `c0b61397faf2ed5e4ca4b8b0ef1a0464` | `16ba2cbf0dfe282cb9c90b9bc5780708d57bbe3041253f8c4c7cce5f4f9d5ee7` |
| `reload-config-rs` | 528544 | `1e910c291ef79a1a26dd10f231a99238` | `a8f8f4be4130be41a50257ebc7dde638a629d8cd67176b88cc343f1eb7289426` |

红证基线（R81 提交 `a903721`，`git worktree` → `oracle:~/r81-uci-base`）：
`uci-rs` md5 `f3e0f406f8fda0b678c4655d791360a2`、`reload-config-rs` md5 `bac8e1717dfdcc0ab880530fc6de91e1`
（两者原生 musl 构建字节数与当时的候选相同）。

## 结论一览

| 项 | 判定 | 修在 |
|---|---|---|
| F25-1 匿名段改成不同长度类型仍匿名 | **成立** | `ops.rs::set` |
| F25-2 `delete p.s.o=` 空索引被拒退 1 | **成立** | `bin/uci-rs.rs::uci_do_section`（`CliCmd::Del`）+ `ops.rs::delete` |
| F25-3 长行内 NUL 截断后粘下一行 | **成立** | `parse.rs::Pctx::{fgets,getln}` |
| F25-4a batch 解析错误缺 `(reason) at line N, byte B` | **成立** | `parse.rs::Pctx::{carry,restore}` + `bin/uci-rs.rs::batch_cmd` |
| F25-4b `add_list p.s=v` 被拒 INVAL | **成立** | `ops.rs::add_list` + `delta.rs::parse_delta_tuple` |
| F25-4c 非 UTF-8 tuple 错误码/顺序不同 | **成立** | `ops.rs::{parse_ptr,validate_bytes}` |
| F25-4d `rename` 到非 UTF-8 名被拒 | **成立** | `ops.rs::rename` |
| F25-4e 扩展索引与 strtol/int 截断不同 | **成立** | `ops.rs::{lookup_ext_section,strtol}` |
| F25-4e′ 改写后 strtol 丢了 `\v` | **本轮新引入，已修** | `ops.rs::strtol::is_c_space` |
| F25-5 delta/commit 逐 token `write(2)` | **成立** | `delta.rs::{save,filter_delta}`、`file.rs::commit` |
| F26-1 子进程超时使整轮提前返回 | **成立** | `engine.rs::{normalize,dispatch}` |
| F26-2 并发调用直接退 75 | **成立**（修法与原脚本不同，见下） | `engine.rs::RunLock::acquire` + `unix.rs::lock` |
| F26-3 输入限制 fail-closed | **成立** | `engine.rs::{scan_config_names,md5_all,read_baseline,write_baseline,dispatch}` |

---

## F25 — uci

### F25-1 匿名段改成不同长度的类型

**判定：成立。** C（`list.c` `uci_set`，更新 section 分支）：

```c
if (strlen(ptr->s->type) == strlen(ptr->value)) {
        strcpy(ptr->s->type, ptr->value);
} else {
        struct uci_section *old = ptr->s;
        ptr->s = uci_alloc_section(ptr->p, ptr->value, old->e.name, &old->e.list);
```

而 `uci_alloc_section` 只在名字为空时才置匿名：

```c
if (name && !name[0])
        name = NULL;
...
if (name == NULL)
        s->anonymous = true;
```

`uci_fixup_section` 已给每个匿名段派了 `cfgXXXXXX`，所以等长改类型保持匿名、不等长改类型**变具名**。
`n_section` 由 `alloc` 加一、`uci_set` 末尾 `n_section--` 抵消，净不变。

修在 `ops.rs::set`：`if s.ty.len() != value.len() && !s.name.is_empty() { s.anonymous = false; }`。

证据（`r83_uci_findings.sh` 步 `retype_*`，红证基线）：

```
retype_show   C: t.cfg010f15=interface           R81: t.@interface[0]=interface
retype_file   C: config interface 'cfg010f15'    R81: config interface
retype_delta  C: t.cfg010f15='interface'（两侧一致，delta 用的是 ptr->section）
```

`rsame_*`（等长 `device`→`bridge`）与 `rnamed_*`（本来具名）两个对照两侧一致，说明只有不等长这一支变。

### F25-2 `uci delete p.s.o=`（空/空白索引）

**判定：成立。** 两层判定都不是“必须是数字”：

```c
/* cli.c:523-524 */
case CMD_DEL:
        if (ptr.value && !sscanf(ptr.value, "%d", &dummy))
                return 1;
/* list.c uci_delete */
if (ptr->o && ptr->o->type == UCI_TYPE_LIST && ptr->value && *ptr->value) {
        if (!sscanf(ptr->value, "%d", &index))
                return 1;
```

* 空值：`*ptr->value == 0`，根本进不了列表分支 → 走整选项删除，rc 0。
* 全空白值：`sscanf` 返回 EOF（-1，C 里为真），**不**被 `!sscanf` 拒，然后拿未初始化的 `index` 走列表。

修在 `bin/uci-rs.rs`（`ops::sscanf_int_no_match` 只在 sscanf 返回 0 时为真）与 `ops.rs::delete`
（`sscanf_int_bytes`）。证据：

```
del_empty_str  rc  C: 0      R81: 1（stderr 无 → "uci: ..." 无）
del_show1          C: t.@rule[0].l='a' 'b'（opt 已删）
                   R81: t.@rule[0].opt='v' 还在
del_delta / del_file / del_show2 同步不同
```

`delv_*` 14 个索引值（` ` `abc` `-` `+` `-x` `x1` `  1` `0x1` `1abc` `0` `2` `2147483648`
`99999999999999999999999` `-1`）逐个比对，其中 `delv_d784fa8b`（值为单个空格）在基线上 rc 1、
候选与 C 一致 rc 0。

### F25-3 长行内 NUL

**判定：成立。** C（`file.c` `uci_getln`，`LINEBUF 32`）：

```c
p = &pctx->buf[ofs];
p[0] = 0;
p = fgets(p, pctx->bufsz - ofs, pctx->file);
if (!p || !*p)
        return;
ofs += strlen(p);
pctx->buf_filled = ofs;
if (pctx->buf[ofs - 1] == '\n') { pctx->line++; return; }
pctx->bufsz *= 2;
```

也就是：NUL 只吃掉“它到本 chunk 末尾”这一段，行仍在自己的 `\n` 处结束；chunk 首字节即 NUL 时
（`!*p`）行就地结束且不计入。R81 的 `read_until(b'\n')` 是整行读，NUL 截断后把下一行粘上来。

修在 `parse.rs`：新增 `Pctx::fgets`（按 `bufsz - ofs` 分块、遇 `\n` 停）与 `bufsz` 字段，`getln`
按 C 的 `ofs`/倍增循环重写。证据（`nul_a_*`，40 个 `a` + NUL + 30 个 `b`）：

```
nul_a_get     C: 59         R81: 0 + "uci: Parse error (EOF with unterminated ') at line 2, byte 64"
nul_a_show    C: t.@a[0].o='aaaa…（40a+19b，共 59）'  R81: 空（整文件丢）
```

`nul_{a..j}` 十组长度组合（跨 31/32/62/63 边界）加 `nul_start`、`nul_multi` 共 30 步，基线上 21 步不同。

### F25-4 batch / add_list / 非 UTF-8 / 扩展索引

**判定：全部成立。**

**(a) batch 错误后缀。** `libuci.c` `uci_get_errorstr`：

```c
if (ctx && ctx->pctx && (err == UCI_ERR_PARSE)) {
        snprintf(error_info, sizeof(error_info) - 1, " (%s) at line %d, byte %zu",
                 (ctx->pctx->reason ? ctx->pctx->reason : "unknown"),
                 ctx->pctx->line, ctx->pctx->byte);
}
```

而 `file.c` `uci_parse_argument` 让 `ctx->pctx` 在同一 stream 上跨命令**存活**：

```c
if (ctx->pctx && (ctx->pctx->file != stream))
        uci_cleanup(ctx);
if (!ctx->pctx)
        uci_alloc_parse_context(ctx);
```

于是 batch 里每条命令自身抛的 `UCI_ERR_PARSE` 都带 batch 的行号；一旦某条命令解析了文件
（`uci_import` 开头 `uci_cleanup` + `uci_alloc_parse_context`，末尾再 cleanup），下一条从 1 重新计。

修在 `parse.rs::Pctx::{carry,restore}` + `bin/uci-rs.rs` 的 `batch_carry`（命令跑完若
`ctx.pctx` 已不是自己那份就丢弃 carry）。证据：

```
b_lines   C: line 1 / line 2 / line 3 三条带后缀
          R81: 三条裸 "uci: Parse error" + 多余空行
b_parse / b_two / b_mixed / b_blanks / b_afterload / b_afterfail / b_afternf
b_afterimport(S)  C: 文件解析失败后下一条仍是 "at line 1, byte 0"
                  R81: 把文件的 "(EOF with unterminated ') at line 2, byte 24" 漏出来
b_nonbatch（非 batch 模式）两侧一致无后缀 —— 对照
```

**(b) `add_list p.s=v`（无 option 段）。** `list.c` `uci_add_list` 只断言 `ptr->s` 与 `ptr->value`，
`uci_alloc_list(ptr->s, ptr->option, NULL)` 接受 `NULL` 名字；`delta.c` `uci_delta_save`：

```c
fprintf(f, "%s%s.%s", prefix, name, h->section);
if (e->name)
        fprintf(f, ".%s", e->name);
```

所以 C 成功（rc 0）并写出一条没有 option 的 delta 行，下一次加载时 `uci_parse_delta_tuple` 才拒。
修在 `ops.rs::add_list`（`option: Option<String>`）与 `delta.rs::parse_delta_tuple`。证据：

```
al_add    rc C: 0   R81: 1 + "uci: Invalid argument"
al_delta      C: |t.cfg0192bd='x'    R81: 文件不存在
al_show / al_commit / al_file / al_batch 两侧此后一致（delta 行加载时被拒，痕迹不进模型）
alo_*（正常带 option 形式）对照一致
```

**(c) 非 UTF-8 tuple。** C 的 `uci_parse_ptr` 是逐段 `strsep` + 各自的 validator，非 UTF-8 只会
让对应段的 validator 失败，不是整个 tuple 先失败。`parse_ptr` 改成按字节 strsep +
`validate_bytes`，section 段非 UTF-8 时打 `LOOKUP_EXTENDED`（之后必然在
`uci_lookup_ext_section` 的 `section[0] != '@'` 上失败）。证据：

```
tup_pkg  C: "uci: Parse error"       R81: "uci: Invalid argument"
tup_opt / tup_4 同类
tup_sec / tup_val / tup_ctl 两侧一致 —— 对照
```

**(d) `rename` 到非 UTF-8 名。** `list.c` `uci_rename` 对新名**零校验**：

```c
n = uci_strdup(ctx, ptr->value);
free(e->name);
e->name = n;
if (e->type == UCI_TYPE_SECTION)
        uci_to_section(e)->anonymous = false;
```

（`uci_parse_ptr` 只对 value 跑过 `uci_validate_text`。）修在 `ops.rs::rename`（`from_utf8_lossy`
入模型，delta 逐字节写出，加载时由 `uci_parse_delta_tuple` 的 `uci_validate_name` 拒）。证据：

```
ren_do    rc C: 0   R81: 1 + "uci: Invalid argument"
ren_delta     C: 42 B / md5 21e2…  R81: 文件不存在
ren_commit / ren_file 同步；renok_*（正常名）对照一致
```

**(e) 扩展索引。** `list.c` `uci_lookup_ext_section` 里 `idx` 是 **int**：

```c
int idx, c;
...
idx = strtol(idxstr, &t, 10);
if (t && *t)
        goto error;
```

所以 `strtol` 的 long 结果被截成 int：`4294967296` → 0、`99999999999999999999999` →
`(int)LONG_MAX` = -1、`-99999999999999999999999` → `(int)LONG_MIN` = 0；`""` 因 `end == s`、
`*end == 0` 合法且为 0，而 `" "`、`"-"`、`"1 "` 都留下垃圾字节 → `UCI_ERR_INVAL`。
修在 `ops.rs::lookup_ext_section`（`v as i32 as i64`）与重写的 `ops.rs::strtol`（溢出钳到
LONG_MIN/LONG_MAX、无转换时 `end == s`）。证据：

```
rext_show   C: t.cfg01b606=zz / t.cfg01b606.k='zero'（@a[4294967296] 命中第 0 段并改了类型）
            R81: t.@a[0]=a / t.@a[0].k='zero'（原样不动）
rext_export、retype_ext/save/t 同步；ext_* 24 个索引里 7 个在基线上不同
```

**(e′) 本轮新引入的回归（我修的）。** 重写把原来显式的
`trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c'])` 换成了
`u8::is_ascii_whitespace`，而后者**不含垂直制表符 `\v`**，C 的 `isspace()` 含。在 rootfs 上直接问 C：

```
esc=011 one  rc=0   esc=013 one  rc=0   esc=014 one  rc=0   esc=015 one  rc=0   esc=040 one  rc=0
```

候选（未修时）`esc=013` → `uci-rs: Invalid argument` rc=1。这是 R81 基线**本来正确**、被本轮改写
弄坏的一处，已最小修回（`ops.rs::strtol` 内联 `is_c_space`），并补了门里的 `extws_011/012/013/014/015/040`
六步与 `libuci_fidelity.rs::ext_index_parsing_matches_strtol_into_int` 的四个用例。
`sscanf_int*` 不受影响：`\v` 过不了 `uci_validate_text`，两侧都在 value 校验就报 Parse error。

### F25-5 delta / commit 的逐 token `write(2)`

**判定：成立。** C 全程走 stdio `FILE*`（`delta.c` `uci_delta_save` 每个 token 一个 `fprintf`、
每个被转义字节一个 `fputc`；`file.c` `uci_commit` 里 `uci_export` 之后才 `fflush`/`fsync`），
Rust 写的是裸 `File`。修在 `delta.rs::save`、`delta.rs::filter_delta`、`file.rs::commit` 三处套
`BufWriter`（`save` 里 flush 失败改为 `Err(Error::Io)`）。

在 oracle（aarch64，musl 静态二进制可直接跑）用 `strace -c -e trace=write` 实测：

| 操作 | R81 基线 | 候选 |
|---|---|---|
| 一次 `uci set`（写 delta） | 10 次 `write` | **1 次** |
| 200 个 option 的包 `uci commit` | 1207 次 `write` | **1 次** |

---

## F26 — reload-config

原脚本全文（rootfs `/sbin/reload_config`，17 行）是唯一裁判，关键三行：

```sh
for config in /var/run/uci/* /etc/config/*; do
	[ -f "$config" ] || continue
	...
	uci show "$file" > /var/run/config.check/$file 2>/dev/null
...
		ubus call service event "{ \"type\": \"config.change\", \"data\": { \"package\": \"$(basename $c)\" }}"
...
md5sum /var/run/config.check/* > $MD5FILE
```

### F26-1 子进程超时使整轮提前返回

**判定：成立。** 脚本**没有任何超时**，只是一直等。在一次性 rootfs 里跑真脚本（慢 `ubus` 适配器
`sleep:3`）：

```
SHELL slow-ubus run: 3.1s exit 0 events ['alpha']
```

即：慢子进程既不中断本轮，也不影响基线重写（合同 C-08）。R81 的
`WaitResult::TimedOut => Err(Error::Timeout(..))` 让 `run()` 提前返回，后续包无事件、基线不写，
下一轮把已送达的事件重发。修在 `engine.rs::normalize`（超时记 `"timeout"` 状态后继续，被杀子进程
的部分输出照哈希）与 `engine.rs::dispatch`（`Delivery::Timeout` 计一次失败后继续）。
`Error::Timeout` 仍保留给取消路径。

**残留差异（有意）**：Rust 到 `--timeout-ms` 会**杀掉**子进程并哈希半成品，脚本会等它写完。
代码注释里写明了。

### F26-2 并发调用

**判定：成立**（修法与原脚本不同，已在 README 写明）。脚本里**没有锁**：两轮并发会共用并互删
`/var/run/config.check`、事件重复派发、基线归谁的 `md5sum` 先写完。R81 的 `flock(LOCK_EX|LOCK_NB)`
失败即退 75、什么都不做，于是第二个调用者提交的包要等到第三轮才被发现——这是比脚本更糟的一档。
修在 `engine.rs::RunLock::acquire` 改为阻塞取锁（`unix.rs::lock`，`LOCK_EX` + EINTR 重试），
`Error::ConcurrentRun` 与 `unix::try_lock` 一并删除。既有门 f05 改名
`f05-concurrent-run-waits-for-the-lock`。

### F26-3 输入限制 fail-closed

**判定：成立。** 脚本对 `/etc/config/*` 只有 `[ -f ]` 一个条件，不看大小也不看编码，
`md5sum … > $MD5FILE` 逐字节写路径。在一次性 rootfs 里跑真脚本，放一个 1,440,017 B 的
`/etc/config/big`、一个文件名为 `\xff\xfe` 的包和一个 `with space`：

```
SHELL baseline after first run (/var/run/config.md5):
    7ed40f38a373264a4dde76313d8fa161  /var/run/config.check/alpha
    9ece37ade67be06c722513dd2c9b1c6e  /var/run/config.check/big
    d41d8cd98f00b204e9800998ecf8427e  /var/run/config.check/with space
    d41d8cd98f00b204e9800998ecf8427e  /var/run/config.check/\xff\xfe
big source bytes: 1440017
SHELL second run exit 0 events ['alpha']
```

（后两条是空摘要——`uci show` 对这种名字失败，脚本照记条目继续。）R81 对同一输入整轮退 64、
零派发。修在 `engine.rs`：删掉 `MAX_CONFIG_SOURCE_BYTES` / `MAX_NORMALIZED_BYTES` 与文件名
UTF-8/控制字符检查，`scan_config_names`/`md5_all`/`read_baseline`/`write_baseline`/`dispatch`
全程 `OsString`/字节，`md5sum -c` 式跳过读不懂的行而不是报错，`MAX_COMMAND_OUTPUT_BYTES`
改成与基线同一预算。ubus payload 用 `json_escape_bytes` 逐字节转义后以 `OsStr` 交 execve。

---

## 门与决定性输出

### `tools/r83_uci_findings.sh`（新，F25 全项）

早期候选（md5 `c0b61397faf2ed5e4ca4b8b0ef1a0464`）连跑 3 次；最终复跑同样通过：

```
identical /tmp/out  (498 files)
identical /tmp/scratch  (56 files)
R83 PASS (554 files compared)
```

红证（R81 基线 md5 `f3e0f406f8fda0b678c4655d791360a2`，同一门）：

```
R83 FAIL (see /tmp/r83-base2/*.diff)
112 个文件不同，覆盖 59 个步骤：
al_add al_batch al_delta al_delta2 b_afterfail b_afterimport b_afterimportS b_afterload
b_afternf b_blanks b_lines b_mixed b_parse b_two del_delta del_empty_list del_empty_str
del_file del_show1 del_show2 delv_d784fa8b_del ext_×7 nul_×21 ren_delta ren_do
retype_export retype_file retype_show retype_show2 rext_export rext_show tup_4 tup_opt tup_pkg
```

`extws_*`（F25-4e′）在基线上**不**报差异——正是因为那处是本轮改坏的。

### 既有 uci 门

```
tools/r16_uci_check.py   →  175 steps: 175 identical, 0 differ
tools/r24_uci_fuzz.py    →  最终复跑 cases=200 differing=0（早期 seed 8310 的 300 例也通过）
```

### 既有 reload-config 门 `tools/r1_candidate_check.py`

最终候选通过整个门：11 个参考场景 + 9 个故障场景，`gate_passed=true`，大小门也通过：

```
ref  c01…c11                                                    全 True
flt  f01-partial-delivery-is-visible-and-absorbed                True
flt  f02-missing-uci-is-visible-and-preserves-baseline           True
flt  f03-hung-delivery-is-a-failure-and-the-round-continues      True
flt  f04-malformed-uci-remains-compatible-but-visible            True
flt  f05-concurrent-run-waits-for-the-lock                       True
flt  f06-sigterm-cancels-with-retryable-baseline                 True
f26  f07-oversized-config-source-is-dispatched-like-the-shell    True
f26  f08-non-utf8-config-filename-is-dispatched-like-the-shell   True
f26  f09-killed-uci-show-does-not-abort-the-round                True
```

红证（R81 基线 `bac8e1717dfdcc0ab880530fc6de91e1`，同一门）：

```
PROBLEMS ['f03-hung-delivery-is-a-failure-and-the-round-continues',
          'f05-concurrent-run-waits-for-the-lock',
          'f07-oversized-config-source-is-dispatched-like-the-shell',
          'f08-non-utf8-config-filename-is-dispatched-like-the-shell',
          'f09-killed-uci-show-does-not-abort-the-round']
```

f07/f08/f09 都是把候选与**真脚本**（`r1_reference_oracle.run_exact`）跑同一棵准备好的树，比事件序列
与 `/var/run/config.md5` 的字节。

### 单元 / clippy（oracle，toolchain 1.98.1）

```
components/uci:            4 + 0 + 15 + 0 passed, 0 failed；clippy --all-targets -D warnings 干净
components/reload-config:  9 passed, 0 failed；clippy --all-targets -D warnings 干净
```

---

## 遗留

1. 原生 musl 构建为 528544 B，曾超过 512 KiB 门限；这是链接页对齐造成的，不需要调高预算。
   使用现有 OpenWrt 包的 `-z max-page-size=4096` 等链接参数后为 **491592 B**，全部 20 个行为用例
   与大小门通过。参数、产物路径和摘要见 [validation.md](validation.md)。
2. `add_list p.s=v` 时 Rust 把 option 名记成 `""`，C 是 `e->name == NULL`。目前**不可观测**
   （delta 行下次加载即被拒；同进程内 `uci show` 会重新 load 从而丢掉内存里那条），两个门都逐字节
   一致，但不是字面等价。
3. `delete p.s.list=<全空白>` 时 C 读的是**未初始化**的 `index`（`list.c` 那支 `sscanf` 返回 EOF
   仍继续）。门里 `delv_d784fa8b` 会比它，3 次连跑稳定，但这一格的“C 行为”本质是 UB。
4. `uci_import` 的 `while (!feof(pctx->file))` 与 Rust 的 `while !pctx.eof` 语义不完全同（feof
   要先读到 EOF 才置位）；本轮未动，既有门未暴露差异。
5. `tools/audit/r81_uci_findings.rs` 已删除（内容并入 `components/uci/tests/libuci_fidelity.rs`）。

最终构建摘要见 [validation.md](validation.md)。未将二进制、rootfs 或原始差分记录纳入 Git。
