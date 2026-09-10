# R83 — logd-rs：R81 发现 F15、F16

日期 2026-09-10。范围：`components/logd`（logd-rs，设备在跑）。**未触碰路由器。**

参照 C（唯一裁判）：上游 ubox `6f78fa496bf36c55864a41e353df7d13f04b1077`（合同 `docs/contracts/logd.md` 钉的
提交），克隆到 `oracle:~/r81-logd-ubox/ubox`，读 `log/syslog.c`、`log/logd.c`；
libubus 重连语义读 `oracle:/home/ubuntu/stage9/ubus/{libubus.c,libubus-io.c}`。

差分环境：
* **C 算法 oracle**：`oracle:~/r81-logd-ubox/harness/c_oracle.c` —— `log_next`（syslog.c:87-93）、
  `log_add`（146-219）、`log_list`（304-325）**逐字节 sed 抽取**，只把 udebug / ubus 钩子打桩，
  外加一个读 `S <cap>` / `A <msg>` / `L` 脚本的驱动；同一脚本喂给 Rust `Ring`
  （`oracle:~/r81-logd-scratch-{fixed,orig}`，用 `#[path]` 直接 include 仓库里的 `ring.rs`）。
* **端到端**：exact rootfs `~/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`
  的一次性副本，镜像自带 `/sbin/ubusd`、`/sbin/logd`、`/bin/ubus`、`/usr/sbin/logread`，
  每侧独立 mount namespace + chroot（沙箱里**不挂 /proc**，于是 C logd 找不到 `/proc/kmsg`，
  与候选的 `--kmsg none` 一样无内核输入，两侧环形缓冲区输入完全相同）。

新增门：`tools/r83_logd_ring_wrap.sh`（F16 混长差分）、`tools/r83_logd_oversize_read.sh`（F15 本地错误）。
R81 演示测试 `tools/audit/r81_logd_ring_wrap.rs` 已并入 crate 单元测试并删除。
**未改动 `components/ubus`**（含 `conn.rs`）——F15 全部修在 logd 内。

## 结论一览

| 项 | 判定 | 修在 |
|---|---|---|
| F15 重连不关旧连接 → `log` 永远注册不上 | **成立** | `main.rs:318-330` `reconnect()` 先 shutdown 旧 socket |
| F15 本地 >1 MiB 回复被当断线 | **成立** | `main.rs:237-246` 改回单请求 STATUS |
| F15 附带：`socketpair` 失败（EMFILE）同样当断线 | **成立**（同类，报告 §F15 提及） | `main.rs:195-209` 单请求 STATUS |
| F16 回绕分支只按队首驱逐 | **成立** | `ring.rs:71-88` `retain(offset > next0 && offset < sentinel)` |

发布二进制：`oracle:~/r81-logd/components/logd/target/aarch64-unknown-linux-musl/release/logd-rs`
md5 **`4ead61417b77e5edd054d37e566d9e42`**，sha256 `17e16164ea79439eb871edc39d9b394942f70917358d3dcdb543e1b7f7d5a772`，
462880 字节（`cargo +1.98.1 build --release --bins --examples --target aarch64-unknown-linux-musl`，构建路径 `/home/ubuntu/r81-logd`）。

---

## F15 — 重连时旧连接还开着，ubusd 拒绝重复注册 `log`

**判定：成立**（机制与后果都复现）。

### 证据（读码）

* Rust（R81 基线）：`reconnect()` 先 `Connection::connect()`、再 `register_log()`，只有成功才
  `self.conn = conn`；旧 `Connection` 整个过程都活着。ubusd 对已占用的 path 直接拒：
  `components/ubusd/src/server.rs` 的 `add_object()`（路径已被占用时 `set_path` 失败 →
  `destroy(id)` + `INVALID_ARGUMENT`；该文件本轮被另一线程并发修改，故不钉行号）。
* C：`ubus_reconnect()` **先关旧 fd 再连**（`libubus-io.c:421-426`），HELLO 后
  `ubus_refresh_state(ctx)`（460 行）重新注册对象；`ubus_auto_reconnect_cb`
  （`libubus.c:395-403`）失败才 1 Hz 重试。C logd 的 connect handler 在 `ubus_add_object`
  失败时 `exit(1)`（`logd.c:231-240`，`main` 在 264-265 装的就是它），交给 procd 重启——两条路都不会“连上但没有对象”。
* 触发面：libubus 客户端侧**没有** MAX_MSGLEN 检查（`ubus_send_msg`，`libubus-io.c:126-152`
  直接 writev），1 MiB 上限是我们自己的（`components/ubus/src/conn.rs:113-116`）。
  也就是说 C 会把超大回复交给 ubusd 由请求本身失败，Rust 却在本地把它变成 `Err` 一路
  unwind 到 `reconnect()`。

### 复现（`tools/r83_logd_oversize_read.sh`，只把 `main.rs` 换回 R81 基线，md5 `1c68cbedbb8d64afb94831c2f5aa1748`）

`-S 1100` 的环填满（1250 条 ~985 B）后 `ubus call log read '{"stream":false}'`：

| 观测 | C `/sbin/logd` | R81 基线 logd-rs | 修后 logd-rs |
|---|---|---|---|
| 超大 read 的 rc | 7（TIMEOUT，ubusd 让请求失败） | 7（超时，logd 根本没回） | **2（INVALID_ARGUMENT，单请求）** |
| 之后 `ubus list` 有 `log` | 1 | 1（陈旧客户端还占着 path） | 1 |
| 之后 `log write` rc | 0 | **249（ubus CLI 超时）** | 0 |
| 之后 read 能看到新记录 | 1 | **0** | 1 |
| `logread -l 5` 能看到新记录 | 1 | **0**（无人服务，logread 阻塞到超时） | 1 |
| logd stderr | `log: connected to ubus` | **1 Hz 刷 `failed to add object: ubus: Invalid argument (2)`（约 5 分钟 19 KB）** | `log read reply not sent: ubus: Invalid argument (2)` 一行 |

即 F15 描述的后果成立，且比“对象消失”更难查：`ubus list` 仍列出 `log`，每次调用超时。

### 修法（三处，全在 `components/logd/src/main.rs`）

1. `reconnect()`（318-330）：进重试循环前，借 `ManuallyDrop<UnixStream>` 对
   `self.conn.as_raw_fd()` 做 `shutdown(Both)`，等价于 C `ubus_reconnect()` 的先 close；
   ubusd 看到 EOF 拆掉陈旧客户端并释放 `log`，随后的 `add_object` 才可能成功
   （仍失败就照 C 的 1 Hz 重试，下一轮必然成功）。`self.conn` 在赋新连接时真正关闭 fd。
2. `handle_read()` 非 stream 分支（237-246）：`reply_data` 失败时改发
   `STATUS INVALID_ARGUMENT`；只有连状态回复都失败（socket 真死）才向上 `Err` → 重连。
3. `handle_read()` stream 分支（195-209）：`socketpair()` / `set_nonblocking()` 失败
   （EMFILE）改发 `STATUS UNKNOWN_ERROR`，对应 C `pipe()` 失败时 handler `return -1`
   的单请求失败（`logd.c:125-128`），不再当断线。

### 门

`tools/r83_logd_oversize_read.sh`：填满 → 超大 read → 断言两侧**都还在服务**
（`ubus list` 有 `log`、`log write` rc 0、read 能取回新记录、`logread -l 5` 能看到、守护进程活着），
并且断言环真的填满（`filled=3`）且超大 read 真的失败（`oversize_rc != 0`）——否则判红说“什么都没证明”。

* 修后：**绿**（exit 0）——C 侧 `oversize_rc=7`，rs 侧 `oversize_rc=2`，两侧 `filled=3 still_listed=1 write_rc=0 marker_read=1 logread_marker=1 daemon_alive=1`。
* R81 基线二进制：**RED_PLACEHOLDER**

---

## F16 — 回绕分支只按队首 offset 驱逐，被覆盖的旧记录仍被 `read` 返回

**判定：成立**，并且比报告写的还多一层：C 在回绕时还会丢掉**哨兵以上**的整段尾巴。

### C 的真实语义（syslog.c:195-206 + 304-325）

```c
next = log_next(newest, size);
if (next > newest) { while ((oldest > newest) && (oldest <= next) && (oldest != log))
                         oldest = log_next(oldest, oldest->size); }
else { newest->size = 0;                       /* 旧写入位变成 size==0 哨兵 */
       next = log_next(log, size);
       for (oldest = log; oldest <= next; oldest = log_next(oldest, oldest->size)) ;
       newest = log; }
```
`log_list` 走链时 `if (!h->size && (h > newest)) h = log;`——从哨兵直接跳回起点。
所以一次回绕丢两组：**(a)** 新记录覆盖掉的（`offset <= next0`）、**(b)** 哨兵到 arena 末尾的
全部记录（链上再也走不到）。R81 基线只从队首弹，回绕后队首恰是上一圈的高 offset 尾巴，
`front.offset <= next0` 立刻不成立 → **一条都不驱逐**。

### 修法

`ring.rs:71-88`：`let next0 = log_next(0, size); let sentinel = self.newest;`
`entries.retain(|e| e.offset > next0 && e.offset < sentinel)`。非回绕分支不用改：修好回绕后
“队首就是物理上 `newest` 之后的第一条”的不变量恢复，队首弹出与 C 的 `oldest` 前进等价
（C 多出的 `oldest != log` 判断在 offset 0 时 `offset > newest` 已为假，等价）。

### 验证 1：与逐字节抽取的 C 算法逐条比对（每次 add 后 dump 保留集）

| 容量 | 单条上限 | seed | 规模 | 修后与 C 不同 | R81 基线与 C 不同 |
|---|---|---|---|---|---|
| 64 KiB | 1000 B | 3 | 111 个 dump | **0 个 dump** | 0 |
| 64 KiB | 1000 B | 8 | 168 个 dump | **0 个 dump** | 0 |
| 32 KiB | 1000 B | 9 | 173 个 dump | **0 个 dump** | 27 个 dump |
| 16 KiB | 1000 B | 7 | 168 个 dump | **0 个 dump** | 140 个 dump |
| 16 KiB | 200 B | 5 | 18933 行 | **0 行** | 4545 行 |
| 4 KiB | 1000 B | 1 | 121 个 dump | 2 个 dump（见下） | 107 个 dump |

（消息不含空格、不以 `<` 开头，`log_add` 的优先级/时间戳剥离是恒等变换，只比环算术。）

### 验证 1 的残余差异 —— C 在小环/长行区间读越界，**故意不复刻**

单条记录占环的比例够大时（≲8 KiB 环配 ~1 KiB 行），C 的驱逐 for 循环会走过哨兵，
`oldest` 落在**从没写过或已被覆盖**的槽上，`log_list` 于是返回伪造记录：
`E 0 4000 0 ||`（calloc 的零槽，id 0、空正文）、`E 2021161080 |…|`（id 是 `xxx` 的字节），
以及正文越过 arena 末端——harness 里有一条记录把**我自己之前的标准输出**读了回来
（同一份输出里出现 6 条重复的 `L end #k`，即 C 越界读到了 glibc 的 stdout 缓冲）。
上表 4 KiB seed 1 的 2 个 dump 全部属于此类（C 自己在该 dump 里就吐了伪造记录）；
4 KiB/8 KiB 配 1000 B 行时 C 的输出已无法逐条配对。
logd-rs 不复刻 C 的陈旧内存读——这会把垃圾行灌进 `logread`。
**设备实际口径是 `-S 64`**（`/etc/init.d/log:32-40`：`log_buffer_size` 缺省 64，rootfs 里
`/etc/config/system` 未设 `log_size`），单条 ≤1024 B，正落在上表“0 差异”的 64 KiB 区间
（两个 seed 共 279 个 dump 全等）；小环区间只在把 `-S` 手工调到 ≤8 KiB 时才会遇到。

### 验证 2：端到端混长差分（`tools/r83_logd_ring_wrap.sh`）

镜像自带 `/sbin/logd -S 4` vs `logd-rs -S 4 --kmsg none`，同一串 320 条记录
（每 17 条一条 ~900 B、每 17k+3 一条 ~300 B，其余 20-120 B），比
`ubus call log read {"stream":false}` 逐条 `id|source|msg`（内核记录剔除、时间不比）与 `logread`：

* 修后（就是发布的那份二进制 md5 `4ead6141…`）：exit 0，`read-all` **27 条记录逐条相同（含 id 与正文）**、`read-5` 5 条相同、`logread` 27 行相同。
* 只把 `ring.rs` 换回 R81 基线（其余同本轮，md5 `63518497e484708665db5dad5fb1172a`）
  **3/3 次判红且输出一致**：
  C 保留 27 条，候选保留 **68** 条——多出 id 252-261 等 C 早已驱逐的记录，
  保留量约 `-S` 上限的 2.5 倍。

### 验证 3：单元测试（`components/logd/src/ring.rs`）

* `wrap_with_abandoned_tail_entry_drops_overwritten_records`、
  `mixed_sizes_never_retain_more_than_capacity`：R81 演示测试原样并入（256 B 环那例
  C 自己会吐伪造记录，故断言的是不变量：被覆盖的 id 不得再列出、保留字节 ≤ 容量）。
* `retention_matches_the_c_oracle_on_mixed_lengths`：**C golden**——2 KiB 环、35 条
  （每 7 条一条 200 B，其余 60 B），C 保留 id 21..=34；R81 基线额外留下 17..=20。
* 红证：把 `add()` 的回绕分支换回 R81 基线的只弹队首循环（`oracle:~/r81-logd-redproof`），
  三条测试**全部 FAILED**，其余两条仍 ok；换回修后代码 5/5 ok。

---

## 复跑的既有门

| 门 | 结果 |
|---|---|
| `tools/r15_logd_check.py`（exact rootfs 差分） | `status=complete`，10/10 输出 identical |
| `tools/r28_logd_fuzz.py`（畸形输入 fuzz） | `outputs=33 differing=0` |
| `tools/r21_logd_reconnect_check.sh`（ubusd 重启，直接覆盖本轮 `reconnect()` 改动） | `reregistered_after_s: 2`、`objects: log`、`read2_before/during/after: 1 1 1`、`logd_alive: yes` |
| `cargo test` | 5/5 通过 |
| `cargo clippy --all-targets -- -D warnings` | 干净 |
| `cargo fmt --check` | 3 处 diff，**全部是 R83 之前就有的**（`main.rs:219` reply_status 长行、`main.rs:449` `lookup_user`、`ring.rs:107` `list`）：在 R81 基线源码上跑同样 3 处；rustfmt 1.9.0-stable 与全仓风格不一致（ubus 7、ubusd 85、uci 37 处），非本轮回归。我自己新增的 2 处已按 rustfmt 调整 |

---

## 遗留

1. **C 在 `-S 1` + ~1 KiB 行时堆溢出**：`log_next(0, size)` 因 `32+PAD(size) >= capacity` 回 0，
   随后 `strcpy(newest->data, buf)` 在 1024 B 的 arena 上写 32+1001 B。未复现、未对齐——
   logd-rs 在该配置下只是保留集不同（不越界）。r15/r28 用 `-S 1` 但最长行 900 B，未触发。
2. **C 的伪造记录（陈旧/零槽）不复刻**，见 §F16；若要求逐字节一致，得把 `Ring` 改成真的
   字节 arena 并照抄陈旧读，代价是 `logread` 会输出垃圾行——建议不做。
3. F15 第 3 处修法（`socketpair` EMFILE）**没有门**：需要 fd 耗尽注入，本轮未做。
4. `read {stream:true}`（`logread` 走的路径）不受 1 MiB 限制（逐条帧走 socketpair），
   本轮未新增针对它的超大用例。
5. 未重建 APK / release-image，未上设备。

## 发布产物（补记，2026-09-10）

`cargo +1.98.1 build --release --bins --examples --target aarch64-unknown-linux-musl`，树 `oracle:~/r81-all`（与本提交同源）：
`components/logd/target/aarch64-unknown-linux-musl/release/logd-rs` md5 `52a7838c93420975eb8d8c349e757335`。
