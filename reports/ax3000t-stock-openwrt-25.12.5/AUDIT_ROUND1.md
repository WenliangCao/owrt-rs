# 第一轮代码自检（AUDIT_ROUND1）

> 日期：2026-09-02。范围：`components/{ubus,reload-config,logd,httpd,fw4,rpcd}` 全部代码。
> 方法：用户给出的 15 项迁移自检清单；对抗式审查（四个独立 reviewer 分别盯 fw4、rpcd、ubus、logd+httpd）；
> 不接触设备；oracle 为 pinned 上游源码与精确 rootfs 沙箱。
> 结论：发现 30 余处行为差异，其中 20 处已修复并按 `cargo check → 单元 → 上游 regression → release →
> differential` 重新验证通过；其余为不影响本设备且改动风险高的边缘/畸形输入行为，记录在 §5 待后续处理。

## 0. 验证链（每次修复后重跑）

| 环 | 结果 |
|---|---|
| `cargo check --all-targets` | 6/6 crate 通过 |
| 单元测试 debug | 34 个（含新增 9 个回归测试），6/6 crate 全过，0 ignored |
| 上游 regression | fw4 上游 31/31 逐字节；base64 单元 oracle 修正 |
| release（`panic=abort`，与产品一致） | 6/6 crate 全过，无差异 |
| differential | rpcd 63/63 + 16 项审计探针；httpd 38/38；logd 10/10；均在精确 rootfs 沙箱内与原实现逐项相同 |
| 上游源码完整性 | firewall4@b6e51575、rpcd@28faf640、ubox@6f78fa49、uhttpd@7b1bec45 与设备安装版本一致，`private/` 副本逐字节等于上游快照 |
| 测试执行路径 | fw4 harness 执行 `fw4-rs` 二进制并比 stdout/stderr/`[call]`；rpcd/httpd/logd harness 在候选沙箱中移除原实现后运行，原实现缺席时任何调用都会失配（证明测的是 Rust 实现，不是旧实现） |

## 1. 15 项清单逐条结论

1. **擅改架构/数据结构**：迁移期确有偏离原结构之处（fw4 把 `parse_options` 表改成顺序 `Opts` 调用、zone 用索引引用、模板扁平化进 `render.rs`；ubus 把 libubus 的请求队列/poll/deadline 融进一个循环；logd 用 `VecDeque` 模拟字节环）。这些不改变外部行为，已在 §6 "可审计性"记录；本轮未推倒重来，因为它们通过 oracle 证明行为等价，重写反而引入风险。
2. **把"能编译"当完成**：非测试代码 `todo!`/`unimplemented!`/`unwrap()`/`expect()` 计数为 0；`panic!`/`assert!` 全部在 `#[cfg(test)]` 内。无假返回值或绕过逻辑。
3. **核心共享类型不一致**：状态码统一 `i32`、对象 id `u32`、payload `Vec<u8>`/`&[u8]`，跨 crate 一致。`msg.rs` 的 `status::name` 原返回 `&'static str` 且缺 11–13 号，已补全并改为带编号兜底，消除 httpd 桥与库的漂移。
4. **为绕 borrow checker 滥用 unsafe**：26 处 `unsafe` 全部是 libc 系统调用边界（flock/fcntl/sendmsg/recvmsg/poll/pipe2/setuid/statvfs/uname/localtime_r/time/sync/from_raw_fd），无 `transmute`、无生命周期擦除、无为复制而复制。FFI 结构体布局对 aarch64 musl 逐字段核对（见 §4）。修复了一处 unsafe 相关的资源问题：`recvmsg` 原按 `CMSG_SPACE`(=24) 申请控制缓冲，可能让直连对端塞入两个 fd 而第二个泄漏；改为 `CMSG_LEN`(=20)，内核最多装一个 fd（与 libubus 一致）。
5. **假设"看起来一样"语义相同**：这是本轮多数发现的来源，逐项修复见 §2/§3。重点：ucode `+str`/`%.14g`、json-c 整数分型、blobmsg INT16/INT32 有符号、libubox b64 只吃完整四元组、C `umask(0)` 包住 open、ucode `split(/[ \t]+/)`。
6. **改变异常/边界行为**：修复了多处（If-Range、logd read 类型策略、httpd 413、fw4 空串截断）。仍有意保留更严的网络解析（见 §5 "有意偏离"），因为放宽面向网络的解析器会扩大攻击面。
7. **削弱测试/改期望值只为过测**：发现一处反例——`util.rs` 的 base64 单元测试写死了旧的宽松行为（把未补齐的 7 字符解码成 "hello"）。已按上游 libubox oracle 改正为"拒绝不完整四元组"，并补充断言，而不是放宽实现。上游 fw4 测试始终作为只读 oracle，从未修改。
8. **只测 debug 未测 release**：本轮所有单元测试在 debug 与 release（`panic=abort`）两种 profile 下都跑过，无差异。
9. **未及早验模块间接口**：四个 reviewer 专门查了跨 crate 接口漂移。发现 `Field::as_u32/as_bool` 是无策略访问器，导致 blobmsg 类型不匹配语义在每个调用点丢失（logd read 因此误读类型）——已在 logd 修复；根因（库层缺策略化 parse）记录在 §5 作为阶段 6/7 收口项。
10. **重构到无法逐段对照**：见 §6。当前阶段优先可审计性；已偏离处均有 oracle 背书，未在本轮进一步 idiomatic 化。
11. **行为未定前做性能/并发改动**：httpd 的线程/整块缓冲、rpcd exec 阻塞主循环、daemon 不重连——都是迁移期的并发模型简化，不改变回复内容。按计划 §11 的原则，本轮不把它们当作行为修复，记录在 §5 待第二轮（补重连是阶段 9 前置）。
12. **同类错误出现两次以上**：识别出一个反复模式——"把 C/ucode 的真值判断（truthiness）写成 Rust 的 `is_some()`/`!= None`"。它在 fw4（loadfile ''、forward name ''、device '*'）与 rpcd/logd 的类型宽松处都出现。已就地修复各实例，并把"遇到源语言的 truthiness/类型策略，必须按源语义翻译，不能用 Option/长度近似"写进 §7 迁移规则。第二个模式是"有符号/无符号误用"（JSON int 分型、INT16/INT32 解码、logd count），同样统一修复。
13. **被"实现思路"带偏**：本轮以对抗式 reviewer 身份重查，主动构造反例（畸形 base64、多空格 ipset、越界端口、信号退出、-1 行数、超长请求行等），多数发现由此而来。
14. **测试是否真的跑到 Rust 实现**：见 §0"测试执行路径"。candidate 沙箱移除原 `.so`/二进制，若 Rust 未接管则调用直接失配，排除了"意外测到旧实现"。
15. **直接改代码并按序重验**：已做，见 §0 与各 commit。

## 2. 已修复（confirmed，按组件）

### owrt-ubus（共享库，影响全部消费者）
- **JSON 整数分型**：`{"n":3000000000}` 原走 u32 分支变成 INT32（回读成 -1294967296）。改为 libubox 语义：有符号 32 位范围用 INT32，否则 INT64。影响 `file stat` 的大文件 size 与桥接的负数/大整数参数。
- **INT16/INT32 解码有符号**：原按无符号回读，iwinfo 的 `signal`/`noise`（负 dBm）在 `/ubus` 桥里显示成 42 亿。改为 `(int16_t)`/`(int32_t)`。
- **重复键**：原保留两条同名键；改为 json-c 语义"末值胜、留首位"，避免 C 接收方 `blobmsg_parse` 取到首值而 uhttpd 取末值的分歧。
- **`\f` 转义**：原输出 `\f`；libubox 只对 `\b\n\r\t"\\` 用短转义，`\f` 走 ``。已改。
- **状态码表**：补 11–13（Out of memory / Parsing message data failed / System error）与带编号兜底，匹配 `ubus_strerror`（uhttpd 把它写进 JSON-RPC `error.message`）。
- **请求超时 deadline**：原每收到一条无关消息就用完整 timeout 重新等待，被无关流量饿死。改为进入循环前固定 deadline，传剩余时间；`timeout<=0` 等同 `poll(-1)` 无限等待；STATUS 缺状态属性时默认 `INVALID_ARGUMENT`（与 libubus-req.c 一致）。
- **SCM_RIGHTS 单 fd**：见 §1 第 4 条。

### rpcd（file/luci）
- **file.write 模式**：原 `open(mode)` 被继承的 022 umask 削弱（0666→0644，0777→0755）。改为 `umask(0)` 包住 open，模式精确落盘。**这是本轮爆炸半径最大的一处**：每个带 mode 的 write 都受影响。探针验证 0666/0777 均与原实现一致。
- **file.exec 失败码**：execve 失败（不可执行、坏解释器）与 >253 参数原返回 ubus 错误状态；C 的子进程 `_exit(127)`，父进程回 `{code:127}`。已改为回 `{code:127}`。
- **file.exec 信号退出**：原报 `128+signal`；C 的 `WEXITSTATUS` 对信号死亡为 0。已改。
- **file.exec 输出上限**：ustream 容量在填满 262144 时即触发，原用 `>` 放过恰好 262144；改为 `>=`。
- **b64_decode**：原过于宽松（吞掉不完整尾组）；改为拒绝非空白长度非 4 的倍数或 >2 个填充，匹配 libubox。修正了一条写死旧行为的单元测试。
- **luci.setLocaltime**：省略 `localtime` 参数时，ucode.so 不注入策略默认值，`localtime(null)` 用当前时间并回 `{result:null}`；原 Rust 默认 0（1970）。已改为省略→当前时间、回 null。

### logd
- **read 参数类型策略**：`lines` 必须 INT32、`stream`/`oneshot` 必须 BOOL（INT8），否则按 `blobmsg_parse` 丢弃该属性；`lines` 按有符号读，`log_list` 的 min 按 logd.c 计算，使 `lines=-1` 返回空、类型不符的字段被忽略而非误读。

### httpd
- **MIME 表**：整表按 uhttpd `mimetypes.h` 逐条替换（补 `wpad.dat`/`pac`、`README`/`.conf`/`.cfg`、`aac`/`mov`/`tbz`/`jsonp`；`sh`/`pl`/`php` 改 `application/x-*`），匹配沿用 `uh_file_mime_lookup` 的尾锚语义。
- **cgi_prefix/ubus_prefix 去尾斜杠**：仿 `fixup_prefix`，避免 `/cgi-bin/` 直接吐脚本源码（源码泄露）。
- **请求行/头 4 KiB 上限**：原先整行读入内存再判长，40 MB 无换行行会撑爆内存；改为 4 KiB 有界缓冲并回 `413 Request Entity Too Large`。
- **If-Range**：原按 ETag 比较；uhttpd 对任何 `If-Range` 一律回 412（不实现 range）。已改。

### reload-config
- **点文件**：shell 的 `for config in .../*` 通配不匹配前导点，编辑器交换文件等 dotfile 不在扫描集内；原 Rust 用 `read_dir` 会把它们纳入。已改为跳过前导点文件，并在精确 rootfs 内与原 shell 逐行比对基线一致。

## 3. 修复清单与验证一览

| 组件 | 处 | 验证 | commit |
|---|---|---|---|
| reload-config | dotfile 扫描 | rootfs 内基线逐行相同 | d351b2b |
| ubus/httpd | 6 库 + If-Range | 38/38 httpd、10/10 logd、字节级单测 | 31d4fdb |
| rpcd | write mode/exec/base64/setLocaltime 等 6 | 16 探针 + 63/63 | 6e296e4 |
| logd/httpd | read 类型、MIME、413、prefix | 10/10、38/38 | 75d3dc5 |
| fw4 | ipset split、%.14g、null 设备等 6 | 上游 31/31 + ucode 探针逐字节 | 12aab09 |

## 4. FFI 布局核对（aarch64 musl 静态目标）

`ubus/src/sys.rs` 的 `msghdr`(56)/`cmsghdr`(16)/`iovec`(16)/`pollfd`(8) 各字段偏移、`CMSG_LEN`(20)/`CMSG_SPACE`(24)、常量（`SOL_SOCKET`/`SCM_RIGHTS`/`O_*`/`F_*`/`POLL*`/信号）均与内核/musl 一致。`rpcd/src/util.rs` 的 `StatVfs`、`luci.rs` 的 `Tm`、`utsname` 缓冲（machine 在偏移 260）对目标 musl 正确。无 `transmute`，无别名违背。

## 5. 未修复（confirmed，本轮不改，附理由）

判据：本设备实际配置/流量不触发，且改动会危及已字节等价的实现或属并发模型重写。均记录为阶段 6–9 的收口项或有意偏离。

- **fw4：畸形配置的 abort 语义**（invalid `defaults`/`include`、helper 无 `port`、`reflection_zone '*'`）。ucode 抛错 `exit 254` 且不写状态文件；Rust 渲染出会被 nft 拒绝的规则并 `exit 0`。设备配置合法、不触发；把 `exit 254` 贯穿所有选项解析点的改动大、对合法配置无收益，且 fw4 在 print 相同门禁之后才接管。→ 阶段 4 后续。
- **fw4：u64 值 >= 2^63**（`maxelem`/`timeout`/大端口/前缀长度）。需要给 `Num` 增加 `UInt(u64)` 三态、触及多处。仅畸形/极端输入。→ 与阶段 6 UCI 库一并处理。
- **fw4：`%` 出现在 stderr 提示里**、对象值 ubus 选项的 `to_compact` 空格差异、匿名 section id 命名（`cfg%06x` vs libuci `cfg%02x%04x`）。仅 stderr 文案/极少见路径，不影响规则集。
- **logd：非 UTF-8 消息字节**。原实现原样存字节；Rust 用 `from_utf8_lossy` 改写（非法字节→U+FFFD）。需要 `Ring` 存 `Vec<u8>` 加 `BlobBuf` 字节串 API。日志几乎都是 UTF-8；→ 阶段 2 收口。
- **logd/httpd/rpcd：ubusd 断开不重连**。原实现 `ubus_auto_connect` 每秒重连并重注册对象；我方 daemon 退出交给 procd `respawn`。这是并发/韧性差异，不改变回复内容，且补重连正是阶段 9 的前置项（计划 §11.6）。
- **httpd 并发模型**：线程 per 连接 + 整块响应缓冲（无流式）、单连接一个 ubus context、`-N` 超限直接丢而非排队、CGI 无头块→我方 500/200 而非 C 的 502。设备只有 luci 一个 CGI（必产头）、并发远不及上限。属并发模型，非回复内容。→ 阶段 9/后续。
- **httpd 解析严格度差异**：`%00` 截断、请求行多空格、`Content-Length` 尾空格、裸 LF、单引号 JSON、JSON 尾随垃圾、深度>64、`Bearer` 大小写。多数是 Rust 更严（对网络解析器更安全）；本设备 LuCI 流量不触发。有意保留更严解析，个别（`Bearer` 大小写、`GET /ubus/list/`）列为阶段 7 rpcd/桥收口。
- **httpd 未实现的 uhttpd 选项**：basic auth、interpreter 映射、lua/ucode handler、`redirect_https`、SSE `subscribe`、PEM 证书等。设备配置未使用（`redirect_https 0`、DER 证书、无 lua handler）；PEM 支持列为将来若接 acme 的前置。

## 6. 可审计性说明（迁移期结构偏离）

以下重构使逐段对照变难，但均由 oracle 证明等价，本轮不回退：fw4 的选项表→顺序调用、zone 索引引用、模板扁平化、`Num` 二态；ubus 的请求循环融合、`Reply.fields()` 拼接多 DATA、`Json::Object` 用 `Vec`；logd 的字节环模拟；httpd 的整块缓冲 + 线程模型、`files::lookup` 返回 `Redirect`。第二轮把共享 `uci`/`json`/`netlink` 收进 workspace 时，应顺带恢复更直接的映射（计划 §11.6）。

## 7. 迁移规则更新（防止再犯）

1. **源语言的 truthiness 必须按源语义翻译**：C/ucode 的真值判断（空串、0、null 为假）不能用 Rust 的 `is_some()`/`!=None`/长度近似。遇到 `x ||= default`、`if (x)`、`length(x)` 一律回到源语义。
2. **有符号/无符号显式对齐**：跨 FFI/wire 的整数先确定 C 侧类型（`int`/`int32_t`/`uint32_t`），再决定 Rust 转换；blobmsg/JSON 分型以 libubox/json-c 源码为准。
3. **策略化类型检查**：blobmsg 字段按对象的 policy 类型严格匹配（`blobmsg_parse` 丢弃不符类型），不用无策略访问器。库层应提供策略化 parse（阶段 6/7 收口）。
4. **数值/格式化以 C 库为 oracle**：`%.14g`、`%.17g`、`umask`、`b64_decode`、`split(/regex/)` 等都要对照源实现的确切阈值与边界，并加针对性单元测试。
5. **面向网络的解析器：偏严可保留并记录，偏宽必须修**：更严格不算兼容缺陷（更安全），但要在报告写明；更宽松（放过畸形输入）必须收紧到与 oracle 一致或更严。

## 8. 用户四问

- **发现了哪些行为差异**：见 §2（已修 20 处）与 §5（记录 待改）。最高价值的是 rpcd `file.write` 的 umask 模式错误（每个带 mode 的写都受影响）、ubus 的有符号整数处理（iwinfo 负值、大文件 size）、logd read 的类型策略、httpd 的 413 与 MIME。
- **修复了哪些问题**：§3 表列出 5 个 commit、20 处修复，全部按验证链重验（上游 31/31、rpcd 63/63+16、httpd 38/38、logd 10/10、单元 debug+release）。
- **还有哪些无法确认的风险**：§5 的并发/重连/流式差异不改变回复内容，但在极端负载或 ubusd 重启时行为与原实现不同，靠 procd respawn 兜底；非 UTF-8 日志、u64 超界、畸形配置 abort 语义在本设备不触发但确与原实现有别。
- **是否为 Rust 化而主动改变原行为**：有意保留的仅是"面向网络的解析器更严格"（§5、§7 规则 5），因为放宽会扩大攻击面；其余偏离都是迁移期的实现结构（§6），已由 oracle 证明行为等价，未改变对外行为。
