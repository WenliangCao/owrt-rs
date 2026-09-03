# R25：第五轮——字节读取、差分模糊、clippy 清零（2026-09-03/04）

> 用户指令："rpcd 里 read_to_string 读 ethers/board.json/resolv.conf 改按字节读；fw4/rpcd/httpd/logd 的差分模糊；clippy 清零；做完了之后直接替换到路由器里。"
> 原始输出 `private/audit/round5/`（沙箱日志）、`private/bench/deploy_round5_*.txt`（设备窗口）。

## 1. 字节读取（B4 余项）

C 端读取这些文件用 fgets/getspnam/getpwnam，逐字节处理；Rust 用 `read_to_string`，文件里任何一个非 UTF-8 字节都让**整个文件**读取失败。
改为读字节后 `from_utf8_lossy`（无效序列变 U+FFFD，DEVIATION：C 会原样保留字节，但这些值最终要进 blobmsg 字符串，本来就装不下原始字节）。

| 组件 | 文件 | 原来的后果 |
|---|---|---|
| rpcd | `/etc/shadow`（`$p$` 密码登录） | 任何一行含非 UTF-8 → 所有 shadow 登录失败 |
| rpcd | `/etc/passwd`、`/etc/group`（file stat 的 uid/gid 名） | 名字解析失败 |
| rpcd | `/etc/ethers`（getHostHints） | 一个坏主机名 → 整个 ethers 被忽略 |
| rpcd | `/etc/board.json`（getBoardJSON）、ACL 文件、`/etc/resolv.conf`（rrdns）、`luci` 对象读的 /proc、/etc 文件 | 同类 |
| fw4 | `include` 文件、`/proc`、`/sys` 读取（`fs.readfile`/`fs.open`） | 含杂散字节的 include 文件被当作不存在 |
| logd | `/etc/passwd`（`-u` 降权用户查找） | 其它行含非 UTF-8 → 找不到用户 |

新增 `rpcd::util::read_lossy`；fw4 `Inputs::readfile/open` 与 logd `lookup_user` 同法。

## 2. clippy 清零

`cargo clippy --all-targets` 七个 crate 全部 0 条（之前 uci 9、logd 2、httpd 1、fw4 21、rpcd 24 + 1 个 deny 级）。
机械修复由 `clippy --fix` 完成并逐条复核（`AssoclistEntry` 的手写 Default 与 derive 等价；`map_or(false, ..)` → `is_some_and`；
字符比较写法；lucirpc 的测试模块移到文件末尾）。手工处理：

- **deny 级 `while_immutable_condition`**（`nl80211.rs` wpactl 扫描）：`while ready { … continue/break }` 与 C 的 `while (ready)` 同义，
  改写为 `if ready { loop { … } }`，行为不变；不是 bug。
- `clamp` ×3、`div_ceil`、`unwrap_or`、`?`、`truncate(false)`、两处 `is_some()`+`unwrap` 改为 `let Some(..) else`/`if let`。
- 五处保留并加 `#[allow]` 说明：`type_complexity`（三处元组类型）、`needless_range_loop`（ether_aton 的字节游标）、
  `wrong_self_convention`（`rpc_session_from_blob` 的 C 名字）、`field_reassign_with_default`（逐项镜像 ucode 的 defaults 解析）、
  `dead_code`（rtnl `Msg.flags`、fw4 zone state 的 `helper`：与 C/ucode 同形，无读者）。

## 3. 差分模糊

四个新工具，都以精确 rootfs 里的原实现为参照：

| 工具 | 方法 | 用例 | 结果 |
|---|---|---|---|
| `tools/r29_fw4_fuzz.py` | 变异上游测试的 `uci/firewall.json`（畸形端口/IP/CIDR/MAC/协议/目标/族/布尔/数字、删/复制/未知 section 与 option、列表↔字符串、长串、非 ASCII），ucode fw4 与 fw4-rs 各跑 `print`，比 stdout/stderr/exit | 2 种子 × 200 | 修复 1 处后 **0 差异**；每种子约 25 例 ucode 自身崩溃（见 §3.1） |
| `tools/r26_rpcd_fuzz.py` | 复用 r17 沙箱；9 个对象 63 个方法，每个方法 8+ 组随机参数（类型对/错、边界整数、怪路径/配置名/section 名、长串、控制字符、缺参、多参） | 2 种子 × 615 步 | **0 差异**（首轮 16 个"差异"全是会话 id/复制时间戳的归一化问题，已修） |
| `tools/r28_logd_fuzz.py` | r15 沙箱 + `nsenter` 从宿主机向 chroot 内 `/dev/log` 发原始报文（无/坏/越界 PRI、空、NUL、坏 UTF-8、控制字符、换行、RFC3164/5424 形状、1–60000 字节、700 条撑爆 64 KiB 环），`log write`/`log read` 坏参数 | 780 报文 + 27 ubus 调用，33 项输出 | **0 差异** |
| `tools/r27_httpd_fuzz.py` | r14 沙箱 + 原始 socket：坏请求行/方法/版本、路径穿越与坏百分号编码、超长/畸形头、Content-Length 与 chunked 冲突、非 JSON/超大/超深/坏 UTF-8 的 JSON-RPC、流水线、绝对 URI、CGI 怪路径；比状态行/头（屏蔽 Date 等）/正文/是否断开/服务是否存活 | 133 例 | 首轮 35 差异 → 修 5 处（§3.2），其余记为有意偏差（§3.3） |

### 3.1 fw4：找到的差异与 ucode 的崩溃

- **真 bug（panic=abort → 无防火墙）**：非 ASCII 的选项值让 fw4-rs 在按字节下标切 `&str` 时崩溃——`parse_num_str` 的
  `&body[..2]`（进制前缀检测，`start_date '名字'` 等任何走数字转换的值）、`parse_date` 的 `split_at(4)`、以及 `parse_v4/parse_v6`
  的分组切片。ucode 只是打印 "specifies invalid value '名字'" 并跳过该 section。三处改为字节级判断 / `is_ascii()` 前置守卫；
  rpcd 里同源的 `ip.rs` 一并修。种子 3 找到（2/150），修后种子 3–6 全部 0 差异。
- **修复**：警告文本里列表值的字符串化。ucode 的 `"" + [a, b]` 是 `[ "a", "b" ]`（括号内有空格、逗号后空格），Rust 用了紧凑 JSON
  `["a","b"]`；影响所有 "option 'name' must not be a list" 一类的 stderr 行。新增 ucode 风格的 `ucode_json`。
- **ucode 自身崩溃（不复刻）**：`config defaults` 或 `config include` 里任何一个非法选项会让 fw4.uc 在 `parse_options` 返回 false 后
  继续解引用（`fw4.uc` 1978、3220 行 "Reference error: left-hand side expression is not an array or object"），进程以 254 退出，
  **设备上就是防火墙加载失败、无规则**。fw4-rs 按 ucode 自己的默认值继续并给出完整规则集。这是有意 DEVIATION：不去复刻解释器崩溃。
  模糊器把这类用例单独计数（`ucode_crashed`）。

### 3.2 httpd：修复

| 用例 | uhttpd | httpd-rs（修前） | 修后 |
|---|---|---|---|
| 双 Content-Length、CL+TE 冲突 | `uh_client_error`：`HTTP/1.1 400` + `<h1>Bad Request</h1>` | `HTTP/1.0 400` | 与 uhttpd 相同 |
| `/cgi-bin/luci/%00` | NUL 截断路径后照常跑 CGI | **不回任何响应就断开**（NUL 进不了 CGI 环境，spawn 失败被吞） | 400（DEVIATION：拒绝而不是截断） |
| chunked 请求体 chunk 长度非法 | 把垃圾当正文交给 JSON-RPC（返回 parse error） | **静默断开** | 400 + 关闭（DEVIATION） |
| 头部阶段错误（坏 Content-Length、TE gzip） | 状态行用请求解析出的版本（`HTTP/1.1 400`）、chunked 空正文（`uh_header_error` 无正文） | `HTTP/1.0 400` + `<h1>…</h1>` 正文 | 与 uhttpd 相同 |
| 请求行多个空格 `GET  /index.html` | `strtok(" ")` 折叠空格 → 200 | 400 | 与 uhttpd 相同 |
| JSON-RPC 正文后有垃圾 / 两个文档 | `json_tokener_parse` 取第一个值 | parse error | 与 uhttpd 相同（`json::parse_prefix`） |

### 3.3 httpd：保留的有意偏差（都在错误路径，不影响任何正常客户端）

- uhttpd 对无法解析的请求行回 400 时头里写 `Connection: Keep-Alive`（`connection_close` 尚未置位）但随后 `uh_connection_close` 立刻关闭；
  httpd-rs 写 `Connection: close`，行为一致、头更真实。请求行只有 1–2 个 token 时 uhttpd 用上一次残留的版本号打 `HTTP/0.9`；httpd-rs 用 1.0。
- `%00`：见上，拒绝而不截断（同样适用于静态文件 `/index.html%00.txt`，uhttpd 返回 index.html）。
- 仅 LF 的行结束、无冒号/续行/含 NUL 的头：uhttpd 不响应并等待更多数据；httpd-rs 接受（LF）或 400。
- 8 KB 以上的请求行、1 MiB 的 JSON 正文：uhttpd 直接 reset 连接；httpd-rs 回 413 / 正常处理（4 MiB 上限内）。
- JSON：json-c 接受字符串里的非法 UTF-8、把 `1e400` 解析成 inf 并原样输出 `"id":inf`（非法 JSON）、5000 层嵌套按批量请求处理；
  httpd-rs 分别返回 parse error / `id: null` / parse error。

## 4. 版本、门禁与部署（2026-09-03 23:22）

SDK 产出的静态二进制全部重新过门禁后，按 uci → fw4 → logd → httpd → rpcd 顺序 `apk add`（用户预授权："做完了之后直接替换到路由器里"）：

| 包 | sha256（apk） | 门禁 | 部署检查 |
|---|---|---|---|
| owrt-uci 0.1.0-r5 | 5793f214…d026d | r16 175/175；r24 种子 4 150/150 | postinst 门禁 export/show/changes identical；`uci export` 哈希不变 |
| owrt-fw4 0.1.0-r5 | 916e9dcd…95eb4 | r09 31/31；r29 种子 3–6 全 0（每种子 12–29 例 ucode 崩溃） | postinst 门禁 identical（203 行）；`fw4 print` 哈希不变 |
| owrt-logd 0.1.0-r5 | 3dcb67b4…504f0 | r15 passed；r21 重注册 2 s；r28 0 差异 | 新 pid 28368；`logger` 后 `logread` 可读 |
| owrt-httpd 0.1.1-r3 | 04cc91fa…55a7b8 | r14 38/38；r27 25 个有意偏差（§3.3），服务在 133 例后全部存活 | 新 pid 28711；`/ubus` JSON-RPC 与 LuCI 登录页正常 |
| owrt-rpcd 0.1.0-r9 | 200aeb90…8cf58 | r17 272/272、r18 74/74、r19 11/11；r26 种子 3、4 0 差异（种子 4 的 1 例是提交时刻 mtime，已加掩码） | 新 pid 29021，单进程，9 对象，`getFeatures`/`getHostHints` 正常 |

reload-config 0.2.0-r5 无代码改动，未重建。overlay 用量不变（23.1 MiB）。3 分钟探针见部署日志 `private/bench/deploy_round5_*.txt`：
pid 不变、无 crash/respawn、ubus 40 对象、LuCI 403+登录表单。

## 5. 剩余

- fw4 的 ucode 在 `defaults`/`include` 非法时崩溃的行为不复刻（记录在 §3.1）；如需"和原版一样失败"再议。
- httpd 的 25 个错误路径偏差（§3.3）保持。
- 发布镜像需用当前包集重建（`docs/RELEASE.md`）。
