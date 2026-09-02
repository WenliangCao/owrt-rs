# R17：rpcd 核心对象 `session`/`uci`/`rc` 由 rpcd-rs 接管（阶段 7）

> 日期：2026-09-02。决策 [0013](../../docs/decisions/0013-rpcd-core-objects-in-rust.md)，合同
> [C7](../../docs/contracts/rpcd-core.md)。代码 `components/rpcd`（`session.rs`、`uciobj.rs`、`rc.rs`、新 `main.rs`
> 事件循环；`uci` 对象基于阶段 6 的 `owrt_uci`）。包 `owrt-rpcd 0.1.0-r3`。原始输出在 `private/stage7/`。

## 1. 结果

| 项 | 结果 |
|---|---|
| 精确 rootfs 双沙箱差分（`tools/r17_rpcd_core_check.py`；原：完整 C rpcd；候选：rpcd-rs + 插件裁剪的 C rpcd） | 272/272 步相同（会话 id、`expires`、ubusd 类型 id 遮罩）；apk 内发货二进制同样 272/272 |
| 覆盖 | `ubus -v list` 三个对象的签名；session 全部 10 个方法（create/list/grant/revoke/access/set/get/unset/destroy/login，含类型保留的 data、ACL 表、默认会话、超时过期、timeout 0、`$5$` crypt 与 `$p$` shadow 登录、空口令、读写组与 `!` 否定、access-group 元作用域）；uci 全部 15 个方法（get/state/add/set/delete/rename/order/changes/revert/commit/apply/confirm/rollback/configs/reload_config，含 `@type[i]` 扩展、type+match（字符串/列表/整数/布尔）、值类型格式化 `%u`/`%llu`/`!!`、列表↔字符串改写、`err` 被 `uci_unload` 清零的状态怪癖、apply 回滚计时器/confirm/rollback、无变化 NO_DATA、拒绝路径）；rc list（含 skip_running_check、`strtoul` 基数 0、11 行首上限、非 root/o+w/不可执行脚本跳过、超时项丢弃）与 init；SIGHUP 冻结→再执行→解冻后会话/数据/ACL/uci delta 保持；结束时 `/tmp/.uci`、会话 savedir、快照目录、配置文件内容与模式 |
| 设备门禁（只读，同一 51 项在原 rpcd 与 rpcd-rs 下各跑一次） | `GATE_IDENTICAL`：三对象签名、默认会话 list/access、错误码（NOT_FOUND 4 / INVALID 2 / NO_DATA 5 / DENIED 6）、9 个真实包的 `uci get` 哈希与字节数、`uci state network`、changes、`rc list`（30 项）、luci/file/luci-rpc 探针、`ubus list` 对象集合全部相同 |
| 设备接管 | `owrt-rpcd-switch enable`：停原 rpcd → 起 rpcd-rs（注册 session/uci/rc/file/luci）→ 起原 rpcd（只剩 iwinfo/luci-rpc/rpc-sys/network.rrdns）；`boot-enable on`（S11 `boot()` 等核心对象注册后才放行 S12）；`owrt-switch status` 六个组件 enabled/on |
| LuCI 路径（经 httpd-rs 的 `/ubus` JSON-RPC） | `session access` → true、`luci getFeatures` 正常、默认会话 `uci get` → Access denied、错误口令登录 → 6；均由 rpcd-rs 应答 |
| 探针窗口（19:19:03、19:23:24、19:24:40 UTC，3 次） | rpcd-rs pid 11269 / 原 rpcd pid 11330 不变、裁剪挂载保持、`session access`/`uci get`/`uci changes`/`rc list`/`luci getVersion` 答案不变、`recent_rpcd_log=0` |

## 2. 结构

- `session.rs`：BTreeMap 复刻 AVL（strcmp 序、ACL 按通配前缀键+插入序），`grant/revoke/allowed` 与 C 的
  `uh_foreach_matching_acl` 等价（`sort_len` 在 C 中从未赋值，故仅 fnmatch）；登录经 `/etc/config/rpcd`
  `login` 节 + `/etc/shadow` + musl `crypt()` FFI；acl.d 用本仓库 JSON 解析器按 blobmsg 类型规则合并；
  冻结/解冻文件格式与 C 一致（`/var/run/rpcd-rs/sessions/<sid>` 头 blob）。
- `uciobj.rs`：uci.c 逐函数移植，每次调用新建 `owrt_uci::Context` 并按 `rpc_uci_replace_savedir` 设 delta
  路径（会话 savedir `/var/run/rpcd-rs/uci-<sid>`，无 sid 用 `/tmp/.uci`，state 追加 `/var/state`）；`tr!`
  宏复刻 `cursor->err` 的赋值/清零时序，保证 `uci_unload` 后状态为 OK 的怪癖。
- `rc.rs`：目录遍历顺序、脚本权限、行首解析、`running` 探测（3 秒超时丢项）与 C 相同；`list`/`init` 在工作
  线程执行，经自管道唤醒事件循环后回复（C 为 uloop 延迟请求）。
- `main.rs`：poll(ubus fd, 自管道) + 会话到期/apply 回滚两类计时器 + SIGHUP/SIGUSR1（冻结后 exec 自身
  并置 `RPC_HANGUP=1` / 退出）；启动时 `RPC_HANGUP!=1` 清 `uci-*` 目录，否则解冻。注册任一核心对象失败即退出。
- 约 2,050 行新增（session 640、uciobj 830、rc 250、main 330）；依赖仍为零外部 crate。

## 3. 探针窗口数字

见 `private/stage7/device/r17-probe-window.txt`：3 次 `state`（enable 于 19:18:20 UTC 完成），rpcd-rs pid 11269 与
原 rpcd pid 11330 不变，`mounted=1`，`plugins=iwinfo.so luci.so rpcsys.so rrdns.so`，`sessions_live=1`（默认会话），
`recent_rpcd_log=0`；`/var/run/rpcd-rs` 只有门禁 `apply` 留下的两个空快照目录。

## 4. 有意偏离 / 未覆盖

- 运行时目录 `/var/run/rpcd-rs`（决策 0013）：C rpcd 启动时会清空 `/var/run/rpcd/uci-*`，两进程共存期间必须
  分离；C 侧仍会创建自己的 `/var/run/rpcd` 与快照目录（无人使用）。
- 登录节的读写组通配（C 用 `fnmatch(...,0)`）与 ACL 匹配（C 用 `FNM_NOESCAPE`）在本实现都不处理反斜杠转义；
  设备与上游 acl.d 中没有反斜杠。
- blob 参数中的非 UTF-8 字符串按缺失处理（更严）；acl.d 用本仓库 JSON 解析器（比 json-c 严，设备 9 个文件
  解析结果与 C 一致，以默认会话与 root 登录的 ACL 表逐字节相同为证）。
- SIGHUP 的冻结在事件循环里完成（C 在信号处理函数里）；再执行用 `/proc/self/exe`（C 用 PATH 查 argv[0]）。
- `-t` 非法值退出码 255（C `return -1`）；`rc init`/`reload_config` 子进程由线程回收（C 靠 uloop SIGCHLD）。
- 沙箱里没有 `service` 对象，`commit`/`apply` 触发 `config.change` 事件的分支只在设备上被真实路径覆盖
  （LuCI 保存并应用）；本窗口未用用户口令登录 LuCI，`uci apply` 的设备端首次真实触发留给日常使用。
- 开机路径（S11 `boot()` 等待）本次未验证（不重启设备），与前几阶段同样待下一次自然重启。
- `rpc-sys`、`luci-rpc`、`iwinfo`、`network.rrdns` 仍由裁剪后的 C rpcd 提供，归阶段 8。
- §11.6 合并：rpcd 内嵌的只读 UCI 文本解析器（`getConntrackHelpers` 用）已删除，改用 `owrt_uci` 按 ucode 插件的
  `cursor().load(绝对路径)` 语义加载（列表选项输出数组、缺失为 null）；沙箱重验 r13 63/63（harness 起动顺序改为
  rpcd-rs 先于 rpcd）与 r17 272/272。该二进制随下一版包发货，设备当前为合并前的 r3。fw4 的内嵌解析器留待阶段 8。

## 5. 退路

`owrt-rpcd-switch disable`：停原 rpcd → 停 rpcd-rs → 卸载裁剪目录 → 起原 rpcd（全部对象回到 C）；
`boot-enable off` 取消开机接管；`apk del owrt-rpcd` 完全移除。enable/disable 都会使 LuCI 会话失效。
本窗口发现 r2 开关的 `disable` 在原 rpcd 持有裁剪目录时无法卸载（顺序错误，r3 已改为先停 rpcd）；
当时按"停 rpcd → umount → 起 rpcd"手工恢复后再升级。
