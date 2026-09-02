# 0013：rpcd 核心对象 `session`/`uci`/`rc` 迁入 rpcd-rs，C rpcd 只剩插件对象

> 日期：2026-09-02。阶段 7（计划 §11.2）。状态：采纳。

## 为什么这样切

- ubusd 拒绝重复对象路径，而 `session`/`uci`/`rc` 编译在 `/sbin/rpcd` 里，无法单独关掉——这是
  阶段 5 把范围收到插件层的原因。本阶段读到的事实改变了判断：`main.c` **忽略**
  `rpc_session_api_init`/`rpc_uci_api_init`/`rpc_rc_api_init` 的返回值。只要 rpcd-rs 先启动并注册
  这三个对象，随后启动的 C rpcd 会静默失去它们，继续只服务其插件目录里的对象。
- C 的 `uci` 对象通过进程内函数 `rpc_session_access` 查自己的会话表，因此 `session` 与 `uci`
  必须在同一个进程里；`file`/`luci` 的 ACL 也改为进程内查询（不再经 ubus 调 `session access`）。
- `iwinfo`、`luci-rpc` 依赖 libiwinfo/nl80211，是阶段 8 的内容；`rpc-sys` 带 `factory`/
  `upgrade_start`/`reboot` 这类不可逆方法，`network.rrdns` 做 DNS 反解。这四个对象**本阶段留在
  C rpcd**（它的插件目录已裁剪为 iwinfo/luci/rpcsys/rrdns 四个 .so），阶段 8 一并迁移，届时 C
  rpcd 进程才停止。计划 §11.2 原文把 rpc-sys/rrdns 划在阶段 7，本决策把它们移到阶段 8。

## 边界

- **替换**：`session`（create/list/grant/revoke/access/set/get/unset/destroy/login，默认会话
  `000…0` 的 unauthenticated ACL，`/usr/share/rpcd/acl.d/*.json` 的读写组解析与否定模式，
  `$p$user` 经 `/etc/shadow` + libc `crypt()` 校验，超时与触碰，SIGHUP/SIGUSR1 冻结/解冻）、
  `uci`（configs/get/state/add/set/delete/rename/order/changes/revert/commit/apply/confirm/
  rollback/reload_config，按会话隔离的 delta 目录，apply 的快照与回滚计时器，commit/apply 后向
  `service` 发 `config.change` 事件）、`rc`（list 含 START/STOP/USE_PROCD 解析、rc.d 链接判定、
  `running` 探测与 3 秒超时；init 的名字/权限校验与动作白名单）。`file`/`luci` 保留并改为进程内 ACL。
- **不替换（本阶段）**：`iwinfo`、`luci-rpc`、`rpc-sys`、`network.rrdns`；ubusd。
- **路径隔离**：rpcd-rs 的会话 delta 目录、apply 快照与冻结文件放在 `/var/run/rpcd-rs/` 下，
  不与 C rpcd 的 `/var/run/rpcd/` 共用——C rpcd 启动时会清空自己前缀下的 `uci-*`，共用会让它误删
  rpcd-rs 的待提交变更。对外可见行为（`uci changes` 内容、LuCI 的 apply/rollback 流程）不受影响。
- **库**：`uci` 对象建在阶段 6 的 `components/uci` 之上，不再有第二份 UCI 解析器。

## 依赖与体积

零新增第三方 crate；`crypt()` 与 `signal()` 是两个窄 FFI。

## 退路

`owrt-rpcd-switch disable`：停 rpcd-rs，恢复完整插件目录，重启 C rpcd（重新注册全部对象）。
rpcd 重启使 LuCI 会话失效，窗口内告知。启用顺序固定为：停 C rpcd → 起 rpcd-rs → 起 C rpcd；
开机由 S11（rpcd-rs）先于 S12（rpcd）保证。
