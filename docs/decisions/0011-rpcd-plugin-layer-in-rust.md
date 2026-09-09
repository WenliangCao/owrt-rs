# 决策 0011：R13 rpcd——用 Rust 接管插件层（file、luci），核心对象保留

> **现状（2026-09-09）**："核心对象保留 C"已被 0013/0014 取代：`session`/`uci`/`rc` 与全部插件对象都在 rpcd-rs 中，C rpcd 已停用（R17/R18）。

> 日期：2026-09-02
> 状态：已定
> 阶段：阶段 5

## 证据

- rpcd 2026.06.04~28faf640：`session`、`uci`、`rc` 三个对象编译在 `/sbin/rpcd` 主程序里
  （main.c 依次调用 `rpc_session_api_init`、`rpc_uci_api_init`、`rpc_rc_api_init`），插件只能整体
  从 `/usr/lib/rpcd/*.so` 加载；ubusd 拒绝重复对象路径。因此计划 v4 的落点 B（Rust 提供 `session`
  而 `uci` 留给原 rpcd）在不打补丁的前提下不可行：两者只能同进同退。
- 设备 LuCI（26.180.75667）静态调用清单（`/www/luci-static/resources` 104 处 `rpc.declare`）落在
  rpcd 的对象上的是：`session`(access/login)、`uci`(10 方法)、`file`(exec/read/write/list/stat/remove
  ——fs.js 共 90 处调用)、`luci`(21 方法)、`luci-rpc`(6)、`iwinfo`(5)、`rpc-sys`(2)、`network.rrdns`(1)。
- `luci` 对象由 ucode 脚本 `/usr/share/rpcd/ucode/luci`（686 行）经 ucode.so 提供；`luci-rpc` 由
  C 插件 luci.so 提供并依赖 libiwinfo/netlink；`file` 由 file.so（1131 行 C）提供。
- 通过 httpd-rs 记录的动态清单目前只有 `session access`：本项目不使用用户的 LuCI 口令，动态清单
  需要用户自己浏览 LuCI 后再读取。

## 决策

1. Rust `rpcd-rs`（`components/rpcd`）作为独立 ubus 对象服务，提供 **`file`** 与 **`luci`** 两个对象，
   方法面、参数类型、返回字段、状态码与原实现一致（合同 C5）。`file` 的 ACL 检查通过原 rpcd 的
   `session access`（scope=file）完成，路径规范化与 exec 命令行拼接规则照搬 file.c。
2. 原 rpcd 继续提供 `session`、`uci`、`rc` 与 `iwinfo`、`luci-rpc`、`rpc-sys`、`network.rrdns`。
   切换方式：`owrt-rpcd-switch enable` 把只含 `iwinfo.so luci.so rpcsys.so rrdns.so` 的目录 bind mount
   到 `/usr/lib/rpcd`（去掉 file.so 与 ucode.so），重启 rpcd（procd 管理），再启动 rpcd-rs；`disable`
   逆序恢复。`boot-enable` 用 S11 init 脚本（rpcd 是 S12）在开机时先挂载再启动 rpcd-rs。
3. 不做：`session`/`uci`/`rc`（需替换整个 rpcd 进程并重写 UCI 变更/回滚语义，触及 R04）、`iwinfo`/
   `luci-rpc`（libiwinfo/netlink）。最终报告按此如实记账。
4. 零第三方 crate；MD5、Base64、statvfs/uname FFI 自写。

## 后果

- LuCI 最常用、也是暴露面最大的 `file`（任意路径读写与命令执行，仅受 ACL 约束）改由 Rust 实现。
- rpcd 进程仍是 C；这是五阶段终点的"收敛"落点，计划 v4 §7 预先接受了这个结果。
