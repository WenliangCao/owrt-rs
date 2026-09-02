# 0012：用 Rust 重写 libuci 的读写/delta 语义，并以 bind mount 接管 `/sbin/uci`

> 日期：2026-09-02。阶段 6（计划 §11.1）。状态：采纳。

## 为什么做

- 用户愿景的根：把"字符串配置"变成强类型、可组合的 Rust 库，后续 rpcd 的 `uci` 对象（阶段 7）
  和 fw4/rpcd 里的两份只读解析器都要建在它上面。
- `/sbin/uci` 有字节级 oracle：同一组命令跑在精确 rootfs 的设备配置上，stdout、stderr、退出码、
  落盘的 `/etc/config/*`、`/tmp/.uci/*` delta、`/var/state/*` 都能逐字节比对；上游 shunit2 测试
  套件（11 组、36 份参考输出）可以直接以 `UCI_BIN=uci-rs` 重放。
- 爆炸半径可控：CLI 的调用方是 27 个 shell 脚本（init、uci-defaults、hotplug、`/sbin/wifi`、
  `/lib/config/uci.sh` 的 `uci_load` 即 `-S -n export`、以及我们的 reload-config-rs）。失效面是
  "某个 init 脚本读到错误配置"，不切断 SSH；`disable` 卸载 bind mount 即恢复。

## 边界

- **替换**：`/sbin/uci` 二进制的全部命令与选项（cli.c 775 行）及其依赖的 libuci 语义：
  file.c 解析器（引号、反斜杠续行、`;` 分隔、`#` 注释、多行值）、导出格式与转义、
  delta 文件格式（`+ - @ ^ | ~` 七种命令）与 delta 路径链（`-p`、`-P`、`-t`、savedir 末位）、
  `/var/run/uci` 覆盖目录（`-C`）、匿名 section 命名 `cfg%02x%04x`（djbhash）、扩展语法
  `@type[idx]`、`uci_open_stream` 的 flock 与文件模式继承、commit 的 mkstemp+rename、
  错误消息 `uci: <errstr> (<reason>) at line N, byte M`。
- **不替换**：`libuci.so` 本身及其库方式使用者（netifd、rpcd 的 `uci`/`session`、odhcpd、
  `ucode/uci.so`、libiwinfo、ujail、validate_data）。两个实现共享同一份 `/etc/config`、
  `/tmp/.uci`、`/var/state` 文件，因此 **delta 文件格式与 commit 原子性是硬兼容面**：任何时刻
  切换实现都不能让另一方读到不同的状态。
- **不改的行为**：解析器对非法名字/类型的拒绝、`-S` 宽松模式下的逐行跳过、`import` 覆盖语义、
  `-P` 的 NOCOMMIT 副作用、`export` 不带 `-n` 时匿名 section 不命名、`show` 的引号规则
  （字符串值总是引号；列表元素含空白才引号；`get` 不引号）。

## 依赖与体积

零第三方 crate。预计静态 musl 二进制 < 600 KB。

## 退路

bind mount 由 `owrt-uci-switch disable` 卸载；`/sbin/uci` 原文件不动；`boot-enable` 是
独立开关（S01，早于任何调用 `uci` 的 init 脚本）。门禁：`uci export`（全部包）、`uci show`
（全部包，扩展语法）与 `uci changes` 三者在原实现与候选之间逐字节相同，且 `/tmp/.uci`
在门禁前后无变化。
