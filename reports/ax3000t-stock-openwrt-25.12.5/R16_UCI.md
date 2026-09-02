# R16：`/sbin/uci` 由 uci-rs 接管（阶段 6）

> 日期：2026-09-02。决策 [0012](../../docs/decisions/0012-uci-library-and-cli-in-rust.md)，合同
> [C6](../../docs/contracts/uci.md)。代码 `components/uci`（库 + `uci-rs`），包 `owrt-uci 0.1.0-r2`，
> 聚合开关 `owrt-switch 0.1.0-r2`。原始输出在 `private/stage6/`。

## 1. 结果

| 项 | 结果 |
|---|---|
| 上游 libuci shunit2 套件（11 组 112 断言，参考输出只读） | uci-rs 112/112；C 原实现同一套件 112/112（去掉 valgrind 包装） |
| 精确 rootfs 差分（`tools/r16_uci_check.py`，候选以 bind mount 覆盖 `/sbin/uci`） | 175/175 步相同：stdout、stderr、退出码，以及结束时 `/etc/config`、`/tmp/.uci`、`/var/state`、额外 delta 目录全部文件的内容与模式 |
| 同一差分对 apk 内实际发货的二进制（动态 musl PIE，354,795 字节） | 175/175 |
| 设备门禁（`owrt-uci-switch gate`，只读） | `export` 400 行、`show` 299 行、`changes` 0 行，三者原实现与候选逐字节相同，`/tmp/.uci` 未变 |
| 设备接管 | `enable` 成功（bind mount，`/sbin/uci` 变为 354,795 字节），`boot-enable on`，S00 rc 链接就位 |
| 集成检查（经 `/sbin/uci` 的真实调用方） | `config_load network/firewall`（`uci -S -n export`）正确；`uci_get_state` 正确；`/sbin/wifi status` 正常；**`reload_config` 用 uci-rs 规范化全部 19 个包，与 C 版基线逐条一致（`changed_entries: []`），未触发任何 config.change 事件** |
| 约 3 分钟探针窗口（3 次） | 挂载保持、`show`/`export`/state 哈希不变、六个组件全部 enabled/on、日志中无 uci 相关错误 |

差分矩阵覆盖：6 个设备真实包的 `show`/`export`/`-S -n export`/`-X show`；`get` 的存在、缺失、扩展
语法（含负索引与各种畸形元组）；`set`（新建、覆盖、同值、类型改写、非法类型、空值）、多行值、
`add`、`add_list`（含字符串转列表）、`del_list`、`rename`、`reorder`（同位、越界、缺失）、按索引删列表
项、`delete`、`changes`、`revert`（option/section/package）、`commit`（含无变化不重写、模式保留）、
`-P /var/state` 的 set/get/show/revert/export、`-C /var/run/uci` 覆盖目录、`-p`/`-t`/`-P` delta 路径
链与 NOCOMMIT、`import`（带名、`package` 行、无包名报错、`-m` 合并、`-f`）、七种畸形配置在严格与 `-S`
模式下的错误文本与行列位置、目录中含点/隐藏/子目录的列举、空目录与缺失目录、`batch`（多行值、注释、
空行、错误累积的 `error_info` 换行怪癖、嵌套 batch、解析错误、`exit`）、CLI 边界（无参数、未知命令
255、参数个数、未知选项、缺参数、`-L`、命令后选项不解析、`--`、大小写不敏感、绝对路径包）。

## 2. 结构

- `components/uci`：`parse.rs`（file.c 解析器，原位解码、字节偏移与行号精确）、`ops.rs`（list.c +
  util.c：lookup/parse_ptr/set/add_list/del_list/delete/rename/reorder/add_section、`cfg%02x%04x`
  djbhash 命名）、`delta.rs`（delta 格式、路径链、load/save/filter/revert）、`file.rs`（load/commit/
  list_configs、flock、mkstemp+rename、模式继承）、`export.rs`、`context.rs`、`bin/uci-rs.rs`（cli.c，
  musl 风格 getopt、`uci_perror` 静态 `error_info` 怪癖）。约 2,300 行，零依赖，4 个单元测试。
- `libuci.so` 与库方式使用者（netifd、rpcd、odhcpd、ucode、iwinfo、ujail、validate_data）不变；两个
  实现共享同一份 `/etc/config`、`/tmp/.uci`、`/var/state`，delta 文件格式逐字节兼容。

## 3. 没有做到 / 注意

- preinit 阶段（`/lib/preinit/*`）在 S00 之前运行，仍使用原 `/sbin/uci`；S00owrt-uci 之后的一切
  init 脚本走 uci-rs。
- 上游套件在 rootfs 的 BusyBox chroot 内运行时有 18 项因测试工具（`diff -qr`/shunit2）而失败，
  C 原实现同样失败同一 18 项，属环境差异，已用主机运行（112/112）与 rootfs 差分（175/175）覆盖。
- r1 门禁用 `ls -la` 检查 `/tmp/.uci` 未变，`..` 项会随 `/tmp` mtime 抖动，启动时可能误判；r2 改为
  `ls -l` 后才 enable。
- 阶段 6 只替换 CLI；rpcd 的 `uci` 对象与 fw4 内嵌的只读解析器在阶段 7 迁到本库。

## 4. 退路

`owrt-uci-switch disable` 卸载 bind mount（原二进制从未修改）；`boot-enable off` 取消开机接管；
`apk del owrt-uci` 完全移除。
