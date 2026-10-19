# 兼容合同 C6：`/sbin/uci` 与 libuci 读写语义（阶段 6）

> 来源：libuci @ 66127cd7（设备安装 `uci`/`libuci20250120` 2025.12.02~66127cd7-r1），
> 源码只读副本 `private/stage6/src/uci/`；决策 [0012](../decisions/0012-uci-library-and-cli-in-rust.md)。

## 1. 职责边界

替换 `/sbin/uci`（cli.c）及其调用的 libuci 路径：`uci_load/import/export/save/commit/revert`、
`uci_lookup_ptr/parse_ptr`、`uci_set/add_list/del_list/delete/rename/reorder/add_section`、
delta 文件的写入、读取与过滤、配置目录列举。不替换 `libuci.so`。

## 2. 必须复刻的行为（SRC = 源码，RUN = 设备/沙箱实测）

### C6-01 解析器（file.c）
- 行读取按 `\n` 计行；`\` 位于行尾（或 `\r\n` 前）时续行，续行不计入 byte 偏移；
  单引号内原样，双引号内 `\` 后一字符原样保留（`\'`→`\'` 两个字符），未闭合引号在 EOF 报
  `EOF with unterminated "`/`'`；未加引号的 `#` 终止整行；`;` 分隔同一行的多条命令。
- 命令词：`package|p`、`config|c`、`option|o`、`list|l`；其它 → `invalid command`。
- 名字校验：section/option 名只允许 `[A-Za-z0-9_]`；类型允许可打印 ASCII 33–126；包名另允许
  `-`。违反 → `invalid character in name field` / `invalid character in type field`。
- `config` 无类型 → `config without name`；`option` 无名 → `option without name`；第一 section
  前出现 option/list → `option/list command found before the first section`；严格模式多余参数
  → `too many arguments`；同名 section 类型不同（严格模式）→
  `section of different type overwrites prior section with same name`。
- 严格模式（默认）任一解析错误使整个包加载失败并报
  `uci: Parse error (<reason>) at line N, byte M`；`-S` 时逐行跳过并继续。
- 同名 section 再次出现：复用既有 section（类型改写），后续 option 合并进去。
- 匿名 section 命名 `cfg%02x%04x`：前两位为包内 section 计数 `n_section`（十进制值按 `%02x`
  格式化），后四位为 djbhash(type, 各 option 名与字符串值) mod 65536；在解析时 fixup 发生在
  `uci_add_section` 即 section 刚创建、尚无 option 时（哈希只含类型）。

### C6-02 导出格式（file.c uci_export_package）
`package <name>` 头（可选）、每个 section 前空行、`config <type>[ '<name>']`（匿名 section 仅在
`-n` 时命名）、`\toption <n> '<v>'`、`\tlist <n> '<v>'`（每项一行）、文件末空行；`'` 转义为 `'\''`。

### C6-03 delta 文件格式（delta.c）
每行 `<prefix><pkg>.<section>[.<option>][='<value>']`，前缀：`+` add、`-` remove、空 change、
`@` rename、`^` reorder、`|` list_add、`~` list_del；remove 无值时无 `=`；值以 `'` 包裹并转义
`'\''`。读取时逐行解析、单行错误忽略并继续（保留尽可能多的 delta）；`section` 为扩展语法或
缺值（非 remove）→ 该行无效；`^` 不能带 option、`@` 的值须为合法名字、`|`/`~` 须带 option。
应用顺序：`-p` 路径按加入顺序，savedir（`-P`/`-t` 设置）永远在最后；`uci_add_delta_path` 重复
路径报 `Duplicate entry`。

### C6-04 加载与覆盖目录
`name` 以 `/` 或 `./` 开头 → 绝对/相对路径外部文件，无 delta（`save` 直接写回）；否则先找
`<conf2dir>/<name>`（默认 `/var/run/uci`，`-C ''` 关闭），再 `<confdir>/<name>`。非普通文件 →
`Entry not found`。

### C6-05 CLI（cli.c）
- 选项 `c C d f m n N p P q s S t X`（`L` 被 getopt 接受但无动作）；未知选项打印 usage 退出 0；
  无命令打印 usage 退出 0；未知命令返回 255 并打印 usage（退出 255）。
- `-P <dir>`：设为 savedir 且 **commit 变为空操作**（CLI_FLAG_NOCOMMIT）；`-t <dir>` 只设 savedir。
- `get`：option 值不加引号；列表以 `-d` 分隔符（默认空格）连接，含空白的元素才加引号；
  section 输出类型；未找到 → `uci: Entry not found` 退出 1。
- `show`：`pkg.sec=type`、`pkg.sec.opt='v'`（字符串总引号）、列表元素同 `get` 规则；扩展语法
  下匿名 section 显示为 `@type[idx]`（`-X` 关闭）；`show` 无参数遍历 `uci_list_configs`
  （confdir 下含 `.` 的文件名与非法包名被跳过，按 glob 排序）。
- `changes`：按 saved_delta 顺序输出 `[-]pkg.sec[.opt][=|+=|-=]'v'`。
- `export [pkg]` 带 `package` 头；`commit [pkg]`；`import [pkg]`（`-m` 合并需给包名；无包名时对
  root 下每个包 `commit(overwrite=true)`）；`add <pkg> <type>` 输出新 section 名；`batch` 从
  stdin/`-f` 逐行读取（uci_parse_argument 语法，`exit` 结束，最多 4 个参数，`Unknown command`）。
- 退出码：成功 0；错误 1；参数个数错误 255（并 usage）。`-q` 抑制全部错误输出。
- `set` 值为空字符串 → 等同 delete（目标存在时）或无操作；`delete pkg.sec.list=<idx>` 删除列表
  第 idx 项；`reorder pkg.sec=<pos>` 只有位置变化才记 delta；`rename` 后 section 不再匿名；
  `add_list` 在字符串 option 上把旧值转为首个列表项。

### C6-06 文件系统副作用
- `save`：savedir 不存在时以 confdir 的 mode 创建（否则 0700）；delta 文件 `O_APPEND`、模式
  0600 或与 `<confdir>/<name>` 同 mode；flock LOCK_EX。
- `commit`：先以写方式锁住配置文件；有 delta 时先 save 再重新 import 再 load_delta(flush)；
  写 `<confdir>/.<name>.uci-XXXXXX` 临时文件、fsync、chmod 为原文件 mode、rename；有 delta 且
  flush 成功则 savedir 中的 delta 文件被截断为 0 字节（文件保留）。
- `revert`：过滤 savedir 中该包的 delta 文件（只保留不匹配 section/option 的行）并重写。

## 3. 参考用例

1. 上游 shunit2 全部 11 组测试以 `UCI_BIN=uci-rs` 重放，参考输出只读（去掉 valgrind 包装）。
2. 精确 rootfs 沙箱内的差分矩阵：对设备 `/etc/config` 的 6 个包执行 §2 覆盖的每种命令形式
   （含 `-S -n export`、`-P /var/state set/revert/get`、`-q get` 缺失项、`show` 全部、`changes`、
   `batch`、`add/rename/reorder/del_list`、`commit`、错误输入），比较 stdout、stderr、退出码及
   `/etc/config`、`/tmp/.uci`、`/var/state` 全部文件字节。
3. 设备门禁：`export` 全部、`show` 全部、`changes` 三者原实现与候选逐字节相同。

## 4. 明确保持未定义/不复刻

- 并发：两个进程同时 commit 依赖 flock，与原实现同粒度，不新增锁协议。
- 内存耗尽路径（`Out of memory`）。
- `ucimap`、Lua 绑定、`uci_hash_options`：不在 CLI 路径上。

### 提交失败时保留草稿

候选有意收紧原版先清空 delta 再写配置的失败边界。commit 重放 savedir 时持有其
排他锁，临时配置完整写入并同步、rename 成功后才清空该 delta；创建、写入、同步或
rename 失败返回 I/O error，原有草稿保留以便重试。锁持续到清理完成，避免丢弃期间
另一个 save 新追加的内容。回归 `components/uci/tests/commit_failure.rs` 验证失败后
同一 Context 重试，list-add 只应用一次。这不承诺配置与 delta 的跨文件断电原子性，
也未改变配置文件原有的 flock/rename 并发粒度。

## 5. R92 非 UTF-8 改名的处置

值仍为原始字节；model 的 package/section/option 名是 UTF-8。`rename` 的新名无法表示时，
在修改 model 和 delta 之前返回 INVAL，避免库调用者在同一 Context 内得到 U+FFFD 改名。
不把此拒绝宣称为原版字节兼容：C 接受瞬态原始名字并保存 delta，但随后加载会丢弃其非法改名。

**R88 的同 batch CLI 描述收窄**：两侧 CLI 在每个 batch 命令后卸载包；精确原版的 rename → export
不会直接导出该 raw 名字，raw delta 与立即报错行为仍不同。`r92_compat_probe.py` 的 `uci_rename`
分别验证 section/option、delta、后续加载、配置文件保持及无 U+FFFD；库单测验证 model/delta 原子拒绝。
