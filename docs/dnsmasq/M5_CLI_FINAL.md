# M5 `log-malloc` 与全部选项 `--test`

## `log-malloc`：按修订合同关闭

用户明确要求匹配接受、启动及 `--test`，分配日志内容列为行为差异。
镜像 C 的分配包装器是真实消费者：`dnsmasq.c:858` 在日志和 helper
启动后启用开关，`dnsmasq.h:1507` 的无条件宏调用 `util.c:931–1019`
中的 malloc/realloc/free 日志。不能把它解释成 musl 不存在消费者。

Rust 接受该选项并正常启动，不输出逐次分配日志，也不安装全局分配器。
C 的函数、行号、尺寸及指针低 24 位日志没有对应的 Rust 日志。详细差异见
[行为差异表](M5_BEHAVIOR_DIFFERENCES.md)。已退休实验保留在 durable refs
和独立归档中；实验结果不算当前生产功能资格。

`f54b65e0` 的实际 Linux ELF 为 1,912,872 字节，SHA256：
`e5422f0f2ea623a029e73d77c1e4a39a9baef109d8ebe916f415c679807eef42`。
`a5a2396e` 工具完成 **15 paired，0 missing，0 failures**：

- 5 个语法控制：配置文件、CLI、重复、禁止参数、`--test` gate。
- 10 个普通运行调用：port=0、local DNS、forward/cache、hosts HUP、
  TFTP、stderr/file/syslog、TERM、64 个正常长度 DNS 查询。

所有非分配日志按原有顺序逐项比较，只去掉时间与 PID 前缀。
DNS 语义、FD 数、TERM 成功与最终退出日志一致。C 实际分配日志保留；
Rust 无分配日志也保留，未伪造地址或 C 调用点。

本地资格收据：
`private/dnsmasq-rewrite/evidence/M5/cli-final/close-logmalloc-f54-20261005.json`。
完整正式归档 SHA256 为
`1c02aabad3c9f465f6e53b8b3e8f699b93fc19535212d0e9ae0ad64a806ebc7c`，
3,729 entries、2,914 regular files。归档在本地逐项核对 SHA256、类型、权限、
所有者、纳秒 mtime、链接、设备号及全部 xattrs 后才删除远端运行目录。

## `--test`：冻结全部 169 个普通选项

清单包含 169 个可用选项，每项 CLI/配置文件各一例，共 338 例；另有
7 个控制：空、重复、未知 CLI 选项、cross-option、CNAME loop、禁止
daemon 运行产物、conf-script 的真实解析副作用。
26 个镜像不支持的选项在清单中另列，不计入 169。

所有案例按镜像 C 的退出码、stdout、stderr 和解析副作用逐项比较。
唯一文本归一化例外是 `--test --version` 的现有 Rust implementation
身份注释；原始字节完整保留。`--test` 不产生 pid/log/dump/leases，
但 C 的 conf-script 在解析时运行，因此它的副作用必须匹配。

`f54b65e0` 正式完成 345 paired：338 个普通形式均成功；344 个结果匹配。
未知 CLI 选项诊断仍有一处差异，尚未关闭 `test`：C 输出
`bad command line options: try --help`，Rust 输出 `bad option`。
正式失败结果已包含在上述归档中，修复后须用新候选重新执行全部冻结清单。

早期完整运行分别保存在 `retired-cal01` 和 `final01-calibration`，
归档 SHA256 为
`39f7ef494f2b95cf186f440df412491512d1d0ee649dab25ff15e56b70979b32` 和
`8d83d7aa2ec75428912d05115696425caa4667b18478f35d35e7d367199e2ae9`。
两者均已完成本地全元数据验证，之后才 prune。极端数值、畸形组合继续
按现有延期范围处理，未执行的场景不计通过。
