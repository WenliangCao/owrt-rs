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

## `--test`：全部 169 个普通选项关闭

清单包含 169 个可用选项，每项 CLI/配置文件各一例，共 338 例；另有
7 个控制：空、重复、未知 CLI 选项、cross-option、CNAME loop、禁止
daemon 运行产物、conf-script 的真实解析副作用。
26 个镜像不支持的选项另计为 excluded capabilities，不计入 169。

所有案例按镜像 C 的退出码、stdout、stderr 和解析副作用逐项比较。
唯一文本归一化例外是 `--test --version` 的现有 Rust implementation
身份注释；原始字节完整保留。`--test` 不产生 pid/log/dump/leases，
但 C 的 conf-script 在解析时运行，因此它的副作用必须匹配。

`39ff36d7` 修复未知/歧义 CLI 的诊断后重新执行完整冻结清单，
**345 paired，0 missing，0 failures**。338 个普通形式全部成功；
7 个控制按 C 的实际状态、输出和副作用匹配。
未知 CLI 选项输出 `bad command line options: try --help`；
配置文件未知选项仍保留 C 的 `bad option` 边界。

候选 ELF 为 1,929,256 字节，SHA256：
`8acf35fd17e5d08aa18e52b35da9e5702dfbeb21629205b48fa431fa38376f62`。
这是同一候选上的全部 169 选项语法复扫；各功能族的运行资格仍绑定各自的
独立候选及完整证据。后续消费者变化需要重跑受影响的普通契约，不能把
本次结果套用到未执行过的代码。

最终归档 SHA256 为
`5a5ee79f87d67d8a69d13d39c27e0a7a44af6ac4a7de5d177874fa01b45145d7`。
3,166 entries、2,426 regular files 均完成本地全元数据验证，之后才 prune。
本地资格收据位于
`private/dnsmasq-rewrite/evidence/M5/cli-final/close-test-39ff-20261005.json`。
此前 `f54b65e0` 的正式失败结果（344/345，未知 CLI 诊断差异）仍在
`final02-f54` 归档中，未删除或改写失败证据。

早期完整运行分别保存在 `retired-cal01` 和 `final01-calibration`，
归档 SHA256 为
`39f7ef494f2b95cf186f440df412491512d1d0ee649dab25ff15e56b70979b32` 和
`8d83d7aa2ec75428912d05115696425caa4667b18478f35d35e7d367199e2ae9`。
两者均已完成本地全元数据验证，之后才 prune。极端数值、畸形组合继续
按现有延期范围处理，未执行的场景不计通过。
