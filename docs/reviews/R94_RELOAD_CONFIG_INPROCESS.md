# R94 reload-config：规范化与哈希都在进程内做，一轮零子进程

2026-09-17。目标同其他八个组件：`reload_config`（unchanged_config lane）既优于 C 原版（17 行 shell），也全面优于正式 R89。R93 实机 26 270 µs CPU 对 R89 26 420，四轮重叠——持平。

候选 `e22deec6`（SDK musl 交叉编译、静态、sstrip，477 931 字节，改动前 498 415；合同预算 524 288）。提交：`71a9e2e`（uci：show 渲染器搬入库）+ `98c827b`（reload-config）`。

## 先搞清楚它到底在算什么

原版是 shell：对 `/var/run/uci/*` 和 `/etc/config/*` 的每个文件起一个 `uci show <name>` 子进程写到 `/var/run/config.check/<name>`，再一个 `md5sum` 子进程算全部摘要，与上一轮 `/var/run/config.md5` 比，不一致的逐条 `ubus call service event`。合同 C1-01 把可观测边界定得很清楚：比较对象是 **`uci show` 的逐字节输出**（C-06），含点文件名按 `uci show` 的元组查找规则得到空条目（C-03），基线文件格式是 `md5sum` 的输出格式（§6），持久副作用只有 `/var/run/config.md5`（§5）。它没有要求"必须起子进程"。

R05 的 Rust 候选按 README 的取舍照搬了 shell 的结构：不实现 UCI 解析，调用系统 `uci show`、`md5sum`。于是一轮 unchanged_config 的成本就是 **N+1 次 exec**——Oracle 命名空间里 24 个配置文件：

| 一轮（改动前 head，strace -f） | 次数 |
|---|---:|
| 系统调用总数 | 1 147 |
| `execve` | 50（每个子进程按 PATH 试 `/usr/sbin`、`/usr/bin` 失败后才到 `/sbin/uci`，md5sum 到第四个） |
| `sigaltstack` / `mprotect` / `futex` | 33 / 59 / 31（**每等一个子进程起一个线程**：2 MiB 栈映射、守护页、两次 sigaltstack、futex 对） |
| `mmap` / `close` / `rt_sigaction` | 116 / 103 / 97（24 个动态链接的 C uci 各自的装载） |

Oracle：C 12.1 ms 墙钟 / 13.4 CPU，R89 6.9 / 7.6，head 6.7 / 7.5。路由器上 R93 记录 25.4 ms / 26.3——每个子进程约 1 ms，正是 A53 上 exec + 动态装载的价钱。

**结论**：这个组件没有"算法热点"，它的算法就是"每个配置的规范化视图 → 摘要 → 比对 → 分发"，而规范化视图的定义是 `uci show` 的字节。uci-rs 库已经有一个与 C `uci show` 逐字节等价、被 r16（193 步）和 r24（1 000 例模糊）差分门护着的实现——只是它躲在 CLI 的 bin 里。把它搬进库，reload-config 就能在进程内得到同样的字节；MD5 是 90 行 RFC 1321；两个子进程就都没有了。

## 改动

**uci（`components/uci/src/show.rs`，从 CLI 搬入库）**：`uci_show_value/option/section/package` 与 `uci_lookup_section_ref`（`@type[i]` 计数）原样搬入 `owrt_uci::show::Show`；新增 `show::tuple(ctx, tuple, show, out)` 复刻 cli.c `package_cmd(CMD_SHOW)` 的顺序——扩展查找、元组不完整即 `NOTFOUND`、再按 package/section/option 渲染，查找成功前不写一个字节。CLI 改为调用库，同时去掉了它每次 `show` 对整个 Package 的 `clone()`。uci 五个门重跑全绿。

**reload-config（`components/reload-config`）**：
- `normalize` 改为 `show::tuple` 进程内渲染；一轮共用一个 `Context`（`uci show` 无参数遍历所有包时就是这样），包加载后不再卸载，mallocng 不再在包与包之间把整组内存还给内核再要回来。任何失败（`uci` 退出 1 的情形）输出为空、trace `exit_1`，与 shell 的 `2>/dev/null` 重定向建空文件一致。
- `md5.rs`：RFC 1321，RFC 七个向量 + 55/56/63/64/65 字节填充边界（对照 Python hashlib）单测；基线行格式 `<hex>  /var/run/config.check/<name>` 不变。文件名含换行的条目照旧丢弃并 trace `no_digest`（md5sum 的行被换行切开，shell 原样写进基线）。
- 不再创建 `/var/run/config.check` 及其中的文件——合同 §5 的持久副作用只有 `config.md5`；并发的 C 版 `reload_config` 也不再被我们删目录。
- `process::wait` 改为 `pidfd_open` + `poll(剩余超时)`：没有每子进程一个线程，SIGINT/SIGTERM 打断 poll 后检查取消标志。这条路径现在只剩 `ubus call`（有变更时才走），门 f03（挂起的 ubus 超时后继续本轮、exit 2）和 f06（SIGTERM 取消、exit 75）覆盖。
- 去掉不再可能发生的 `Error::Dependency`/`Error::Timeout`（它们只描述过 uci/md5sum 子进程）。

**门工具（`tools/r1_candidate_check.py`）**：f02（`/sbin/uci` 缺失）和 f09（`/sbin/uci` 被换成对 alpha 睡 3 s 的垫片）原本断言"子进程设计"的表现。现在两种设计都判：子进程设计仍须 exit 70 / trace `timeout`；进程内设计则须**表现得与 uci 在场时完全一样**（f02：alpha 的变更照常分发、基线前进；f09：垫片留下的"被调用"标记不存在且本轮完成）。结果里记 `normalizer` 与 `uci_shim_invoked`。其余 18 例断言未动。

## 正确性门（Oracle，aarch64）

3/3 exit 0（`~/r94-rcb/gates2`，候选 `e22deec6`），uci 的五个门在库改动后也重跑了一遍（`~/r94-rcb/gates`，18:03 UTC，uci-rs `2b2e8090` 即搬入 `show.rs` 后的 CLI）：

- `reload-config-unit` 14 用例（含 md5 的 RFC 向量与填充边界 2 例、pidfd 等待）
- `reload-config-clippy`（`--all-targets -D clippy::undocumented_unsafe_blocks`）
- `reload-config-r1`：**11 个参考用例 + 9 个故障注入用例全部通过**，`gate_passed=true`。f02 记 `normalizer=in-process`（`/sbin/uci` 缺失时 alpha 的变更照常分发、基线前进、exit 0）；f09 记 `uci_shim_invoked=false`（睡 3 s 的垫片从未被调用，本轮正常完成）。基线文件 `/var/run/config.md5` 与 shell 版逐字节相同（参考用例的比较对象）。
- `uci-unit`、`uci-clippy`、`uci-r16`（193 步相同）、`uci-r24`（1 000 例 differing=0）、`uci-r83`（554 文件相同）：5/5 exit 0——CLI 改为调用库的 `show::tuple` 后行为未变。

第一次跑 r1 时（`~/r94-rcb/gates`）它是红的：f02/f09 还在断言子进程设计的表现（exit 70、trace `timeout`）。改门的判据（上节）后重跑绿，两次的 reference 11 例都绿——门的改动只触及这两个故障用例。

## 性能（Oracle 私有命名空间，unchanged_config，N=100，四侧交错）

单位 µs/轮；`child cpu` 受 10 ms tick 量化，看墙钟。

| 侧 | 墙钟 | CPU | 系统调用/轮 | `execve`/轮 | `mmap`/`munmap` | 线程 |
|---|---:|---:|---:|---:|---:|---:|
| C（shell） | 11 297 | 12 600 | — | 25+ | — | 0 |
| R89 | 7 028 | 7 800 | 1 147 | 50 | 116 / 44 | 24 |
| head（改动前） | 6 851 | 7 700 | 1 147 | 50 | 116 / 44 | 24 |
| **候选 `e22deec6`** | **1 062** | **900** | **223** | **1**（进程自身） | **31 / 28** | **0** |

候选比 R89 **-84.9%** 墙钟、-88.5% CPU；比 C -90.6%。剩下的 223 次系统调用里约 24×（`stat`+`openat`+`fcntl`+`flock`×2+`read`+`close`）是逐包加载，其余是运行锁、基线读写与 Rust 运行时序言——这条 lane 里它们已经不是主项，不再追。

## 性能：实机三侧四轮（stock C / 正式 R89 / 候选）

AX3000T，全 C 生产栈未切换（health 探针 24 项前后逐项相同，`boot_id` `c972c9a8` 一致，窗口后无残留进程与 `/tmp/r85-*`，`/sbin/reload_config` 仍是 17 行 shell）；私有命名空间内每轮 100 次操作，三侧交错四轮共 12 次负载测量，`acceptance_eligible=true`、`host_gates_passed=true`。单位 µs/轮，中位数 [四轮最小–最大]。`private/r94/device-rc-01`。

| lane | 指标 | stock C | R89 | **候选 `e22deec6`** | 比 C | 比 R89 | 与 R89 逐轮范围 |
|---|---|---:|---:|---:|---:|---:|---|
| unchanged_config | p50 | 40 082 [39 978–40 384] | 25 404 [25 348–25 492] | **4 450 [4 368–4 522]** | **-88.9%** | **-82.5%** | 不重叠 |
| unchanged_config | CPU | 41 570 [41 480–41 920] | 26 350 [26 320–26 400] | **4 070 [4 020–4 120]** | **-90.2%** | **-84.6%** | 不重叠 |

**对 C：1/1 双优；对 R89：1/1 双优，范围不重叠。** R93 记录的"与 R89 四轮重叠、持平"变为 -82.5%。路由器上 R89 每轮 25.4 ms 对候选 4.5 ms，差额 21 ms 就是 24 个 `uci show` 子进程 + 1 个 `md5sum` 在 A53 上的 exec、动态装载和每子进程一个 2 MiB 栈线程的价钱；候选剩下的 4.5 ms 里大头是 24 个配置文件的读取与解析（与一次 `uci export` 的 1 ms 同量级 ×24 的一小部分，因为共用一个 Context 且不写输出）。

只覆盖 unchanged_config lane（基准矩阵就这一条）。改动传播路径（有差异 → `ubus call service event`）由 r1 的 11 个参考用例在 Oracle 上逐字节校验（分发集合、顺序、基线更新、exit 码），没有实机性能数字——它的成本由 ubus 调用次数决定，本轮未改。

## 可复用件

`~/r94-rcb/`：`build.sh`（`CRATES`/`MANIFEST_CRATE`/`BIN_NAME`/`OUT`/`SYMS`/`EXTRA_RUSTFLAGS`）、`prof/run.sh cpu|strace|perf|probe unchanged_config N SIDE...`（workload 复刻 isolated.sh 的双侧 prime + `cmp` 基线）、`run-gates.sh`（`GATES=` 子集、`OUT_DIR=`）。
