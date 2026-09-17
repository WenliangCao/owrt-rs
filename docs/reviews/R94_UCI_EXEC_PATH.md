# R94 uci：一次执行的系统调用与分配，逐条对账

2026-09-17。目标同其他组件：`uci -S -n export network`、`export r84fixture`（64 节）、`set`+`commit`+`get` 三条 lane 既优于 C 原版（libuci + 动态链接），也全面优于正式 R89。方法仍是先量再改，但 uci 和别的组件不同：它是一个几百微秒就退出的进程，没有守护进程的算法热点，成本几乎全在"进程一生"里——exec、运行时初始化、每次 open/read 的系统调用、每个值的复制。所以这轮的研究对象就是一次执行的完整系统调用序列和堆调用序列，逐条问"这一次是必要的吗、libuci 也做吗"。

候选 `c3b51560`（SDK musl 交叉编译、静态、sstrip，486 155 字节，改动前 506 635）。一个提交：`14c02a6`。

## 量出来的东西

**基线（Oracle 私有命名空间，N=100）**：export_network C 516 µs 墙钟 / 400 CPU，R89 316/100，改动前 head 289/100；export_64 791/700、475/400、483/400；set_commit_get 2 711/2 700、2 050/2 000、2 057/2 000。R89 与 head 是同一段代码加 R92 修复，实机上 R93 已记录 head 三条全胜 R89 且范围不重叠。

**一次 `export network` 只有 36 次系统调用**，`strace -f -tt -T` 逐条看：

| 类别 | 次数 | 内容 |
|---|---:|---|
| Rust 运行时序言 | 14 | stdio `ppoll`、`rt_sigaction`×5（SIGPIPE 忽略、SIGSEGV/SIGBUS 栈溢出处理器）、`sigaltstack`×3、备用栈 `mmap`+`mprotect`+`munmap`、`rt_sigprocmask` |
| musl/mallocng 初始化 | 5 | `set_tid_address`、`brk`×2、首批组 `mmap`×2 |
| **本体** | 17 | conf2 `stat`、配置 `stat`+`openat`+`fcntl(F_SETFD)`+`flock`+**`lseek(0)`**+`read`+**`read`(EOF 探测)**+`flock(UN)`+`close`、delta 目录 `stat`×2、`mmap`/`munmap`（BufReader 组）、`write`、`exit_group` |

本体 17 次里三次是多余的：刚打开的描述符本来就在偏移 0，`lseek(0)` 白做；`BufReader` 8 KiB 缓冲要一次 `read` 读满再一次 `read` 读到 0 才知道到头，而文件大小 fstat 早就知道；8 KiB 缓冲本身让 mallocng 新开一个组，`mmap`+`munmap`+一次零页缺页。`set_commit_get` 里同一模式乘三次执行：`lseek` 13 次、`load_delta` 为读 delta 文件还 `try_clone()` 复制描述符（`fcntl(F_DUPFD_CLOEXEC)`+`fcntl(F_SETFD)`+多一次 `close`）。`fcntl(F_SETFD, FD_CLOEXEC)` 紧跟每次 `openat` 的那一次是 musl 自己的 `open()` 包装加的，C libuci 同样付，不动。

**堆**：uprobe 打在 `__libc_malloc_impl`/`__libc_realloc`/`__libc_free`，带帧指针的符号构建，按调用链归属。export_network 每次 129 malloc / 95 free，其中 **`export::escape` 34 次**——每个节名、类型、选项名、值都先 `to_vec()` 复制一份再写，绝大多数值里根本没有需要转义的 `'`；`parse::import` 20（值本身）、`load_delta` 9、`load_impl` 7.5（10 KB，就是那个 8 KiB BufReader）。set_commit_get 482 malloc，`load_delta` 60 次 42 KB（每个 delta 文件一个 BufReader）、`commit` 17 次 21 KB。另外 `main` 一进来就 `Box<BufReader<Stdin>>` 分配 8 KiB——只有 batch/import 才读 stdin。

**perf**：uci 进程 32% 在内核、4.8% 在用户态；用户态里分配器 1.4%，解析器 0.6%。没有可砍的算法热点，只有上面这些"每次执行都付一遍"的固定开销。

## 改动（一个提交）

- `export::write_escaped`：直接向流写，遇到 `'` 才分段写 `'\''`，不再复制；`size_hint` 按包内容估一次输出长度。export 走一块预定容的缓冲一次 `write(2)`，`BufWriter` 对 export 改为零容量（只有 show/changes 逐行输出才要 8 KiB）。
- `file::read_whole`：fstat 取长度，`len+1` 的缓冲一次 `read` 读完（常规文件短读即 EOF；只有锁下被人写大的文件才继续读到 0）。`load_impl`、`commit` 的重读、`load_delta_file`、`filter_delta` 全部改用它，解析器从切片读。`try_clone()` 的描述符复制删除。
- `open_stream` 不再对刚打开的描述符 `lseek(0)`，只在 `seek_end` 时移到末尾。
- stdin 读取器改为首次使用才打开；argv 只在解析选项词时转成 `String`，命令元组保持字节。

结果（Oracle）：export_network 每次 malloc 129→92、free 95→62；set_commit_get 482→437；`lseek` 13→0、dup 的 `fcntl` 6 次→0、EOF 探测 `read` 消失。行为不变：r16 差分、r24 1000 例模糊差分、r83 均逐字节相同。

**Rust 运行时序言**（14 次系统调用加一个 16 KiB 备用栈映射）是三条 lane 里最大的单项，先用试验构建单独量了它（`nm-patch.py`：上面几项都不含时 export_network 311→287、export_64 478→451、set_commit_get 2 118→2 046），确认值得，才并入候选：bin 加 `#![no_main]`，从 libc 拿 `main(argc, argv)` 自己组 argv，其余 std 照用（`process::exit` 仍会冲刷 stdout）；SIGPIPE 从 Rust 默认的忽略回到系统默认——C uci 本来就是默认。静态 musl 链接因此少了一个对 `getauxval` 的引用，`compiler_builtins` 的 outline-atomics 初始化在链接顺序上晚于 libc.a 就找不到它；`build.rs` 只在 musl 目标上加 `-Wl,-u,getauxval`，让链接器提前从 libc.a 取出该成员。build.sh/CI 的参数不动。

## 正确性门（Oracle，aarch64）

5/5 exit 0，且每个门都真的比了东西：

- `uci-unit`：lib 17 + config_listing 3 + bin/doc 16 用例
- `uci-clippy`（`--all-targets -D clippy::undocumented_unsafe_blocks`）
- `uci-r16`：两份 rootfs 副本、候选 bind-mount 到 `/sbin/uci` 后跑同一命令脚本，**193 步全部相同**（stdout/stderr/rc + `/etc/config`、`/tmp/.uci`、`/var/state` 内容与权限）
- `uci-r24`：以镜像自带配置为种子的字节级模糊差分，**1 000 例 differing=0**
- `uci-r83`：R81 F25 findings 差分，**554 个文件逐字节相同**

候选还在 macOS 上做了 batch（stdin 惰性打开）、`-f`、usage、not-found、`-q` 的冒烟；`config_listing` 里有一例只在 macOS 失败，改动前同样失败（glob 语义回退路径），Linux 上通过。

## 性能（Oracle 私有命名空间，N=200，四侧交错）

单位 µs/次；`child cpu` 受 10 ms tick 量化，看墙钟。

| lane | R89 | head（改动前） | **候选 `c3b51560`** | 候选比 R89 | 候选比 head |
|---|---:|---:|---:|---:|---:|
| export_network 墙钟 | 323 | 315 | **272** | **-15.8%** | -13.7% |
| export_64 墙钟 | 470 | 484 | **456** | **-3.0%** | -5.8% |
| set_commit_get 墙钟 | 2 132 | 2 142 | **2 038** | **-4.4%** | -4.9% |
| export 系统调用/次 | 36 | 36 | **21** | | |
| set_commit_get 系统调用/次（含 sh） | 276 | 276 | **234** | | |
| export malloc/次 | 129 | 129 | **86** | | |

C 原版同一命名空间：export_network 516、export_64 791、set_commit_get 2 711。

## 性能：实机三侧四轮（stock C / 正式 R89 / 候选）

AX3000T，全 C 生产栈未切换（health 探针 12 项前后逐项相同，`boot_id` `c972c9a8` 一致，窗口后无残留进程与 `/tmp/r85-*`）；私有命名空间内每轮 100 次操作，三侧交错四轮共 36 次负载测量，`acceptance_eligible=true`、`host_gates_passed=true`。单位 µs/次，中位数 [四轮最小–最大]。`private/r94/device-uci-01`。

| lane | 指标 | stock C | R89 | **候选 `c3b51560`** | 比 C | 比 R89 | 与 R89 逐轮范围 |
|---|---|---:|---:|---:|---:|---:|---|
| export_network | p50 | 2 030 [2 026–2 033] | 1 171 [1 170–1 173] | **1 012 [1 010–1 015]** | **-50.1%** | **-13.6%** | 不重叠 |
| export_network | CPU | 1 760 [1 760–1 760] | 930 [920–940] | **770 [760–780]** | **-56.2%** | **-17.2%** | 不重叠 |
| export_64 | p50 | 3 627 [3 612–3 634] | 2 174 [2 159–2 179] | **1 956 [1 940–1 977]** | **-46.1%** | **-10.0%** | 不重叠 |
| export_64 | CPU | 3 270 [3 260–3 280] | 1 860 [1 860–1 880] | **1 660 [1 640–1 660]** | **-49.2%** | **-10.8%** | 不重叠 |
| set_commit_get | p50 | 9 366 [9 347–9 451] | 7 263 [7 228–7 323] | **6 567 [6 537–6 662]** | **-29.9%** | **-9.6%** | 不重叠 |
| set_commit_get | CPU | 9 000 [9 000–9 020] | 6 900 [6 880–6 940] | **6 250 [6 220–6 300]** | **-30.6%** | **-9.4%** | 不重叠 |

**对 C：3/3 双优；对 R89：3/3 双优，六项逐轮范围全部不重叠。** 路由器上的收益比 Oracle 大（export_network 墙钟 -13.6% 对 Oracle 的 -15.8%，CPU -17.2%；set_commit_get -9.6% 对 -4.4%）：A53 上每次系统调用、每次 mallocng 调用、每个零页缺页都更贵，而这轮砍掉的正是这三样。

## 可复用件

`~/r94-ucib/prof/`：`run.sh cpu|strace|perf|probe LANE N SIDE...`（无守护进程，命名空间内写 isolated.sh 的同一份 network/r84fixture 夹具）、`probe-setup.py`、`attrib.py`、`phases.py`、`nm-patch.py`（试验用 C 入口补丁）。
