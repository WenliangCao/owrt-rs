# R94 fw4：flowtable 判定直接问内核 + 解析/渲染零拷贝

2026-09-17。目标同其他八个组件：`fw4 print` / `fw4 check` 既优于 C 原版（ucode 解释器），也全面优于正式 R89。本轮是**重做**：前一轮（`bc48e09`/`2355740`，候选 `4624414b`）用一个 208 行的自定义 `#[global_allocator]` 换掉 musl 的 mallocng，用户不满意，已从分支移除（保留在 `refs/discarded/fw4-opus-r94`）。本轮不替换分配器，而是先量清楚 fw4 每次运行到底把时间花在哪里，再只改那些地方。

候选 `3be616b0`（SDK musl 交叉编译、静态、sstrip，1 043 155 字节，比改动前的 1 059 539 还小）。两个提交：`5ee91a9`（内核判定）、`4b515a8`（零拷贝解析/渲染）。

## 量出来的三件事

**1. 一个布尔值花掉一半的 print。** `strace -f -tt -T` 时间线（Oracle，命名空间内 C ubusd + C netifd）：一次 print 共 12.0 ms，其中 4.85→10.77 ms 在等子进程 `sh -c "/usr/sbin/nft --terse --json list flowtables inet"`——两次 execve、nft 的四个动态库、一次 JSON dump 和解析，只为回答"表 `inet fw4` 里有没有 flowtable `ft`"。路由器上直接计时：`sh -c nft --json list flowtables` 每次约 5.5 ms，R89 的 print 是 10.7 ms。上游 `fw4.uc` 就是这么做的，R89 照抄了它。

**2. 剩下的用户态一半在分配器里，而分配的一半是复制。** 带符号 `perf record -a`：fw4 自身用户态 7.2%，其中 `__libc_free`/`__libc_malloc_impl`/`alloc_slot`/`nontrivial_free`/`__libc_realloc` 合计 3.3%，单个业务函数最高只有 0.26%（UCI 词法）。于是给 musl 的 `__libc_malloc_impl`/`__libc_realloc`/`__libc_free` 挂 uprobe（`malloc` 是弱别名探不到；探针要打在命名空间 bind-mount 进去的那个 bundle inode 上），用 `-Cforce-frame-pointers=yes` 的符号构建录 20 次 print，按调用链归属到 fw4 函数：

| 每次 print | 次数 | 主要来源 |
|---|---:|---|
| malloc | 2 075 | `Json::clone` 392（`load()` 逐节 `.cloned()`、`Opts::opt/list` 每次取值 `.cloned()`）、`Config::from_package` 331、`owrt_uci::parse::import` 154、`field_to_json` 115、`to_str` 97、`parse_helper` 86、`Zone::clone` 79、`Helper::clone` 69、`defaults()` 69、`includes` 42、`to_lowercase` 37 |
| realloc | 204 | `from_package` 31、`parse_helper` 30、`quote` 16、`render_zone_match` 14 |
| free | 2 071 | 对应上面 |

1 681 次（81%）不超过 32 字节。总量只有 161 KB，问题是次数：A53 上一次 mallocng 调用几百纳秒，四千次就是毫秒级。

**3. 系统调用 303 次，其中 mmap/munmap 46/28 全是 4–28 KiB 的 mallocng 组来回换页**——短命对象成批生灭，组空了就 munmap，下一批再 mmap。这是分配次数的副产品，减少分配就减少它，不必换分配器。

## 改动

### `5ee91a9`：flowtable 判定改问 nf_tables（`components/fw4/src/flowtable.rs`，115 行含测试）

一个 `NETLINK_NETFILTER` 套接字发 `NFT_MSG_GETFLOWTABLE`，属性 `NFTA_FLOWTABLE_TABLE="fw4"`、`NFTA_FLOWTABLE_NAME="ft"`，family `NFPROTO_INET`——正是 nft 那条命令过滤出的三元组。**不带 `NLM_F_ACK`**：存在时内核只回一个 `NEWFLOWTABLE` 对象，不存在（表或 flowtable 任一缺失）只回一个 `NLMSG_ERROR(-ENOENT)`，两种情况都是恰好一个数据报，一次 `recvfrom` 结束。请求在 64 字节栈缓冲里组装，回复 8 KiB 栈缓冲，`MSG_TRUNC` 让超长回复被识别并拒绝，序列号校验。共 5 次系统调用：socket、setsockopt（1 s 接收超时，只为回复被丢时能回退而不是挂死）、sendto、recvfrom、close。

任何非干净回答（没有 netfilter netlink、EPERM、未知消息类型、截断、超时）返回 `None`，调用方原样走 nft popen；mock 后端（上游测试集用 `FW4_MOCK_DIRS`）完全不走这条路。因此可观察输出不可能与 firewall4 不同。`check_set_types()`（`reload-sets` 用）仍走 nft：集合类型名在 netlink 里是位域，不在 print/check/start 路径上。

### `4b515a8`：解析与渲染不再复制配置

- `Opts::opt`/`Opts::list` 借用选项值（原来每次 `s.get(key).cloned()`，约 600 次/print），只有解析结果是自有的；列表就地遍历，其他类型仍走 `to_array()`。
- `load()` 原来对每类节 `of_type(..).cloned().collect()` 才能在遍历时调 `&mut self` 的解析器；两个配置改成 `Rc<Config>`，遍历借用 Rc 句柄（`parse_zone` 还要查 `self.firewall` 解析 network/ipset，所以不能简单地把配置挪出去）。
- `Config::from_package` 消费 libuci 的 Package：节名、类型、选项名移动进 JSON 对象而不是复制，每个对象一次定容。
- `render_ruleset` 原来把 helper、ipset、zone 三个向量整个克隆，逐 zone 的三个链循环又各克隆一遍 zone；`parse_zone` 为 auto-helper 克隆整张 helper 表。现在全部借用。
- `defaults()` 原来每次返回 `Defaults` 的克隆（策略查询、offload 标志都调它）；改为返回已解析默认值或静态空值的引用。
- `includes()` 原来 Vec 收集格式化行再 concat；`write_includes` 直接追加到输出。`set()` 直接写花括号列表，不再 Vec + join + format。
- `parse_enum` 原来把值和每个候选的前缀都 `to_lowercase()`；所有候选都是 ASCII，改为逐字节忽略大小写比较（非 ASCII 输入保留原路径）。`parse_protocol` 不再小写到一个串再复制到另一个串。

每次 print：malloc 2 075→1 140，realloc 204→160，mmap/munmap 27/25→22/20，系统调用 303→142（含内核判定省下的 161 次）。剩下的 1 140 次里，`owrt_uci::parse::import`+`add_section` 207 次是 libuci 忠实解析器内部、`field_to_json` 115 次是 ubus 回复转 JSON、`from_package` 174 次是每节四个元数据键与选项值本身——都是数据，不是复制。

## 正确性门（Oracle，aarch64，候选 `3be616b0`）

7/7 exit 0，且每个门都真的比了东西：

- `fw4-unit` 17 用例（新增 3：请求字节布局、回复解释含外来序列号/`NLMSG_DONE`/短错误、`exists()` 全域不 panic）
- `fw4-clippy`（`-D warnings`，`undocumented_unsafe_blocks`）
- `fw4-upstream`（r09，firewall4 上游测试集）31 用例 0 失败
- `fw4-r29` 200 例模糊差分 `differing=0`
- `fw4-defaults`（r83）12 例
- `fw4-image` 镜像 rootfs 隔离运行
- R92 兼容探针 `r92_fw4_probe`（abort/include/state 用例全 passed）

另加两态判定差分（`prof/run.sh ftcheck`）：命名空间里 `nft -f -` 真建出 `inet fw4` 的 flowtable `ft`，C fw4 与候选 `print` 逐字节相同；`nft delete table inet fw4` 后重跑仍相同；`delete flowtable inet fw4 ft` 一行有:1/1、无:0/0。

## 性能（Oracle 私有命名空间，N=60 print / N=30 check，与 R89 和改动前 head 交错）

单位 µs/次。`child cpu` 是子进程 user+sys 合计除以次数（tick 量化）。

| lane | C（stock） | R89 | head（改动前） | 仅内核判定 | **候选** | 候选比 R89 |
|---|---:|---:|---:|---:|---:|---:|
| print 墙钟 | 19 646 | 2 591 | 2 567 | 1 121 | **1 042** | **-59.8%** |
| print CPU | 19 333 | 2 333 | 2 333 | 833 | **667** | **-71.4%** |
| check 墙钟 | 30 892 | 13 662 | 13 622 | — | **11 719** | **-14.2%** |
| check CPU | 22 333 | 5 000 | 5 667 | — | **3 667** | **-26.7%** |

check 的墙钟大头是 `nft -c -f -` 子进程在内核里做真正的校验（Oracle 约 10 ms，路由器约 50 ms），不是 fw4 的开销；fw4 自己那部分就是 print 那一列。

## 性能：实机三侧四轮（stock C / 正式 R89 / 候选）

AX3000T，全 C 生产栈未切换（health 探针 12 项前后逐项相同，`boot_id` `c972c9a8` 一致，窗口后无残留进程与 `/tmp/r85-*`）；私有命名空间内每轮 100 次操作，三侧交错四轮共 24 次负载测量，`acceptance_eligible=true`、`host_gates_passed=true`。单位 µs/次，中位数 [四轮最小–最大]。`private/r94/device-fw4-02`。

| lane | 指标 | stock C | R89 | **候选 `3be616b0`** | 比 C | 比 R89 | 与 R89 逐轮范围 |
|---|---|---:|---:|---:|---:|---:|---|
| print | p50 | 98 843 [98 522–99 138] | 10 778 [10 657–10 800] | **4 109 [4 049–4 155]** | **-95.8%** | **-61.9%** | 不重叠 |
| print | CPU | 95 850 [95 600–96 200] | 9 500 [9 500–9 500] | **3 200 [3 200–3 200]** | **-96.7%** | **-66.3%** | 不重叠 |
| check | p50 | 149 642 [140 609–149 894] | 59 977 [59 917–60 051] | **54 939 [50 049–59 705]** | **-63.3%** | **-8.4%** | 不重叠 |
| check | CPU | 107 300 [107 200–107 400] | 19 900 [19 900–20 000] | **13 400 [13 400–13 600]** | **-87.5%** | **-32.7%** | 不重叠 |

**对 C：2/2 双优；对 R89：2/2 双优，四项逐轮范围全部不重叠。** R93 记录的 check 延迟对 R89 +1.24% 反转为 -8.4%（check 的墙钟由 `nft -c` 主导，四轮里 50–60 ms 的摆动是 nft 自己的）。

**与被否决的前一轮相比（同一路由器、同一 boot）**：前一轮 print p50 3 619 / CPU 2 600，本轮 4 109 / 3 200——本轮每次 print 慢约 0.5 ms。差额就是仍留在 musl mallocng 里的那约 1 100 次数据分配和 22/20 次组换页：前一轮用自定义分配器把它们全部吃掉，本轮选择不替换分配器，只删掉复制。剩余分配里 `owrt_uci` 解析器内部约 230 次、ubus 回复转 JSON 约 115 次，都在共享 crate 里，属于下一个可量化的目标，但不在本轮范围。

check 的墙钟仍有约 50 ms 在 `nft -c -f -` 子进程——那是 nft 在内核里做真正的校验，不是 fw4 的开销；CPU 一栏（13.4 ms 对 R89 19.9）才是 fw4 自己的部分。

## 研究过程的可复用件

`~/r94-fw4b/prof/`：`run.sh cpu|strace|perf|probe|ftcheck LANE N SIDE...`（命名空间内 C ubusd + C netifd，`probe` 模式会把 uprobe 打到本次 bundle 的 inode 上再 `perf record -a -e fw4:*`）、`probe-setup.py`（从符号构建算 `__libc_malloc_impl`/`__libc_realloc`/`__libc_free`/`calloc` 的文件偏移并写 `uprobe_events`）、`attrib.py`（把每次堆调用归属到调用链里第一个 fw4/owrt 函数）、`phases.py`（strace 时间线分阶段）。
