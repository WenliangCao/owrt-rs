# R125 八事件对象 fan-out：精确 ELF 平坦采样结果

冻结计划的 8 个正式 Oracle 窗口全部完成，计数、身份、ACK、丢样和节流检查通过。
R124 的 6,856 个样本中内核态占 89.75%；703 个用户态样本全部能匹配精确 ELF 的符号范围。
C 的 6,933 个样本中内核态占 84.51%；1,074 个用户态样本仍有 600 个未知。
这些是 daemon 的平坦 self PC，用于定位后续源码审查对象，不能解释 caller CPU 差距，也不构成路由器性能比值。

本轮按 [冻结计划](R125_UBUSD_FANOUT_PROFILE_PLAN.md) 和
[固定 JSON](r125-profile-plan.json) 执行；完整派生检查、逐窗计数、符号统计、未知覆盖和
269 个原始文件的 SHA-256 索引见 [结果 JSON](r125-fanout-profile-results.json)。
两个 `n=1000 / warmup=100` 的仪器 smoke 窗口排除在正式统计之外。

这里的 `listeners=8` 是**同一个 libubus listener 连接上的 8 个已注册事件对象**，不是 8 个独立客户端。
[helper 源码](../../tools/benchmark/user_event_libubus.c) 的 `run_user_event` 创建一个 sender 连接和一个 listener 连接，
随后把 `handlers[8]` 逐个注册到同一个 listener；这个函数从 perf-control 引入提交 `16917f2` 至今未变化。
64-held 表示另外 64 个经过 lookup 验证的空闲连接。
每次发送 `bench.user` 后，同步处理 listener，直到收到 8 个带预期 `value=0x12345678` 的回调，再发送下一次。
它不覆盖 8 个独立 listener 连接的调度与队列成本。

实际 caller 固定为原 v3 ACK ELF，SHA-256
`d8240a8fd3d7035349e20fed27eac53e51bf07e5098f77a52915044db87e00e7`；本轮未重建 helper。
被测 C ELF 为 `cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88`，
R124 ELF 为 `42435a31e2917186fb353e2c70143f4b3f6d82ec3dd53265bf6d826897b69926`。
runner 固定为 `92b33e3449d833d64a28076abf8bb12d5d2deb52685ea51788d90c6910789ec9`；
其余工具、库与符号证据哈希均在 JSON 的 `identity` 中。

每窗 `n=100000 / warmup=5000`，实收 `800000 / 40000`；daemon 固定 CPU1，caller 固定 CPU0，
统一 daemon argv0 为 `/sbin/ubusd`。`cpu-clock` 499 Hz、无 callgraph、`--strict-freq`、8 MiB ring buffer；
perf 初始关闭，helper 在 warmup 后等待 enable ACK，在循环及计时读取后等待 disable ACK。
平台为 Oracle aarch64，内核 `6.17.0-1020-oracle`。

| 正式顺序 | ELF | held | 块 | 总样本 | 内核态 | 用户态 | 未解析用户态 |
|---|---|---:|---:|---:|---:|---:|---:|
| 001 | C | 0 | 1 | 1709 | 1452 | 257 | 147 |
| 002 | R124 | 0 | 1 | 1718 | 1538 | 180 | 0 |
| 003 | C | 64 | 1 | 1761 | 1487 | 274 | 146 |
| 004 | R124 | 64 | 1 | 1715 | 1538 | 177 | 0 |
| 005 | R124 | 64 | 2 | 1718 | 1552 | 166 | 0 |
| 006 | C | 64 | 2 | 1740 | 1493 | 247 | 141 |
| 007 | R124 | 0 | 2 | 1705 | 1525 | 180 | 0 |
| 008 | C | 0 | 2 | 1723 | 1427 | 296 | 166 |

根目录及八窗均有 COMPLETE，无 FAILED 标记。每窗 `LOST / LOST_SAMPLES / THROTTLE / UNTHROTTLE` 均为 0，
report 的 Total Lost Samples 为 0，原始样本数与 perf stats、解析结果一致，无未解析文本行。
PID/starttime、单线程、affinity、启动命令、前后可执行映射及精确 ELF/库身份一致；
C 的 `/proc/exe` 是精确 musl loader，实际 C ELF 另以 maps 验证，R124 验证静态 ELF。
24 个子进程 PID 互异；client/daemon 退出码均为 0，perf 均为 runner 正常 SIGINT 停止的 −2。
269 个原始文件逐一匹配从 Oracle 取回的哈希索引，解析及整理后保持不变。

符号解析沿用 `tools/r121_symbolize.py`：R124 使用与测量 ELF 配套的精确 linker map；
C companion 按加载地址核对 `.text` 字节，共享库仅使用精确 ELF 的动态 FUNC 符号。
“R124 全部解析”仅指本次采到的 703 个用户态 PC 均落在已知范围，不代表所有内联函数、路径或调用次数都有覆盖。
原始 stripped ELF 和 IP 证据保持原样，未用诊断重建 ELF 替换测量对象。

| ELF | 总样本 | 内核态及占比 | 用户态已解析 | 用户态未知 |
|---|---:|---:|---:|---:|
| C | 6933 | 5859（84.51%） | 474 / 1074 | 600 / 1074（55.87%） |
| R124 | 6856 | 6153（89.75%） | 703 / 703 | 0 |

C 未知样本全部为 `no_function_range`：libc 455、libubox 145。
已解析 C 用户态主要是 `client_cb` 73、`blob_parse_untrusted` 49、`ubusd_send_event` 45、
`recvmsg` 30、`uloop_run_timeout` 29、`sendmsg` 24。
隐藏函数和无匹配范围的成本保留未知，不能因没有函数名就当作零成本。

| R124 用户态符号（简写） | 样本 | 占 R124 全部样本 |
|---|---:|---:|
| `__syscall_cp_c` | 122 | 1.78% |
| client `HashMap<u64, Box<Client>>::get_mut` | 108 | 1.58% |
| `ubusd_rs::main` | 61 | 0.89% |
| `Server::event_send` | 48 | 0.70% |
| `__syscall_ret` | 40 | 0.58% |
| object `HashMap<u64, Object>::get_mut` | 40 | 0.58% |
| `Server::handle` | 39 | 0.57% |
| `attrs_of` | 39 | 0.57% |
| object `HashMap<u64, Object>::get` | 38 | 0.55% |

client `get_mut` 在四个 R124 窗口中分别为 28/29/23/28 个样本，低连接合计 56、64-held 合计 52。
这使客户端表查找成为可检查的源码位置，但 1.58% 不是所有哈希工作的成本，也不是更换容器的收益上限。
本轮没有 PC 落在 R121 所列的五个 allocator 符号
（`__libc_malloc_impl / __libc_free / alloc_slot / nontrivial_free / __libc_realloc`）内；
这不证明没有分配，也不能把不同负载的 R121/R125 样本差直接归因为优化效果。

两方内核可见符号都集中在 syscall 入口、Unix stream 接收、唤醒、slab/memcg 分配回收：
例如 R124 的 `el0_svc` 491、`__slab_free` 376、`unix_stream_read_generic` 371、
`__wake_up_sync_key` 307；C 对应为 484、378、383、312。
这些内核名称由 perf 报告，用户 ELF 符号工具没有独立验证 kernel ELF。

当前不能作进一步因果归因：每窗 R124 用户态只有 166–180 个样本，C 用户态符号覆盖不完整，且没有调用链、
内联归属或调用次数。总样本及其比例不能换算成 AX3000T 性能比值，不能解释 caller CPU 差距或此前实机
−41.09% wall 窗口，也不足以声称某个小函数差值或两个反序块具有统计优势。
下一项“response 对 `peer=0` 的解析是否可提前排除”仅记为**需要源码核查**；本采样不证明可跳过或其收益。
本结果未触发新采样、运行时修改、部署或最终版本选型。
