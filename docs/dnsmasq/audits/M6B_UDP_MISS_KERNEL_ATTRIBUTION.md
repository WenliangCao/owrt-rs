# M6b UDP-miss 内核成本归因草稿

2026-10-08。只读取本地已归档证据和源码，没有 Oracle 访问、构建、测试、插桩或产品修改。本文供第 3 项候选排序使用，不改变正在执行的无 A 基线或 TCP 方案 A 的顺序。所有性能数字仅代表 Oracle 构建机。

当前证据能确认 Rust 的 UDP miss 比 C 多三个逐请求调用：一次 4 字节随机数读取、一次设置非阻塞、一次设置 CLOEXEC。C 和 Rust 都逐请求创建和关闭随机源 socket；两侧本场景都不调用显式 `bind`。旧 trace 的 mmap/munmap 次数和新基线的缺页数很小，不能用“每请求 64 KiB mmap”解释 Rust 多出的内核 CPU。**新基线的全部内核成本差距仍未完全归因**，不能承诺下面三个调用的优化会解决 28–40 µs，也不能据 s 的 user/system 分项迁移声称它新增了内核工作。

## 证据边界和身份

本文的 `E` 指 `private/dnsmasq-rewrite/evidence/M6B/`。

| 证据 | 身份与范围 | 用途 |
| --- | --- | --- |
| `E/baseline-70097c66/` | 无 A 源码 `70097c66`；feature-off opt3 `34b3b80a39ea619f616f9d003372640d6dc0af35d5941788ae15aa64c07a3050`，1,949,736 B；s `b91d3f0ad8ab0759a1c447ed7029035cc2c6561d6a3a7e9e017f8c28c239c62a`，1,630,248 B | 新 CPU、proc、缺页和内存读数；没有 trace |
| `E/diag-6f3bed3d/` | 旧无 A 源码 `6f3bed3de272162bf3cbbb0914de4c5367e324fb`；opt3 `5fe806fef0c07714f9674a7d768f4f57aab4ab6ad57a1f323177a51e429d97a7`；s `8ca7071cd01b5ed7914caa1d56288d3f82aba39c3653950b7ca7de3d988a1fb5`；27 个诊断窗口，formal=0 | 机制线索及 syscall 计数，不能代替新 CPU 资格 |
| 精确镜像 C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`；匹配参考源码 `private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/` | 配对参考，不用 Rust 生成期望 |

新窗口保存的协议 SHA 为 `e172112051a5bde3f4732c367cc19626fa12274e985100d2a8de360708145d9f`，runner SHA 为 `503b77ade4553b2e7fba4b60e5f3bc886c52cc145d49763b60490cc04c9b66f7`。daemon/upstream/loadgen/controller 分别绑定 CPU 0/1/2/3，20 客户端，30 s 预热、90 s steady + 30 s saturation。这里的 CPU 分母只用 `steady.correct_in_window`，不混合两种负载或预热。

旧 trace 是 `strace -f -C -ttt -T -s 0`，daemon CPU 0、tracer CPU 3；覆盖预热、负载和当时记录的稳定排空。分母是 `warmup.correct + measurement.correct`，包括跨窗正确完成；本诊断为 2 s 预热、15 s 负载。attach/detach 及 raw errno 已保留。ptrace 改变完成速率和批量机会，因此 count 是该诊断范围的摊销计数；`-C` 摘要 seconds 也不能直接换算为 70097 无插桩 CPU。

`git diff 6f3bed3d 70097c66` 确认 `source_sockets.rs`、`forward.rs`、`cache.rs` 未改；`upstream.rs` 增加真实 route resend 的唯一复用 Vec 与 caller 清除合同，`main.rs` 改变 runnable/接口调度。特别是旧普通 Linux 100 ms 接口刷新已撤除。旧 raw 中的这部分工作不能算成新基线仍存在的热点。以下 Rust 源位置绑定 `70097c66`。

## 新基线：CPU 分项确实不同，总 CPU 仍是 Rust 较低

CPU 均为 µs/窗口内正确请求。所有六个窗口 `accepted=true`、`measurement_valid=true`，wrong/timeout/transport_error 为 0。当前是一轮机制基线，没有五轮 W/4-of-5 显著性资格。

| 场景 / 组 | steady 正确数 | 总 CPU | user | system |
| --- | ---: | ---: | ---: | ---: |
| hit / C | 899,599 | 12.279765 | 3.116702 | 9.163062 |
| hit / R3 | 899,848 | 16.559241 | 7.454224 | 9.105016 |
| hit / Rs | 899,849 | 17.947062 | 7.622488 | 10.324574 |
| miss / C | 897,746 | 94.736688 | 85.963108 | 8.773580 |
| miss / R3 | 898,600 | 84.310280 | 46.810654 | 37.499626 |
| miss / Rs | 898,542 | 83.346624 | 34.346289 | 49.000336 |

miss R3 相对 C：user 少 39.152454 µs，system 多 28.726046 µs，总 CPU 少 10.426408 µs。Rs 相对 C：user 少 51.616819 µs，system 多 40.226756 µs，总 CPU 少 11.390065 µs。Rs 相对 R3 总 CPU 只少 0.963657 µs（1.143%），同时 user 少 12.464365 µs、system 多 11.500710 µs；这不是 s 多出多少网络/分配调用的测量，也不是切换 s 的结论。

hit R3 的 system 与 C 相差 -0.058046 µs，而 user 多 4.337522 µs。可见 miss 的新差距与转发、随机数、源 socket、插入/淘汰等路径相关；不能归因于所有请求共同承担的固定 poll 空转。具体类别的时间仍需最终完整数据之后再选择诊断。

一个待验证的调度假设是：施加 10,000 QPS 对应约 100 µs 的到达节奏，C miss 的 user 85.963 µs 已接近这个节奏；Rust user 46.811/34.346 µs 更短，可能更常在等待回复或下一个请求时真的进入阻塞，随后由 CPU 1 的上游或 CPU 2 的客户端跨核唤醒。阻塞/调度/唤醒成本可能使 system 分项上升而总 CPU仍下降。旧 trace 的 Rust ppoll/正确数1.063低于C的2也提醒：**调用次数不等于真实阻塞次数、等待时间或唤醒成本**。这里只提出与现有数字相容的假设，旧源码/ptrace计数不能证实它，更不能用这个解释填满28–40 µs。

若最终完整结果仍有这类差距，后续同源码独立诊断可以选择：每正确请求的实际 poll 等待时长分布、voluntary/involuntary context switch、sched wakeup/迁核计数、on-CPU kernel栈（网络收发/随机数/调度）和off-CPU等待栈；同时保留客户端/上游绑定与完成数。正式窗口内不开这些工具，当前不补测。需要看到一致的等待与调度证据之后，才能将这个假设升为归因；s 的分项迁移本身不是证明。

### 父进程 proc 与 cgroup 交叉核对

计算同一 `cpu_points[measurement-start..saturation-start]` 的父进程 `user_ticks/system_ticks` 差值，除以记录的 100 Hz，再除以相同正确数。UDP 两端采样均无 child，三组单线程，不存在遗漏 TCP 子进程 CPU 的解释。

| 场景 / 组 | proc Δuser / Δsystem ticks | proc user / system µs | cgroup user / system µs | 最大单分项绝对差 µs/正确请求 |
| --- | ---: | ---: | ---: | ---: |
| hit / C | 281 / 823 | 3.123614 / 9.148521 | 3.116702 / 9.163062 | 0.014541 |
| hit / R3 | 667 / 823 | 7.412363 / 9.145989 | 7.454224 / 9.105016 | 0.041862 |
| hit / Rs | 681 / 935 | 7.567936 / 10.390632 | 7.622488 / 10.324574 | 0.066058 |
| miss / C | 7,717 / 788 | 85.959726 / 8.777538 | 85.963108 / 8.773580 | 0.003959 |
| miss / R3 | 4,207 / 3,370 | 46.817271 / 37.502782 | 46.810654 / 37.499626 | 0.006617 |
| miss / Rs | 3,086 / 4,403 | 34.344527 / 49.001605 | 34.346289 / 49.000336 | 0.001762 |

miss 的最大累计单分项差为 5.946 ms；端点 capture lag 为 0.857–5.172 ms，质量门通过。hit 最大累计差为 59.442 ms；不能把它全部说成端点 lag，但折算仅 0.066058 µs/请求。两种读取的方向、量级和总账基本一致，远小于 miss 的 28–40 µs 差距。这个核对只证明账一致；它们均来自 Linux CPU 账户，不能当成两个独立函数级 profiler，也不能据此定位 RNG、socket 或 allocator 占据多少新 system CPU。

## 旧 UDP-miss trace：可复算的 syscall 账

每格是 raw 完成调用数 / 每正确请求。分母 C=43,239，R3=39,621，Rs=39,905；三组 wrong/timeout/transport_error 均 0。所有 raw 完成调用数与 `syscall-analysis.json` 一致，unfinished/resumed 未解悬项为 0。detach 时未完成的最终等待不作为完成调用。

| 调用 | C 次数 / 每正确请求 | R3 次数 / 每正确请求 | Rs 次数 / 每正确请求 |
| --- | ---: | ---: | ---: |
| socket | 43,239 / 1.000000 | 40,110 / 1.012342 | 40,397 / 1.012329 |
| bind | 0 / 0 | 0 / 0 | 0 / 0 |
| close | 43,239 / 1.000000 | 40,273 / 1.016456 | 40,561 / 1.016439 |
| read | 0 / 0 | 40,110 / 1.012342 | 40,397 / 1.012329 |
| ioctl | 0 / 0 | 39,947 / 1.008228 | 40,233 / 1.008220 |
| fcntl | 0 / 0 | 39,784 / 1.004114 | 40,069 / 1.004110 |
| mmap | 2 / 0.000046 | 841 / 0.021226 | 936 / 0.023456 |
| munmap | 0 / 0 | 784 / 0.019787 | 879 / 0.022027 |
| brk | 0 / 0 | 8 / 0.000202 | 8 / 0.000200 |
| ppoll | 86,478 / 2.000000 | 42,099 / 1.062543 | 42,403 / 1.062599 |
| recvmsg | 43,239 / 1.000000 | 39,622 / 1.000025 | 39,906 / 1.000025 |
| sendmsg | 43,239 / 1.000000 | 39,621 / 1.000000 | 39,905 / 1.000000 |
| sendto | 43,239 / 1.000000 | 39,947 / 1.008228 | 40,233 / 1.008220 |
| recvfrom | 43,239 / 1.000000 | 40,273 / 1.016456 | 40,561 / 1.016439 |
| openat | 0 / 0 | 163 / 0.004114 | 164 / 0.004110 |
| fstat | 0 / 0 | 163 / 0.004114 | 164 / 0.004110 |
| 全部 | 345,914 / 8.000046 | 403,745 / 10.190177 | 406,816 / 10.194612 |

除表内所列调用外本范围没有其它完成调用。Rust 各 1 次 `recvmsg` EAGAIN，C 为 0；miss 的差距不是此前扫描未就绪 socket 产生的大量 EAGAIN。

### 逐请求部分与旧接口刷新拆分

raw 请求路径是 `recvmsg → read(fd=5, requested=4, returned=4) → socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) → ioctl(FIONBIO,[1]) → fcntl(F_SETFD,FD_CLOEXEC) → sendto → ppoll → recvfrom → close → sendmsg`。其中每组 Rust 的 IPv4 socket、4 字节 read、FIONBIO、上游 55 B sendto、60 B recvfrom、source close 都恰为 N；没有独立 `bind` 或 `getsockname`。

剩余 socket 数是 R3 的 163 个 `AF_NETLINK/SOCK_RAW|SOCK_CLOEXEC` 和 326 个 `AF_UNIX/SOCK_DGRAM|SOCK_CLOEXEC`；Rs 分别为 164、328。每次旧接口刷新恰有：3 socket、2 SIOCGIFINDEX、1 fcntl、2 sendto、4 recvfrom、4 close、3 read、1 openat(`/proc/net/if_inet6`)、1 fstat，即可直接分离的 21 个调用。R3 共 3,423 次（0.086394/正确请求），Rs 3,444 次（0.086305/正确请求）。`ppoll` 没有按来源拆分，不凭空给这些刷新再分配等待次数。旧 `main.rs:1636` 的 100 ms 普通扫描是该部分的机制线索；新 `InterfaceRefresh::complete` 在 `main.rs:2106–2124` 仅对 pending listener 使用 1 s deadline，100 ms fallback 只留给非 Linux。

R3 相对 C 的总次数差可以闭合为：3 个确定的附加逐请求调用，减去 ppoll 0.937457/请求，再加已拆接口调用 0.086394、mmap/munmap/brk 相对差 0.041169、一次末尾 EAGAIN 0.000025，合计 **2.190131 个附加调用/正确请求**。这是旧 trace 的次数账，不能直接变成新 70097 的 28.726046 µs。

R3 的 `-C` 摘要分别报告 read/ioctl/fcntl 0.130084/0.102034/0.091844 s，按旧 N 摊销为 3.283208/2.575250/2.318064 µs；mmap+munmap 为 0.011356 s（0.286616 µs/请求），后者只占该旧摘要全部 seconds 的 0.553%。这些数只支持先研究前面三个明显逐请求调用的排序，不承诺同样的无插桩收益，也不把摘要耗时当作新 CPU 差距的完整解释。

## 源码机制与不能放宽的合同

| 类别 | Rust `70097c66` 位置 | 精确 C 位置与解释 |
| --- | --- | --- |
| 随机数读取 | `dns/upstream.rs:223–235`，`OsRandom` 启动开一次 `/dev/urandom`，每 `next_u32` 读 4 B；`dns/forward.rs:392–401` 为 ID 抽签并检测冲突。本配置关闭 0x20，故正常每 miss 一次。源端口范围非零、ID 冲突、0x20、loop probe 都可能增加读取，不能把这一场景的次数推广到全部配置 | `util.c:41–103` 启动读种子后用 SURF 生成器提供 `rand16/rand32`；旧 raw C 此范围 read=0。候选可研究批量读取 OS 随机字节，不改成可预测 ID、不删除冲突检查或错误传播；不据此直接照抄 SURF |
| 源 socket 设置 | `dns/source_sockets.rs:301–323` plain socket，`:386–399` 独立 `set_nonblocking(true)` 和 F_SETFD；`dns/upstream.rs:1034–1095` 创建 owned socket | `forward.c:2800–2822` plain random socket 但不 `fix_fd`；`network.c:1497–1498` 的 `fix_fd` 是预分配持久源 socket，不能混淆。Rust 单 poll owner 仍需要非阻塞与 CLOEXEC；只研究 Linux 原子创建 flags 是否可合并两个调用，不能直接撤安全属性 |
| bind、源端口和寿命 | `dns/source_sockets.rs:336–381` 对 wildcard:0 跳过 bind；`dns/upstream.rs:1098–1199` 保留 pool/port-limit/源匹配；`:1209–1216` 无 owner、probe、persistent 引用后 drop socket | `network.c:1395–1408` wildcard:0 跳过 bind；`forward.c:2922–2936` 有空槽时创建，`:3034–3037` 最后引用关闭；`:3061–3063` 回收的是 link 内存。两侧均由首次 sendto 隐式取得端口。跨独立请求缓存 fd 会改变随机端口/生命周期，不能当作纯内存优化 |
| 临时 forwarding 容器 | `dns/forward.rs:403–435` packet、Name、recipient、key、map；`dns/upstream.rs:239–243,667–671` 每事务 map/Vec，`:251–264,1076–1093` 每 socket owner HashSet，`:725–746` 内部就绪批次临时 Vec | `forward.c:2938–2941,3061–3063` 复用 rfl_spare；forward records 另保留 high-water/回收语义。Rust 单元素 map/Vec/HashSet 和短 packet 可能增加 allocator 工作；该次 trace 没有 malloc 栈，不能给各容器指定 mmap 或 CPU 次数 |
| 缓存短名字、小 A RDATA 与索引 | `dns/cache.rs:137–157,238–245` Name、RDATA Vec、Arc Record、`HashMap<Vec<u8>,Vec<usize>>`；`:555,607–625,632,648–656,802–805,1033–1053` 新 key/索引复制、单元素 Vec、淘汰与转换；`dns/wire.rs:142–154` 规范名及内部转义名字返回新的 Vec | `cache.c:176–196` 启动预分配 cache-size 定长 crec，`dnsmasq.h:498–510` inline 小名字/addr/hash links，`cache.c:737–782` 复用 LRU 记录。可瘦身已知堆对象、借用规范 key、内联单元素与小 RDATA；不能改变压力下先全表清 expired、RRset 淘汰、generation、CNAME 或 TCP 私有视图合同 |

本负载器 `m6a_loadgen.c:220–231` 生成唯一 `u%012x.m6a.test` 名字；`m6a_upstream.c:56–59,77–89` 返回 TTL3600 的单个 A、4 B RDATA。预热后持续填满并淘汰 4,096 槽。因此名称/索引/小 RDATA 候选与该 miss 路径吻合；C 和 Rust 都有压力下 expired 扫描（`cache.c:780`、`cache.rs:590–598`），C 高 user CPU不能仅凭读码归因于该扫描的具体比例，更不能删除合同来优化。

## allocator、mmap 与缺页：排除过大的解释

该组件没有自定义 `global_allocator` 或重型 allocator 依赖。新 opt3 的保存 link map 确认链接 Rust 1.98.1 self-contained musl `libc.a(malloc.lo/free.lo/realloc.lo)`；这不证明它与镜像 C 动态 libc 的 allocator 版本和策略逐字相同。没有堆调用栈/尺寸追踪时，只能说上表堆对象为申请/释放来源，不能把 libc 的一次 mmap 精确归给某个 Rust Vec。

旧 R3 mmap 的主要长度是 32 KiB×311、4 KiB×296、16 KiB×125、8 KiB×101，64 KiB仅 2 次；Rs 是 4 KiB×302、32 KiB×294、8 KiB×234、64 KiB×52、16 KiB×48，余为增长阶段其它长度。R3/Rs 的 mmap+munmap 分别仅 0.041014/0.045483 次/正确请求。**malloc 不是每次都要 syscall，mmap 也不是一个 Rust 分配的计数器。**

同源码新 baseline 的 raw `proc-snapshots/{measurement-start,saturation-start}.13.stat` 给出下表。minflt/majflt 是原始 proc stat 字段 10/12（剥离 pid 和括号内 comm 后的数组下标 7/9），采用与 CPU 相同的 steady 两端与分母。

| 场景 / 组 | minflt 起点→终点 | steady Δminflt | 次/正确请求 | Δmajflt |
| --- | ---: | ---: | ---: | ---: |
| hit / C | 332→332 | 0 | 0 | 0 |
| hit / R3 | 1,118→1,118 | 0 | 0 | 0 |
| hit / Rs | 1,119→1,119 | 0 | 0 | 0 |
| miss / C | 335→335 | 0 | 0 | 0 |
| miss / R3 | 2,093→2,208 | 115 | 0.000128 | 0 |
| miss / Rs | 2,065→2,267 | 202 | 0.000225 | 0 |

新 R3 的 steady PSS 为 3,968→3,984 KiB，Rs 3,848→3,860，C 1,664→1,664；hit PSS 固定为 C/R3/Rs 1,660/3,524/3,400 KiB。缺页事件量很少，既有证据不支持把大量新映射/逐请求缺页作为 28–40 µs 内核成本的主要解释。该表也不测量每次缺页耗时或其它内核函数，因此保留“未完全归因”，不宣称完全排除了 allocator 影响。

新 `main.rs:2999,4446,4502` 是一个复用 65,535 B 接收 buffer，随后只复制实际 datagram 的短 query；upstream `:368,1450` 也复用 edns packet buffer。旧 6f 版本已包含接收复用。`upstream.rs:1313–1315` 新增 route resend 的单 Vec 只保留容量、每次成功发送保存精确 wire，不 pin fd；不能把它删掉或说它每请求申请 64 KiB。

## 第 3 项候选排序参考

TCP 方案 A 的语义/服务/资源/CPU 硬门仍先执行。下面排序只针对它之后的 UDP/缓存候选；本次没有实施任何一个候选。

| 顺序 | 候选与预期机制 | 已有依据 | 收益边界与主要风险 |
| --- | --- | --- | --- |
| 1 | Linux source socket 原子设置 NONBLOCK/CLOEXEC，保持当前失败处理与跨平台路径 | old raw 恰每 miss 各 1 ioctl/1 fcntl；70097 对应源码未变 | 理论减少两个逐 miss syscall，未测 CPU 收益；必须保留非阻塞、CLOEXEC、IPv6/source-bind/故障边界，不承诺消除 28 µs |
| 2 | 小批 OS 随机字节缓冲，继续用 OS 熵、ID 冲突检查及错误传播 | old raw 恰每 miss 一个 4 B read；hit没有这个读取，源码未变 | 摊销一个 syscall；要审查 entropy failure、prefetch/剩余字节寿命、reload/TCP/0x20/端口范围 caller，不能用不安全 PRNG换速度 |
| 3 | A 后缓存规范 key/单元素索引/小 RDATA 瘦身，并减少淘汰路径临时复制 | 4096持续churn，明确 owned Name/Vec/Arc/索引；hit R3多4.338 µs user，缓存 PSS多1,864 KiB | 以 PSS/live bytes、申请次数和用户 CPU为目标；old mmap仅0.02级/请求，不用它承诺 kernel 大收益。必须逐 mutator 过精确 C，避免与 A共享索引实现并行冲突 |
| 4 | forwarding/socket owner 单元素容器与有界批次 scratch 复用 | 每 miss新 transaction/owner小容器；C有rfl_spare，与缓存/churn路径分开 | 可减少申请/释放与用户路径开销，未定量；保留 duplicate/all-servers/port-limit/溢出/取消/retry/route exact-save合同，不持久缓存独立请求的随机源 fd |
| 暂不按本证据排序 | allocator替换或大范围网络重构 | 没有同源码 allocator/kernel栈，proc缺页少；Rs/R3旧调用类别近同 | 当前无证据承诺收益；会增加体积/依赖/合同风险。若最终完整数据仍显示大system差距，另开同源码诊断确认成本分布后再选 |

普通 Linux 100 ms 接口扫描已修，不作为待做候选。初始 465 QPS/2 ms瓶颈、接收大 buffer复用、最终135窗口和 s选择分别由既有第1包及最终协议处理，不用本文旧 trace顶替。尚未解释的部分保留到最终报告；需要追踪时只在正式窗口结束后，按同源码独立诊断身份执行，不阻挡当前baseline/A。

## 复算入口与摘要 SHA

新六个 `result.json` 均位于 `E/baseline-70097c66/archives/r01-{udp-hit,udp-miss}-{c,r3,rs}/attempt-1/plain/formal/`。计算公式为 `(saturation-start.cgroup_cpu[key] - measurement-start.cgroup_cpu[key]) / load.steady.correct_in_window`；key 为 usage_usec/user_usec/system_usec。proc 用相同两点的 tick差除以100并乘1e6；缺页用同目录 raw stat同两点差。没有复用 steady总correct或整120秒CPU。

| 文件 / 身份 | SHA256 |
| --- | --- |
| 旧 `syscall-analysis.json` | `64fa89b42e5b9dec45e3cf15b2925166c0dff4225c8d92dc08b6deddc9085c55` |
| 旧 diag manifest | `009c5f1c58562460da461b128ce5990dc563993c91ab5eeccbd46d3db9b6a514` |
| 旧 C UDP-miss raw strace | `c5594d8edb1a31485b16ca99d719bc9c68167ccc78b0f523fcc8979ac3ac4336` |
| 旧 R3 UDP-miss raw strace | `e83b329eae3212ad430d540f38227fa270c8d2e076384e25f06f13047e2ebcbb` |
| 旧 Rs UDP-miss raw strace | `18bc5af963add4ee586c23249eb2a9ac37cb30c46388bdf91581599f75c4ae86` |
| 新 miss C result | `39c7ef4c2dfc89f1a40cc7bfd3d07187d4d27e12be3ce798b11327a1ab9ece78` |
| 新 miss R3 result | `53a4a250bf5ab334f5c8d680253f974122b08bef36bbb81320ec5261cea59f59` |
| 新 miss Rs result | `79a1a74aad58ad7d7e78909c027ee355d93154903499f1fbb2b2a2629f807dcb` |
| 新 hit C result | `8ccbdc116c30f0305223ac11fbf7ca22c88cc75ae3269c60272c9e08e2dc0ec0` |
| 新 hit R3 result | `1f52bfdcc3181328aa9c950d16a9eb25079f66a2c68ab8d1331394b22a2fc839` |
| 新 hit Rs result | `2a777f5630b1e531f75c0ebd1fe2119a5c9b91dd0f216d73061ab45cecb0c3f9` |
| 新 opt3 link map | `307f3d1b683a4040aa4404f6cecda43fb6b391c3a5e65c890f82e0cb520ec6fd` |

本次完成本地 raw计数复算、CPU两种读取交叉核对、stat缺页复算和源码身份差分。未完成同源码 kernel/allocator时间归因或任何候选的前后实测，不把这些未执行项记为通过。
