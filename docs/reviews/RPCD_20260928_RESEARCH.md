# RPCD H1 性能研究与工程收尾（2026-09-28）

保留 **H1**，在本轮已测试候选与负载内完成工程验收。正式构建、36 项相关功能/恢复门、AX3000T 三方九窗及十轮资源循环通过；生产九组件继续运行精确镜像 C，未部署、刷写或重启。性能目标**部分达到，未全面胜出**：24 项实机负载中，H1 主体 CPU 的三窗中位数在 22 项低于 R89、23 项低于 C；mean 分别为 17/20 项，p99 为 14/20 项。这些是指标中心值计数，不是显著性判定或实际流量加权成绩。

主要新增收益来自 UCI 工作模型复用、保留回复缓冲所有权及大 ACL 跳过无关前缀。大 UCI 的实机主体 CPU 对 R89 降低 30.17%/35.37%（单客户端/四并发），对 C 降低 69.30%/71.67%。仍有四并发短请求、file list 尾延迟、`luci_devices` 对 C 的差距，以及小额共享 CLI 成本和常驻内存增加；下文逐项解释为什么接受，不能将这些负载称为胜出。

详细交付：

- [三方完整性能表](RPCD_20260928_BENCHMARKS.md)：24 项 mean/p50/p95/p99、吞吐、分层 CPU、错误/超时、每轮范围、绝对和百分比差及方向。
- [同进程资源表](RPCD_20260928_RESOURCES.md)：C/R89/H1 主体与 C ubusd 的 186 个启动/活动/扩容/回收快照。
- [正式当前版本→H1 增量与共享消费者](RPCD_20260928_INCREMENTAL.md)：将本轮新增收益与继承收益分开。
- [候选/拒绝索引](rpcd-20260928-candidates.json)：13 个候选、实际组合、源码/ELF/CSV 身份、保留与拒绝理由、不利结果。
- [门禁清单与身份](rpcd-20260928-validation.json)、[补充 UCI handler 数据](rpcd-20260928-extended-profile.json)。原始二进制、rootfs、配置、日志和备份保留于 ignored `private/rpcd-20260928/`，不进入 Git。

## 起点与产物身份

部署规范为 AX3000T / MT7981B 双核 A53，OpenWrt 25.12.5 `r33051-f5dae5ece4`，Linux 6.12.94。依据仓库 manifest 复核 rpcd 上游 `28faf6403792d25b9826043aaf37880624c19568`；本地精确 C 副本见 `private/stage5/src/rpcd/`，libuci 见 `private/stage6/src/uci/`，luci-rpc 见 `private/stage8/src/`。这些提取目录不是独立 Git checkout，不能用向上搜索得到的仓库 HEAD 代替其上游身份。

| 比较对象 | 源码/正式构建 | RPCD ELF SHA256 |
|---|---|---|
| 精确镜像 C | rpcd `28faf6403792d25b9826043aaf37880624c19568` | `94bed60981a6e71638b5bb4552c1f3539c550d4625af7d5ada7d71bbafdb8947` |
| 正式 R89 | `d9c10483d95590143f9d6a1f41310e2a13e63fb3`；设备 `/root/r89-before-r90` | `a58c2f7039369c4dde7b0f0fdb45053c147f823c178651b1867c7843e3217a18` |
| 本轮起点，重建正式产物 | `f5233e50e25fe3602523f43947eb521acd0898e1`；workflow `36454159150` | `679f86c29f9bf19d6b2e911ce14ae59d5ee95e680ca84d5addabc9fa6138013e` |
| H1，最终正式产物 | `da7b9e2283e3b3cd2cb17b949c91aed41172c0e1`；workflow `36457327815` | `158031f2382c832fc067f2d20e2a2683a877b8ff491723f4df869301f37cc309` |

H1 运行时代码提交为 `7a005811497b34a14bff9f64c3fcdf6fd5798ea2`，`da7b9e2` 增加隔离 benchmark 工具能力。正式 APK、core archive、manifest 和九组件提取 ELF 均核验；RPCD 为无 PT_INTERP 的静态 AArch64 ELF，1,256,211 字节，较起点 1,252,115 字节增加 4,096 字节（0.33%）。Oracle 的诊断构建与正式产物分开记录，不互相替代。

正式性能比较统一使用精确 C ubusd：`cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88`。三侧调用者为同一现代 benchmark：`eb4d563084f5f6270ccfddf8e8244582ab1a3d3802c89071996b2267bf743dd5`；namespace launcher：`fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2`。镜像执行面和其它依赖保持一致。

开始时已有的四份 prompt 改动单独保留。本轮修改了 `components/rpcd` 与共享 `components/uci`，**没有修改共享 ubus**，也未重新开启 UBUSD R136、NETIFD H10、HTTPD H12、FW4 H13 研究。UCI 实际消费者补功能与关键性能回归；HTTPD 不链接 UCI，其原有 H12 性能证据继续适用，本轮只补边界单测。

## 先确认已有工作，再定位成本

| 路径 | 起点已经具备 | 本轮仍观察到的成本 | 精确 C 接口与不变量 |
|---|---|---|---|
| UCI get/state | 单项 `ReadCache`；两次相同完整读取后缓存解析；每次仍加锁、读到 EOF、重放当前 delta | 读取 Vec 再复制进缓存；命中仍深克隆工作模型；Blob 从小容量增长；`into_payload` 移动整个回复 | `rpc_uci_getcommon`→load/delta→dump→unload；原始值字节、section/option/type/match、权限和错误优先级保持 |
| session ACL | wildcard-free prefix key；有序 Vec；简单 glob 快路径；单 DATA 容器 | 大 scope 从头扫描无关规则；set/get/unset 拷贝中间字段 | `rpc_session_acl_allowed` 的前缀候选与 fnmatch；grant/revoke/list 顺序、重复项和原始 object 字节保持 |
| file list | 直接 Blob 编码；每次请求内最后 UID/GID 查询复用 | 每项独立 full path 分配 | `rpc_file_list` 的完整路径 lstat/readlink/stat、遍历顺序、坏链接与错误映射保持 |
| LuCI | 真实 helper 探测、原有 JSON→Blob 路径 | 每次校验重新构造 21 方法签名；sysfs 栈缓冲→Vec→String | ucode policy 在注册时建立；保持 C 的 127 字节读取上限等规则，并保留 Rust 既有有损 UTF-8 显示策略 |

起点短实机筛选（每侧一窗、18 项、N=2000）确认大 UCI 线索：`get64` 主体 CPU C/R89/当前为 1521.27/681.21/720.94 µs，c4 为 1540.49/669.94/698.04 µs。它只决定研究优先级，不与最终三方成绩拼接。R94 的历史 0.75%/2.10% 线索没有直接当成本轮事实。

真实 `uci_profile` 调库，`uci_reply_profile`、session/file/LuCI examples 通过 `#[path]` 包含实际 handler；不是另外写一个理想化编码器。统一 fixture、工具链和独立 target 核身份，主代理串行安排同机计时，三个代理负责 UCI、session/ACL、file/plugins 的独立实现和审查。

## 候选、证伪与最终实现

### UCI：复用拥有者，不缓存访问决策

精确 C 在共享文件锁下 import，加载 delta，将所选字段写进可复用全局 Blob，再发送和 unload。起点 Rust 已省解析，但热 `get64` handler 仍约 70.2 µs、406 allocations、12 reallocations、56,076 requested bytes。分配计数是一次探针调用的分配请求，不是 live bytes、RSS 或所有输入上界。

| 候选 | 验证所得 | 决定 |
|---|---|---|
| U1：转移/复用完整读取 Vec | 单独 `get64` 70.156→73.967 µs，+5.43%，三轮都慢 | 单独方案拒绝；不能只凭少一次分配选它 |
| U2：从已验证 base 重写可回收工作模型 | 37.536 µs，较起点 −46.50%，19 allocations | 保留机制；节/选项及每个元字段都覆盖后才重放当前 delta |
| U3：整包回复容量估算 | 36.063 µs；相对 U2 −3.92%；19 alloc/6 realloc/11,851 bytes | 仅无筛选整包路径启用；预留上限 64 KiB，超大回复正常增长 |
| U4：模型+容量，保留原 I/O | 同批 36.635 µs；U3 36.010 µs | 控制 U1 的组合效应，不假定单独慢就组合也慢 |
| U5：Reply 持有 BlobBuf | 同批约 29.646 µs | 保留；借用 `payload()`（已跳过四字节头），删除整个 payload 的重叠移动 |
| U6：U5 加读取 buffer 复用 | 最终配对 U5→U6：network 10.502→10.288 µs（−2.04%），64 节 29.341→28.855 µs（−1.65%），20→19 allocations | 选择 U6 作为最终 UCI 组合 |

各行属于标明的不同筛选批次，不跨批次相减；完整范围、实际组合和所有不利项在候选索引。最终 H1 的正式增量另行同批比较。

`ReadCache` 保存的 base 和备用工作模型合计仍限制在 128 KiB 的输入/模型容量，scratch 限制 32 KiB；分配器元数据另计。模型只是可用的内存，永远不是下一会话的权威配置：从当前完整字节命中的 base 覆盖 name、section、anonymous、option 类型/值、计数、delta 与路径等字段，然后加载当前 SID/state 链。miss、错误与超限路径不会将脏工作模型当作 base。锁、短读、EINTR、EOF、超时/取消、同尺寸同 mtime 重写与 delta 删除均保留验证。

`Payloads::Blob` 保留 builder 所有权，发送时借用现有 payload，正常 drop 释放；没有新池或跨请求引用。保留四字节头不会比原 `drain` 多保留 backing capacity，因为原 Vec 也未缩容。只有 UCI get/state 使用新构造器；空 DATA/无 DATA、多 DATA 顺序及原始字节单测通过。

最后补齐真实 handler 的非整包与缓存失配路径，Oracle 三对 AB/BA/AB、每阶段 3000 op，前后验证完整回复：

| 路径 | 起点→H1 运行均值中位数，µs/op | 差额 | alloc 起点→H1 |
|---|---:|---:|---:|
| warm network | 12.249→10.321 | −15.74% | 42→19 |
| warm 64 节整包 | 69.607→28.579 | −58.94% | 406→19 |
| 单节 | 42.411→17.196 | −59.45% | 408→21 |
| 单选项 | 42.366→17.228 | −59.33% | 410→23 |
| type+match 筛选一节 | 49.632→24.712 | −50.21% | 470→83 |
| 交替 network→64 节，**每 op 两请求** | 156.989→148.063 | −5.69% | 457→455 |
| configs 控制 | 4.149→4.173 | +0.59% | 12→12 |

交替使用同一个真实 Ctx，每次先 drop reply，单项 cache 持续失配；不是手动清 cache 的理想模型。它证明所测交替流量没有只为热缓存付出明显代价，不代表冷文件系统缓存、daemon 第一请求或所有大小分布。[数据](rpcd-20260928-extended-profile.json)保留每轮数值、范围、绝对差、分配与 ELF/夹具身份。

### Session：跳过无关前缀，保留首项快路

S1 使用现有排序 Vec 的二分边界跳过不可能匹配的前缀区间，不添加索引结构、失效机制或授权缓存。复杂模式仍交给匹配镜像 libc 语义的 fnmatch；等 key、较短前缀、空 wildcard key 都必须检查。小于等于 8 项沿用线性扫描。

S1 的 ACL256 last/absent 微测约省 92%，却使首规则约慢 120%、首 wildcard 约慢 500%。S3 先尝试首规则后再搜索其余项，恢复原有常用首项路径，同时保留大表末端收益。生成模式对照原线性实现，加上复杂 glob、NUL/原始 object 字节、动态 grant/revoke 等门验证权限未扩大。最终实机 ACL256 的大收益包含这一机制；所有 R89→H1 收益不能全部归到本轮，因为传输库变化早于起点。

S2 尝试全部字段借用，grant64 微测约 +20.16%（约 6 µs），拒绝 grant/revoke 部分。S4 只对 set/get/unset 借用字段；get64/set/unset 微测分别约 −36.78%/−4.36%/−5.39%。未改 grant 的选定组合仍出现约 +3.94%（约 1.2 µs）的 grant 样本变化，保留为代码生成/组合未归因结果，不声称无退步。session 存储、到期维护、重连保留与 multi-DATA 生命周期不重写。

### File 与 LuCI：保留小而明确的分配改进

F1 在一条 file list 回复中复用 PathBuf，继续完整路径解析；list 分配 41→32、realloc 15→7，微测只有约 −0.3%，不能将分配下降等同于大幅延迟收益。stat 控制样本 +2.03%，正式增量 list own CPU −3.33%，c4 +2.15%，均披露。没有使用 dirfd 替代完整路径：父目录 rename/替换期间的路径解析语义会改变。

F2 用静态 LuCI policy 校验请求，启动 signature 仍按原 API 生成。每次少 8 次分配，getVersion 回复微测约 −13.45%；正式进程主体 CPU 增量为 −0.47%，说明 handler 微测收益不能直接移植为进程收益。未知字段、重复字段、类型及 SID 例外不放宽。

F3 的 `readstr` 从 127 字节栈缓冲直接转换 String，去掉中间 Vec，保留读循环、截断、ASCII 尾空白、原始错误与 Rust 既有有损 UTF-8 规则。Oracle helper 4.247→4.177 µs，2→1 allocation；devices handler 193.524→190.710 µs，105→86 allocations、realloc 仍 30，三轮时间范围重叠。对于 `luci-rpc getNetworkDevices`，C 和 Rust 都直接构造 Blob，没有本轮可消除的 JSON 树；这不概括其它 LuCI 方法。

F2/S2/F3 某些实验实际包含前置候选，不能当作单独增量：见下方身份纠正及索引。只把正式组合对起点的同批测量作为总收益。

## 系统调用：区分继承与新增

Oracle 在 exact-image namespace 用 N=1000/2000 的 `get64` trace 作差，消去固定启动成本，差值对应 100 次正式请求。它只计调用，不提供 CPU 排名：

| 每请求调用差分 | C | R89 | 起点 | H1 |
|---|---:|---:|---:|---:|
| recvmsg | 2 | 3 | 1 | 0.98 |
| sendmsg | 2 | 1 | 1 | 1 |
| read | 7 | 2 | 2 | 2 |
| openat / close | 1 / 1 | 1 / 1 | 1 / 1 | 1 / 1 |
| flock / newfstatat | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 |
| lseek | 1 | 1 | 0 | 0 |
| mmap / munmap | 2 / 2 | 0.04 / 0.04 | 1.06 / 1.06 | 0.04 / 0.04 |

读取、锁和 delta 检查没有为了得分被省略。起点相对 R89 的多余 SEEK_SET 已消除，以及大部分收发调用变化，属于继承工作。0.98 是窗口和缓冲批处理差分，不表示每次恰好少 0.02 次调用。H1 组合消除了起点 trace 中随这 100 请求增加的 100 次 16 KiB mmap/munmap；没有实验能唯一归因于某一个子候选。过滤器只列了 `epoll_wait`，未覆盖实际 AArch64 `epoll_pwait/ppoll`，因此 readiness wait **缺测，不能填零**。原始八份 trace 身份及差分保存在 `syscall-counts.json`。

## 正式实机确认与剩余差距

先冻结 `final-plan.json`：24 项，普通请求每窗 6000 次，大 UCI/devices 600 次，features 60 次；每客户端预热 20，c4 正式量平分四客户端。三个随机 block，seed `202609281`，实际顺序 **H1/R89/C；H1/C/R89；C/H1/R89**。注意阈值预先定为 CPU 或 mean 同时增加 ≥3% 且 ≥2 µs，p99 同时增加 ≥10% 且 ≥100 µs；更小变化也全部报告。没有看到分数后加轮至获胜。

所有调用直接走隔离 ubus；没有 HTTPD→ubusd→rpcd 的端到端测量、TLS 或真实 LuCI 页面提速承诺。客户端也消耗路由器 CPU。单次墙钟延迟结束后进行回复验证，因此吞吐不等于 mean 的倒数。c4 主体/依赖 CPU 外窗含预热 80 次，调用者 CPU/延迟不含；c4 吞吐外窗含客户端启动和预热，受 `/proc/uptime` 粒度影响，不能无条件将三层不同边界相加。主体 process CPU clock 与回收子进程 tick 单列，features 的 helper CPU 不藏入主体或忽略；时钟接口分辨率不等于计量准确度。

代表性主体 CPU，单位 µs/请求，三窗中位数；完整绝对差、范围与方向在[三方表](RPCD_20260928_BENCHMARKS.md)：

| 负载 | C | R89 | H1 | H1 对 C | H1 对 R89 |
|---|---:|---:|---:|---:|---:|
| get network | 189.507 | 154.188 | 130.515 | −31.13% | −15.35% |
| get64 | 1522.436 | 669.353 | 467.399 | −69.30% | −30.17% |
| get64 c4 | 1550.047 | 679.457 | 439.115 | −71.67% | −35.37% |
| authorized get | 205.545 | 162.514 | 136.407 | −33.64% | −16.06% |
| state network | 249.346 | 325.847 | 190.198 | −23.72% | −41.63% |
| get delta | 249.842 | 342.395 | 199.210 | −20.27% | −41.82% |
| ACL256 | 29.608 | 70.473 | 21.555 | −27.20% | −69.41% |
| file list | 483.588 | 249.940 | 242.387 | −49.88% | −3.02% |
| LuCI version | 179.322 | 69.511 | 59.131 | −67.03% | −14.93% |
| LuCI features（仅自身） | 20035.383 | 8860.348 | 8464.788 | −57.75% | −4.46% |
| LuCI devices | 962.902 | 1149.138 | 1133.611 | **+17.73%** | −1.35% |

最终 **216 个负载观察均通过回复、成功计数和身份校验，报告错误为零**。1,096,740 次正式请求全部完成，未观察到超时；原始格式没有独立超时计数器，超时零是从完整成功数和驱动正常退出推导。三次重复不能证明小差异稳定，也没有对该合成矩阵作实际流量加权。下列不利结果是选择 H1 的明确成本：

| 剩余项目 | 中心值差额及使用影响 | 判断与停止边界 |
|---|---|---|
| `uci_configs_c4` 对 R89 | 主体 +1.894 µs/+3.69%；mean 326.973→366.572 µs，+39.599/+12.11%；吞吐 −11.29% | mean 三块方向 ↑↓↑；整体成本与延迟未改善，没有分阶段证据可归因。保留，不称相同或胜出 |
| `file_stat_c4` 对 R89 | 主体 +2.084 µs/+3.62%；mean +4.576 µs/+1.20%；吞吐中心值相同 | 主体达到预定注意阈值，绝对约 2 µs；没有为此引入元数据缓存或改变路径语义 |
| `session_access_c4` 对 R89 | own CPU −8.01%，mean +24.545 µs/+10.62%，吞吐 −4.88% | mean 三块均升高。CPU 与墙钟边界不同；没有调度因果证据，不能拿 own 降低抹掉延迟退步 |
| `session_access_granted_c4` 对 R89 | own −9.87%，mean +50.354 µs/+20.72%，吞吐 −16.33% | mean 配对 ↑↓↓，中位数之差不是配对差中位数；C 对比 mean 也高 9.79%，公开不一致性 |
| `session_access_64_c4` 对 R89 | own −4.74%，mean +46.464 µs/+19.55%，吞吐 −14.89% | mean ↑↓↑；对 C mean +4.83%。mean 延迟增加不足 0.05 ms，但不能声称四并发全面更快 |
| `file_list`/`file_list_c4` 对 R89 | 单客户端 mean +0.491 µs/+0.12%，p99 +159.654 µs/+21.00%；c4 mean +137.607 µs/+10.85%，p99 +1256.543 µs/+52.45%，吞吐 −7.43% | c4 mean/p99 ↑↓↑；自身 CPU 分别 −3.02%/−3.24%。约 1.26 ms 尾部代价单独接受，未用分配计数宣称尾延迟改善 |
| `luci_devices` 对 C | own +170.709 µs/+17.73%，mean +188.643 µs/+16.58%，p99 +287.687 µs/+19.23%；对 R89 own −1.35%，mean −0.10%，p99 +2.20% | 未达到胜 C；保留 F3 的小收益。没有 C 分阶段 profile 可解释全部差額；不能宣称剩余机会已穷尽 |

三方表另外保留所有小额不利值，包括单客户端 stat 吞吐、session granted/64 的 p99、delta 对 C p99。依赖/调用者也有达到关注阈值的退步：devices 对 C 的 ubusd +12.386 µs/+14.06%，delta 对 C 的 ubusd +5.818 µs/+9.72%，stat c4 对 R89 的 caller +3.319 µs/+5.33%；完整关注表列出其余项。主体、依赖和调用者并非总是同方向：例如 `session_access_c4` 对 R89 own −1.340、ubusd −0.214、caller +0.968 µs；`file_list_c4` 为 −6.651/+0.987/+1.454 µs。它们只说明计量成本与等待边界不同，不能证明调度、频率、网络或某个分配器是原因。

资源成本同样接受但不隐藏：H1 启动 RSS 1124 KiB，R89 1040、C 1884；十轮销毁后 H1 第 4–10 轮为 1300 KiB，R89 1220、C 1932。对 R89 **+80 KiB/+6.56%**，其中该快照 Anon +12 KiB、RssShmem +68 KiB；不是全部归因于模型缓存。主体 fd/线程 7/1，C 为 11/1；采样点没有未回收直接子进程。expanded 最后一轮仍多 4 KiB，释放后平台结论不扩大为所有阶段零增长。VmHWM 输出在同 PID 下下降，保留原值但不视作可靠连续峰值；PSS/USS 缺测。

## 新增收益与共享依赖代价

Oracle 正式起点与 H1 三对 AB/BA/AB、24 项同批确认，机器计时期间没有并发编译/压测。主体 CPU：network 22.687→20.780 µs（−8.4%）、get64 85.698→44.255（−48.36%）、get64 c4 83.566→47.119（−43.61%）、authorized −12.57%、state −15.45%、delta −11.07%、ACL256 −11.31%。这才是本轮增量；设备相对 R89 的更大或不同收益包含 R89 后已有工作，不能全部计入 H1。

该增量样本也有 configs +4.77%（约 0.668 µs）、configs c4 +5.13%、file stat +4.62%（约 0.704 µs）、session access c4 +2.83%、access64 +2.11%/c4 +2.36%、file list c4 +2.15%。[完整增量表](RPCD_20260928_INCREMENTAL.md)保留所有值。没有把 Oracle 百分比移植为 AX3000T 保证。

共享 UCI 消费者采用正式产物 ABBA 两窗/侧，9 项关键回归。五个短命令使用 `getrusage(RUSAGE_CHILDREN)` 回收命令树 CPU，不拿粗 `/proc` tick 代替：UCI export network **224.160→238.1825 µs，+14.0225/+6.26%**，请求 mean +3.59%；export64 **404.425→417.735 µs，+13.31/+3.29%**，请求 mean +2.48%；reload_config CPU +1.48%、mean +1.23%。FW4 print CPU −5.46%、mean −2.74%，UCI set/commit/get CPU −1.70%、mean −1.88%，四个 netifd 查询 mean −0.53% 至 −3.71%。

本批 export 单次额外约 13–14 µs CPU，发生于 Oracle；本轮接受这一已量化代价。大 UCI 主路径的数百 µs 收益来自 AX3000T，是另一平台的独立收益证据，不将两者相减或计算净收益比。没有采集生产 CLI 调用频率，不能把“低频”当作已测事实。共享非缓存读取从初始 Vec 分配改为公共 `read_into`，源码语义一致，但没有实验唯一证明这就是回归原因，不能写成“分配器导致”或“共享消费者完全不变”。未将完成组件重新扩展成全量性能研究。

## 功能、恢复与物理隔离

完整结果见[门禁 JSON](rpcd-20260928-validation.json)：36 项有效通过；7 个 native 单元/集成套件合计 425 tests，另有 Linux raw filename/symlink 定向测试、rpcd/uci clippy、45 个 benchmark 工具测试。R26 为 **733 steps，其中 729 fuzz calls，差异 0**，不误称 733 次 fuzz。FW4 上游 mock 31 cases 零失败。

| 门类 | 实际覆盖 |
|---|---|
| core/plugin | r13 file/LuCI、r17 session/UCI/rc、r18 sys/iwinfo/rrdns、r19 luci-rpc；既有夹具覆盖的方法与错误路径差分 |
| 权限/字节 | raw Blob 类型与字节、复杂 libc glob、grant/revoke、无效 SID/UTF-8 拒绝合同、lease/plugin boundaries |
| UCI 文件合同 | 完整读取、短读/EINTR、错误前缀、锁预算/取消、同 mtime 字节变化、SID/state delta、重排/删节、bounded spare、apply/confirm/rollback |
| 服务生命周期 | busy 时会话到期/worker；真实 features 含/不含 SIGCHLD；延迟执行/reexec；closed output/empty/output limit 回收 |
| 总线恢复 | disconnect 与 half-header：离线文件回滚、会话保留/到期、通知补发、旧 worker 隔离及恢复服务；共享 ubus 单测含传输/FD 边界 |
| 共享消费者 | UCI r16/r83、FW4 上游/defaults、reload-config r1、netifd restart；HTTPD 边界单测 |
| 动态 hints | 双正式二进制、私有 network namespace 的固定邻居六阶段查询 |

门禁均在 Oracle 的精确 rootfs 副本或私有 namespace 中执行。r13 部分动态回复只比较 shape，r19 遮罩合同声明的易变计数；r18 没有真实无线硬件，iwinfo 主要覆盖不存在设备等路径。RPCD 的 reload/sysupgrade 用可控 marker 替身；factory/reboot 不调用。已有 C/R89 差异继续保留：[core 合同](../contracts/rpcd-core.md)、[file/LuCI 合同](../contracts/rpcd-plugins.md)、[插件边界](../contracts/rpcd-plugins-stage8.md)。C 在总线退出丢失回滚、pipe EOF 早于子进程结束等既有缺陷不要求候选模仿，也未借此豁免候选新失败。无线执行面没有修改，本轮不声称重新完成真实射频扫描差分。

物理测试前两次复核离线备份、配置 manifest 与 recovery gate，最近一次为 17:28:23 UTC。Wi-Fi 管理；600 秒 guard，独立 mount/PID/network namespace，生产九组件 ELF/配置/boot/客户端健康与 owned mount/process 清理逐窗核验。boot ID 未变化；最终 `COMPLETE`、host/health 与 checksum 校验通过。十轮资源探针共核 576 个原始文件及三份归档。没有修改生产进程、无线状态或持久配置。

## 失败证据与身份修正

1. 初次正式构建错误指向远端旧 `main`，workflow `36453905978` 取消并排除；正确冻结起点另建 `36454159150`。最终 H1 workflow 为 `36457327815`。
2. 初次 profile bundle 的绝对 symlink 在 namespace 内不可达，改为自有复制文件后重启新筛选批次。macOS 无法建立 raw-FF 文件名，Linux 定向夹具补跑通过；未删合同测试伪装通过。
3. 在 ignored 源码副本里 `git apply --reverse` 向上找到主仓库，路径前缀导致 patch 实际跳过。根据源文件与 ELF hash 查出并修正：S2 实际为 S1+S2，F2 为 F1+F2，F3 为 F1+F2+F3；不作独立增量声明。U3 screens02/03 实际源码是 `956f143`，后续 `a98b68f` 本地更新未重建/重测，索引从实际提交重建身份，不引用后来目录 hash。
4. features fixture 最初错误预期 firewall=false；精确镜像 fw3 兼容路径使 C 返回 true。保留原失败响应，修正预期后 C/Rust pilot 均通过。
5. 一轮 Oracle 诊断组合计时中有小型 APK 传输重叠，整批在看成绩前排除；待传输结束，以正式产物按冻结方案完整重采，作为唯一最终增量批次。
6. 资源 v3 探针把多个路径交给 BusyBox readlink，负载前失败；v4 逐个读取 namespace 并重新完成三方。没有把工具失败计入候选资源失败。
7. Oracle 门禁 SSH reset 后远端进程继续，保留全部已执行结果。36 项中只有 reload-config r1 首次被 RPCD 安全夹具里的替身脚本身份拦下；此门需要精确原脚本。用原 rootfs 和该门自己的隔离 ubus shim 补跑，11 参考+9 故障用例通过。原 aggregate 的 `passed=false` 和失败日志保留，新的有效门状态单独派生，未覆盖原记录。
8. 最终实机第 5 窗负载成功，但收集 `environment-after.txt` 的 SSH 退出 255。成绩查看前排除整窗，保存于 `device-final-failed-window-05-transport`；重核远端 checksum/COMPLETE 后只清理该测试自有 run-05。前四窗保留，设置、工具、顺序、请求数不变，用既有 `--resume` 从第 5 窗继续到第 9 窗。未为改善成绩选择性补测。

## 停止理由

UCI 的主要已测成本已处理：整个热 get64 handler 的分配从 406 次降至 19 次，回复整段移动消除，容量增长减少；缓存失配交替/筛选路径未出现抵消收益。进一步使用 metadata-only freshness、wire reply cache 或借用可变 cache model 会触及字节新鲜度、delta 键和会话隔离；没有相应证据支持引入新失效层。多项 LRU/COW/全局回复池未被证明必要，不宣称它们已被穷尽或证伪。

ACL 大表扫描已优化，首项与 wildcard 反例已经修正；grant/revoke 的全字段借用因明显退步明确拒绝。小 scope 维持简单扫描，不引入更重 trie 或额外有序索引。file list 的剩余主要操作仍是逐项 metadata 与身份/编码；dirfd 方案会改变父路径替换语义，不能拿简单调用次数替代合同。

LuCI devices 对 C 还多约 **0.171 ms/次主体 CPU、0.189 ms mean**，这是明确未达到目标的负载。源码还存在路径格式化、String、rtnetlink 两次 64 KiB 缓冲和消息/属性复制；没有占比证据可把差额唯一归因。统计路径的嵌套 format 可再省每设备十个临时分配，但未测且没有证据足以追回差距；已测去掉十九个分配仅带来约 1.45% handler 改善。更大变化如 netlink 统计快照、dirfd/openat、减少读循环涉及采样时点、路径替换或短读/EOF 语义，另需专门证据和验证。这一项保留差距收尾，不冒称机会全无。

最终选择以主要 UCI/ACL 收益换取已量化的少量资源、单次 CLI 和部分短请求/尾延迟代价。没有性能分数要求放松权限、锁、解析、超时或回收。十三个有机制差异的候选、组合反例、统一筛选、正式增量及独立三方确认已足以支持保留 H1；继续枚举小参数或反复采样直到尾延迟变好不能增加当前结论的可信度。**本轮结束于“有边界的 H1 工程改进”，不宣布全负载胜 C/R89、全局最优或生产已上线。**
