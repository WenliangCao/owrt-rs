# fw4 H13 工程结案（2026-09-28）

**保留一个小改动：渲染直接写入最终 String。正式构建、相关合同门和一次 AX3000T 三侧确认完成；未部署。** 本轮相对重建的当前源码，Oracle 普通 print 三窗 CPU 中位数减少 **32.881 µs（4.28%）**，mean 减少 **33.492 µs（3.32%）**。这是小幅的增量收益；下方相对镜像/R89的大幅差距包含 R94 与共享库的既有成果，不能全部记到本轮。

check 没有新增提速结论：Oracle 相对当前源码的命令树 CPU 中位数 **+37.145 µs（1.08%）**、p99 **+878.488 µs（5.12%）**，第三窗 p99 **+1.844 ms（10.80%）**。普通 print 首窗 CPU 也有 **+0.73%**，两侧范围重叠。保留这些结果和 +4 KiB 的 Oracle print 最大 RSS，不宣称逐轮全胜、统计等价或所有场景更快。完整候选/拒绝、每窗指标、所有不利项、hash 和缺测见[索引](fw4-20260928-candidates.json)。

开始时核对了 AGENTS、fw4 合同、R94 报告与完成审计，再读取当前 fw4 全路径。三个初始方向是 UCI→Json 所有权、Blob→JSON 中间对象、渲染临时对象；三个子代理分别研究不重叠的源码/工具问题，候选只在私有副本实现，Oracle/设备窗口由父线程串行执行。

| 身份 | 本轮核验 |
|---|---|
| 精确镜像 | OpenWrt 25.12.5 r33051-f5dae5ece4；image SHA256 `a94ac2c7…` |
| 参考实现 | **shell/ucode + nft**；firewall4 `b6e5157527d361f99ad52eaa6da273cb0f2dfd59`、ucode `85922056ef7abeace3cca3ab28bc1ac2d88e31b1`、nftables 1.1.6-r2。wrapper/main/fw4.uc/templates/helpers 共16文件与上游逐字节一致 |
| 正式 R89 | `/root/r89-before-r90`，manifest与实际ELF均核验；fw4 `c8837ab9…`，1,051,347 B |
| source05 | 历史 ELF `e6bdb321…`，1,055,443 B；单独核 hash，本轮未计时 |
| 当前对照 | HEAD `c41c3d0`，1911文件完整快照及当前 fw4/uci/ubus/Cargo.lock；fresh target 重建 ELF `1849b615…`，1,039,059 B |
| Oracle候选 | fresh target、SDK musl release，`dce40da2…`，1,034,963 B；另有独立 frame-pointer profile ELF，不能混入正式计时 |
| 正式候选 | 代码提交 `a88e443a7a521e489bfb42154ee6d07ffe1a7354`；CI run [36448821280](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36448821280)成功；APK解出ELF与Oracle候选逐字节一致 |

当前对照重建后恰与 H12 正式 fw4 相同，但这由 hash 核验得出，未直接复用旧身份。R94 的 1,140 次分配和旧 ELF 不作为当前基线。所有复制构建使用独立 target，重新设置源码 mtime；正式 CI 是新 runner，核 manifest source commit、official toolchain、APK hash、解包 ELF hash、AArch64/无 PT_INTERP。完整正式 ELF：`dce40da22acb56678010261a060e09b81e626494a92ebad0d40501a6a1e9a614`；APK：`170b88fdd76e2976147e84752af836b9c4e5bc5fb50333fcecb08545d9d9f56d`。结案提交只补工具来源记录和报告，运行时代码仍是 a88e443。

nft 1.1.6 源码压缩包按镜像 recipe 的 SHA256 `372931bd…` 校验；OpenWrt 源码目录 HEAD 实际是 `f0a60eee…`，没有冒充镜像 revision。用 `git show/diff` 另核镜像 `f5dae5ece4` 的 nft recipe/三份构建时间戳补丁，内容相同。`-c` 设置 dry-run，仍发送批量 netlink 命令并等待内核检查，省略提交 batch end；本轮保留真实校验。

同一条调用链的所有权和提交边界如下：

```text
镜像：caller → /sbin/fw4 → utpl/main.uc → fw4.load
       UCI cursor → section动态对象 → foreach解析 → state
       ubus.call → 动态对象 → network/service state
       templates → 顺序输出 → stdout / 管线 nft -c -f → 等待退出

Rust：caller → main::render → Fw4::load
       Context拥有Package → 消费Package → Config<Json> / Rc
       section/type/name移动；Bytes转自有String；Opts借用section
       ubus Reply拥有Blob → fields_to_json拥有Json → 解析为state
       [原位置写state] → renderer借用state、拥有最终out:String
       旧：format!临时String → 复制到out → 释放临时String
       新：write!/writeln! → 直接追加out
       完整String返回 → stdout.write_all / nft stdin → close → wait
```

文件读取/锁、ubus连接、flowtable netlink与失败后nft fallback、进程生成/等待和最终输出提交点均保留。输出不是流式提前提交；state 在 renderer 前已写入。最小反例包括引号/中文注释、空/重复set、include前后空行、log-limit递归和异常输入；现有上游/R29/错误门覆盖这些类型，不用“分配变少”代替逐字节比较。

| 假设与机制 | 可观察预测、反例与处置 |
|---|---|
| H1a：消费UCI字节直接变String | 若存在可移交Vec，可少一次复制；15/16字节和非法UTF-8可证伪。当前 `Bytes` 是≤15字节内联或私有Box，短值没有堆缓冲可转移。静态拒绝，未生成伪候选 |
| H1b：借用四个metadata key | 每section最多省4次分配/26字节key；须保留name/index/anonymous、mock覆盖和警告。Json键必须拥有String，需改9个parser及共用输入边界；收益没有证明足以支持扩大接口，拒绝 |
| H2：Blob直接进最终state | 当前 `field_to_json` 约100 malloc/print；需保留嵌套、重复/缺失字段、Bytes/数字语义及ubus失败边界。profile未证明必须修改共享库；不把HTTP直接编码器套到需要语义访问的fw4。未进入候选 |
| H3：直接格式化到out | 每个执行站点省外层String/复制/free；若实测分配/print CPU不降则拒绝。实际改113站点（78 write、35 writeln）；逆变换后9,880个非注释token与旧代码一致。保留，范围只含同一格式化机制 |

当前 `write_includes` 已直接写出；set的去重Vec、quote和loadfile缓冲仍有成本，但没有混入第二机制。`render.rs` 是唯一运行时修改，无共享uci/ubus改动，因此没有重开rpcd/netifd/reload-config性能矩阵。全部九组件仍由正式构建产出，生产始终使用精确镜像实现。

Oracle/aarch64 的普通负载重新做20次分配采样（17+3预热），与未插桩性能窗口分开：malloc **984→942**、realloc **139→124**、free约**981→939**。`from_package`约151、Blob→JSON约100、UCI option分配约106仍在，减少定位到renderer。每次系统调用中位数 **140→140**，mmap/munmap **21/19→21/19**；没有系统调用减少声明。

筛选先pilot，后冻结普通 print 1000次/check 200次，三组 AB/BA/AB；短/大配置print 200、check 20，预热3。大配置8 zone、256 rule、128 set entries，含helper声明和regular include。Oracle真实内核没有相应helper模块，警告被保留；可用helper渲染由上游mock门覆盖，不把这组性能当作可用helper性能。短配置1 zone/2 rule/2 entry。普通print门槛为CPU同时3%及20 µs、mean方向一致；大print门槛5%及100 µs。大型print CPU **9447.990→9271.455 µs（−1.87%）**，未达到大配置5%门槛；第二组大print p99还升了0.185%。短check p50 **+7.76%**、树CPU **+6.53%**；普通check调用方CPU **+12.84%**。全部23项Oracle单窗不利指标保留在索引。

第三组普通check p99 **17063.100→18906.714 µs** 超过10%及100µs关注门槛。逐窗复核时设备pilot已完成，正式确认尚未启动；暂停后只做一次 **7.78秒**诊断（每侧10次strace）。进入nft前的中位耗时 **5.084/5.051 ms**，wait4中位 **15.788/18.238 ms**，波动主要在nft等待边界。插桩改变了绝对时长，不能回溯证明原p99的原因；原结果保持不变，未补筛选轮直到变绿。保留候选是对print局部收益及小改动的工程选择，不以print平均收益宣布check尾部退步消失。

正式ELF再次通过：unit **17/17**、clippy、release/正式打包；R09当前runner **31文件31例**、R29 **200例/0差异**（23例上游自身异常按既有合同比较）、R83 defaults **12/12**、镜像真实nft check、R92 **16/16**（errno、abort、state、信号/30秒include超时）。另外真实建立/删除flowtable后输出均与镜像相同；注入netlink socket EPERM后确认spawn并等待原nft fallback，stdout/stderr相同。start、zone/network/device、reload-sets、reload、stop、flush、restart、check的正常动作链也逐项比较。当前与正式候选八份state文件逐字节相同；stock的null/空数组与省略默认字段是既有表示差异，不声称state文件与stock逐字节相同。

AX3000T确认使用Wi-Fi en0管理、精确镜像ubusd/netifd/nft/ucode依赖、私有mount/PID/network namespace和600秒guard。pilot全窗 **18.301秒**，正式按预定三block顺序 **候选/R89/镜像；镜像/候选/R89；R89/镜像/候选**，每侧每lane每窗300次、预热3。一次正式队列共 **5400次成功、54次预热、0错误，414.424秒**（含准备/传输/校验/清理），未追加窗口。生产九组件、离线备份、配置、同boot、客户端健康与每窗清理门全过。

下表是三个窗口统计量的中位数，CPU/延迟单位µs；**命令树CPU包含短命子进程**，不能标作fw4自身check CPU。吞吐为次/秒。全部范围、每个原始窗口和绝对/%差值在索引。

| lane | side | 命令树CPU | mean | p50 | p95 | p99 | 吞吐 |
|---|---|---|---|---|---|---|---|
| print | 镜像 | 96344.573 | 100567.383 | 99296.075 | 107520.119 | 118530.550 | 9.941 |
| print | R89 | 9526.290 | 10882.494 | 10686.426 | 11619.350 | 14577.855 | 91.650 |
| print | 候选 | 3185.727 | 4275.407 | 4082.554 | 5078.724 | 7057.754 | 232.281 |
| check | 镜像 | 108130.870 | 149756.914 | 149954.671 | 170033.815 | 190112.423 | 6.677 |
| check | R89 | 19808.720 | 61188.363 | 60007.074 | 79948.724 | 89856.112 | 16.341 |
| check | 候选 | 13470.267 | 55323.524 | 50231.182 | 70021.026 | 79469.760 | 18.073 |

| lane | 指标 | 相对镜像：绝对 / % | 相对R89：绝对 / % |
|---|---|---|---|
| print | 命令树 CPU | -93158.847 µs / -96.69% | -6340.563 µs / -66.56% |
| print | mean | -96291.976 µs / -95.75% | -6607.086 µs / -60.71% |
| print | p99 | -111472.796 µs / -94.05% | -7520.101 µs / -51.59% |
| check | 命令树 CPU | -94660.603 µs / -87.54% | -6338.453 µs / -32.00% |
| check | mean | -94433.390 µs / -63.06% | -5864.839 µs / -9.58% |
| check | p99 | -110642.663 µs / -58.20% | -10386.352 µs / -11.56% |

这些正式指标的中位数均优于两基准，但不等于每个资源或每轮全胜，也没有设备上current→H13增量A/B。候选print三窗p99为 **11.006 / 5.125 / 7.058 ms**；第一窗最大16.115ms也保留。check p50三窗 **50.184 / 59.474 / 50.231 ms**，真实nft等待仍主导墙钟，不能把这部分当renderer收益。

依赖和调用方CPU单独列出（µs/次；各列独立取中位，不能相加重造另一中位数）：

| lane | side | 镜像netifd自身 | 镜像ubusd自身 | 调用方自身 |
|---|---|---|---|---|
| print | 镜像 | 133.998 | 576.673 | 690.369 |
| print | R89 | 124.569 | 769.996 | 541.355 |
| print | 候选 | 123.393 | 530.880 | 536.248 |
| check | 镜像 | 142.874 | 577.365 | 478.606 |
| check | R89 | 132.264 | 771.438 | 466.432 |
| check | 候选 | 131.587 | 499.925 | 462.137 |

这两项依赖的已回收child CPU增量均为0；uci/ubus库内工作包含在调用它们的进程里，没有单独库CPU计数。设备fw4自身与nft独立CPU未分离，明确缺失。另做的Oracle `cpu-clock` profile只用于归因：镜像shell+utpl约 **18867 µs**、R89 fw4约 **1229 µs**、候选fw4约 **858 µs**；nft分别约 **3636/3537/2290 µs**，额外sh约 **403/430/5 µs**。候选ubusd/netifd/调用方约 **155/34/245 µs**。这些是含3次预热的采样估计，有采样误差，不与正式数据混算；零个uci/ubus进程样本不代表链接库零成本。

正式各block不利CPU项如下（own/tree相同项合并；索引保留14条原始分列），没有延迟p95/p99跨冻结阈值的block退步：

| block | lane | 基准 | 指标 | 增加µs/次 | 增加% |
|---|---|---|---|---|---|
| 1 | print | r89 | caller | +33.364 | +6.20% |
| 1 | print | r89 | netifd_own | +6.723 | +5.44% |
| 1 | check | r89 | caller | +3.968 | +0.85% |
| 1 | check | r89 | netifd_own | +1.845 | +1.42% |
| 3 | print | stock | ubusd_own | +27.207 | +4.78% |
| 3 | print | stock | dependency_own | +17.868 | +2.54% |
| 3 | check | stock | ubusd_own | +21.355 | +3.70% |
| 3 | check | stock | dependency_own | +10.346 | +1.44% |

资源方面，Oracle十次独立print启动的 `time -v` 最大RSS：当前源码每次 **920 KiB**，候选每次 **924 KiB（+4/+0.43%）**；minor fault为49–50与50–51。正式三侧各10次，镜像/R89/候选最大RSS中位数 **1912/1938/924 KiB**，候选分别少 **988/1014 KiB（51.67%/52.32%）**。这个指标是waited-child maxrss，**不是多进程并发RSS之和**。各轮退出并被等待后无fw4残留，依赖RSS/匿名页/fd在各自Oracle窗口稳定；观察的是重复新进程回收，不证明长期同进程无泄漏。

设备依赖resident中，候选侧ubusd RSS/HWM中位数 **924 KiB**，镜像/R89侧均908，**+16 KiB/+1.76%**；RssFile **840 vs 828（+12/+1.45%）**，RssAnon相对镜像 **84 vs 80（+4/+5%）**。这些是相同ELF依赖的各窗驻留差异，未证明由renderer造成；索引保留全部7项增加、范围和fd/线程。设备fw4启动RSS/fd、瞬时峰值、整棵树并发峰值未采到，不能写成相同或已验证降低。每窗数百次启动/退出及PID namespace销毁验证了本次退出/清理边界。

失败尝试也保留：最初将`/dev/null`用作include，真实nft两侧均拒绝“非普通文件”；只纠正为私有regular文件后重跑该无效夹具。一次Python转义错误让旧夹具再次启动，已终止并排除。uprobes删除通过tee失败，随后用重定向清掉本轮独立事件组；未让探针进入正式计时。旧strace汇总误把total行再次计入，正文140/140来自原始表。首次scp无权读perf.data，改为有SHA核验的归档回传。没有错误ELF参与筛选，未覆盖或删除这些原始日志。

停止理由：已定位并保留一个简单、无共享接口改动的print机制；UCI转移假设被实际存储类型证伪，metadata/Blob进一步改造没有充分收益证据。check的尾部与资源代价已单列，不继续调参数、追加机制或补轮。未证明所有配置分布、reload-sets/start等动作的性能、真实整栈组合收益，亦未部署。原始数据、ELF和备份留在ignored `private/fw4-20260928/`、Oracle同名目录及`fw4-20260928-final/`；Git只保留代码、通用fw4负载选择、工具来源、主报告与索引。

工具身份：最终isolated.sh `19f06aaee743fc5778a508f5918e471ae41eb0222aa46e977af2f9ef98c2d077`；benchmark ELF `eb4d563084f5f6270ccfddf8e8244582ab1a3d3802c89071996b2267bf743dd5`；ns-exec `fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2`。其余已采工具/源码/profile ELF/正式manifest、APK和原始归档SHA256列在索引。早期Oracle私有workload没有逐窗输出脚本hash，索引保留归档版本及调用记录，不冒充追溯执行证明；正式设备每窗工具/脚本和主体/依赖身份均已核验。
