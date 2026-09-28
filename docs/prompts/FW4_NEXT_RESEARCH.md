# fw4 H13 研究提示

你是这个项目的系统性能工程师。继续九组件 Rust 控制面优化；本轮组件是 **fw4**（OpenWrt firewall4 的 Rust 替代实现）。立即检查、研究、实现、构建和验证，不只给计划。目标是在保持规则输出、安全、错误、恢复和清理合同的前提下，改善 `fw4 print`/`fw4 check` 的实际热路径；没有值得保留的新改动时，保留现状并结案。

## 先建立事实边界

先读 `AGENTS.md`、`docs/contracts/fw4.md`、`docs/reviews/R94_FW4_KERNEL_QUERY_NOCLONE.md`、`docs/reviews/R94_COMPLETION_AUDIT.md` 和当前 `components/fw4/`，然后按需读取精确 OpenWrt 镜像中的 firewall4/ucode/nft 源码与最新证据。不要扫描整个仓库或把历史候选当作当前身份。

fw4 的镜像参考实现是 shell/ucode 加 nft；不要把它称作不存在的 C 实现。核对精确镜像、正式 R89 bundle `/root/r89-before-r90`、当前源码和每个候选 ELF。R89、source05、Oracle 诊断构建和正式候选必须分开记录。R94 fw4 证据早于 httpd H12 对共享 `ubus` JSON/Blob 代码的改动，不能直接把旧 ELF、旧分配计数或旧矩阵当成当前基线；先冻结当前完整源码与依赖快照，按当前快照重建需要的对照。生产九组件始终使用精确镜像实现；候选只在现有隔离 mount/PID/network namespace 运行，不部署、刷写、重启、替换生产进程或修改生产 Wi-Fi、网络设备、nft、ubus 状态。

## 已知线索与研究方向

R94 已定位：当前 fw4 候选每次 `print` 约 1,140 次 malloc；剩余可量化来源包括 `owrt_uci::parse::import`/`add_section`、`field_to_json`、`Config::from_package`，以及 render/includes/set 路径的临时 `Vec`/`String`。flowtable netlink 查询、失败 fallback、规则零拷贝解析和渲染已经有实证收益，不要先重写它们。

开始时只给一个小证据表和最多三个可证伪假设。优先验证：

1. UCI package 到 fw4 内部状态的 clone/中间 `Json` 是否还能安全减少；
2. ubus Blob→JSON 或 render/includes/set 的临时对象是否仍占主要成本；
3. 某个剩余分配是否只影响 `print` 而不会改变 `check`、状态文件或 fallback。

不要预设需要缓存、替换 allocator、重写事件循环或改变 nft 子进程调用。由 profile 和精确上游行为决定顺序。每个候选只改变一个机制；最多两个子代理处理不重叠的源码/证据问题，同一设备性能窗口串行。若 Oracle 无法把收益归因，或连续两个有依据的方向没有实际收益，停止新增机制，不自动转做 UCI 或其他组件。

## 把它当作算法研究

先画出精确参考实现与 Rust 的同一条调用链：输入所有权、借用/复制边界、对象生命周期、分配点、系统调用和输出提交点。每个假设都必须写出：具体函数/数据结构、参考实现为何这样做、Rust 当前多做了什么、预期节省的操作、必须保持的不变量、最小反例和会证伪它的指标。没有代码级机制和可观测预测的“优化想法”不进入候选。

同一个假设若有多个可微调方向，主动并行拆分。例如对“减少 UCI→JSON 中间对象”可以分别让两个子代理研究借用字段、一次定容/直接写出等变体；每个代理只拥有自己的 worktree 或私有候选副本，提交机制说明、差分、测试和 profile 结果，不能同时改共享主工作树。父线程比较各变体后再合并一个候选；不得让多个代理重复跑同一证据，也不得把未核验的代理结果当成最终结论。可以并行做静态源码/微基准/候选实现，但 Oracle 性能窗口和 AX3000T 窗口必须串行。

先用 `components/fw4/src/{uci,val,parse,render,emit}.rs` 与匹配的 firewall4/ucode 实现做代码级对照，再选择小型确定性 profile。可复用 `tools/r09_fw4_check.py`、`tools/r29_fw4_fuzz.py`、`tools/r83_fw4_defaults.sh`、`tools/r92_fw4_probe.py` 和现有 benchmark/isolated 工具；工具只补通用负载选择，不另建研究框架。不要通过随机改写、连续试参数或“看起来更快”的单次 wall 样本前进。

## 实验和候选边界

先在 Oracle/aarch64 做 release profile 和定向正确性筛选；实际工具、源码、ELF hash 都要记录。复制源码或使用增量构建时主动处理 mtime/cache，强制确认产物确实来自本候选，不能拿旧 ELF 参加筛选。先用短 pilot 测量包含准备、采样、传输、校验和清理的完整窗口，再冻结负载、请求数、预热、轮数、顺序、指标和实际影响门槛。预算不足时缩小尚未冻结的次要范围，不把“再确认一次”变成无界队列。

`print` 是主要性能目标；`check` 的墙钟通常由真正执行 `nft -c -f -` 的子进程和内核校验支配，应把它作为边界保护并单独归因，不把 `child_cpu` 写成 fw4 自身收益。筛选至少覆盖普通 `print`、`check`、flowtable 存在/缺失 fallback，以及包含 zone、set、helper、include 的短/大配置；只有改动实际影响时才加入 `reload-sets`、`start` 或 `stop`。不要把所有配置规模、并发、状态和子命令做笛卡尔积。最终只做一次有代表性的精确镜像实现/R89/候选三侧交错确认。

分别报告 fw4 自身、nft/ubus/uci 依赖、短命子进程和调用方的 CPU，及 mean/p50/p95/p99、吞吐、错误、分配/系统调用（可测时）和启动/关闭资源。短命 `nft` 子进程 CPU 不得冒充 fw4 自身 CPU；插桩和 trace 不得混入正式对照。缺失的峰值明确记缺失，不写成相同。

候选必须保持：

- nft 输出逐字节相同，包含排序、空行、制表符、注释和 include；
- zone、set、helper、flowtable、state 文件和 ubus 输入语义相同；
- netlink 查询失败时仍走原 nft fallback，mock 后端仍走原路径；
- 错误文本、errno、警告、退出码、信号、超时、锁、子进程等待和清理边界相同；
- `start`/`reload`/`stop`/`flush`/`restart`/`check`/`print`/`reload-sets` 及查询子命令的既有合同不被性能取舍放松。

共享 `uci` 或 `ubus` 库只有在 profile 证明必要时才修改；届时补所有实际受影响的 rpcd、netifd、reload-config 合同回归，但不重开已关闭组件的性能矩阵。不得用放松错误处理、无限缓存配置、跳过 nft 校验或改变规则应用顺序换分数。

## 验收和收尾

筛选候选先跑受影响的 unit、clippy/release、fw4 upstream/R29 differential、R92 兼容和相关恢复门。最终候选必须再通过干净正式构建、manifest/APK/ELF 身份核验、完整相关功能门和一次代表性 AX3000T 三侧确认后才能写成“已验收”。生产仍使用精确实现；本轮不做部署。

保留每轮原始数据、异常、失败身份、资源差异和工具 hash。不以平均收益抵消尾部退步，不把测不准写成持平。性能异常原样保存并停止该队列，最多做一次问题明确、有时间上限的诊断；不补轮直到结果变绿。短命 fw4 也要在适用时重复启动/关闭或配置处理，区分一次性页增长和持续增长。

完成定义是：实现并验证最有希望的单机制或确认现状更好；完成相关合同门、正式构建身份和代表性三侧结果；提交一份人话主报告、候选/拒绝索引和清晰 commit。报告必须说明相对精确镜像实现/R89 的绝对量与百分比收益、每项退步、依赖/子进程成本、资源与回收观察、尚未证明的范围、工具/ELF hash 和停止理由。未完成的构建或门如实标记，不能为赶时间写成通过。可自主运行已授权的本地、Oracle 和隔离测试，不逐步请求确认。
