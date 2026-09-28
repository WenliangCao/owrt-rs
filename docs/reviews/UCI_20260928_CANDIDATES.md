# UCI 候选与拒绝索引（2026-09-28）

冻结起点：`2855345597e0ba42bbdcae05e5b9f1bb7cf49275`。本索引区分源码归因、Oracle SDK 筛选、正式构建和 AX3000T 验收。以下 Oracle 数字只裁决本轮增量，不能替代精确 C／正式 R89／R94 原 ELF／最终正式 ELF 的四侧实机表。正式构建、设备身份与验收见 [研究报告](UCI_20260928_RESEARCH.md)。

## 原始候选、机制与处置

| ID | 原始提交 | 具体改动及不变量 | 证据与处置 |
|---|---|---|---|
| C1 | `ca2e3c5` | 新建读取缓冲从 `Vec::new()+resize` 改成 `vec![0; bounded_hint]`，引导零初始化分配；仍是一笔分配，不能说少一次分配。共享 `read_into`、EOF／短读／EINTR、预算、缓存复用保持。 | **拒绝。** 实际 CLI 收益不一致：export_64 CPU −4.12%，但 export_network +0.50%、delta_64 +2.41%、show_long +1.98%、batch +1.28%；与 C2 组合后小包 export/get 分别 +3.46%/+5.06%。未证明值得增加的新收益，不撤销已有读取正确性修复。 |
| C2 | `1edd29d`（原分支父提交为 C1；集成只取 CLI diff） | 借用剩余 argv 切片；命令直接 ASCII 不区分大小写比较；不再复制 Vec/两参数缓冲和两个命令字符串。原始 tuple bytes、未知命令／usage／退出码、每 batch 命令卸载保持。 | **保留。** 真实 CLI 分配归因少 5 次；Oracle 单独 C2 的 export_network/export_64/set_commit_get CPU 为 −2.53%/−2.72%/−2.16%。show_long +2.04% 同时披露。集成提交 `a2ed3bb`。 |
| D1-delta | `bd6f74c` 的 delta/export 部分 | `delta_save` 复用现有 export 分段转义 helper，普通连续值一次写，单引号仍转成四字节转义；原始字节和首次写错返回保持，无新分配。 | **保留。** 8192 字节无引号值：Write 调用 8199→8；每 31 字节含一个单引号时 8199→537。仅作为归因；没有单独 D1 CLI 性能声称。集成 `c4dd4de` 的净保留部分。 |
| D1-show | `bd6f74c` 的 show 部分；`50186d5` 撤回 | 同 helper 在首次写错后早退，而旧 show 会忽略该次错误继续输出。普通输出微基准虽大幅减少调用，失败行为不等价。 | **拒绝并撤回。** 不为此引入恢复状态机；最终 show 与起点相同。集成撤回提交 `c9ba14e`。其正常路径收益不记入最终候选。 |
| D2 | `07e5cd3` | Changes 只读借用 Package；load_delta 先从借用路径/包名构造 owned filename；filter_delta 把 Ptr 字段移入保留项。路径和包索引不被 delta 操作改变；不改锁／重读／截断／flush／fsync／mode／rename。 | **保留。** 固定 128 保留 delta 的归因：load 少 3 次分配，revert 少 387 次；Changes 删除的原整包 clone 单独需 651 次分配。与 C2+D1-delta 组成 simple 重新计时，不相加单项收益。集成 `5dcbf1e`。 |
| P1 | `321a32c` | parser 临时命名节 HashMap，已有节数达到 64 后的下一次查找才建表；保持首项/重复定义/匿名节/跨包顺序及错误位置。没有改全局模型或 ReadCache。 | **拒绝。** 重复名字扫描是实际平方级热点，1024 节 CLI CPU −52.91%；但独立规模对照的 8 节 CPU +21.13 µs/+8.94%，mean +16.752 µs/+5.82%，ELF 约增 12 KiB。大合成配置收益不足以接受常见小包成本与索引复杂度。未执行本候选正式设备/共享消费者门，不标通过。 |

C2、D1-delta、D2 是最终 `simple` 组合。`combined` 特指 C1+C2，不是最终方案；`parse` 指 P1，不能把六种筛选标签混淆。保留既有 15 字节内联 Bytes、ReadCache 当前字节重核实/模型复用与全部 R95 I/O 修复；没有重启已收尾组件优化。另一个“缓存最近 list option”想法没有实现：单长列表每行一次比较，未取得新机制证据，停止扩展。

## 同批 Oracle 确认：最终 simple 对冻结起点

读取已有 `oracle-screen.tar.gz/confirm`，没有新增性能测量。六种 SDK 诊断产物，三个交错轮次，每 lane 每轮 5 次预热、200 次正式执行；`exec-strict` 校验 stdout/stderr/退出。CPU 为 getrusage 已回收命令树 user+system；set_commit_get 包含 shell 和三个 CLI。单位 µs/次，单元格为三轮中位数 [最小–最大]；百分比用中位数相除。本表保留不利结果，不把范围重叠写成相等。

| 负载 | 起点 mean | simple mean | 起点 CPU | simple CPU | CPU 差 µs / % |
|---|---:|---:|---:|---:|---:|
| export_network | 290.161 [281.919–294.443] | 277.234 [265.869–289.905] | 236.065 [224.395–240.270] | 218.160 [215.595–234.400] | -17.905 / -7.58% |
| export_64 | 472.831 [458.418–476.831] | 460.340 [456.703–465.092] | 425.585 [408.635–427.270] | 413.845 [407.015–416.150] | -11.740 / -2.76% |
| set_commit_get | 1978.020 [1969.626–2013.967] | 1956.154 [1937.362–2023.288] | 1953.855 [1947.115–1988.925] | 1933.320 [1921.200–1995.160] | -20.535 / -1.05% |
| get_network | 284.930 [273.792–286.789] | 272.705 [272.308–275.340] | 238.510 [227.760–242.525] | 226.500 [224.775–229.540] | -12.010 / -5.04% |
| export_multi | 975.745 [967.644–981.568] | 967.275 [966.236–973.070] | 921.010 [918.250–929.685] | 916.710 [915.435–922.230] | -4.300 / -0.47% |
| show_long | 1380.900 [1358.723–1381.003] | 1397.978 [1371.988–1400.373] | 1311.375 [1287.240–1312.885] | 1331.020 [1306.460–1331.450] | +19.645 / +1.50% |
| delta_64 | 552.789 [552.567–559.296] | 538.840 [520.967–542.099] | 492.915 [486.130–497.830] | 476.960 [460.420–481.685] | -15.955 / -3.24% |
| batch_read16 | 1703.812 [1695.205–1716.004] | 1722.791 [1703.562–1726.266] | 1642.445 [1627.620–1650.065] | 1658.885 [1635.765–1660.755] | +16.440 / +1.00% |

边界：simple 的 show_long CPU +1.50%、batch_read16 +1.00%；为保留错误语义，show 的输出循环已撤回。未据此宣称常驻共享消费者净收益或路由器胜负。各被拒绝方案的完整八 lane 绝对值/三轮范围留在 `uci-20260928-candidates.json`；P1 的四档规模数据另见 `private/uci-next-20260928/parse-summary.md`。不复用相邻平台/不同负载计算“总净收益”。

## 验证与原始证据索引

- `construct-summary.md`／`construct-profile-final.json`：C1/C2 机制、分配阶段、输入输出身份；27 个起点/候选 CLI 配对场景字节与模式一致。C1/C2 原生 Linux 48 测试通过；最终 simple 与四消费者累计 310 个顶层测试和五个规定 clippy 命令通过，见 `construct-final-native-validation`。这些不是旧消费者 ELF 的证明。
- `delta-summary.md`／`delta-research`：36 步 × 起点/D1/D1+D2/final 四源码侧完整 stdout/stderr/exit、配置/delta/state bytes+mode 一致；4865 字节 raw 值包含 0xff/0xfe、引号、反斜杠，覆盖 batch、import/-m、-P、revert、commit。另有 45 项本机 UCI 测试及规定 clippy 通过。Count/profile 从未当成 CLI 总耗时。
- `private/uci-next-20260928/parse-summary.md`／`profiles/parse`：确定性比较次数 N(N−1)/2、临时索引实现和 10 parser 测试、Oracle 独立 scale 对照；小包退步作为拒绝反例保留。
- `oracle-screen.tar.gz`：`pilot` 因精确镜像 BusyBox 无 stat 而失败，原失败记录保留；`pilot-fixed` 用兼容权限检查后完成；`confirm` 为有限三轮裁决；`scale` 为 P1 规模裁决。不得把失败 pilot 标为通过或计入性能总结。
- `uci-20260928-candidates.json`：从 confirm 原始 getrusage 与 mean 机械导出的各方案中位数/范围及原 archive SHA256。所有 raw、ELF、源拷贝留 private。

## 测量工具的补强与审查

- `bdcda9c` → 集成 `3bc3880`：新增 exec-strict，普通 exec 行为保持，测量每次 stderr 均校验；2 个 exec-journal 测试通过。
- `52c6b42`/`ba11fe6` → 集成 `802e2ef`/`c1e657a`：为 subject=None 提取 command_tree_cpu_us_per_op，保留 legacy tick；不完整/回退旧输入不伪造精细指标，caller clock 与完整 getrusage 同时有效才通过短命 CPU 门。12 个分析测试通过。
- `38aea61`：扩展 UCI 八 lane、四侧、三轮分析与 fixture 反例；`2565a54`：真实 main 生成 markdown 优先精细 command-tree CPU，守护进程继续 own clock。13 个 candidate-side 测试通过。
- `exec_resource.c` 只读审查及本机功能检查：wait4 重试 EINTR、正确转发 exit7/信号143/exec失败127；wx 保留旧文件；mode 由 0666&umask 决定，umask077 时实测0600。资源诊断的输出均为计数，无配置值。功能结果在 `helper-audit/functional-results.json`；macOS 的 ru_maxrss 单位不同，本机数值没有用作 Linux/路由器资源证据。
- helper 的限定边界：在 wait4 后才打开 JSON，所以输出碰撞/目录不可写时命令已经执行一次然后返回2。本轮使用新目录中的独立样本名，不构成当前执行错误；不得宣称“输出路径错误必在命令前拒绝”。不为此改动已冻结计量工具。
- Linux ru_maxrss 是相关单进程峰值的最大值，不是并发进程 RSS 总和；可包括小型 launcher 的 fork→exec 区间。shell/reaped-child CPU 不冒充 UCI 自身；资源样本 stdout 到 tmpfs 文件，计时 stdout 到 pipe，两类观察分开披露。

本索引记录筛选证据；最终 canonical、r16/r24/r83、物理恢复门与四侧实机数据由主报告独立列出。停止理由是主要机制已有可检验结果，简单组合已筛选，C1/P1 与 show 快路径均有明确拒绝边界，继续调阈值或增加恢复抽象不足以改变工程决策。

最终组合的补充真实 CLI 分配插桩：同 argv/路径/fixture 下，network 与 64-section 的 CLI/other 分配都从 38 降至 29（各少 9 次）；读取、解析、Bytes 与 export 缓冲分配次数均不变，requested-live peak 分别 5493→5426 和 39952→39882 字节。此计数排除 libc 内部/allocator 元数据/退出清理，不能当作 RSS。证据为 `private/uci-next-20260928/final-allocation.json`。
