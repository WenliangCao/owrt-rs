# R136 覆盖补测：CPU 全部下降，注册/对象事件仍有四项慢尾负项

18 条负载的平均延迟配对中位数均下降，daemon CPU 的 18 项均按冻结规则记胜；平均延迟仅 11 项记胜、7 项未分辨。全部 90 个指标为 **60 胜、4 负、26 未分辨**。四个明确负项仍是注册/对象事件尾延迟；小包扇出的驻留增量也仍有代价。

**原 `completion-01` 保持 FAILED。** 本页汇总原已完成的性能/背压窗口、原通过的 6 个内存窗口，以及另行冻结并通过的 6 窗内存补测。共 46 个合格窗口来自两个明确区分的集合；另有 1 个原失败内存窗口单列诊断，不进入合格统计。不能将它写成原 46 窗计划无失败通过。

候选固定为 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`，控制为匹配镜像 C `cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88`。采集期间生产保持九个精确 C 组件；没有部署候选。

## 18 条性能负载

主矩阵 15 条：16 窗、ABBA × 4、每条每窗 10,000 次；两侧使用相同 Rust `owrt_ubus::Connection` benchmark。直接 SEND 3 条：独立 16 窗、ABBA × 4、每条 5,000 次及 200 次预热，使用匹配镜像 libubus 调用者。CPU 全部使用 daemon 进程时钟，无 tick 回退。`event_*` 是 ADD+REMOVE 对象生命周期通知；`user_*` 才是直接 SEND。

表中百分比是**八个不复用相邻 AB/BA 配对的百分比变化中位数**，不是各侧中位数之比。低于 −1% 且至少 7/8 对下降记胜；高于 +1% 且至少 7/8 对上升记负；其余未分辨。判定使用未四舍五入的有理数计算。±1% 是工程带，未分辨不证明等效；没有多指标显著性校正。

| 负载 | Mean | p50 | p95 | p99 | Daemon CPU/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| lookup | -9.878% 胜 | -8.579% 胜 | -22.854% 胜 | -9.731% 未分辨 | -28.123% 胜 |
| lookup_all_64 | -28.969% 胜 | -29.903% 胜 | -28.260% 胜 | -14.857% 未分辨 | -70.428% 胜 |
| invoke | -10.833% 胜 | -9.685% 胜 | -21.905% 胜 | -7.818% 未分辨 | -30.981% 胜 |
| lookup_c4 | -22.943% 胜 | -30.720% 胜 | -29.481% 胜 | -22.484% 未分辨 | -31.442% 胜 |
| lookup_all_64_c4 | -61.996% 胜 | -56.294% 胜 | -65.528% 胜 | -64.699% 胜 | -73.159% 胜 |
| invoke_c4 | -8.407% 未分辨 | -10.182% 未分辨 | -7.664% 未分辨 | -6.212% 未分辨 | -31.477% 胜 |
| lookup_prefix_64 | -30.735% 胜 | -31.724% 胜 | -27.477% 胜 | -14.043% 胜 | -70.408% 胜 |
| lookup_prefix_64_c4 | -63.841% 胜 | -56.507% 胜 | -72.656% 胜 | -71.763% 胜 | -74.020% 胜 |
| lookup_all_128 | -35.563% 胜 | -32.870% 胜 | -43.337% 胜 | -48.635% 胜 | -70.045% 胜 |
| lookup_all_128_c4 | -63.160% 胜 | -59.435% 胜 | -63.947% 胜 | -65.290% 胜 | -74.438% 胜 |
| register_1 | -1.294% 未分辨 | -10.372% 胜 | +29.328% 负 | +8.513% 未分辨 | -17.408% 胜 |
| register_16 | -7.577% 胜 | -8.639% 胜 | -1.691% 未分辨 | -1.881% 未分辨 | -13.250% 胜 |
| event_1 | -3.538% 未分辨 | -8.217% 胜 | +17.363% 负 | +9.544% 未分辨 | -19.887% 胜 |
| event_8 | -23.744% 胜 | -25.579% 胜 | -7.734% 胜 | -8.026% 未分辨 | -39.296% 胜 |
| event_nomatch | -3.926% 未分辨 | -10.732% 胜 | +33.407% 负 | +13.800% 负 | -20.385% 胜 |
| user_1_1 | -20.277% 未分辨 | -12.120% 胜 | -36.791% 未分辨 | -31.328% 未分辨 | -25.736% 胜 |
| user_8_1 | -8.594% 未分辨 | -9.580% 未分辨 | -7.762% 未分辨 | -9.321% 未分辨 | -24.506% 胜 |
| user_1_0 | -8.868% 未分辨 | -7.987% 胜 | -20.712% 未分辨 | +6.822% 未分辨 | -19.807% 胜 |

主矩阵为 55 胜/4 负/16 未分辨；直接 SEND 为 5 胜/0 负/10 未分辨。SEND 的三项平均延迟都未达到 7/8 同向门，不能称其平均延迟全部获胜。R134 历史“各侧中位数＋7/8 同向”规则在 JSON 单独派生，本次数量恰好相同，不与主规则混算。

### 全部更高的时延中位数

以下同时保留配对中位变化或各侧中位数比值为正的项目。两种估计有时方向相反；主判定只使用前者和冻结同向门。绝对值列是各侧逐窗中位数，单位 µs。

| 负载/指标 | C | R136 | 配对变化 | 各侧中位数比值变化 | 上升对数 | 主判定 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| register_1 p95_us | 116.413 | 154.577 | +29.328% | +32.783% | 7/8 | 负 |
| register_1 p99_us | 206.397 | 218.747 | +8.513% | +5.983% | 6/8 | 未分辨 |
| event_1 p95_us | 187.738 | 217.630 | +17.363% | +15.922% | 7/8 | 负 |
| event_1 p99_us | 264.258 | 281.108 | +9.544% | +6.376% | 6/8 | 未分辨 |
| event_nomatch p95_us | 116.683 | 148.960 | +33.407% | +27.662% | 7/8 | 负 |
| event_nomatch p99_us | 211.590 | 233.558 | +13.800% | +10.382% | 7/8 | 负 |
| user_8_1 p99_us | 361.512 | 368.361 | -9.321% | +1.894% | 3/8 | 未分辨 |
| user_1_0 p99_us | 161.810 | 132.995 | +6.822% | -17.808% | 4/8 | 未分辨 |

没有据结果删窗、改变性能门或追加性能样本。既有 R134/R135/R136 定向和 Oracle 样本没有拼入本表；本次没有同期 R134 控制，不能据负项数量变化宣称历史慢尾已修复，也不能将对 C 的差距精确归因为 R136 三个小改动。

## 三类内存夹具

每侧每夹具两个合格观察，以下均为描述性中位数，单位 KiB。idle 的四窗来自原通过记录；large 的首个 C/候选窗来自原记录，后一个候选/C窗来自独立补测；fanout 四窗全部来自独立补测。large 跨越失败与补测间隔，不是连续的一次 ABBA 采集。PSS 不可用，保留 NA；VmRSS 包含共享映射，不能等同系统总内存节省。VmData 也不是驻留内存。

### 空闲连接

| 连接数 | RssAnon C / R136 | VmRSS C / R136 | VmData C / R136 | 同进程匿名增长 C / R136 |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 72 / 40 | 880 / 496 | 44 / 48 | 0 / 0 |
| 1 | 72 / 44 | 864 / 500 | 44 / 48 | 0 / 0 |
| 8 | 76 / 42 | 894 / 498 | 48 / 48 | 4 / 0 |
| 32 | 96 / 58 | 932 / 514 | 68 / 64 | 24 / 16 |
| 64 | 120 / 72 | 956 / 528 | 96 / 80 | 48 / 32 |

64 连接相对于各自同一进程连接前样本，匿名增长 C 48/R136 32 KiB，即 0.75/0.50 KiB 每连接。低连接数下 R136 的 VmData 仍可能高 4 KiB，不能把较低的绝对 RSS 扩展成所有内存指标都更好。

### 单 handler 大消息

| Payload KiB | held 5s RssAnon C / R136 | held−connected 匿名增长 C / R136 | 断开 5s−empty 匿名保留 C / R136 |
| ---: | ---: | ---: | ---: |
| 32 | 108 / 80 | 36 / 36 | 36 / 36 |
| 256 | 332 / 302 | 260 / 260 | 260 / 260 |
| 768 | 844 / 816 | 772 / 772 | 772 / 772 |

大消息新增匿名驻留两侧相同；断开后这些样本仍保留相同增量。此夹具只描述固定负载和时点，不证明峰值、长期无增长或完整分配器行为。

### 八 handler 扇出

八个 handler 共享一个监听连接。表中 held/connected 及断开状态均取对应 5s 采样。

| Payload KiB | held 绝对 RssAnon C / R136 | held−connected RssAnon C / R136 | held−connected VmData C / R136 | 断开−empty RssAnon C / R136 | 断开−empty VmData C / R136 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 78 / 60 | 4 / 16 | 4 / 32 | 4 / 20 | 4 / 36 |
| 8 | 96 / 76 | 20 / 28 | 28 / 28 | 20 / 32 | 28 / 32 |
| 32 | 112 / 82 | 36 / 36 | 36 / 36 | 36 / 40 | 36 / 40 |

**1 KiB 扇出 held 增量仍多 12 KiB RssAnon、28 KiB VmData；断开后的匿名保留多 16 KiB。** 8 KiB 的 held 匿名增量多 8 KiB、断开保留多 12 KiB；32 KiB 断开匿名保留多 4 KiB。绝对匿名驻留更低不能抵消这些增长项。

### 全部合格内存正向差值

以下完整列出 77 个 R136−C 正向差值，按 59 个夹具/相位合并显示；单位 KiB，横线表示该指标没有正向差值。`*_minus_*` 是先在每个进程内计算相位增量，再取两窗中位数。重复的 1s/5s、绝对值和增量是指标明细，不是独立实验次数。全部两侧原值与每窗观察保存在 JSON。

| 夹具 | 对象 | 相位/增量 | ΔRssAnon | ΔVmRSS | ΔVmData |
| --- | --- | --- | ---: | ---: | ---: |
| idle | clients_0 | after | — | — | +4 |
| idle | clients_0 | before | — | — | +4 |
| idle | clients_1 | after | — | — | +4 |
| idle | clients_1 | before | — | — | +4 |
| idle | clients_8 | before | — | — | +4 |
| idle | clients_32 | before | — | — | +4 |
| idle | clients_64 | before | — | — | +4 |
| large | bytes_32768 | connected_1s | — | — | +4 |
| large | bytes_32768 | connected_5s | — | — | +4 |
| large | bytes_32768 | disconnected_1s | — | — | +4 |
| large | bytes_32768 | disconnected_5s | — | — | +4 |
| large | bytes_32768 | empty_0s | — | — | +4 |
| large | bytes_32768 | held_1s | — | — | +4 |
| large | bytes_32768 | held_5s | — | — | +4 |
| large | bytes_262144 | connected_1s | — | — | +4 |
| large | bytes_262144 | connected_5s | — | — | +4 |
| large | bytes_262144 | disconnected_1s | — | — | +4 |
| large | bytes_262144 | disconnected_5s | — | — | +4 |
| large | bytes_262144 | empty_0s | — | — | +4 |
| large | bytes_262144 | held_1s | — | — | +4 |
| large | bytes_262144 | held_5s | — | — | +4 |
| large | bytes_786432 | connected_1s | — | — | +4 |
| large | bytes_786432 | connected_5s | — | — | +4 |
| large | bytes_786432 | disconnected_1s | — | — | +4 |
| large | bytes_786432 | disconnected_5s | — | — | +4 |
| large | bytes_786432 | empty_0s | — | — | +4 |
| large | bytes_786432 | held_1s | — | — | +4 |
| large | bytes_786432 | held_5s | — | — | +4 |
| fanout | bytes_1024 | connected_1s | — | — | +4 |
| fanout | bytes_1024 | connected_5s | — | — | +4 |
| fanout | bytes_1024 | disconnected_1s | — | — | +36 |
| fanout | bytes_1024 | disconnected_1s_minus_empty | +16 | +16 | +32 |
| fanout | bytes_1024 | disconnected_5s | — | — | +36 |
| fanout | bytes_1024 | disconnected_5s_minus_empty | +16 | +16 | +32 |
| fanout | bytes_1024 | empty_0s | — | — | +4 |
| fanout | bytes_1024 | held_1s | — | — | +32 |
| fanout | bytes_1024 | held_1s_minus_connected | +12 | +12 | +28 |
| fanout | bytes_1024 | held_5s | — | — | +32 |
| fanout | bytes_1024 | held_5s_minus_connected | +12 | +12 | +28 |
| fanout | bytes_8192 | connected_1s | — | — | +4 |
| fanout | bytes_8192 | connected_5s | — | — | +4 |
| fanout | bytes_8192 | disconnected_1s | — | — | +8 |
| fanout | bytes_8192 | disconnected_1s_minus_empty | +12 | +12 | +4 |
| fanout | bytes_8192 | disconnected_5s | — | — | +8 |
| fanout | bytes_8192 | disconnected_5s_minus_empty | +12 | +12 | +4 |
| fanout | bytes_8192 | empty_0s | — | — | +4 |
| fanout | bytes_8192 | held_1s | — | — | +4 |
| fanout | bytes_8192 | held_1s_minus_connected | +8 | +8 | — |
| fanout | bytes_8192 | held_5s | — | — | +4 |
| fanout | bytes_8192 | held_5s_minus_connected | +8 | +8 | — |
| fanout | bytes_32768 | connected_1s | — | — | +4 |
| fanout | bytes_32768 | connected_5s | — | — | +4 |
| fanout | bytes_32768 | disconnected_1s | — | — | +8 |
| fanout | bytes_32768 | disconnected_1s_minus_empty | +4 | +4 | +4 |
| fanout | bytes_32768 | disconnected_5s | — | — | +8 |
| fanout | bytes_32768 | disconnected_5s_minus_empty | +4 | +4 | +4 |
| fanout | bytes_32768 | empty_0s | — | — | +4 |
| fanout | bytes_32768 | held_1s | — | — | +4 |
| fanout | bytes_32768 | held_5s | — | — | +4 |

## 原失败窗口与独立补测

原 `memory/large/03-candidate` 的工作负载返回 0，21 个内存相位原始文件及 proc 快照可核对；随后 production `system watchdog` 健康探针的 SSH 退出 255，驱动留下 `passed=false`、`cleanup_verified=false`，整轮随即停止。原 FAILED、结果、健康与 raw 文件均保持不变。

之后只读检查确认同 boot、九个精确 C 身份与配置未变、watchdog 正常、无所属测试目录/挂载。它是延后的观察，不能补成原即时健康检查成功。独立六窗计划只运行新的 large 候选/C各一窗及 fanout 四窗；六窗自身的健康、身份、raw 和清理门均通过。

失败窗口从合格内存中排除，但其全部 21 行 raw 内存诊断与 63 个对合格 C 中位数的具名诊断差值同时公开。**全部 21 个相位的 VmData 都高于对应合格 C 中位数 4 KiB**；没有把这些正项隐藏。RssAnon/VmRSS 未出现同类绝对正差。该单窗没有合格健康门，以上比较只作原始诊断，不构成验收或独立优势结论。

## 背压、恢复与证据边界

同一 ELF 的既有实机 wire/FD 前置继续作为冻结证据；新增 C/候选 grouped、interleaved、monitor、slow 各一案，共 8 案功能检查通过。正常场景每案 16,000 个回调；slow 场景堵塞期保留 C 542/候选 574 个回调，恢复发送后总数 550/582。内容、顺序、FD 恢复和对象清理均通过；这些两窗只作功能门，不作性能排名。

主矩阵曾在窗口 12 后失去本地采集会话。窗口 12 的远端 raw 已完成，但原 SSH 退出码未观察到；延后 host-after 相对最后 resident 快照晚 206.84s，窗口 13 的 host-before 晚 513.86s。间断处于 ABBA 块和不复用配对之间，不跨间断配对；时序间断仍是限制。

首次恢复工具错误地将 namespace 内 PID 当作宿主 PID 检查，并安全停止。修正后改用宿主 executable/root/namespace/所属路径清单；已下载 raw 与首次延后 host-after 保留。恢复日志与原归档哈希证明 1–12 保留、只测 13–16。公开 JSON 保留原计划、恢复工具、实际命令的脱敏形式、失败日志及所有证据哈希；未把未知退出码写成 0。

所有原始归档与展开文件已逐项核对。主矩阵还核对每窗及跨窗宿主进程身份、每个被测 daemon 的跨负载 starttime；daemon CPU1 与归一 argv 由冻结 harness 执行，矩阵本身没有单独的 live argv/affinity 快照。idle 内存同样保留既有 live 身份元数据限制。

本页不撤销此前注册慢尾、FD handcrafted sender 契约差异或 RandomState ID 生成的已知边界。有限窗口不能证明没有 bug；结果不涵盖九个 Rust 组件共同运行、长期稳定性或语言极限。

- [完整派生值、逐配对、来源、全部内存正项和失败诊断](r136-ubusd-completion-results.json)
- [原冻结覆盖与统计规则](R136_COMPLETION_PLAN.md)
- 原冻结计划 SHA-256：`937cdaa1bd9570cbe69c145eadc3f032f9f1eeba10ee86400f38829a8bee4d65`。
- 独立内存补测计划 SHA-256：`deb5995604d1e47a9b1ed38e336998056621f50fe6e0ea5da2943c36aed9cca5`。
- 原始证据保存在 ignored `private/r136/completion-01/`（FAILED 保留）及 `private/r136/memory-supplement-01/`；延后只读审计为 `private/r136/post-failure-health-01/`。
