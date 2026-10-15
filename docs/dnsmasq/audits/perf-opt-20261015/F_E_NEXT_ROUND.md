# F/E 下一轮完整配对准备

状态：工具身份已固定；F 的 source、SDK ELF 和完整正确性资格尚未填写，
**本轮尚未冻结、未启动，也未改变路由器暂存文件**。机器可读身份见
[`f-e-tool-inputs-preparation.json`](f-e-tool-inputs-preparation.json)。
后续填写身份应另增冻结/启动回执，保留这份准备记录。

## 事前增量判据

本轮按最新用户目标，以已接受的 E 为基线：UDP 命中须有可辨别改善，
TCP 命中也完整报告；11 个场景的 p50、p95、CPU 均不得出现可辨别回退，
完整正确性、内存、FD、ELF 大小及健康门保持不变。E 已按原部署版/E
多数场景规则接受，本次针对命中路径的增量不重复要求多数 11 场景改善。

在本轮任何性能窗口启动前明确：用户指出的是 UDP 命中的 CPU 差距，
因此增量主要目标是 **UDP 命中 CPU/query 的可辨别下降**。仅延迟改善、
CPU 仍在波动或计数精度内时，要如实报告，不能据此宣布 CPU 差距已缩小。
这里明确目标指标，不改变下面的统计函数、窗口长度或精度门。

仍用五对中位数与全距 W、至少 4/5 同向；CPU 每轮至少 10 ticks 且
中位差超过 8 ticks；生命周期延迟受 1 ms 观察精度限制，不满 10,000
样本不报 p99。负载和统计函数不变。F/E 是新的直接增量比较，不能与
历史数据拼成部署版/F 的直接结论；如需后者，另跑新配对。

## 身份与最小改动

| 用途 | 固定身份 |
| --- | --- |
| 生产健康保护 | 已部署 `8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7` |
| 比较左侧 `c` | E：`8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27`，2,136,859 bytes |
| 比较右侧 `rust` | F：待冻结，不能使用占位值启动 |
| 工具源快照 | `91409ea3d3c4b15274e7f3377558480828b320b9` |
| 新 SDK loadgen | `f7c7d8e94a96e5c23f06aec1396539c439516fa4408a3657835cf78bdceb618e`，544,760 bytes |
| 新窗口校验器 | `7020420968ef050aad43d52e94055c0972280cac7c7b1fce4acfed54de275d44` |
| 未改统计分析器 | `10addedf927936df6bc112e4dcc8d5f0c9ef9af8466a6cde11dc1a56ebad2283` |

`c/rust` 是已有文件和左右侧标签。将 `c` 设为 E 不改变生产保护中的
`PRODUCTION=8472…`。Oracle 运行器已经接受 `--baseline/--candidate`，
设备运行器已经接受 `--c-hash/--rust-hash`，统计分析器从各轮 identity
读取比较产物。三者都不需要为 E/F 再改代码。

下一轮采用已分别修复的两个工具缺陷：固定速率请求排队
`0f8ced6c`（原 `9e6556cf`），以及 miss 无饱和窗口按完整
warmup+measurement cohort 核对 `a2dc1fa6`。后者仍要求精确 5,000 个
请求/回复，不增加容差。原 E 运行和补测继续使用原工具，既有无效窗口
不重新判定。新 SDK loadgen 已通过原控制及 6/150 客户端真实续租验证；
本次只读取并核对其已保存的 ELF，没有重建或新增远端负载。

唯一新增补丁 `91409ea3` 让表格生成器显式接受候选比较基线的 SHA256
和名称；两个参数必须一起提供。默认部署版标签、生产身份门、110 窗口
顺序、原始文件身份和统计门不变。4 项身份正负控制通过；真实旧
base2/E 有效摘要在补丁前后生成的报告逐字节相同。

## 待执行顺序和命令

以下命令是准备好的运行说明，**本准备阶段没有执行负载、上传或暂存操作**。
使用原样工具快照；F 的精确源、SDK ELF、build receipt 和完整正确性
receipt 均须先由协调者核定。F 已选 admission `c1ea66f6`、local answer `6f594d7b`、static IPv4
`5a03fffe` 三个性能变更，不增加行为修复；最终组合源和 ELF 仍待核定。
完整正确性资格通过后，协调者已授权 Oracle 与设备两份独立 110 轮并行；
Oracle 自身仍全局独占，统计和归档不得跨环境合并。

1. 保留 F/E 各自精确 ELF 和已核定 SHA256。将固定工具源快照放到 Oracle
   `/home/ubuntu/dnsmasq-perf-20261015/root/tools-fe/`，新测量输入放到
   `root/private/inputs-fe/`。本地已核好的输入在本工具工作树的
   `private/perf-opt-20261015/inputs-fe/`；旧 `inputs/` 不动。
   Oracle 运行器与其导入的 `perf_opt_device_run.py` 必须来自同一固定快照，
   以便使用新 cohort 校验。先核对 JSON 中每个工具源/ELF/script 的 SHA256。

2. 取得独占 Oracle 测量时段，在完整正确性资格通过后执行全 110 窗口。
   `--out` 必须不存在；CPU 2，奇数轮 E/F，偶数轮 F/E。不要用旧的
   `device_perf_oracle_supplement.py` 或 `analyze_device_perf_oracle.py`，
   它们绑定历史 C/旧 Rust 的另一份实验。

   ```sh
   sudo -n python3 /home/ubuntu/dnsmasq-perf-20261015/root/tools-fe/tools/dnsmasq/perf_opt_oracle_run.py \
     --out /home/ubuntu/dnsmasq-perf-20261015/root/private/oracle-f-vs-e \
     --baseline /home/ubuntu/dnsmasq-perf-20261015/root/private/sdk-e/dnsmasq-rs \
     --candidate /home/ubuntu/dnsmasq-perf-20261015/root/private/sdk-f/dnsmasq-rs \
     --inputs /home/ubuntu/dnsmasq-perf-20261015/root/private/inputs-fe --cpu 2

   python3 /home/ubuntu/dnsmasq-perf-20261015/root/tools-fe/tools/dnsmasq/perf_opt_analyze.py \
     /home/ubuntu/dnsmasq-perf-20261015/root/private/oracle-f-vs-e \
     /home/ubuntu/dnsmasq-perf-20261015/root/private/oracle-f-vs-e-summary.json
   ```

3. 确认精确 F 完整正确性资格后，可在 Oracle 测量同时，由唯一设备
   owner 做实时 preflight：生产 file/live ELF、PID/starttime，无 STOP、
   无 active group、无本任务活进程，至少 64 MiB 可用内存；保留旧暂存
   exact C、E、旧 loadgen 的已核离线副本。新健康记录使用独立
   `health-fe/`，至少 120 秒，按原公式 `max(200 ms,10*p95)` 固定阈值，
   大于 700 ms 则先调查。不得把先前 `[3086,2115]` 当成未经复核的实时身份。

4. 经协调者启动授权后，仅在任务 `/tmp/dnsmasq-perf-20261015` 暂存：
   E 到 `dnsmasq-c`，F 到 `dnsmasq-rust`，新 loadgen 到 `m6a_loadgen`。
   各自先写 `.new`、核 SHA256/模式、再原子重命名；核所有其余工具和
   case/group script 仍匹配清单。保存 stage/qualification/health 启动回执。
   不改 `/usr/sbin/dnsmasq`、生产配置、设备接口、频率或 affinity。

5. 在固定工具工作目录执行以下新设备轮。`F_ELF_SHA256` 必须取自已核的
   F build receipt；不能从未知暂存文件直接推定。controller 仍拥有独立
   guard、双栈 HTTPS 检查、每窗口 100 秒上限及失败归档。

   ```sh
   python3 tools/dnsmasq/perf_opt_device_run.py \
     --out private/perf-opt-20261015/candidate-f-vs-e --prefix candidate-f-vs-e \
     --c-hash 8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27 \
     --rust-hash "${F_ELF_SHA256:?set from the verified F build receipt}" \
     --health-baseline private/perf-opt-20261015/health-fe/summary.json

   python3 tools/dnsmasq/perf_opt_analyze.py \
     private/perf-opt-20261015/candidate-f-vs-e \
     private/perf-opt-20261015/candidate-f-vs-e-summary.json
   ```

   不传 `--scenes`，因此运行原 11 场景 × 五对 × 两侧。若需 `--resume`，
   先由 owner 核同一工具快照、全场景、两侧精确产物和健康身份；现有
   resume 检查并未自动比较 controller SHA，不能以重新 checkout 的代码续跑。

6. 使用新表格参数生成派生报告。历史 base2 只作上下文，单独显示，
   不进入 F/E 的五对统计。

   ```sh
   python3 tools/dnsmasq/perf_opt_tables.py \
     --baseline private/perf-opt-20261015/base2-summary.json \
     --candidate private/perf-opt-20261015/candidate-f-vs-e-summary.json \
     --candidate-baseline-sha256 8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27 \
     --candidate-baseline-label 'Accepted candidate E' \
     --oracle private/perf-opt-20261015/oracle-f-vs-e-summary.json \
     --output private/perf-opt-20261015/f-e-report-tables.md
   ```

保持 [`FROZEN_TOOL_WINDOW_SUPPLEMENT.md`](FROZEN_TOOL_WINDOW_SUPPLEMENT.md)
的对称补测规则：先完成原 110；只对有独立证据的工具无效整对最多补测
一次，原顺序、原工具、两侧都重跑，原失败全部保留。产品错误回答、
响应超时或崩溃不适用。若需要补测，再冻结补测清单与控制器身份；
普通完整运行器没有选择轮号功能，不应为此修改原轮或混用单侧。

完成后核所有原始归档、清单成员及文件 SHA，检查生产身份与健康、
没有剩余本任务进程，再考虑清理已核的远端有效副本。失败证据保留。
