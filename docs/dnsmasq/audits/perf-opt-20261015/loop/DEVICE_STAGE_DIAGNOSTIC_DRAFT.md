# A53 软件采样可行性与阶段诊断草案

状态：能力审查与流程草案，未启动新的 C/E 负载或阶段切点实验。
root 负责完整 owner 分配计数与代码切点；本记录只约束设备流程和解释边界。

## 先分清软件 perf 与硬件 PMU

不能由“无硬件 PMU”推出“不能用软件 cpu-clock”。Linux perf core 启用时
会单独注册 software、cpu_clock、task_clock，不依赖 A53 硬件 PMU 驱动。
[匹配 Linux 6.12.94 的 perf core](https://github.com/gregkh/linux/blob/v6.12.94/kernel/events/core.c)

但本机已有更具体的失败证据：R137 的24次 `PERF_TYPE_SOFTWARE` /
`PERF_COUNT_SW_TASK_CLOCK` 自线程 disabled 打开全部返回 ENOSYS；attr为64B，
sample_type=0，不是请求了不支持的user-stack采样。其kernel.txt的SHA与
当前`6.12.94\n`逐字相符。新只读检查又确认perf sysctl和整个event_source
bus不存在；读取者为root、Seccomp0、NoNewPrivs0。生产与既有工具身份和
5秒轻量DNS/LuCI健康检查通过。[能力与证据回执](DEVICE_SOFTWARE_PERF_CAPABILITY.json)

结合 `CONFIG_PERF_EVENTS` 对events/core的编译控制及未实现syscall的
ENOSYS路径，这些证据支持“perf接口整体缺失”的强推断，而非仅硬件PMU
不可用。最终.config、/proc/config.gz及kallsyms不可读，因此不写成已直接
读到`CONFIG_PERF_EVENTS=n`。本次也未重新打开perf事件，不把历史task-clock
探针冒充当次cpu-clock采样。[内核编译门](https://github.com/gregkh/linux/blob/v6.12.94/kernel/Makefile)、[未实现syscall路径](https://github.com/gregkh/linux/blob/v6.12.94/kernel/sys_ni.c)

若协调者认为需要当次启动的直接确认，最小后续仅对新临时工具自身尝试
software config0和config1、attr64、disabled、sample_type0、无ring buffer，
立即关闭；记录源/ELF、原始返回值、errno、UID/seccomp、全部attr字段。
不启用事件，不附加生产进程。EPERM/EACCES与ENOSYS必须分开，不能用
安装perf或改sysctl掩盖权限/内核能力边界。打开成功也不等于已验证采样。

如果软件事件实际可用，优先对**未改的精确C/E ELF**在隔离实例上验证
软件采样，而不是先向产品加插桩。先固定event/period、enable/disable
边界、ring容量、lost-sample门、用户/内核过滤、PID/starttime和map身份。
TCP必须覆盖继承子进程；缺少内核符号时保留未归属类别，不能猜内核函数。
采样结果始终作为excluded诊断，独立于未插桩的验收窗口。

## 软件 perf 不可用时仍能做什么

POSIX process CPU clock与perf软件event不是同一个接口。既有R137诊断已
使用前者；它可提供进程CPU累计时间，不能提供PC样本、硬件IPC或自动
拆分用户/内核。`/proc` ticks和已回收子进程CPU也可作独立核对，但不能
绕过原验收的8-tick精度门。高分辨率读钟不自动等于同等准确度。

阶段诊断应先冻结以下三类分开的证据：

| 车道 | 产物与输出要求 | 可说明的内容 |
| --- | --- | --- |
| 原样完整路径 | 精确C与E；每条DNS回答正确、完整计数和健康门 | 当次整进程CPU与端到端差距 |
| 完整owner计数 | root的独立诊断构建；正确输出，完整owner路径不删阶段 | 实际alloc/realloc/free/复制等计数；不冒充原样计时 |
| 累计阶段切点 | root逐项定义；每个独立source/ELF/map，明确EXCLUDED | 相同输入下、该被干预构建的累计CPU或工作量 |

切点输出若仍宣称DNS回答，必须逐条正确；若提前终止、不回复或只做诊断
ack，必须明确excluded并采用匹配的诊断接收/发送契约。不能把预期超时
喂给普通请求/应答负载器后，将其背压、重试和分母变化当作某段节省。
不回复的车道不得用“正确回复数”作CPU分母；必须保留真正消费的输入数。

由root事前固定切点后，每窗维持相同输入序列、到达率、数据集、预热、
循环预算与可验证工作量。只在窗前/窗后读累计CPU，减少逐请求读钟干预；
另有空观察器控制，记录开销而不从结果机械相减。每个切点先验证输出
契约与计数，再运行固定数量、固定交错顺序的诊断窗，不按结果追加。

相邻累计切点的差值不是原样整程序某函数的精确成本：截断可能改变
死代码消除、内联、栈帧、布局、缓存状态和内核发送路径。必须保留各自
实际产物/map，先核仍执行的路径，再解释差异；不得把不同诊断车道的
收益相加，或填入正式E/F/G验收表。

## 设备执行门（待分工确认后才启动）

- 继续由同一设备owner操作；先固定root提供的诊断源、精确ELF/map、
  输入和expected-output/EXCLUDED标记。当前不编译、不下载或访问Oracle。
- 用既有恢复门核离线备份、生产8472…及PID/starttime、guard/工具SHA、
  独立健康基线和64MiB内存门；只用隔离loopback namespace与任务/tmp。
- 全部产物、启动命令、原始计数、错误、退出和完整归档按新独立label留存。
  已完成且验证的临时设备副本在窗外回收，避免再次用归档占满内存。
- 健康或输出契约失败即停，保留失败；不改生产配置、内核、sysctl，
  不安装perf包，不为取得采样而刷内核。设备事实与Oracle筛选继续分开。
