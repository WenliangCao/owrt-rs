# R144：固定 daemon 的 caller 交叉筛选

本轮只检验 `Connection::request_until` 的接收分配变更。daemon 固定为精确 C
`cfb83044…` 和 generic R136 `ce3d1aa…`；旧 caller 为原 R135
`85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d`。
新旧 caller 的编译输入只允许 `components/ubus/src/conn.rs` 不同，构建 flags 完全相同，
控制须逐字重现旧 ELF。最终源码、ELF、单测、工具及库身份在 manifest 中冻结。

先要求候选单测通过，再用独立目录执行 **12 个功能 smoke**：两 daemon×两 caller×
三个负载，各 N=10、warmup=20、全新 daemon。smoke 只检查计数、回复验证、fixture、
身份和清理；保留原始输出，不计算筛选排名。成功 proof 绑定同一新 ELF 后才生成正式
manifest；正式采集由 root 明确放行，不能与 Oracle 构建或其他计时任务并行。

正式固定 **6 block×2 daemon×2 caller×3 lane=72 case**，每 case N=10,000、warmup=20。
每个 case 新建 daemon；daemon CPU1、caller CPU0、provider CPU0。daemon argv0 固定
`/sbin/ubusd`，同一串行采集使用同一独占 socket 路径，默认空 ACL 目录随目录隔离。
所有 provider 和启动 helper 永远使用旧 85dd caller，避免接收优化同时改变服务端 fixture。

| lane | 被测旧／新 caller 的原始命令 |
| --- | --- |
| register_1 | `register-cycle SOCKET 1 8 N 20 DAEMON_PID` |
| lookup_1 | `lookup SOCKET bench.target N 20 DAEMON_PID` |
| invoke_1 | `rpc SOCKET bench.target ping INPUT EXPECT N 20 DAEMON_PID`，INPUT=`{"n":1}`，EXPECT=`{"ok":1}` |

lookup/invoke 各自启动旧 caller `serve SOCKET 1`，等待对象表恰好为 `bench.target`，
记录 provider ELF/PID/starttime/argv/CPU，结束后确认对象表不变、停止 provider、等待表空。
注册负载没有 provider。复用原始命令的校验和计时定义：lookup 核对目标存在，invoke
核对返回 JSON；register 使用既有签名预检与空表检查。provider CPU 不计入 daemon CPU。
三个负载的绝对时延含义不同，不互相比较。

[机器规则](../../tools/r144/screen-policy.json) 固定三组四组合顺序及各自逆序；每对组合
相对先后各三次，每 block 包含全部十二格。三个负载采用全部六种排列，使每个负载
在三个位置各出现两次。六 block 无法使四组合的每个位置完全等频，不作这种声明。

主门按 daemon 分开：每个 block 对三个 lane 的 mean `new/old` 比取等权几何平均，
六个 GM 的中位数必须 **<0.99** 且至少 **5/6 GM<1**。C 与 R136 分别都须通过。
同时检查 **18 项否决**：两 daemon×三 lane×mean/p95/p99，若配对比值中位数 **>1.03**
且 **6/6>1**，终止该候选方向。原始指标和比值使用 Fraction；GM 使用 60 位 Decimal，
先保留小数点后 30 位再取中位及严格比较。

全部 case 的 mean/p50/p95/p99、outer wall、daemon/caller process CPU 与六个配对比值
完整报告。CPU 只作描述，不能挽救未过延迟门；包含边界的 ±1% 为未分辨区间。
这是 Oracle 工程筛选，不作显著性、实机排序或采用结论，也不把 caller 收益归为 daemon
优化。原 R136 注册慢尾与 R140–R142 否决结论保留。

固定一个新 caller 和唯一 72-case 系列。失败、异常日志、身份改变、错误回复或清理失败
保留原始目录并停止；不挑 block、不补采、不因结果重选源码、阈值或样本数。每个 case
存全部 raw latency、原进程 CPU 快照、启动命令、daemon/provider 身份、退出和对象表；
完整序列结束复核输入与归档清单。所有文件和运行产物只写独占 Oracle/private 目录。
