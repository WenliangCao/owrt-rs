# R135：Oracle 全因子预实验，路由器最终裁决

目标是解决 R134 已确认的注册慢尾，保留其平均延迟和 CPU 收益。R134 的五项实机负判不因本次亲和性控制或服务器筛选而撤销。生产只运行 C，本计划不部署候选。

## 冻结因素

以 `c84108b` 运行时为源，生成 2³ 个隔离快照；不改变运行时工作树。

| 因素 | 1（R134） | 0（消融） | 要区分的机制 |
| --- | --- | --- | --- |
| s | 无 FD 的短读后返回 readiness loop | 继续非阻塞读取至 EAGAIN | 处理回复期间到达的新请求能否立即处理；空读成本与 epoll 往返 |
| b | 无 monitor 的 ADD DATA/STATUS 合并 | 分别发送 DATA/STATUS | 系统调用数量与接收者的可运行时序 |
| k | 带密钥计数哈希生成 ID | 原逐 ID getrandom | 随机数系统调用及不同 ID 序列的综合影响 |

`s1b1k1` 为未改 R134；另外保留精确镜像 C 和 R131 ELF 作外部参照。`s0b0k0` 仍然使用共享 read-ahead 和借用派发，不能称 R131。k 因素同时改变 ID 序列，不能把结果全归因于系统调用。暂不引入第四因素或变动 FD 契约。

## 流程和证据

1. 先盘点 Oracle 实际可用 CPU、quota、perf 权限和现有负载。多版本可并行构建；计时只有在 CPU 对互不重叠时才并行，构建/正确性负载不与计时重叠。不同 CPU 对轮换对照，不把不同核心的结果直接相减。
2. 诊断 helper 仅在现有计时区间外补输出客户端前后快照及 CPU mask/最后 CPU；保留冻结旧 helper，不新增每操作 syscall。
3. 预筛负载为 register_1、register_16、event_1，每窗 10,000 周期、20 warmup；同核对内分离钉核与允许客户端使用该 CPU 对两条件。四个重复区块、正反平衡次序，保留全部原始数据、身份和失败。筛选规则先排序慢尾，再检查 mean 和 daemon CPU，±1% 记为未分辨；这是探索性排名，不冒充正式显著性。
4. 对有效方向补分阶段 recvmsg/EAGAIN/sendmsg/getrandom/epoll_wait 计数；trace 时间不计入性能。必要时使用有符号 profile 定位，不能只凭异步整机计数宣称原因。
5. 只有通过功能、FD、事件及背压检查的少量优选版本进入路由器，同一实际 ELF 验证。服务器排名不自动推广到 AX3000T；正式窗保留 C、R134 和候选，完整清理隔离进程与文件。

Oracle 和路由器同为 Linux/aarch64 只减少了一部分平台差异；微架构、内核、虚拟化和调度条件仍不同。[Linux CPU capacity 文档](https://docs.kernel.org/scheduler/sched-capacity.html)说明相同工作在不同 CPU 能力下也会有不同利用率。结构性削减可作筛选依据，尾延迟相关性必须用实机检验。

本轮不能以大量候选增加“碰巧胜出”的机会：完整公开全部八组合，优选结果必须用新窗口确认；若 Oracle 不复现慢尾，记录不可迁移性，仅将结构诊断带回实机。

## 预筛后的定向检查（实机采集前冻结）

双组初筛 480 case 已完成，随后在同一 CPU 对串行复核 C、R134、`s0b1k1`、`s1b0k1` 各四块。服务器没有复现 R134 的实机厚慢尾。`s0b1k1` 注册有小幅延迟方向，CPU 更高；`s1b0k1` 不作为性能赢家，而因原 R130 的合并发送已出现尾部代价，保留作唤醒时序反证。

因此实机仅做四窗、每窗四版本的定向诊断：C、R134、继续读到 EAGAIN（drain）、分开发 ADD（split）。四个 Williams 平衡顺序，客户端独核/允许 0–1 两条件交替，各 register_1/register_16/event_1 每窗 10,000 周期。守护进程始终 CPU 1，argv0/socket/ACL 相同。角色映射为主 candidate=drain、before=R134、额外 ELF=split；借用收集器的 event-benchmark 文件槽承载后者，实际调用角色在脚本明确记录。

生成器为 `tools/r135/make_router_plan.py`，冻结输入哈希与窗口脚本保存在 ignored `private/r135/router-plan-02/plan.json`。01 尚未运行，在采集前核对旧矩阵时发现它使用默认 socket 和默认 ACL，因此 02 恢复相同参数，避免增加初始配置差异；01 原计划保留，不覆盖。这是少量假设判别窗，不能用四窗替代原 7/8 门或正式宣布胜利；若出现可重复改善，再用独立正式窗口验证。没有改变 R134 既有负项、±1%规则或生产状态。Oracle 功能门完成后才启动这四窗。

Oracle 前置门结果：drain 整套通过；split 的 events、FD、五个 ubusd functional 项、两个 ubusd recovery 项均通过，但通用 recovery 套件中的 **original/C netifd_overflow subsequent_events=false**，因此 split 整套 aggregate 仍为失败。该案例 `component=netifd, side=original`，使用 `/sbin/netifd` 和 `/sbin/ubusd`，未执行本轮候选；完整失败保留，不推断是并发导致，也不通过重试刷绿。实机继续的依据限定于已通过的 ubusd 前置项，不声称所有组件恢复检查通过。
