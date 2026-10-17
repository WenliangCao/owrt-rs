# v0.2.2 / v0.2.3：唯一一次刷机前隔离 A/B

用户新增的发布门：只做这一轮，任何指定项目新版慢于噪声便停止并汇报，不刷机、
不追加性能轮次或 PGO。功能验证和镜像构建已完成；本计划在真机采样前冻结。

## 模型与预测

fw4 时间 = 读取/生成规则 + 等价性证明 + nft 检查/提交。旧版没有等价性证明；
新版不变 reload 省去提交，但 start/变化 reload 增加成功状态快照。因此预测不变
reload 更快，start/变化 reload 可能更慢，check/print 大致不变。作为可推翻的
事前估计：不变 reload 至少降低 10%，其余差异在校准噪声内；绝对时间尚无可靠
真机数据，本轮直接测出，不从 Oracle 数字推算。

netifd 时间 = ubus 解码/状态比较 + 地址/路由内核请求 + 后续事件处理。旧版每次
相同 IPv4 续租有两个可省写，新版以完整 keep 比较替代。预测单事件 CPU 至少
降低 5%；内核请求占比未知，是本轮要裁决的量。若新版更慢，不再优化或重测。

## 环境与身份

在现役 v0.2.2 路由器运行实际 SDK ELF；每个被测实例有独立 mount/net/PID/IPC/UTS
namespace、只读根、私有配置与 ubusd。只创建无物理端口的空 bridge，不改生产
规则、接口、服务、内核参数或调频。不安装模块，不改 CPU affinity。原始配置与
输出只留在 ignored private/；已验证的离线配置备份及 v0.2.2 恢复材料保持可用。
namespace init 的父进程消失会清除所有后代；整个批次另有 600 秒寿命上限。
前后核对生产 boot/ELF/配置，并完成客户端 TCP DNS 和双栈 HTTPS 健康检查。

| ELF | SHA256 |
| --- | --- |
| fw4 A (v0.2.2) | `ee5a9c5685f7363be3fc2bd5039546b2f01327633afc24031b446fc0fb7f5b55` |
| fw4 B (v0.2.3) | `2a077d0d268fca821463919219ee339b629c37cab2f47b2584b382074a83a72c` |
| netifd A | `0131ce3feeec074bfa6f5046ff3732ec235495442956407e7ea17559ce747a93` |
| netifd B | `cd02d474cfc557fb43231c947c29b442a0178efdaea6902e9b4bf2a0d03310ef` |

Oracle 只校验仪器功能和隔离，不能作为候选性能筛选。真机唯一批次顺序为计时
地板、netifd、fw4；两组件不并发测量，原始失败与不完整输出也保留，禁止补样。

## 固定样本及判据

- 地板：fw4 的直接 fork/exec/wait4 仪器执行 6 次 BusyBox true；分别记录，不扣除。
- netifd：A/B 两个持久实例，初次租约在计时外。8 个配对轮次，轮首间隔 30 秒，
  AB/BA 交替，后侧偏移 2 秒；同侧实际间隔交替 28/32 秒。前三对校准，后五对
  正式。每次相同 IPv4 地址、默认路由、DNS/data，通过私有 ubus notify_proto。
  用 POSIX 进程 CPU 时钟测目标 netifd（含线程，不含子进程/ubusd/客户端），
  保存请求至回复及固定 1 ms 后采样；以含这段尾部的 CPU 为门，回复点作诊断。
  单独测 1 ms idle floor，不扣除。不用 100 Hz /proc tick 代替精细时钟。
- fw4：依次不变 reload、变化 reload、首次 start、check、print；每场景校准顺序
  `ABBAAB`，正式顺序 `ABBABAAB`，共 70 次。每次独立恢复初态、计时前安静 1 秒。
  不变 reload 只变已捕获的无效 WAN6 子网定义；变化 reload 只改私有规则端口；
  start 没有规则/cache/state。check/print 已有相同已安装规则，print 输出到 null。
  初次 start 指首次防火墙状态，不冒充清空 CPU/page cache 的整机开机。
  直接计 fork 至 reap 墙钟、wait4 用户+系统 CPU（包含 fw4 已回收的 nft 子树）。
  两指标均检查；私有 ubusd/provider 成本不在 CPU 内。前后真实 nft handles 验证
  跳过或提交效果，仪器与验证不在计时内；不使用 FW4_MOCK_DIRS 或 nft wrapper。

每项/每指标独立噪声 `N = max(A 校准极差, B 校准极差, 2 × 计时量化)`。
fw4 墙钟读取实际 CLOCK_MONOTONIC 分辨率，CPU 输出量化 1 µs；netifd 读取实际
CPU 时钟分辨率。两者远细于拟观察的毫秒及数十微秒量级，但分辨率不是实际噪声。
正式相邻 AB/BA 配对计算 B−A，**任一对 > N 就停止后续发布并汇报**，不得用总体
均值抵消失败。固定批次全部采完后分析一次，保留中位数、各配对差、最大退化和
校准地板。仪器失败、隔离不成立或超时同样停止，不开第二批。

这是同硬件、近自然续租间隔的隔离比较；空 bridge/私有 ubus 不代表真实上游等待、
转发负载或整机联网延迟。现网自然事件带来的调度噪声由校准与配对显式呈现。
下一步只裁决此发布门；若触发停止条件，报告数字和决定，保留候选而不自行修补。
