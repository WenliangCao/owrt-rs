# 上线前 Rust 修复记录

日期：2026-10-14。分支：`fix/predeploy-20261014`，从 main
`98ad7ee3` 建立。范围为审计 A 的 B01/B02，以及审计 B 的 B1/B6。
物理路由器未操作；未推送、未合并。

四项代码修复已完成，B02 先以缩减实验定位根因，再修改共享查询路径。
最终运行时验证使用真实 SDK 从冻结源码编译、打包后提取的同一 ELF。
**代码修复不等于上线批准：原 ELF/APK 体积门限仍失败，部署门槛另行验收。**

## 修复与根因

### A / B02：本地域规则遮蔽已经学到的终点

先做了独立缩减复现：仅预热一次外部 alias 的 A，得到 CNAME 与本地域
终点 A，随后直接查终点；不执行 B01 中后续的 alias AAAA/TXT/ANY
序列。旧 Rust 仍返回 NXDOMAIN，精确镜像 C 返回缓存 A。UDP 预热也能
复现，因此 TCP 子缓存导入/发布不是触发的必要条件。

根因是共享本地/缓存入口先接受了 `local=/…/` 转发规则生成的答案，
尚未查询动态缓存就结束；该规则的名字存在性判断还遗漏动态缓存。
修复保留 hosts、配置记录与 CNAME 的既有先后关系，将转发规则答案延迟
到缓存查询之后，并将动态缓存纳入本地域名字存在性判断。只有实际选中的
答案才提交相应查询日志事件。

同一区域补测了原配置启用的 `domain-needed`：CNAME 指向无点号终点时，
预热后查询 alias 或直接终点的 AAAA，SDK01 中间版仍将 C 的 NODATA 错答成
NXDOMAIN。共享查询结果与转发策略现在使用各自当前/连接缓存视图中的
名字存在性；UDP、同连接 TCP 和新 TCP 都纳入对照。

### A / B01：保留缓存 CNAME 遍历后的选路名字

缓存未能完成请求时，显式返回遍历后的名字，而不丢掉 C 的 `namebuff`
游标。TCP 和 UDP 继续使用同一个本地/缓存查询入口，不重复遍历、轮转或
过期处理；调用方保留匹配 C 的传输差异：TCP 用遍历后的终点选路，UDP
在转发前重新使用原问题名。TCP 的转发报文仍保留原始问题。

终点规则与普通规则共用直接构包代码，选路名字和客户端问题明确分开，
不重新执行本地记录轮转或租约过期处理。新增长 alias 与大量字面地址的
极限复现：2,332 条 AAAA 返回 65,513 字节完整答案；2,333 条由 C 返回
217 字节、带 TC 的空答案。曾试过的“按终点构包后替换问题”中间实现会在
后一种情况关闭连接，已修正，不能用历史 48 组其它大报文用例替代此验证。

### B / B1：hosts 重载分配失败保持进程存活

将 hosts 名字复制、展开、暂存记录、索引增长与快照复制改为可失败分配。
索引在发布新记录前预留必要容量；无法分配的记录跳过，不留下半条索引。
删除 source 的重定位空间不足时跳过该次更新，不用低内存下的平方复杂度
扫描代替。源码路径没有引入新依赖或新的 hosts 存储结构。

重载保留一个此前可用的 owner 视图，释放另一份旧表后构建新表。发布复制
失败时释放不完整的新表并尽力恢复旧视图；该失败不再传播为退出 owner loop
的错误，也不立即安排无限重试。后续 HUP 可恢复正常载入。C 的逐条跳过与
Rust 发布失败时的旧视图恢复并非逐条缓存状态完全等价；本修复的故障边界是
进程存活、尽量保留服务、解除限制后无需重启可恢复。

扩展压力测试还找出分块 `hostsdir` 路径的遗漏：暂存分配失败后，如果仍将
占满内存的半成品留到下一轮，poll owner 的常规分配仍可能中止。现在在
返回 owner 前释放未完成的暂存记录与诊断，结束该 source 读取，保留其已
发布记录。正常路径不新增完整 hosts 副本。

连续两次快照复制失败时，显式标记待恢复的 owner 视图；后续其它 hostsdir
源的增量更新必须先恢复旧表，防止以空表发布并抹掉无关源。分块读取改为
借用 owner 配置，省去每次打开文件的整份配置深复制。

### B / B6：停机持续刷新仍可连接的日志队列

移除主进程最终 flush 的 100 ms 截止。沿用现有非阻塞日志写入与 poll，
在队列排空或连接失效后结束，与匹配 C `log.c:flush_log()` 的边界一致。
接收端保持连接却始终不读取时，停机会继续等待；这正是此次对齐的行为。

新增无 overflow 的尾日志复现，先确认 query/answer 已入队，再发送 TERM，
延迟读取并检查三条尾记录的内容、次数和顺序。旧 Rust 负对照确实丢失这些
记录，将原审计 B6 的“尾日志丢失疑似”缩减为可验证的具体场景。

## 对照身份与验证

行为 oracle 为镜像原 ELF，SHA-256：
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
匹配 patched C 源码的 148 个文件重新核验通过，OpenWrt recipe revision
为 `f0a60eee2fe051741c643ea6118718aae1ef17fb`。native matching-source C
仅用于原工具需要的 fixture，不替代镜像 ELF 的行为对照。

实际配置保持原捕获的 SHA-256
`273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`。
实验运行在 Oracle 独立 network/mount/PID namespace，原始配置、报文、日志、
ELF 和 APK 留在 `/home/ubuntu/dnsmasq-predeploy-fixes-20261014/` 的 private
目录；Git 仅保存工具、无秘密身份和派生报告。

最终产品冻结提交：`807db8a15e43452414acc048874bf04a4c639bd9`。
包内 Rust ELF SHA-256：
`0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`。
178 个构建输入逐项匹配 Git、冻结目录及 SDK 准备目录。
[对照身份](audits/20261014/predeploy_fixes/root/reference.json)、
[构建身份与原始证据索引](audits/20261014/predeploy_fixes/root/build.json)。

下表各行的计数单位不同，不相加成一个“协议用例总数”。中间构建用于发现
问题和负对照，不计入最终候选通过数量。

| 验证 | 最终结果 |
| --- | --- |
| 原 B01/B02 focused | 每侧 19 场景、26 次交换；断网时 alias 查询本地完成，上游只收到 A 预热；终点 A/AAAA 正确。52 个响应独立解码；1 个缓存 TTL 相邻秒差异按实际时间界限核验 |
| B02 最小隔离 / dotless | 14/14、8/8 交换全字段与 C 相同，上游请求仅在预热阶段；见 [DNS 根因与边界](audits/20261014/predeploy_fixes/dns/README.md) |
| 历史 DNS 终点、链式、N1 | 428 场景：420 个合法结果全字段相同，8 个 C 本身畸形报文 raw 相同；旧 18 个 O1 差异已消除，不再豁免 |
| 历史大报文 / 负缓存 | 48 组大报文全字段相同；NX24 + SOA64 + cursor12 共 100 场景、840 对 DNS（819 严格、21 按既有 SOA 时间界限）、180 对 DHCP；另 6 组 large-SOA 的 24 对 DNS 和 12 对 DHCP 相同 |
| 实际配置日常 DNS | 71 场景、每侧 452 次交换；含双栈 UDP/TCP、失败与恢复、缓存、并发和转发表压力。4 个缓存 TTL 相邻秒差异，余下字段相同；上游总数均 420，阶段总数相同，具体端点分配仍非逐项相同 |
| 公网终点缓存控制 | 每侧 3 次交换、1 次上游预热；1 个缓存 TTL 相邻秒差异，其他字段相同 |
| 实际配置重载 | 60/60 对照通过；两侧各 160/160 次并发 HUP 查询成功，租约保留 |
| 完整边界输入 | 补齐镜像 passwd/group/hosts/ethers 后重跑每侧 316 DNS、31 DHCP、20 健康检查；仅保留原 B03 两种异常 TCP EOF/RST 表示差异，无新增差异 |
| 原 B1 ENOMEM / 无压力控制 | 真正出现 ENOMEM 后 C/Rust 均存活并继续回答配置记录，解除限制后 HUP 恢复、退出 0；无压力 30,000 条的最后记录均可查询 |
| hosts 扩展压力与功能族 | 文件/hostsdir × expand 开关 × C/Rust 共 8 组合，各两次失败；UDP/DHCP 存活及恢复验证通过。正常边界 8 对、48 MiB 注释文件 3 对、helper 顺序 3 对、启动 DHCP gate 1 对、世代/轮转/PTR/TCP 快照每侧 204 次查询零差异；见 [hosts 分项](audits/20261014/predeploy_fixes/hosts/README.md) |
| B6 停机日志及功能族 | 3 类定点场景 × C/Rust，共 6 次运行通过：2.1 秒背压后恢复排空、三条尾记录按序各一次、接收端关闭后退出；完整日志族 329/329、0 失败。原工具标注的 C TCP OPT 缺陷类别仍单列，非宣称日志全族所有原始包逐字相同；见 [日志分项](audits/20261014/predeploy_fixes/logging/README.md) |
| Rust 测试 | 同一冻结源码 AArch64 musl：784 lib + 78 bin + 5 分配故障测试通过；23 ignored 未执行。首次 bin 运行因共享 `/tmp` 中已有同名 FIFO 失败，保留原日志；改用任务独占 TMPDIR 后同一测试 ELF 全通过，未删除原 FIFO。见 [单测记录](audits/20261014/predeploy_fixes/root/tests.json) |

完整矩阵与原始结果索引见 [回归分项](audits/20261014/predeploy_fixes/regressions/REVIEW.md)。
六个实际配置 TTL 差异都保留在原严格 `comparison.json`，没有覆盖成严格相同：
用各侧预热上游时间、请求/响应文件时间界定整数秒老化，5 个 A 的范围为
119–120，1 个 NX SOA 为 28–29，其余字段仍严格检查。TTL 加 2 与 flags
变异均被拒绝。另有不导入产品/原探针 decoder 的
[52 响应独立检查](audits/20261014/predeploy_fixes/root/focused-independent.json)
和[校准](audits/20261014/predeploy_fixes/root/checker-timing-calibration.json)。

新增 literal 完整点的 RR 顺序存在旧差异，不能称全部 DNS 字节等价：已用
原审计 Rust 的直接 literal 控制证明前存；长度、flags、TTL、地址多重集合
相同，溢出点则最终包逐字与 C 相同。压力中 C 的 TCP child 在本限制下可
失败而 Rust 仍应答，也没有将它包装成压力下每个报文完全一致。

### 真实 SDK 打包

使用匹配的 OpenWrt 25.12.5 Filogic SDK，归档 SHA-256
`ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25`。
真实执行 `make .../prepare`、`make .../compile` 和 Cargo release 编译，
**未输入 frozen ELF**。Rust 1.98.1、SDK GCC 14.3.0、AArch64 musl static
PIE、opt3/LTO、默认 feature-off；SDK sstrip 结果与 APK 提取 ELF 一致。
metadata、文件合同、源码/SDK 输入稳定性检查通过，SDK recipe 已恢复。

| 产物 | 大小 | 原门限 | 结果 |
| --- | ---: | ---: | --- |
| 包内 ELF | 2,071,323 B | 1,000,000 B | 超限 |
| `dnsmasq-2.93-r3.apk` | 1,126,561 B | 700,000 B | 超限 |

APK SHA-256：`f5a0284e2676a73f77f7c31cf629bed1f3581e96b910cae8f769852ad6b25624`。
原预算未修改，driver 的返回码 **1** 和 `size-target` 拒绝保留。因此结论是
源码编译、打包与内容校验成功，不能写成全部 release gate 通过。现有 Oracle
SDK host wrappers 继续使用；没有额外声称原生 x86 SDK 宿主或跨路径可复现构建。

## 提交与收尾

产品修复提交：B02 `2869dde2`；B01 `d0c978a2`、`f8f8b5a0`；同族
domain-needed `5850e9af`；hosts `e3afb480`、`29ecebc9`、`4fc48183`；
日志 `a3271a13`。后续本任务提交保留复现工具、派生证据与本报告。
共享工作区中其它会话的资源审计、部署工具提交及原有未提交文档均保留，
不将其算作本修复会话的交付或验收。

收尾重新读取 54 项证据文件身份，无散列差异；本任务没有残留进程或宿主
挂载，最终产品代码与冻结提交一致。JSON、Python 语法和报告链接检查通过。
[收尾记录](audits/20261014/predeploy_fixes/root/closeout.json)。仅有 main 与
当前活跃修复分支，无本任务应清理的旧分支；没有推送或合并。

## 范围限制

本次没有修复或验收审计 B 的 B2 自动回退、B3 包激活、B5 stock UBus ACL
边界。B4 空间/体积门槛未满足：体积检查已执行且失败，现场空间未验。
审计 A 的 B03 异常 TCP EOF/RST 表示差异也不在
修复范围。修复这四项 Rust 问题不能代替部署恢复与真实客户端健康验收，
不能据此宣称已经可以上线。

Oracle 内核仍不同于路由器。未覆盖全局 OOM killer、所有分配点持续失败、
物理设备、断电或 flash 写入。本次 ENOMEM 证据绑定原审计的进程地址空间
限制与合成 hosts 输入，不表示对任意系统内存耗尽均有存活保证。
