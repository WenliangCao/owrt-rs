# 上线前独立复核

日期：2026-10-14。分支 `fix/predeploy-20261014`，复核起点 `aa8f12db`。

## 结论

**当前不能按这套机制在路由器上进行受监护试运行。**

A 的两项正常 DNS 行为阻断已经修好，B6 日志修复也成立。但 B1 只关闭了
原最小 ENOMEM 复现，同类合法 hosts 重载仍能使整个 Rust daemon 中止；
更直接的阻断在恢复机制：回退途中监护进程单次退出，可以留下没有任何
dnsmasq 进程、且监护重启后不再启动 C 的状态。正常 C TCP 连接还会把
已经成功的回退误判为永久失败。这不是增加几轮健康检查就能消除的风险。

本结论针对**最终包内 ELF 与最终上线脚本的组合**。没有把旧 ELF 的监护
验证直接转移给新产品，也没有把“返回了回退命令”当作“恢复 C 成功”。
这轮仅增加复核工具、派生证据和本文；没有修改产品/上线脚本，没有推送，
没有在物理路由器上接管、停止或替换生产服务。

## 身份和证据边界

| 对象 | 本轮实际使用 |
| --- | --- |
| 精确镜像 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 最终产品冻结源码 | `807db8a15e43452414acc048874bf04a4c639bd9`；当前 `components/dnsmasq`、`components/ubus` 无产品差异 |
| 最终 SDK 包内 Rust ELF | `0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`，2,071,323 B |
| 最终控制器 | `83e8f1a3312e7583b319fc179af6795efae7354ffad5093ad881bd4639f6aef1` |
| init 拦截入口 / 协议探针 | `4947f6da…28ad7` / `f4640517…00b9`；完整 hash 在监护证据中 |
| 原实际配置 | `273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe` |
| 行为、ENOMEM、监护环境 | Oracle 的独立 network/mount/PID namespace；精确镜像用户空间，宿主内核 6.17.0-1020-oracle |
| 压力对照环境 | 原 AX3000T / Linux 6.12.94；沿用审计 C 的回环端口和配置映射 |

精确镜像 ELF 是行为标准；matching patched C 源码用于解释路径，不以宿主
重编译 C 替代行为 oracle。原始配置、报文、内核日志、ELF 和完整 rootfs
保留在 private；Git 中仅有工具、身份和派生结果。

DNS 修复分项使用捕获的实际配置；hosts 故障输入为合成数据；监护分项在
精确镜像 rootfs 内使用生成的单实例配置与合成客户端。压力分项沿用审计 C
的回环配置映射。没有把这些隔离条件写成完整真实家庭网络的部署验收。

## 发现及对试运行的影响

P1 表示能造成共享 DNS/DHCP 服务中断或失去核心恢复保证；P2 是条件触发的
功能/管理故障；P3 是低影响差异。级别描述后果，不代表已测得现场发生概率。

| ID | 等级 | 本轮判定与实际影响 |
| --- | --- | --- |
| R1：C 启动前的回退记录窗口 | **P1，阻断** | 回退时单次杀死监护，重启后无 daemon，永久 `recovery-failed`；不能保证自动回 C |
| R2：hosts ENOMEM 残余 | **P1，产品残余** | 初始 2,000 条、各自 VmSize +1 MiB、HUP 30,000 条，最终 Rust 3/3 SIGABRT，C 3/3 存活恢复；需要可靠回退兜底，而 R1 未闭合 |
| R3：把正常 C TCP child 当竞争实例 | **P2，恢复机制缺陷** | 正常 TCP 查询后回退状态永久失败；C 仍服务，但监护与正常交还流程失效 |
| R4：C 第二次总线恢复预算耗尽 | **P2，管理状态不完整** | 两个 UBus 对象消失，仍报告 `fallback`；DNS/DHCP 好不代表管理对象已恢复 |
| R5：监护自身停止运行 | **P2，覆盖边界** | SIGSTOP 监护可越过确认期限仍保留 Rust；procd 只对退出重启，不检查活着但停止调度的监护 |

### R1：一次监护退出就可能使回退无法完成

在最终 Rust 已进入 trial 后执行正常 `rollback`，用 ptrace 精确观察真实
监护的 `openat`，在 `/run/dnsmasq-deploy/c_attempted` 创建成功、尚未启动
C 的位置发一次 SIGKILL。没有修改控制器、procd、ujail，也没有再注入第二个
故障。procd 随后启动新的监护，但结果是：

- `c_attempted` 存在，长度为 0；实时 daemon 列表为空。
- `phase=recovery-failed`，15 秒后仍无 C，也不重试。
- 对照：在同一个 `openat` **执行前**杀死监护，重启后正常启动精确 C，
  DNS/DHCP 恢复，15 秒后仍保持同一 C。

[控制器第 130 行](../../tools/dnsmasq/deploy/dnsmasq-deploy#L130) 仅以文件存在
判断“C 恢复已经尝试过”，[第 145 行](../../tools/dnsmasq/deploy/dnsmasq-deploy#L145)
却在 `launch` 前创建这个文件。新监护不能区分“尚未 launch”与“确实 launch
失败”，因此禁止恢复。写入完整的 `1` 也不能解决两步之间的崩溃窗口。

runbook 末尾已经承认“监护恰在 C 启动交接的指令间再次终止”可能失败；
本轮把这个限制做成了可重现的正负控制，并证明正常手动回退加**单次**监护
退出就足够。既然试运行要依赖监护在故障后恢复，这个限制仍然阻断放行。
需要可重入的恢复阶段和实际进程核验，不能把尚未执行的 C 启动永久锁掉。
见 [监护发现](audits/20261014/recheck/guard/FINDINGS.md) 及
[独立结果](audits/20261014/recheck/guard/independent-summary.json)。

### R2：B1 原用例修好了，但同类故障仍使整个服务退出

原“初始单条 hosts、+1 MiB、HUP 30,000 条”的 C/Rust 新复跑都存活、可恢复。
这是真修复。但把初始集合改为 2,000 条、保持相同新增余量后，Rust 三次均在
HUP 后 SIGABRT，精确 C 三次均存活，解除限制再 HUP 后 UDP/TCP 恢复。
Rust 每次记录 23,848 次 ENOMEM 后退出 -6，不是测试清理杀死。+256 KiB 也
重复两次失败；+512 KiB 却通过，不能从单一余量通过点推出通用安全阈值。

旧审计 Rust 的同一 2,000/+1 MiB 对照也中止，因此这是 **B1 残余，不能
声称是本次新增回归**。尚未取得失败分配调用栈，不把某个日志或 owner
分配点冒称唯一根因。这是合成资源压力，不证明当前少量真实 hosts 会触发，
也不估计现场概率。作为共享 DNS/DHCP 进程的故障边界，仍须准确保留。
详见 [B1/B6 复核](audits/20261014/recheck/hosts_logging/README.md) 和
[新运行汇总](audits/20261014/recheck/hosts_logging/summary.json)。

### R3–R5：健康 C 和“仍有监护进程”都可能被误解

R3 没有故障注入：在已健康 fallback C 上保持一个正常 TCP 查询连接。
C 的 fork child 与父进程具有同一 ELF 和 `-C` 参数；
[`daemons()` / `verify()`](../../tools/dnsmasq/deploy/dnsmasq-deploy#L34)
把二者都当成独立服务，要求恰好一个 PID，于是立即
`recovery-failed/c-identity-failed`。关闭连接后也不复位。独立客户端仍能
取得 DHCP ACK，UDP/TCP DNS 继续成功；这是监护误判，不是 C 服务中断。
它会停止正常健康监护并使仅接受 `fallback` 的 release 路径不能按 runbook
执行，必须识别实际父实例及其合法 children。
这里要求连接跨过一次监护取样，不声称每次很短的 TCP 查询都必定触发。

R4 中 C 第一次 ubusd 重启能通过显式重启恢复对象；第二次耗尽预算后对象
为空，状态仍是 `fallback`，仅 reason 改为 `bus-repair-exhausted`。有限恢复
预算本身合理，但状态必须明确区分 DNS/DHCP 健康与管理对象缺失，不能把
fallback 当作所有健康项恢复。[相关分支](../../tools/dnsmasq/deploy/dnsmasq-deploy#L357)。

R5 是单独的覆盖限制：把监护 SIGSTOP 后等待超过真实 180 秒期限，候选仍
运行、状态仍 trial。恢复监护调度后才回 C。没有因此声称必须无限叠加
watchdog；但现方案只覆盖监护退出，不覆盖监护自身挂住，必须在试运行
保证与恢复设计中明确处理。以上均有逐阶段 PID、状态及客户端证据，见
[监护分项](audits/20261014/recheck/guard/FINDINGS.md)。

## 审计 A、B 逐项复核

| 原发现 | 当前结论 | 新证据 / 限制 |
| --- | --- | --- |
| A/B01、B02 | **修复成立** | 原配置 focused 19 场景、26 对严格一致；新 558 对查询中 555 严格一致、3 仅为按真实时间界定的 TTL 跨秒差异；上游请求 251/251 一致 |
| A/B03 | 未修，仍非本轮阻断 | 原两类畸形超长 TCP 的 EOF/RST 差异不在修复范围；没有把旧证据冒称新复跑 |
| B/B1 | 最小复现修好，同类边界未闭合 | 原 8 组合压力、每侧 204 次正常 hosts 查询新跑通过；R2 重现 SIGABRT |
| B/B2 | 大量故障路径有效，整体不通过 | 最终 ELF 已与最终 guard 组合复跑；R1/R3/R5 使“可靠恢复”结论不成立 |
| B/B3 | 受限流程绕开 APK 激活问题 | bind 激活并核验 `/proc/PID/exe` 有效；没有修改 APK scripts，直接装包仍不能以事务成功代替活进程身份 |
| B/B4 | 紧急恢复减少空间依赖，体积门仍失败 | 私有 tmpfs、预留空间和 ROM bind 避开回退 APK 写 overlay；ELF 2,071,323 B / APK 1,126,561 B 仍超过 1,000,000 / 700,000 B；未豁免原门限 |
| B/B5 | 首次恢复有效，有限预算仍有边界 | 保留 stock ACL，通过显式重启恢复对象；R4 不能记为管理恢复成功 |
| B/B6 | **修复成立** | 三场景 × C/Rust 共 6 次新跑通过：持续背压后排空、三条尾日志完整按序、接收端关闭后退出 |

DNS 新矩阵覆盖本地域/无点终点、三跳 CNAME、7 类 RR、RD/CD/EDNS/DO、
TTL 过期、HUP、既有与新 TCP 视图；独立 decoder 检查 1,168 个原始响应，
TTL+2/flags 变异被拒绝。见 [DNS 复核](audits/20261014/recheck/dns/README.md)。
未发现可证实的新增 DNS/日志正常路径回归；没有据此宣称全产品无回归。

最终候选与最终脚本的原监护矩阵 **19/19 新跑通过**，包括崩溃、daemon
挂住、启动失败、DNS/DHCP 黑洞、overlay 满/只读、共享 tmp 满、真实 180 秒
未确认、确认后故障、普通监护退出、B5、交还、租约与 hosts 更新。
见 [完整组合矩阵](audits/20261014/recheck/guard/matrix-summary.json)。新增
定向场景正是原矩阵没有覆盖的边界；19/19 不能抵消 R1/R3。

B6 的修复使“连接仍在但日志接收端永久不读”时停止可持续等待，这是精确 C
共有语义。监护用 CONT/TERM 后有界升级 KILL，不能依赖日志 flush 自行结束。
原全族 329 场景证据只作审阅，本轮没有重复算作新执行数量。

## 对其他服务的影响与可恢复范围

上线机制会临时接管 dnsmasq 的 init、生成配置、租约/PID 路径和 odhcpd
回调入口。这是可见的系统管理行为改变：受控期间必须冻结 UCI/LuCI apply、
普通 init 管理和相关包操作；它不是透明的常规包升级。

新共存实验先启动真实 odhcpd，再接管 Rust、回退 C。两个阶段均得到真实
DHCPv6 Reply，并能通过 DNS 查到 odhcpd 生成的 AAAA；odhcpd PID 保持不变。
ubusd/logd/procd/netifd 保持存活；另一 WAN 模拟接口上已占用 UDP/68 不影响
LAN 探针。证明这些已测路径没有被接管破坏，**不代表真实 Wi-Fi、VPN、满速
转发或所有 hotplug/helper 组合均已验收**。

磁盘 stock C 保留、临时挂载在重启后消失的设计方向正确；新包不会被写成
开机默认。Oracle 没有物理断电、UBIFS 损坏、真实硬件启动、全局 OOM/内核
死锁证据。已经开始的回退仍存在 R1，不能以“最终重启可能恢复”替代本次
自动恢复承诺；监护自身停止调度也不在现有保护内。

## 1,000 QPS REFUSED 对照

**原因已定位：本机共享 conntrack 表达到容量边界，新的上游 UDP 发送被
内核拒绝，daemon 返回本地 REFUSED。精确 C 与 Rust 的这个错误回退一致，
不再作为 Rust 独有的阻断。** 这不是“1,000 QPS 零错误容量通过”。

先原 ELF 配对 C/Rust，再最终 ELF 配对 Rust/C，使用审计 C 未修改的配置
映射、生成器和 180 秒窗口：990 UDP +10 TCP 查询/秒、2 DHCP 周期/秒，
20/2 DNS 客户端，bank=800，初始 128 条租约，120 秒计量。结果为：

| 无跟踪窗口 | UDP 发出 / 正确 | REFUSED | UDP 计划槽跳过 |
| --- | ---: | ---: | ---: |
| C，与原审计 Rust 配对 | 118,789 / 118,788 | 1 | 11 |
| 原审计 Rust | 118,798 / 118,772 | 26 | 2 |
| 最终包 Rust | 118,800 / 118,799 | 1 | 0 |
| C，与最终包 Rust 配对 | 118,794 / 118,773 | 21 | 6 |

四窗 TCP 各 1,200/1,200、DHCP 各 240/240；所有已发请求无超时/传输错误。
全部错误包独立解码为 REFUSED，保持请求 ID 和 question。没有清空共享
conntrack，初始表状态并不完全相同；不能从这四窗推断拒答率统计等价或
Rust 更快/更慢。[原 ELF 结果](audits/20261014/recheck/pressure/original-pair.json)、
[最终 ELF 结果](audits/20261014/recheck/pressure/final-pair.json)。

最终配对的只读采样达到上限 **15,360 项**，drop 增加 23。为进一步定位，
另加空 OPT 的诊断客户端，并只对测试 PID 做限时只读 ptrace：

- 最终 Rust 6 个、精确 C 15 个错误，**每一个**均匹配到同问题、同请求
  时间窗口内的 `sendto(127.0.0.1:15354) = -1 EPERM`，随后得到 EDE23
  （Network Error）REFUSED；无其它 socket/bind/send 错误。
- 对应内核记录是 conntrack 表满丢包。独立时钟校准处理 MONOTONIC、RAW
  与 dmesg 的实际差异，没有直接混用时间戳。
- Oracle 对两种精确 ELF 的 EPERM/ENOBUFS/ECONNREFUSED、无 OPT/有 OPT
  共 12 个发送失败用例，返回包逐字节相同，下一查询正常。

这条证据链排除了本次的 DNS 转发表满、无上游路由、上游自身 REFUSED、
DNS ID 碰撞即拒答等解释。ptrace 会改变调度，诊断窗的 UDP 计划槽跳过为
265/1,786，不能拿它们作性能对比。
[逐请求诊断](audits/20261014/recheck/pressure/diagnostic-pair.json)、
[精确 C 故障对照](audits/20261014/recheck/refused_source/send-error-controls.json)。

原审计 Rust 的 13+38 个拒答与仍保留的旧内核满表事件全部有强时间关联，
支持与本次同因；时钟模型仅用新诊断校准，并通过 C 外部验证和时间平移
负控。保留一项邻近警告歧义；旧 C 的 17 个错误包已缺失，不事后补造其
RCODE，也不把旧 51 包说成当时逐包抓到了 errno。
见 [历史关联与限制](audits/20261014/recheck/refused_source/historical-clock.md)。

连接跟踪表为全路由器共享资源：只用回环并不意味着压力不会影响其他新
连接。六个新窗口的 **66 次生产健康检查全部通过**，生产 PID/starttime、
ELF 与配置 hash 不变，最低 MemAvailable 103,876 KiB；这仍不证明所有业务
QoS 零影响。没有调高上限、清空 conntrack 或改变防火墙来使结果通过。
原 1.056 秒发送前 TCP 长尾没有原时刻的 connect 跟踪，本轮未将其唯一原因
也宣称已定位。完整方法、身份与清理见
[压力分项](audits/20261014/recheck/pressure/README.md)。

## 放行前必须解决的事项

1. 修复并重新验证 R1 的可重入 C 启动，以及 R3 的合法 C 子进程识别；同时
   明确 R4 管理降级状态、R5 监护自身失活的恢复边界。
2. 对 R2 关闭已复现的 ENOMEM 残余，或明确把进程退出纳入经过验证的恢复
   合同。不能继续把原最小用例通过写成所有同类 hosts 重载已安全。
3. 用最终同一候选与最终监护组合重跑这些反例和正常路径。解决/明确处理
   既定体积门，保持实际 ELF 身份、离线备份和恢复入口可核验。
4. 真正获准部署时，仍需现场准备与恢复门，以及至少一个真实 LAN/Wi-Fi
   客户端验收；本次 `/tmp` 测量没有代替这些步骤。

这些是完成复核后的整改条件，不是本轮已经执行或获准的生产部署。

## 收尾

Oracle 各分项均核验没有本任务残留进程或宿主挂载。路由器三个正式独占
`/tmp` 根均已删除，测试进程与测试端口监听均为零。最终只读检查中，测试
端口相关的回环 conntrack 条目也已自然回收为零，没有清空生产网络状态。
70 项私有压力证据身份重读零差异，见
[收尾记录](audits/20261014/recheck/pressure/closeout.json)。原始证据留在
本地/Oracle private，本文和分项报告提供复现入口及 SHA 索引。

产品、部署脚本和探针对复核起点的 diff 为空；新增 Python 工具语法、JSON、
报告链接和 diff 格式已检查。仅有 main 和本次活跃分支，没有需要清理的
废弃任务分支。原有未提交文档保留；复核按有意义的证据单元本地提交，
没有推送或部署。
