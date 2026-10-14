# dnsmasq 完整替代审计

审计日期：2026-10-14。冻结审计基线：`main e9d89b17d72a58b723cce88038ceaa1be58d7f8c`。开始时已 fetch 并确认远端 `main 9f251f6e…` 是本地 main 的祖先；本地包含较新的全部修复，不能退回远端旧版本审。后续审计主线只增加审计工具和派生材料；接棒时 main 为 `afd3775e`，产品代码仍与该冻结基线一致。用户原有未提交文档保持原状。

**基线 main 还不能作为这台路由器的无条件、长期 C dnsmasq 替代品。正常功能和关键组件共存已经相当完整，真正阻断替换的重点是资源故障边界，以及自动恢复在自身中断时不能完成。** 这不是“没有测够所以不敢放行”：本轮用新构建的当前产品，独立复现了两个可使共享 DNS/DHCP 进程退出的问题，并证明当前 trial 可以失去全部自动恢复者。

**后续修复候选与 main 分开评价。** 组合候选 `19bd6162` / ELF `fbeabf4f…` 已独立关闭已知 TCP 内存反例，并通过正常快照、低内存 HUP 和九组件主矩阵；它仍暴露 F9 的 inotify 不完整发布，F10 的多地址轮转和多 PTR 兼容差异也确实存在。后继 `340ed73e` / ELF `edb5b4f9…` 的事务发布修复已通过 F9 原反例、定向邻界和新一轮 Rust9 集成，F10 在这一新 ELF 上仍复现。候选分支的通过不能改写成 main 已修好，更不能写成最终部署放行。

这个结论不抹掉已有成果。DHCP、租约持久化、脚本、TFTP，以及与九个当前 Rust 组件的主要管理路径，有大量本轮新运行的正面证据。日常小配置下的已测资源开销也不像一个无法承受的设计。剩余工作应围绕下列具体反例及其失败边界，不能继续以“本次修复相对旧 main 没有新增回归”代替整产品替代验收。

## 范围、身份与可信度

目标是这台 AX3000T 的 **OpenWrt 25.12.5 r33051-f5dae5ece4，dnsmasq 2.93-r1 / nodhcpv6**。精确镜像的实际 ELF 是行为对照，匹配的 patched upstream 源码用于解释；未拿宿主重编 C 当作镜像。镜像不编译的 DHCPv6/RA、DNSSEC 验证、auth、DBus、conntrack、ipset/nftset 不计成 Rust 漏实现；相关配置入口及现有调用契约仍须兼容。IPv6 DNS、odhcpd 的 DHCPv6/RA 共存则在范围内。

| 对象 | 本轮身份 |
| --- | --- |
| Rust 产品输入 | 冻结 main；185 个 dnsmasq/ubus/配方/工具链文件与 Git、本机、Oracle 快照逐项一致，0 缺失、0 不符 |
| fresh Rust release ELF | `e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`；2,073,056 B |
| 镜像 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`；269,305 B |
| 当前 trial 脚本 | `179eefcf190a95984109cad53d08c3de02c633672e8bf46ae65e3a50c2c7ab21` |
| 构建 | Rust 1.98.1，AArch64 musl，匹配 SDK linker，opt3/LTO，feature-off，static PIE；本轮尚未经完整 SDK strip/APK 包装 |
| 执行环境 | Oracle AArch64 / Linux 6.17.0-1020-oracle，独立 network/mount/PID namespace，精确镜像用户空间；真实 veth 客户端，不等于真实 Wi-Fi/路由器内核 |

[身份清单](audits/full-20261014/identity.json)、[逐文件输入](audits/full-20261014/product-inputs.json)、[构建/资源收据](audits/full-20261014/performance-summary.json)。固件 SHA 和配方来源沿用已保存的精确镜像证据；本轮未重新拆解固件 archive，但集成专项从保留的匹配 root SquashFS 新提取并核对了 881 个普通文件与 213 个符号链接，全部相同。原始配置、包、ELF、完整日志、抓包和设备备份只在 `private/`，Git 只含工具、无秘密清单及派生报告。

审查按协议、状态持久化、资源故障和系统集成独立分工，再由主审交叉核对。以实际 daemon 差分、可重复最小反例和负控制为依据；不把同一个 corpus 多次重跑当作更多独立覆盖，不用全部忽略 TTL/计时器的比较掩盖差异，也不把旧已修问题重新列为当前缺陷。

## 发现，按严重程度排列

P1：能中断共享 DNS/DHCP，或破坏本次试运行依赖的自动恢复保证。P2：特定操作/配置下的实质可用性、管理或交付问题。P3：低影响的证据/维护问题。级别表示后果与修复优先级，不是现场概率。本轮没有确认 P0、远程执行或内存越界漏洞；这不是对此类问题不存在的证明。

| ID | 级别 / 性质 | 冻结对象的结论与实际影响 |
| --- | --- | --- |
| F1 | **P1，Rust 产品** | TCP 连接深复制全部 hosts；大 hosts 下少量普通连接即可耗尽内存，整个服务被杀 |
| F2 | **P1，Rust 产品** | 合法 hosts 重载遇到分配失败后 SIGABRT；一次重载影响所有 DNS/DHCP 客户端 |
| F3 | **P1，恢复机制** | rollback 先取消全部监护；单次退出后超过原期限仍是无人监护的 Rust |
| F4 | **P2，共有交付边界** | APK upgrade/downgrade 成功不保证活进程切换，修复或回退可能实际未生效 |
| F5 | **P2，共有管理边界** | ubusd 重启后 dnsmasq 对象丢失，DNS 正常但 LuCI/RPC 管理能力不完整 |
| F6 | **P2，操作文档** | 按 runbook 把脚本放 `/tmp/dnsmasq-trial`，与其运行目录冲突，启动必失败 |
| F9 | **P2，组合候选正确性** | `19bd6162` 无 TCP 连接时，内存不足的 hostsdir 更新发布不完整记录；释放限制后仍缺记录，需下一次更新恢复 |
| F10 | **P2，条件性 DNS 兼容** | 基线与组合候选在重复地址配置下少返回合法 PTR 名称，部分双 A 组的轮转也不同 |
| F7 | **P2，交付预算** | ELF/APK 显著大于 C，既定体积门仍红；需明确解决或重新论证预算，不能冒称 release 全通过 |
| F8 | **P3，审计工具** | TFTP 驱动把新 ELF 的结果硬编码为旧提交，污染证据归属 |

### F1：TCP 本地 hosts 快照按“hosts 数 × 连接数”占内存

位置：[main.rs:5408](../../components/dnsmasq/src/main.rs#L5408) 的 `finish_tcp_accept`：创建 `LocalDnsService` 时对 `parent.local.config` 和 `parent.local.hosts` 无条件 `clone()`。动态 DNS cache 已有共享视图，并未解决这里的本地 hosts 深复制。C 的 TCP fork 以写时复制共享未变的页；不能用“Rust 只有一个进程”推导更省物理内存。

新配对实测使用合成 `addn-hosts`、cache-size=1000，每条连接只做一次正常 DNS 查询后保持连接。PSS 统计 C 父进程和全部 TCP 子进程，避免 RSS 重复计算共享页：

| hosts / TCP 连接 | C 进程树 PSS | Rust 进程树 PSS |
| --- | ---: | ---: |
| 0 / 20 | 3,589 KiB | 2,544 KiB |
| 10,000 / 20 | 4,536 KiB | 51,424 KiB |
| 50,000 / 0 | 6,244 KiB | 24,060 KiB |
| 50,000 / 20 | 8,631 KiB | **227,632 KiB（222.3 MiB）** |

50,000 / 20 独立重复为 C 8,709、Rust 227,596 KiB，结论稳定。进一步给两侧各自整个进程树相同 **64 MiB cgroup 限额、swap=0**：C 20 条连接全部正常，UDP 持续服务，峰值 10,797,056 B，无 OOM；Rust **第 5 条正常连接**触发 cgroup OOM kill（退出 -9、`oom_kill=1`），UDP 随即失效。这里已经从“可能多占内存”推进到整 daemon 故障，不是仅看代码推测。

实际影响：当前少量家庭 hosts 不会自动触发这个规模；使用大 hosts 广告过滤或局域网目录后，少量正常/慢 TCP 客户端即可将 DNS 与 DHCP 一起拖垮。64 MiB 是可复现实验预算，不是假称 AX3000T 当前只有 64 MiB，也不能把 Oracle PSS 精确换算成路由器 RSS。但 222 MiB 对这台约 233.4 MiB 总内存的平台显然不是合理连接成本。

应共享不可变 hosts/配置代际，保留 C 的既有连接快照和 HUP 后新连接视图；同时检查 host-record、租约、接口和 inotify 更新的边界。修复验收须用同一 corpus 重跑 PSS/cgroup，以及旧/新 TCP 连接的协议视图，不能只给普通无 hosts 的 TCP benchmark。[资源专项](audits/full-20261014/performance-review.md)、[全部派生数值](audits/full-20261014/performance-summary.json)。

### F2：hosts ENOMEM 仍会中止整个 DNS/DHCP 服务

本项是 [PREDEPLOY_RECHECK R2](PREDEPLOY_RECHECK.md) 的**当前残余**，不是本次新增回归。之前“初始单条 hosts”的修复确实存在，但不足以覆盖同类合法输入。

本轮 fresh main 与镜像 C 独立重放：初始 2,000 条 hosts，将各自 `RLIMIT_AS` 设为自身 VmSize +1 MiB，随后 HUP 载入 30,000 条合法 hosts。C 经 18,036 次 ENOMEM 后存活，并可解除限制再重载恢复；Rust 经 23,848 次 ENOMEM 后 **SIGABRT(-6)**，不是清理动作杀死进程。另行新跑的 5 项局部 `hosts_allocations` 测试全部通过，恰好说明局部错误处理通过不能代表整个重载链安全。[新证据](audits/full-20261014/performance-summary.json)、[资源专项](audits/full-20261014/performance-review.md)。

实际影响：hosts/HUP 是正常管理入口，内存不足会扩大为所有 DNS/DHCP 服务中断。RLIMIT_AS 是确定性注入，并不证明当前小配置的路由器已发生 malloc 失败，也不能将 Linux 全局 OOM 与可返回 ENOMEM 混为一谈；F1 的 cgroup 证据是另一种故障机制。

需要沿读取、索引、发布和日志的完整调用链传播分配失败，明确保留/回退状态，避免错误路径继续分配。修复方另从同源 debug build 获取栈，指向 `logging::startup::hosts_read` 的 `extend_from_slice` 经重载 Complete notice 被调用；这是修复方定位线索，不能把该单一栈写成审计已经证明的所有根因。验收应覆盖初始 1/2,000 条、相邻内存余量、解除限制恢复、UDP/TCP 和 DHCP 健康，保留已有 ENOSPC/租约事务语义。

### F3：回退幂等不能保证回退被中断后自动接续

位置：[dnsmasq-trial:62](../../tools/dnsmasq/deploy/dnsmasq-trial#L62)。`rollback` 先 `stop_helpers`，取消 deadline 与 watch，才卸 mount、restart C。旧状态机虽然已换掉，恢复责任仍存在空窗。

新实测：正常 trial，25 秒未确认期限，真实客户端 DHCP/UDP/TCP 通过；手动 rollback，在两个 helper 都被取消、尚未卸载的真实系统调用窗口注入 **一次 SIGKILL**。再等 35 秒：原 Rust 仍运行、bind 仍挂载、C 为零、helper 文件为零。人工再执行 rollback 才恢复 C，客户端重新通过。未改产品脚本、procd、ujail、候选，仅 ptrace 观察并杀死一次回退进程。[专项与重放](audits/full-20261014/trial-review.md)、[新结果](audits/full-20261014/trial-kill.json)。

本例 Rust 一直健康，**没有实测断网**；证明的是自动恢复与期限保证失效。若在故障触发回退时进入同一空窗，故障服务将没有恢复者，这是代码推断。应该让独立恢复责任持续到真实 C 身份和协议健康确认，测试卸载前后、停止后、启动前后的中断。重复手动执行可恢复，不能替代 Wi-Fi 失联后无需操作者的恢复保证。

因此本审计没有把这套机制继续用于家庭生产切换。用户授权真机测试并不消除项目要求的已验证恢复门。

### F4：包事务成功与实际进程替换是两件事

[既有精确镜像 APK 实测](PREDEPLOY_AUDIT_INTEGRATION.md) 已证明：升级后数据库/磁盘为 Rust，活进程仍是 C；降级后磁盘为 C，活进程仍是 Rust `(deleted)`，显式 restart 才切换。本轮确认自该次冻结版本至审计基线，Makefile 和所有 package files 没变，只有 README 改动；相应机制仍适用。**本轮没有 fresh APK 安装测试，不将旧运行冒称新运行。**

原因是继承的 `default_postinst` 调用 init start，procd 根据 command/config/files 等判断实例变化，不以可执行文件字节改变自动替换同一命令。新的 Rust procd 也有此行为。全新安装自动启动和卸载 stop 的已有验证不受此结论否定。

实际影响：可能以为漏洞已修/故障已回退，实际上旧 ELF 仍服务。完整交付必须定义 upgrade/downgrade 后的显式 restart、`/proc/PID/exe` hash 与客户端验收，并避免满 overlay 时依赖 APK 事务紧急救援。不能只看包版本、磁盘 SHA 或 `running=true`。[当前集成专项](audits/full-20261014/integration-review.md)。

### F5：ubusd 重启会留下仍服务但缺少管理对象的 dnsmasq

本轮以**同一套 fresh Rust 九组件**分别搭配 C/Rust dnsmasq，均复现：ubusd 重启后两个 dnsmasq 对象消失，DNS 持续正常，显式 init restart 后对象恢复。匹配 stock ACL 与 dnsmasq 降权后的重注册边界相关；这是精确 C 共有问题，不是 Rust 替换新增回归。[集成专项及新配对结果](audits/full-20261014/integration-review.md)。

实际影响：metrics、DHCP事件订阅和DNS doctor通知丢失；LuCI IPv4租约还有文件读取路径，不能扩大为所有LuCI租约查询失效；只检查 DNS 应答无法确认管理栈已恢复。长期交付应明确总线代际恢复与可观测状态。如果调整 ACL，要最小化权限并分别对 C/Rust 做权限负控制；不要为本审计临时放宽真机 ACL。

### F6：公开试运行步骤按原样无法启动

runbook 让用户上传脚本为 `/tmp/dnsmasq-trial`，脚本 `DIR` 恰好也是此路径。新镜像环境按文档执行，得到 `mkdir: File exists`、`cp: Not a directory`，最后误导为 `copied candidate hash mismatch`，退出 1。C 保持正常。现有测试使用 `/usr/sbin/dnsmasq-trial`，漏掉了用户实际步骤。[新实测](audits/full-20261014/trial-path.json)、[解释](audits/full-20261014/trial-review.md)。修复应区分脚本与工作目录，并直接执行文档命令验收。

### F9：组合候选的 inotify 更新会在 ENOMEM 后发布不完整 hosts

**这是后续组合候选 `19bd6162` / `fbeabf4f…` 的独立新反例。未在原 main 对同一场景重放，不能冒称本轮已证明基线也有相同故障。** 共享 DNS/DHCP、无已连接 TCP、初始 2,000 条 hosts，按该进程 VmSize+1,024 KiB 限制地址空间，经 hostsdir close-write 更新为 6,000 条。源文件已读到 EOF，随后遇到 ENOMEM：新记录开头/中间可查，结尾缺失，旧记录已删除。解除内存限制、不再写文件时仍不完整；下一次成功 close-write 才恢复。

独立重复在解除限制后完整查询 old 2,000、new 6,000、next1 6,000 个名字：Rust 只保留 new 的前 **3,520/6,000** 条，末 **2,480** 条缺失，old/next1 全无；同条件精确 C 已完整更新到 next1 的 6,000 条。28,000 个 C/Rust 查询无超时、无错误地址。Rust 配置 DNS、lease DNS、UDP/新 TCP、DHCP ACK 和进程都健康，**不是整进程中止或整网失效**。[独立重载审查](audits/full-20261014/integrated-reload-review.md)。

源码对应 `19bd6162:main.rs` 的 `publish_hosts_source`：逐条 `local.hosts.insert` 忽略失败；部分记录插入失败后被释放，末尾克隆又可能成功，因而存在把不完整代发布给本地 DNS 和 daemon 的路径。这一静态解释与观测相符，未以 allocator 调用栈证明具体失败点。实际影响是受 hostsdir 管理的局部名称丢失/回退到上游，且解除资源压力本身不能恢复。正常小文件、held TCP 和 HUP 通过都不足以覆盖这一条路径。应先完成私有代构造与所有必要克隆，再一次发布两个 owner；构造失败保留完整旧代，不在恢复路径上重新申请它。

后续状态：`340ed73e` 改为私有工作代构造，逐项传播分配失败，并在两个 owner 更新前完成全部发布副本。独立重新查询全部14,000个名字后，旧表 **2,000/2,000** 完整保留，新/next1均为0；无错误/超时，下一close-write恢复。held/no-held、无压力正控、失败HUP缓存清除及9个分配故障测试通过。该结论只关闭已复现的 F9，不宣称任意分配点或其它行为完整正确。[新修复独立验收](audits/full-20261014/inotify-fix-review.md)。

### F10：重复地址下遗漏部分 PTR 名称，且多地址轮转不同

**原 main 和组合候选均有这一条件性兼容差异，不是分页修复新增回归。** 同一批 hosts 多次复用地址时，独立精确 C 的 cache dump 可见某地址拥有多个 `F_REVERSE` 名称。查询合成地址 `192.0.3.64`，精确 C 的 UDP/TCP PTR 回复均含 `host000063.test` 和 `host000313.test`；原 main `e0ec…` 与组合 `fbeabf4f…` 都只含前者。相邻单 reverse-owner 地址的结果三者相同，共 12 条目标 wire，进程均健康。[独立 TCP/PTR 审查](audits/full-20261014/integrated-tcp-review.md)。TCP 同样缺记录，排除了仅由 UDP 截断造成差异的解释。后继 `340ed73e` / `edb5b4f9…` 也独立补测目标地址 UDP/TCP，两条均仍遗漏第二个 PTR 名称，F9修复没有关闭F10。

另独立对两个名字各做 4 次 UDP、4 次 TCP 查询，共 48 次 C/基线 Rust/组合 Rust 观察：受影响 `host000313` 在 C 中保持固定双 A 顺序，两个 Rust 均交替；邻 `host000312` 在三者中均轮转。A 地址集合完整，差异不依赖连续开关连接，也不是 C 不同启动之间的初始顺序变化。原大样本的 188 条差异均仅为两个 A 地址顺序互换。

匹配 C 的 `cache_find_by_name` 只在相同 `F_REVERSE/F_IMMORTAL` 组内轮转，故两地址具有不同 reverse 标志时保持固定顺序。C 载入时临时按地址链与名字查询复用链接，实际可能让重复地址拥有多个 reverse 名称；Rust 的单一 reverse-owner 索引不能表示这一行为。现场影响仅限符合条件的重复地址 hosts：反向查询不能获得 C 会返回的全部名称，优先首条 A 的客户端选择也不同。**未观察到错误 A 地址、进程退出、DHCP 故障或网络中断。**

处置仍开放。仅调整轮转标志不解决多 PTR；完整匹配还涉及载入顺序、临时索引和 C 名字哈希遍历，应先明确要兼容的多 PTR/顺序契约，再评估峰值内存及实现复杂度。本轮保留现有 first-owner 行为并记录差异，没有批准兼容豁免，也不以增加复杂状态来换取未经验证的“全等”。

### F7：交付体积预算没有闭合，但不是这台设备“装不下”

fresh ELF 为 **2,073,056 B，C 的约 7.70 倍，增加约 1.72 MiB**。最新既有 SDK 包内 ELF 2,071,323 B、APK 1,126,561 B，仍超过曾冻结的 ELF≤1,000,000 B / APK≤700,000 B 门限；本轮未新打 APK，不能给 fresh ELF 虚构一个包体积。[既有最终包门结果](PREDEPLOY_RECHECK.md)、[当前构建身份](audits/full-20261014/performance-summary.json)。

本轮真机只读观察 overlay 可用约 54.6 MiB，因此不能声称当前设备无法容纳；大小也不能再与映射 RSS简单相加。实际问题是 release 预算仍不成立、镜像与临时回退空间成本增加。建议在功能/故障修复后，用最终同一产物重新打包并明确允许的 flash、RAM 与 CPU 预算；若放宽原门限，写明设备余量与取舍。不要为追求单一体积数字贸然更换 allocator/链接方式，或让未经功能资格的 opt-s 继承 opt3 结论。

### F8：TFTP 审计工具错误标注被测提交归属

[audit_20261011_tftp.py:238](../../tools/dnsmasq/audit_20261011_tftp.py#L238) 无条件写入 `source_commit=3e7df6c1…`。本轮输入 fresh `e9d89b17` ELF，结果依旧含旧提交，和同时记录的 `e0ec7531…` SHA 自相矛盾。主审以实际输入/hash 重新核对，未误归属本轮结论。[新证据](audits/full-20261014/dhcp-evidence.json)、[专项 D1](audits/full-20261014/dhcp-review.md)。

这不直接影响路由器运行，但会使后续汇总把新旧结果接错，是证据优先项目不能保留的工具缺陷。改为显式且经验证的输入清单/提交参数，或去掉无法证明的字段。旧模块注释中“DHCP pre-dispatch/lease 扩展/TFTP listener 尚未实现”也应清理；本轮已经实际执行它们，不把这些旧注释当产品缺功能。

## 已证明能工作的部分，以及尚未证明的部分

生命周期专项还在当前fresh ELF重新关闭原审计A01–A05/A09：345对CLI、33对daemonize、6对身份、7对capability、5对配置退出均通过；16次normal/debug信号运行之外，实际验证了dump、ALRM提前持久化、HUP改变hosts和USR2日志轮换。详见[生命周期专项](audits/full-20261014/lifecycle-review.md)。DNS专项恢复并核验原会话两轮协议证据，接棒后另补有状态缓存/TCP场景；详情见[DNS审计](audits/full-20261014/dns-review.md)。

| 本轮新运行 | 结果与范围 |
| --- | --- |
| 普通单测 | lib 784、bin 78 通过；23 ignored 未运行；另 hosts_allocations 5/5 通过 |
| DNS协议/异常输入 | 两轮各368对，同一corpus；每轮366字节相同。另2条是C的名称压缩循环，Rust返回合法答案，不要求复制C畸形输出 |
| 有状态缓存与TCP调用补测 | 基线ELF新跑110对，337客户端观察/侧；受限规则比较通过、452负控拒绝；4项DHCP/TCP见证和9负控通过，不冒称完整cache family通过 |
| DHCP 独立有状态组合 | 750 个请求，两次执行同一 corpus；第二轮严格核对 577 回复/173静默、逐包 lease、计时边界和双方264 helper事件；5类检查器负控制均拒绝 |
| 租约恢复/持久化 | 70 对场景、50 边界通过，含真实 ENOSPC 后约60秒重试、partial EIO、restart/HUP、名称碰撞、脚本初始化 |
| helper/OpenWrt hook | 16 对场景全部通过，含凭据、慢/死 helper、实际 dhcp-script/hotplug、shutdown |
| TFTP | 24 对中22对一致；另2对为C失败、Rust正确完成，不要求Rust复制C的错误 |
| 当前九组件共存 | C/Rust dnsmasq各23项主矩阵与5项实际helper检查通过：init/ujail、真实veth DHCP+DNS、LuCI HTTP→rpcd、fw4、UCI/reload_config、odhcpd→AAAA、netifd resolver切换、procd崩溃恢复/stop；总线重启边界另列F5 |

九个组件是 **ubusd、procd、netifd、uci、reload-config、rpcd、logd、httpd、fw4**；`components/ubus` 是共享库，不应误算为额外 daemon。所有九个用于本轮共存矩阵的 ELF 都由冻结 main 新构建，不是把九月份旧镜像当最新 main。详见 [DHCP/lease/helper/TFTP](audits/full-20261014/dhcp-review.md)、[集成](audits/full-20261014/integration-review.md)。

上述结果表明常规可用性已超出原型阶段，但不等于真实硬件上的十组件长期共存证明：Oracle 不覆盖 Wi-Fi 空口、实际 OpenWrt 内核、硬件加速、VPN/满速转发竞争、数周运行、真实 relay/PXE 多网段与手机随机MAC/睡眠/漫游。普通测试和特定压力通过不能推翻 F1/F2。未执行长时间全族 fuzz；未声称所有 malformed 报文或分配点穷举安全。

## 性能评价：历史小配置成本可接受，基线大配置并发成本不可接受

本轮新增资源实验证明 F1 的严重扩展性问题；没有在多组并行编译的 Oracle 上造一个“精确 CPU 提升/退步”数字。普通小配置的日常量级参考仓库已有 [AX3000T 配对实测](PREDEPLOY_AUDIT_RESOURCES.md)，身份与边界必须一起保留：

- 20 DNS/s +0.1 DHCP周期/s：C/Rust 单核 CPU 0.350%/0.692%，额外整机占比约0.171个百分点；主进程RSS约1,220/2,496 KiB。本地 UDP p95约0.469/0.782 ms。
- 1,000 DNS/s +2 DHCP周期/s：单核CPU约19.133%/27.679%，压力TCP和DHCP长尾更差。这些窗口有错误与计划发送跳过，**不是零错误容量合格、也不是吞吐上限**。
- 后续 REFUSED 归因已定位为共享 conntrack 容量/上游发送失败，C/Rust共有；不能继续当成Rust独有bug。短期内存观察支持当时小配置可达平台，不证明大hosts或数周无泄漏。

这是**历史指定 ELF、回环与合成上游**的实机证据，不是本轮fresh main、家庭广播路径或最终修复产物的新benchmark；不能把它无条件转签给下一份 ELF。C 的进程树 RSS重复计共享页，Rust tmpfs映像页也不是堆泄漏。F1专门使用PSS与同预算cgroup，回答了旧小配置benchmark没有回答的问题。

产品取舍上，正常家庭小配置的额外约1MiB级常驻页和亚毫秒本地DNS成本，比F1/F2的整进程故障次要。先修除连接数乘法与错误路径中止，再为最终ELF做有界配对；不建议为了跑分引入大依赖或重写成熟执行平面。

## 修复交接与独立验收

用户追加授权后，审计与修复保持独立：修复在专用 worktree、小提交中进行；审计主线不合并产品、不 push、不修改家庭服务。接棒后已重新确认双方会话并恢复自动引导通信。活跃修复分支和失败产物继续保留。

组合候选源码冻结为 `19bd6162e1b33c92a1e5ea26e864497800c7cfed`，ELF `fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b`，2,089,440 B。主审从 Git 独立计算并核对全部 647 个 dnsmasq/ubus/packaging/tools 文件，0 缺失、0 不符；复制 ELF 后再次核验 SHA。**审计采用已核验的修复方构建，没有独立重新编译该候选。** [身份与构建收据](audits/full-20261014/integrated-identity.json)。

| 项目 | 独立验收状态 |
| --- | --- |
| F1 原 hosts 复制与后续轮转表复制 | `19bd6162` 通过：旧版32 MiB第9连接OOM，新版同输入20/20、peak21,102,592 B；60k warmed/64 MiB、single50k/64 MiB通过，98对快照和6,020条unique rolling观察一致，rolling PSS无增长。[结果](audits/full-20261014/integrated-tcp-review.md) |
| F2 HUP 整进程中止、失败时缓存清理及旧代保留 | `19bd6162` 所测 held/no-held HUP 与配置DNS/lease/UDP/TCP/DHCP恢复通过；这不覆盖新发现F9。[结果](audits/full-20261014/integrated-reload-review.md) |
| F3/F6 回退中断与文档路径 | `18d83527` + `fd62cf85` / 脚本 `dfa94d52…` 已独立通过6场景。组合 `fbeab…` 后再独立重跑真实rollback-killed与deadline通过；精确C和veth客户端都核验。[前次](audits/full-20261014/trial-fix-review.md)、[组合重放](audits/full-20261014/integrated-trial-review.md) |
| 九组件组合资格 | `fbeab…` + 已核验当前Rust9，C/Rust各23项管理、5项helper通过；新 `edb5…` 又独立完成Rust23+5，C复用同fixture前轮对照。共有F5仍存在。[19bd结果](audits/full-20261014/integrated-stack-review.md)、[340ed结果](audits/full-20261014/integrated-stack-inotify-review.md) |
| F8 工具归属 | `dc733337` 删除无法证明的硬编码提交字段、保留ELF/tool SHA；主审已逐行静态确认。修复仍在独立工具分支，未冒称本轮重跑TFTP证明运行结果。 |
| F9 不完整增量发布 | 后继 `340ed73e` / `edb5b4f9…` 独立原反例全量census、held/control/HUP邻界与9项allocator测试通过；19bd失败证据保留。[结果](audits/full-20261014/inotify-fix-review.md) |
| F10 多PTR/轮转兼容 | main、19bd均独立复现；340ed再次确认遗漏PTR。保持开放，未批准豁免、未扩大产品改动。 |

`340ed73e83e58ba845e0a645eb21e9ead0d0f108` 的 ELF 为 `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d`，2,089,440 B；审计再次独立核对647个源码/配方/工具文件，均相同。它是在19bd基础上只增加hostsdir事务发布的候选，不是另一个工具链或allocator变体。

修复方另在19bd提供 Linux musl lib789、bin78、native allocator8 通过，23 ignored 未运行；trial12场景/39客户端健康检查、TCP HUP 及42条快照收据保留在修复分支。340ed的回交则为lib789、bin78、allocator9、19个inotify场景、TCP HUP/42条快照及一个confirmed-rollback-killed场景；所用同ELF与精确C压力失败均单独记录。这些是**修复方回交**，与上表审计重新执行的数量分开，不叠加计数。F4/F5为共有部署约束，F7为预算决策，仍需在正式交付流程解决。

### 修复侧最终收尾索引

修复方最终交接为 `0f99310b`，文件
`docs/dnsmasq/audits/full-20261014/FIX_HANDOFF.md`，保留在
`fix/dnsmasq-full-r2-20261014`。已核对其身份、验收范围和开放项与本报告一致；
此次仅归档最终回交索引，没有新增运行或扩大独立验收结论。
可用 `git show 0f99310b:docs/dnsmasq/audits/full-20261014/FIX_HANDOFF.md` 读取固定版本。

| 修复方证据 | 固定提交 |
| --- | --- |
| 19bd 身份/单元；TCP与12场景/39健康检查 | `c2fbaf4e`；`13fc6472` |
| 340ed 原反例与19组inotify；同源码核心/一次真实回退中断 | `28f0aee6`；`c5a1d74f` |
| F10 大样本归因；六行PTR反例；具体合同/成本处置 | `c2e75c23`；`07e851be`；`adf4861f` |

已解析并确认两个持久标签分别指向产品提交：
`audit/dnsmasq-full-19bd6162-20261014` → `19bd6162`，
`audit/dnsmasq-full-340ed73e-20261014` → `340ed73e`。
F10仍为 **P2 OPEN，无豁免**；合同分支没有产品修改。活动工作树、未合入修复和
失败证据继续保留。本轮修复与审计均已收尾，产品合并、正式部署资格仍未完成。

## 真机安全与收尾核对

本轮经 Wi-Fi 对 `ssh openwrt` 仅执行只读取证和轻量DNS健康查询。**没有停止、替换、重载或向生产 dnsmasq 发信号，没有写闪存、装包、改配置或新增挂载。** 因F3的恢复门反例，未把家庭网络用于验证一个已知不能保证自动恢复的机制；F1/F2低内存故障全部留在Oracle隔离环境。

首次取证前，已把完整 `/etc` 直接归档到电脑 `private/full-audit-20261014/router/etc-before.tar.gz`，限制目录访问并检验可读；SHA `7fa606784bcc8e8454506d5bc75d6663d3d9bf1825c446eeda7e6e222d83a183`。`sysupgrade -l` 列出的文件全部在该离线备份中，缺失为0。另备份生成配置、租约、hosts、resolv和helper到 `runtime-before.tar.gz`，SHA `bf8a1ac5a8ae4f8be7152b8091b610f40838d6ff09097b57440e8fb41d48998b`；所有秘密保留在private。

收尾新核对：[router-closeout.json](audits/full-20261014/router-closeout.json)。`/etc` 的261个归档项前后内容、权限、属主、符号链接全部相同；`sysupgrade -l`备份覆盖缺失为0。生产dnsmasq前后均为PID2812、实际ELF为精确C `097a9e21…`；可见文件与ROM一致。所核对的控制平面文件/常驻进程hash及PID、全部mount记录前后一致。最终管理电脑经Wi-Fi向路由器做本地UDP/TCP DNS查询均返回正确地址，两个ubus对象仍在，WAN状态正常。整个过程保持原有C服务，故无需执行会改变状态的“恢复”命令；没有把未做的手机DHCP重连记为通过。

接棒收尾再次只读取证（2026-10-14 13:49 UTC）：`/etc` 261项仍完全相同，压缩归档SHA与初始备份也相同；生产C仍为PID2812，12条mount记录与前次逐条一致，两个ubus对象在，管理电脑的UDP/TCP `localhost` 查询均正确。[再次收尾](audits/full-20261014/router-closeout-resume.json)。未进行家庭网络切换。

最终仍需用户配合的验收：在已验证恢复门和最终候选下，让**一台**手机/电脑重新连接Wi-Fi，确认真实DORA、续租、网关/DNS选项、主机名解析、IPv6、上网和LuCI；再观察睡眠恢复/随机MAC/漫游。不要同时释放全部家庭客户端租约，也不要把本机回环探针或Oracle veth当成这一步已经完成。长期十组件运行、重启恢复和最终APK资格仍需单独完成；本报告不授权刷机或安装包。

## 后续产品交付顺序

1. 将F1/F2已验证修复与F9事务发布修复组合，保留失败重载的完整旧代；F10须单独确定多PTR与轮转兼容合同及实现成本，不能当成已解决。
2. 纳入已独立验证的F3/F6恢复脚本与文档路径修复；对最终组合继续核对恢复责任、真实C身份与客户端健康。
3. 固定一组最终source/ELF/APK/九组件身份，明确F4/F5的运维恢复及F7的资源预算；把F8这类错误身份字段清除。
4. 对同一最终产物跑原反例、相邻边界、主要协议与九组件矩阵，再做单客户端真Wi-Fi试运行和有限长期观察。每个门只陈述它实际证明的范围。

本次审计交付已完成。main 的阻断、分支修复的实际验收、F10开放兼容问题与尚未执行的产品交付门分别保留；没有把“审计完成”写成“产品全部修好”或“允许正式部署”。
