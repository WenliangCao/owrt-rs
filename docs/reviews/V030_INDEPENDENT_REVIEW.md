# v0.3.0 独立代码质量与可靠性审查

**原样 v0.3.0 还不能作为可以放心长期无人值守的版本：已复现两条 PID 1 启动恢复缺陷，以及配置回滚、网络恢复和输入内存上界问题。修复只在审查分支，未部署；包卸载与慢脚本积压仍有明确限制。**

本轮从 2026-10-18 21:01 UTC 开始，经断流恢复，按用户补充要求从高影响路径扩展到系统覆盖。最终产品源码冻结于 `211849e4`；下面明确区分源码阅读、Oracle 实测、设备推断和仍未验证的边界，不以测试全绿替代长期运行证明。

## 基线与授权范围

- 标签 `v0.3.0` 的源码是 `6fb236a3d3cae4c1fa2e0c80e8f0aae552437bd2`（annotated tag 对象 `7bd405b9`）。初始 main `1ab3db67` 及本次恢复时 main `766aa6f7` 对标签的 `components/`、`packaging/`、指定 release manifest、`tools/ci_*`、工作流均无代码差异。审查修复另外列出，不冒充线上版本。
- 第一阶段只读设备身份是 OpenWrt `25.12.5 r33051-f5dae5ece4`、`native-eleven`、`0.3.0-r1`、源码 `6fb236a3`。11 个 Rust 程序及 dnsmasq init/ACL 共 13 项、对应 C 恢复集合 13 项都通过已安装 manifest 校验；当时 uptime 约 20,121 秒，不是数周稳定性证明。
- 先读 AGENTS、研究指导、contracts、精确源码/镜像，再复现；历史报告只在对应发现成立后定向去重。没有导入旧项目代码。
- 匹配参考：procd `58eb263d`、netifd `cbb83a18`、rpcd `28faf640`、ubus `24864e78`、uci `66127cd7`、ubox `6f78fa49`、uhttpd `7b1bec45`、firewall4 `b6e51575`、odhcpd `5d7be43f`，以及精确 OpenWrt patched dnsmasq `2.93` 的 **nodhcpv6** 变体。DHCPv6/RA 属于 odhcpd。
- 所有 Rust 构建、测试、fuzz、网络空间实验均在 `ssh oracle`；Mac 没有构建 Rust。路由器未写入、未 reload/restart、未刷机；没有 push、tag、发布或触发工作流。
- 分支 `review/v030-independent`。并发旧会话的修复和 UCI 未提交副本先保全，继续工作使用独立副本，最后整合回原审查工作树；main 的用户文档改动不混入提交。

以下 **E** 指原仓库根目录的 `private/review-v030/independent-2101-evidence/`；**O** 指 `E/oracle/`；**D** 指 `private/review-v030/dns-dhcp-2101/`。原始日志、ELF、rootfs、源码副本、设备信息均保留在 private，不提交 Git。公开内容仅回归工具、合同修订和本报告。恢复历史见 `E/RESUME_STATE.md`，逐文件和逐命中证据见 `E/COVERAGE.md`、`E/SCAN.tsv`。

## 已复现的问题

行号指 v0.3.0。等级按明确前提下的后果，不表示问题已经在物理设备上自然发生。“已修复并验证”均限 Oracle；整体设备资格仍待单独验证。

| ID / 等级 | 文件:行 | 触发条件与用户可见后果 | 实证位置 | 提交 / 状态 |
|---|---|---|---|---|
| F01 / P0 | procd/main.rs:2634、2398 | 初次总线 ADD_OBJECT 失败，PID 1 退出且未到 sysinit；真实系统可能 panic/重启 | O/procd-stock-diff-red-{1..4}、final/procd-strengthened-* | `0a1068de`；已修复并验证 |
| F02 / P0 | procd/main.rs:2553、2564 | 首次 ubusd exec 失败，没有 child 可 reap，恢复文件后仍不重试；PID 1 活着且继续喂狗，但不起网 | O/procd-early-exec-red-{1..4} | `308de674`；已修复并验证 |
| F03 / P1 | rpcd/uciobj.rs:980、1103 | 快照 ENOSPC/短写仍开始 apply，之后残缺快照覆盖原配置 | O/rpcd-snapshot-baseline、rpcd-snapshot-regression-red | `6de88614`；已修复并验证 |
| F04 / P1 | rpcd/uciobj.rs:1070、1078 | 有方法权限的另一登录会话用 rollback:false 删除 owner 的回滚快照；真实 HTTP 请求已验证 | O/rpcd-owner-http-red、final/rpcd-owner-http | `b7266d23`；已修复并验证 |
| F05 / P1 | odhcpd/main.rs:432、457、675 | UDP/547 暂时冲突释放后无主动重试；进程存活但 DHCPv6 不回复 | D/evidence/odhcpd-socket-recovery.jsonl | `921fd92e`；已修复并验证 |
| F06 / P2 | netifd/netlink.rs:271、282 | DUMP_INTR 或 DONE 错误被当作完整快照；未证明 daemon 错误撤回前缀的端到端后果 | O/netlink-transport-red-*、netlink-kernel-churn-v2 | `b85ce2b7`；已修复并验证 |
| F07 / P1 | odhcpd/leases.rs:349 | leasetrigger 挂起，后续变化持续 spawn，无数量/寿命上界 | D/evidence/trigger-resume-*、E/oracle/odhcpd-resume | `6dee72c2`；已修复并验证 |
| F08 / P1 | procd/hotplug.rs:250、278 | press 未回收时 release 入队；press 完成后才创建 timeout，release 错过取消，误执行 timeout 动作 | E/procd-systematic/oracle/button-diff-{red,green} | `d5b77054`；已修复并验证 |
| F09 / P1 | procd/main.rs:888 | inittab 空 respawn 命令的失败日志访问 argv[0]，父进程 panic，sysinit 不到达 | E/procd-systematic/oracle/inittab-{red,green}-* | `f8284c0f`；已修复并验证 |
| F10 / P1 | odhcpd/router.rs:573–588 | 前缀寿命短于最小 RA 间隔，unsigned 算术产生过长间隔；99 秒窗口只见 3 包 | D/evidence/ra-short-prefix* | `407ef825`；已修复并验证 |
| F11 / P1 | ubusd/server.rs:412、420 | 本地慢读客户端持续发 LOOKUP，挂起命令队列无界，消耗总线进程内存 | E/ubusd_queue_probe.py、O/ubusd-*；coverage-parts/ubusd.md | `e5b2e312`；已修复并验证 |
| F12 / P2 | ubus/conn.rs 同步 request 路径 | 无有效接收者的迟到 DATA/STATUS/FD 排入 pending；原 257 条，修后仅 1 条合法 INVOKE | E/ubus-experiments.md、coverage-parts/ubus.md | `178111bc`；已修复并验证；httpd 已有池隔离，不宣称新 HTTP 泄漏 |
| F13 / P1 | netifd/main.rs:1673、2503；proto.rs | 协议脚本暂时不可执行，setup 无 child 却停在 pending；恢复文件仍不起网 | E/netifd-systematic/oracle/red-6..9、green-spawn-final | `d7b38502`；已修复并验证 |
| F14 / P1 | netifd/main.rs:3749 | 下层接口迟到或反复 down/up，没有重放 host dependency 事件，依赖接口不恢复/不 teardown | E/netifd-systematic/oracle/*dependency-cycle* | `4268aebf`；已修复并验证 |
| F15 / P1 | netifd/main.rs:3909、reload 路径 | reload 删除 UCI bridge port 后内核仍保留旧成员；最后端口移除也未撤地址 | E/netifd-systematic/oracle/*bridge-final*、green-all | `2c35b0e2`；已修复并验证 |
| F16 / P2 | rpcd/rpcsys.rs:137 | 本地 APK DB 的单字节 g 行触发 line[2..] 越界；未模拟真实 APK 断电截断 | E/rpcd-systematic、coverage-parts/rpcd.md | `39d98e41`；已修复并验证 |
| F17 / P1 | rpcd/uciobj.rs:1030 | 回滚写回遇只读目录/ENOSPC仍丢快照，配置未恢复且无法再试 | E/resume-0823-preserved/rpcd/inherited-restore | `9a10c3f1`；保留快照并重试，已修复并验证 |
| F18 / P1 | uci/file.rs:312、delta.rs:215 | commit 先清 saved delta，随后临时文件创建/写/rename失败；配置未改且草稿丢失 | E/resume-0823-preserved/uci-oracle | `a6d65524`；成功rename后才清delta，已修复并验证 |
| F19 / P1 | reload-config/syslog.rs:33–41 | /dev/log 存在但队列满，trace send 无限阻塞并持有配置锁；预算和 SIGTERM 不解阻塞 | E/resume-0823-preserved/reload-fw4/oracle/regression-{red,green}.json | `cb4d79c5`；日志socket设NONBLOCK，已修复并验证 |
| F20 / P1 | rpcd/file.rs:242；ubus/digest.rs | 授权读取64 MiB普通文件并算MD5，128 MiB地址空间限制下4/4 abort；C正常 | E/resume-0823-preserved/rpcd/oracle/md5-assert-* | `edb199ba`；8192字节读缓冲，已修复并验证 |
| F21 / P1 | rpcd/rpcsys.rs:197 | passwd 不存在账户使 stdin 早关，write失败提前返回未wait；5次请求积累1/2/3/4/5个僵尸 | E/resume-0823-preserved/rpcd/oracle/password-final-* | `686a4592`；关闭stdin并wait，已修复并验证 |
| F22 / P1 | httpd/http.rs:573、643 | 请求头只限单行，4 MiB短头使RSS约1 MiB→6 MiB仍200；默认100连接下缺乏总内存界限 | E/httpd-resume1115/header-memory-red.json、header-wire-green.json | `f55246d8`；64 KiB/512字段，超限413关闭；已修复并验证 |
| F23 / P1 | dnsmasq/main.rs:1753–1837 | bind-dynamic 新地址只有UDP或TCP成功，另一半失败后永久缺失；释放端口也不恢复 | E/dnsmasq-systematic/oracle、EXPERIMENTS.md | `ee3596ee`；每秒仅重试缺失DNS协议，已修复并验证 |
| F24 / P1，操作边界 | tools/native_image.py:195–254；packaging/image | 管理员卸载原生包：apk成功删除13条active路径、13条C备份及恢复工具，包括PID1；不能把卸载当回滚 | E/packaging-systematic/oracle/apk-remove* | **仅报告**；`f16f5aa1`补文档，不宣称产品已防止删除 |
| F25 / P1 | dnsmasq/dhcp/lease.rs:128–137；dhcp/daemon.rs:2548 | 运行期helper永久挂起，ACK/RELEASE循环不断积累deleted租约；活跃租约上限不限制这条队列 | E/dnsmasq-systematic/HELPER_BACKLOG.md、oracle/helper-queue-* | **仅报告**；需要有界投递策略，未丢弃事件或改变脚本超时合同 |

表内组件路径以 `components/` 为前缀，除另注明的打包工具。F24 是既有不支持 live APK 升级/迁移边界的新增卸载实证，不把它说成受支持的 sysupgrade 回归。

另有**审查候选自身的组合回归 C01**：F17 的重试逻辑与 F04 的 owner 合法 unchecked apply 交互，取消快照后遗留 timer/owner，commit 被拒。`8225d784` 显式清除取消状态；C 与修后四轮均 commit=0、confirm=5，非 owner 仍返回6且保留快照。它不属于 v0.3.0 的原有问题，也不重复计入发现数。

独立复核随后发现并核实四个候选边界，分别提交，不当作 v0.3.0 的新增原始缺陷：

| ID | 问题与反例 | 修复与验证 |
|---|---|---|
| C02 / P1 | F18在配置rename成功后ftruncate失败，旧delta尚存，下一次list-add重复；4/4真实CLI syscall注入复现 | `211849e4`先留同目录旧inode备份；清理失败恢复旧配置再报Io，恢复也失败报Unknown并保留备份。四类故障各4轮、同Context4轮、overlay两例、193步C差分及49单测通过 |
| C03 / P1 | F17部分恢复后delta目录只读，owner apply/confirm仍成功清除快照，磁盘与运行面分离；两类各4/4红 | `f23b9c10`回滚一旦开始就拒绝确认/取消，保留timer/快照直到完成；8/8新用例绿，正常pending取消保持 |
| C04 / P2 | F17原子替换丢已有目标uid/gid；apply后故意改变config/delta所有者隔离其它路径，4/4红 | `7cc5a1f2`临时文件先fchown再恢复mode；4/4绿。默认root-owned文件不会显露此边界 |
| C05 / P2 | F17 canonicalize遇悬空symlink时替换链接本身，4/4红 | `18947c60`区分真实不存在与悬空链接；后者保留快照/链接并重试，目标恢复后写入目标；4/4绿 |

C02没有承诺配置与delta任意双故障/掉电原子性：Unknown意味着必须人工恢复，不能盲目重试；硬链接支持成为这条delta提交路径的前提，备份删除失败可留下旧备份，既有flock/rename的并发粒度未改变。C03没有承诺故障期间磁盘与执行面一直一致，而是关闭了“部分回滚后仍成功确认”的窗口。C03–C05的16次定向绿例使用`f55246d8`加最终`uciobj.rs`，尚不含同时进行的UCI修复；最终组合的覆盖另见下方验证结果。

### 对后果和修复的必要限定

- F01/F02 用真实 PID namespace 中的 PID 1 与精确 C 比较。C 能继续启动不等于首次注册失败后每个对象也恢复。候选的核心对象与新对象 watch 已实际验证；没有在物理设备制造 PID1退出。
- F03 是 C/Rust 共同的快照失败边界；新一轮 `rollback:false` 同样需要完整快照，空间不足明确拒绝。F04 的另一会话有 `uci.apply` 方法权限，但没有目标 UCI write 权限；不是匿名请求，也未证明设备默认已配置该角色。
- F07 真实 daemon 在约36.079秒完成挂起trigger超时与重试，期间180个有效DHCPv6响应、最多1个child；退出回收。新策略合并中间变化，35秒后终止进程组，因此合法但超过35秒的脚本也会被终止；脚本自行脱离进程组的后代不在该保证内。F10 修后第3至第4包间隔48.907–58.332秒；已证实RA实际间隔，客户端地址过期的影响仍是协议推断。
- F18 的红例是只读临时目录，原配置可锁定/写入；不是实际overlay ENOSPC或掉电。回归包含失败后同Context重试list-add仅执行一次；fsync错误开始传播，不代表已经做过物理持久性实验。
- F20 实际比较完整已知MD5和ACL拒绝/允许对照，修后 VmHWM 约1132–1136 KiB；没有测物理设备 OOM。F22 累计上限保留原300字段兼容用例；64 KiB限制的是wire请求头，字段结构与UTF-8转换另有有界开销，不等于连接或进程的精确RSS上限；`-N 0`仍可取消连接数上限。C无累计限制仅静态确认，未冒称测过C的内存压力。
- F21 已验证连续5次请求的僵尸累积被消除，没有实测进程表耗尽。新增wait仍依赖passwd自行结束，没有新增慢passwd超时保证。
- F23 四轮 C/Rust 旧实现均不自动补齐TCP。回归验证TCP/UDP分别失败、已有socket inode保留、失败中地址移除及重加、恢复后不反复重建。仅加固DNS缺失协议，未扩展TFTP语义。
- F24 启用scripts和no-scripts各4轮均复现，离线重装原生APK4轮恢复全部hash。没有真实卸载后重启。apk 3.0.5忽略pre-deinstall返回值后继续purge，不能靠一个`exit 1`钩子声称已保护；全局pre-commit也没有供该脚本判断的交易清单。本轮不引入会阻断全部包管理的新策略。[匹配版本实现](https://github.com/alpinelinux/apk-tools/blob/v3.0.5/src/database.c)

- F25 在lease-max=1下先2048次renew暖机，再2048次真实ACK/RELEASE，C/Rust各4轮。512→2048轮RSS增量Rust1144–1148 KiB、C532 KiB；纯状态active=0/deleted=2048，helper只进入1次；释放后继续投递。这是消费者停滞的继承资源边界，不是普通续租泄漏、已发生OOM或默认脚本已挂起。丢事件、停DHCP或强杀脚本各有兼容代价，本轮不借“有界”名义擅自选择。

## P2/P3 与静态边界

已动态复现的低等级问题与源码发现分开说明；后者不计入已复现P0/P1。

| 等级 / 组件 | 依据和具体边界 | 证据 / 状态 |
|---|---|---|
| P2 ubus | convert.rs:31/32/42/48，100000层、800016字节TABLE使Rust两入口4/4 abort、C格式器4/4 segfault；64层正常 | E/ubus-depth-probe.*；仅报告，未证明匿名LAN可达 |
| P2 netifd | reload igmp_snooping 0→1，status/config变但内核属性旧；C正确更新 | E/netifd-systematic/oracle/red-6..9/*bridge_options；四轮复现，仅报告，green-all未包括此例 |
| P2 uci | reorder的18446744073709551617被Rust wrapping，C strtoul饱和，最终顺序不同；普通1一致 | E/uci-systematic及恢复账本；四轮复现，仅报告 |
| P2 fw4 | lib.rs:36–46锁文件open失败变None，调用方仍执行nft；把lock设目录时C4次退出1/零nft，Rust4次退出0/调用nft | E/resume-0823-preserved/reload-fw4/oracle/fw4-lock-results.json；只测记录器，不宣称实际并发损坏 |
| P2 logd | ring.rs:173–181的ID回绕窗口丢历史列表；注入近u32回绕状态时Rust空、C两条，正常对照一致 | E/logd-systematic；4轮模型复现，不是实际写入40亿条日志 |
| P2 platform | netifd.rs:123–140的GSTRINGS仅按caller len验长度；12字节slice后2048字节canary被内核改写 | E/platform-systematic/oracle/gstrings-*；4轮，实际allocation足够；生产caller先查询固定feature表，未证实线上可达 |
| P2 odhcpd | dhcpv6.rs:75，无总长度上限；4096项DNS配置生成65536B option却wire length=0 | D/config-boundary-probe；管理员配置边界，仅报告 |
| P2 procd | instance.rs:566–842顶层类型策略不全；main.rs:1536缺instance.update；trigger.rs:105/171负timeout成49.7天；watchdog.rs:80驱动实际timeout未采纳；jsonscript.rs:79/148忽略include | coverage-parts/procd.md；代码对照，未分别动态注入 |
| P2 netifd | wireless.rs:1210跨vif累计VLAN/STA索引；main.rs:5255的SET_DATA仅保留字符串；wireless.rs:842状态ifname不完整；proto.rs:1324接受0/65..128长度但ip.rs移位依赖1..64 | coverage-parts/netifd.md；静态，未宣称当前Wi-Fi配置受影响 |
| P2 rpcd | session破损freeze UTF8/时间溢出、非法UTF8 SID降None、UCI错误被unload清除、非规范base64 padding、LuCI显式空name过滤 | coverage-parts/rpcd.md；静态，未证明HTTP权限绕过 |
| P2 legacy打包 | logd/httpd/rpcd switch的start本身失败可绕过后续rollback；httpd init缺部分stock参数/证书生成、logd init缺logread实例；verify PIDfile无exe身份校验 | coverage-parts/packaging.md；静态；这些legacy工具不在当前native启动链 |
| P3 rpcd诊断 | --all-targets中lucirpc_profile/rpc_profile/session_acl_profile各2项失败：include的session测试撞上purge_dir故意panic stub | E/resume-0823-preserved/rpcd；正式daemon套件通过，诊断失败照实保留 |
| P3 httpd/logd/CI | httpd日期解析只取函数指针压dead_code；logd合同仍说socketpair；PGO候选workflow仍限制已退役分支 | 日期/CI仅报告；logd合同已用`bca1814f`改为实际pipe |

扫描中的“待复现”还包括内核异常长度、真实I/O错误、极端配置、时钟和慢worker边界，不自动等于缺陷。具体文件和行都在SCAN.tsv，不能把“已分类”解释为这些疑点已证伪。

## 系统覆盖

除dnsmasq外，**12组件180个非测试源/诊断文件、85022行**完成至少函数级通读，I/O、状态机、解析、unsafe相关文件精读。打包/CI原索引55文件6239行逐行读，内嵌postinst/prerm不重复计数；额外精读实际集成器 `tools/native_image.py` 413行。行数包含嵌入的单测，生产函数逐个另有索引。

| 组件 | 文件 / 行 | 精读 / 通读 / 抽读 / 排除 | 扫描：安全 / 确认 / 待复现 |
|---|---:|---|---:|
| dnsmasq | 136 / 88616 | 0 / 87 / 41 / 8 | 6278 / 0 / 2 |
| fw4 | 15 / 7974 | 14 / 1 / 0 / 0 | 290 / 1 / 2 |
| httpd | 9 / 6783 | 8 / 1 / 0 / 0 | 385 / 1 / 0 |
| logd | 3 / 1509 | 3 / 0 / 0 / 0 | 96 / 2 / 2 |
| netifd | 22 / 15585 | 19 / 3 / 0 / 0 | 552 / 0 / 7 |
| odhcpd | 10 / 8567 | 10 / 0 / 0 / 0 | 507 / 3 / 1 |
| packaging/CI | 55 / 6239 | 55 / 0 / 0 / 0 | 0 / 0 / 0 |
| platform | 18 / 1965 | 16 / 2 / 0 / 0 | 204 / 2 / 7 |
| procd | 19 / 10061 | 13 / 6 / 0 / 0 | 450 / 4 / 2 |
| reload-config | 7 / 1441 | 6 / 1 / 0 / 0 | 115 / 0 / 0 |
| rpcd | 36 / 15198 | 32 / 4 / 0 / 0 | 849 / 22 / 11 |
| ubus | 10 / 4945 | 8 / 2 / 0 / 0 | 508 / 4 / 3 |
| ubusd | 16 / 6592 | 11 / 5 / 0 / 0 | 548 / 0 / 0 |
| uci | 15 / 4402 | 12 / 3 / 0 / 0 | 246 / 3 / 1 |

扫描合计：11028条安全、38条待复现、42条已确认问题；全部11108个ID唯一。dnsmasq的136个原索引必读条目中，128个实际生产文件、8个非安装诊断probe；另32个test/fuzz原本不计该文件数。78个核心文件的1643个生产函数全部通读，其余41个生产文件按要求抽读。全dnsmasq生产函数1721完整读、138部分上下文、409未读；这些未完整函数集中在具名抽读文件，不隐藏为“全覆盖”。

全仓扫描固定基线 **11108条**，模式包括unwrap/expect/panic/unreachable/unsafe/忽略返回/ok/整数cast/process exit。按原id/path/line/column/kind/snippet合并校验，未改扫描身份。测试、fuzz、诊断排除均注明准确区间/用途；例如dhcp/logging.rs在test模块后仍有生产函数，未把文件尾一概排除。机械命中数不是缺陷数；无界push_back和阻塞send本来就不会命中这些词法模式。

## 验证结果

最终组合 `211849e4` 在Oracle以 `-Dwarnings`、串行harness运行：**13组件1677 passed / 0 failed / 28 ignored**，另dnsmasq/platform **4 passed**。总计 **1681 passed**。procd/rpcd子进程嵌套harness输出不重复计数。记录在 `E/final1115/results-211849e4/results.json`（Oracle `/home/ubuntu/review-v030-final1115/`）；日志hash全部与该manifest一致。

下表列出各阶段的专项证据；除明确标注最终组合外，不把早期候选的运行身份迁移为 `211849e4`。最终组合的守护进程与故障回归另列在表后。

| 验证 | 实际结果及限度 |
|---|---|
| 组件单测/集成 | platform10、ubus72、uci49、reload20、logd18、httpd61、fw4 19、rpcd62、ubusd58、netifd175、procd89、odhcpd78、dnsmasq966；28个ignored不计通过 |
| 首次独立platform命令 | 因其无独立Cargo.lock，--locked退出101；以父dnsmasq锁作为输入在Oracle离线解析后4项通过；保留失败，不伪称初次全命令exit0 |
| HTTP修复 | 同一musl ELF的4轮字节/字段上下界、前导空行、双64KiB管线及拒绝后关闭均验证；133-case C/旧Rust/候选，candidate_changes=[]、survival_failures=[]；既有22项C分歧保留 |
| DNS监听恢复 | 新netns真实daemon回归、UDP/TCP各冲突跨两次retry、移除重加、健康inode保持；966完整套件通过 |
| UCI / fw4 | 193步UCI字节/状态/元数据差分一致；固定C fw4 golden31/31；第一阶段另300个变异输入含38个C异常退出，不称全为有效规则 |
| netifd系统回归 | 175单测、green-all10/10、R90 22/22；3个新增修复有各4轮C/Rust红绿。bridge属性未修例不藏在绿表里 |
| 实际60秒WAN租约 | C/Rust各70秒，3ACK/1OFFER、同helper、UP 1→71秒、地址/路由事件0字节；仅两个真实续租，非数周设备soak |
| 日志与队列 | logd5场景恢复，健康读者850条、3慢读者淘汰、64流可回收；ubusd实际拥塞拒绝/正常消费/FD比较通过 |
| DNS/DHCP输入 | 第一阶段DNS wire 5219416、DHCPv4 4454013 ASan fuzz输入，DHCPv6 500000结构化变异无panic报告；有限运行，非整体无漏洞证明 |
| 长期/时钟模型 | DHCPv4 150条60秒租约、快进28天/12096000续租；DHCPv6 20160前缀变化/161280请求；DHCPv4六时钟轨迹34状态点C一致；不是28天物理运行 |
| 打包身份门 | 首轮组合的native17测试中16通过、1失败：源码不同于冻结DNS product。后续四个提交未改变DNS源码与冻结manifest，未重新完成发布资格。另CI/PGO/target22项通过。**该失败阻止把修复候选当已资格化发布物，未更新参考hash绕过门** |
| APK与恢复 | 普通卸载4/4删除13路径及备份；no-scripts对照4/4同样；离线重装4/4恢复hash。恢复第1/6/12个rename后TERM，3/3重跑到13项C；不代表掉电原子性 |
| FFI/SDK | Oracle目标ABI断言通过。实验musl重建有既有SDK runas.so/链接器stderr诊断，未冒充正式发布的零警告SDK门；没有重建完整发布镜像 |

最终组合 `211849e4` 的独立回归驱动完成 **22条命令、全部exit 0**，其中20条验证命令、2条构建命令；这22条不重复加进1681项测试计数。结果与ELF身份在 `E/final1115/regressions-211849e4/results.json`，22份日志hash全部吻合。覆盖：

- procd：7个启动故障点、空respawn命令和按钮事件顺序；netifd：协议exec失败、依赖恢复、bridge成员与既有生命周期；odhcpd：547端口释放后主动恢复。
- rpcd：快照失败、owner隔离、MD5内存、passwd回收；恢复测试的10类场景全部通过，包含最终UCI修复组合下的部分回滚后apply/confirm拒绝、uid/gid、悬空链接，以及健康owner取消。C03–C05各一轮最终组合验证，与此前各四轮定向红绿分开记录。
- reload-config：满syslog队列；dnsmasq：UDP/TCP半缺监听重试；UCI：正常、清delta失败、安装rename失败、恢复rename也失败四类各4轮，共16/16通过。

同Context重试4轮、overlay正常/注入两例和193步C差分另见 `E/final-review-followup/uci-oracle/`；这些是UCI定向验证，相关源文件hash与最终组合一致，不将其扩写成整棵源码已在物理overlay上验收。193步差分的原始stdout/stderr/退出码已重新逐项比较，全部一致；该早期运行未记录当时ELF的hash，因此不把它计作最终ELF身份验证。最终证据汇总见 `E/FINAL_VALIDATION_211849e4.md`。

失败或无效夹具均保留：HTTP首次缺目标CC/首次C rootfs权限失败；dnsmasq未设私有TMPDIR时PID namespace同名FIFO冲突，改用私有TMPDIR后完整通过；reload日志实验前两版未填满接收队列；首轮60秒WAN拓扑被netifd清理。仅使用有阳性控制、真实字段比较的有效运行；未删失败输入或把旧产物充作新构建。

## 历史去重与独立复核

- F01/F02：未找到同一初始注册/exec无child反例；F01有先前未提交候选，本次独立反例成立后接续。运行期恢复结论不能覆盖启动期。
- F03/F04/F05/F06/F11/F12：分别为已知C快照语义的新ENOSPC后果、已知purge-before-check的HTTP跨会话后果、先前“释放并notify”之外的主动重试缺口、已知DUMP_INTR、C共同队列弱点的新证据、已知迟到reply pending。不会全部标为首次发现。
- F07–F10、F13–F15、F17–F23：本轮复现；关键词去重未发现同条件有效证据，或为旧范围之外的补证。F16承接中断会话的实际红绿记录。C01–C05仅候选回归，不计入v0.3.0原始发现数。
- F25：先前AUDIT_FIX4只把慢脚本背压列为未覆盖，本轮补出删除队列在单活跃租约下增长的C/Rust证据。
- F24：既有文档明确native APK不是live升级工具，本次新增普通卸载会同时丢失恢复集合的实证并补明“不要卸载”；没有推翻完整sysupgrade门。
- 各静态P2历史归属未全量核对；不把只读代码的新疑点宣传为已确认线上新缺陷。

全新复核者仅收到本报告与累计diff，没有原始日志、额外源码或历史结论。它保留F01/F02的条件性P0，要求收窄触发范围与资源/设备保证，并指出C02–C05。根代理随后在Oracle复现、分别修复；同一复核者只看新增diff与结果摘要，补充裁决“原反馈已由新控制流解决，未见可以从diff确定的新阻断”。这不是第三方重新运行原始实验。

复核原文：`E/FINAL_INDEPENDENT_REVIEW_1115.md`、`E/FINAL_INDEPENDENT_REVIEW_1115_ADDENDUM.md`；跟进红绿、源码与ELF身份：`E/final-review-followup/`。报告保留了35秒trigger语义、HTTP wire上限不等于RSS精确上限、passwd未新增超时、F24不支持操作、F25未修等限制。

## 具体未覆盖与下一步裁决

没有未读的非dnsmasq必读源文件。dnsmasq其余抽读文件、准确函数范围和残余疑点由分账本逐一列明，见下方；配置与诊断抽读不冒充所有parser组合全验收。

dnsmasq抽读范围（下表以外的核心生产模块已完整通读；每函数状态另见`E/dnsmasq-systematic/functions.tsv`）：

| 文件 | 实际阅读行段 |
|---|---|
| components/dnsmasq/src/config/auth.rs | 81–87 |
| components/dnsmasq/src/config/dhcp.rs | 1–52, 168–178, 274–284, 315–326, 479–489, 529–545 |
| components/dnsmasq/src/config/dhcp_host.rs | 8–18, 35–88, 120–130 |
| components/dnsmasq/src/config/dhcp_network.rs | 55–66, 102–112 |
| components/dnsmasq/src/config/dhcp_options.rs | 351–361, 391–401, 485–510, 531–560, 570–589, 596–608, 637–647, 652–662 |
| components/dnsmasq/src/config/dhcp_pxe.rs | 58–70, 77–98, 147–157, 181–191 |
| components/dnsmasq/src/config/dhcp_relay.rs | 43–53, 99–109 |
| components/dnsmasq/src/config/dhcp_tags.rs | 1–140 |
| components/dnsmasq/src/config/dns.rs | 18–28, 243–267, 292–302, 457–467, 518–533, 595–639, 644–654, 663–698, 701–711, 763–773, 791–801, 820–830, 833–843 |
| components/dnsmasq/src/config/domains.rs | 12–22 |
| components/dnsmasq/src/config/dump.rs | 70–80, 85–97 |
| components/dnsmasq/src/config/edns.rs | 56–67, 128–150 |
| components/dnsmasq/src/config/ethers.rs | 217–227, 380–405 |
| components/dnsmasq/src/config/interface_records.rs | 17–27, 98–108 |
| components/dnsmasq/src/config/loader.rs | 335–367, 375–410, 428–463 |
| components/dnsmasq/src/config/logging.rs | 67–77 |
| components/dnsmasq/src/config/mod.rs | 89–99, 217–227, 263–273 |
| components/dnsmasq/src/config/options.rs | 1–22 |
| components/dnsmasq/src/config/records.rs | 107–117, 147–157, 249–259, 261–273 |
| components/dnsmasq/src/config/rrtypes.rs | 15–25 |
| components/dnsmasq/src/config/scalar.rs | 71–82, 88–102, 118–132, 161–175, 205–215 |
| components/dnsmasq/src/config/synth_domain.rs | 28–49, 58–68, 79–91, 181–195, 227–242, 276–287, 294–304 |
| components/dnsmasq/src/config/tftp.rs | 66–76, 113–123, 206–216, 255–281 |
| components/dnsmasq/src/dns/interface_records.rs | 46–60, 73–92 |
| components/dnsmasq/src/dns/local.rs | 520–534, 833–847, 849–863, 876–890, 969–983, 1051–1065, 1088–1102, 1476–1490, 1593–1608, 1670–1753, 3381–3396 |
| components/dnsmasq/src/dns/loop_detect.rs | 57–104, 110–124 |
| components/dnsmasq/src/dump.rs | 50–95, 136–155, 201–218, 259–282, 287–324, 326–344 |
| components/dnsmasq/src/hosts.rs | 7–21, 102–116, 161–186, 274–288, 345–390, 857–871, 914–928, 945–964, 1060–1109, 1260–1326, 1410–1458, 1535–1549, 1575–1589, 1714–1729 |
| components/dnsmasq/src/interfaces.rs | 61–75, 108–122, 140–158 |
| components/dnsmasq/src/interfaces_broadcast.rs | 107–121 |
| components/dnsmasq/src/interfaces_ipv4.rs | 191–205, 212–226, 255–269, 275–299, 315–355 |
| components/dnsmasq/src/lib.rs | 1–14 |
| components/dnsmasq/src/listeners.rs | 18–32, 259–273, 437–451, 474–488 |
| components/dnsmasq/src/logging.rs | 14–28, 296–325, 329–357, 386–400, 461–484, 692–749, 1003–1015 |
| components/dnsmasq/src/logging/query.rs | 99–127, 203–220 |
| components/dnsmasq/src/logging/startup.rs | 1–70 |
| components/dnsmasq/src/neighbors.rs | 213–227, 433–469, 488–523, 541–580 |
| components/dnsmasq/src/net.rs | 63–79, 152–174, 225–239, 269–283, 305–319, 508–522, 528–542, 604–639 |
| components/dnsmasq/src/sorting.rs | 12–26 |
| components/dnsmasq/src/startup.rs | 156–170, 190–204, 226–240, 287–301, 373–389 |
| components/dnsmasq/src/startup/daemonize.rs | 86–100, 115–139, 185–201 |

上游C按对应入口与关键路径核对；尤其DNS缓存/上游大函数没有全部展开，其确切C阅读区间见`E/dnsmasq-systematic/remaining-notes.md`。不声称C内部也已全文审计。

已经读过但仍未动态验证：procd的物理PID1/watchdog/冷启动掉电；netifd `wireless.rs`/`ip.rs`的实际MT7981驱动及非法PD长度；rpcd `session.rs`破损freeze、`rtnl.rs`异常kernel边界、`iwinfo`全驱动状态；odhcpd `main.rs:990`满8槽队列丢Refresh；uci `parse.rs`中途read错误；fw4 `reload.rs`真实内核缓存竞态及`val.rs`极端mask；logd `main.rs`真实kmsg故障；platform每一syscall errno及多线程fork复用。打包未做 `ci_build_image.sh`/`ci_integrate_image.sh`完整重建、实际overlay恢复掉电、APK升级中断和全部legacy switch失败分支；依赖 `tools/dnsmasq/build_package.py`只跟踪了集成接口，没有全量重审其内部。

当前模型是：主要风险来自**依赖/子进程/存储发生局部失败后，进程仍存活却失去继续推进的事件**，以及**容量限制只覆盖一个容器，未覆盖旁路队列或整个请求**。默认路径C等价、正常测试通过和RSS短时平稳都不能排除它们。下一步最有价值的是设备上验证启动与回滚的完整恢复链、慢helper时的有界事件策略、数周自然WAN/租约观察；不是继续省几条指令。

## 待单独授权的设备验证

本轮没有执行。共同前提是离线备份可读、实际镜像/ELF身份核对、自动回滚经过演练、客户端持续观察DNS/IPv4/IPv6/SSH/Wi-Fi。Wi-Fi管理允许，不把LAN网线列为前提。

| 验证 | 风险和恢复办法 |
|---|---|
| 修复镜像冷启动/重启/断电 | 早期PID1故障可同时失去SSH，普通rcS后guard不足；先验证failsafe/TFTP、保留已知镜像与配置，启动超时回原镜像 |
| ubusd消失/重启、全部组件重新订阅 | 控制面暂时不可达；外部/独立guard恢复完整程序集合与启动顺序，客户端未恢复不确认 |
| odhcpd 547冲突、DNS部分监听冲突 | 窗口内DHCPv6或部分DNS无回复；停止注入后核对自动补建与旧客户端，失败恢复原ELF/init或已知镜像 |
| LuCI apply/confirm/rollback与空间错误 | 误操作network/wireless会失联；使用隔离测试包/受限目录，不填满全机/tmp；逐包备份和外部guard |
| 完整C恢复与中途掉电 | 文件组不是原子切换；先核对完整13项备份和救援通道；恢复完成前不重启，不以APK卸载回滚 |
| WAN6频繁变化、真实60秒租约长期观察 | 只读自然观察与主动抖动分开；需要注入时另授权，备份配置、停止注入并自动恢复；不能从短窗口推断数周 |

修复分支没有更新任何冻结发布ELF资格。下一次发布必须重新通过实际SDK、完整镜像、自动回滚和客户端验收。
