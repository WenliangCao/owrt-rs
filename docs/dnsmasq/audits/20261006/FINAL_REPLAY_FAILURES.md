# M5 统一回归失败索引

本次实际冻结为`12b3ecfac9e764d0820a912f15056318546374d3`，ELF `80a7213277fd8e71ca1687ea63007493c327460ae86acc3d2ae8159d7107dc1c`，1,929,256B。706库＋10main实际通过，20ignored不计。首轮44族/68命令已有23族登记完整通过；12族红、9族尚未执行。本表保存失败归因和修复身份，均不替代新freeze的实际完整资格。

| 族/阶段 | 实际失败 | 处置与下一验证 |
| --- | --- | --- |
| logging-all / listeners / lease-recovery | 深运行路径使host AF_UNIX bind超过sun_path108；logging154基础设施异常、listeners32/side、lease70异常及RO清理cascade。 | `a851e54e`以live目录FD的`/proc/self/fd/N/basename`绑定，短路径原样；`32c575e2`接lease receiver。Oracle DGRAM/STREAM真实长路径阳性，完整族须fresh重跑。 |
| cli-log-malloc | malloc syslog长路径使两侧14/15；结尾访问已迁移plan字段KeyError。 | `7b3a45da`使用shared binder并迁移extreme_disposition；真实264B路径收发/cleanup通过。 |
| cli-test | 两侧345case完整、0missing/failure，qualifier访问known_deferred抛KeyError。 | `7b3a45da`字段修复；旧345原rows诊断qualify通过，不能算新formal运行。 |
| script-ARP | ptrace之前向trace传packet_builder，冻结helper未接该参数而TypeError。 | `ea9de186`恢复可选参数；默认EDNS行为保持，全ARP须fresh。 |
| DHCP tags/options | legacy--bad-masked-mac两侧exit1，C通用error、Rust bad hex constant。 | `5f5700ab`仅在DhcpMac caller将parse_hardware失败映射通用error，来源option.c4541–4554；不改共享hex。现有MAC mask/type单元通过，完整syntax/runtime待新ELF。 |
| helper / helper-shutdown | Rust-only DNS-during-init .8s要求重复失败。 | exact-image C和Rust配对诊断都init期间0DNS/无PID，约2.008s结束后即答复，恢复2old callbacks、正常exit0。C dnsmasq.c300–311/lease.c180–195也先init后socket；`67c3b128`修对称夹具，8负控有效；完整族待新freeze。 |
| logging foreground-relative-paths | full sequence存了Rust[capture,capture]而Cnull；短路径独立case通过。 | 测试器在ready exchange之前缓存proc_state，Rust可在稍后dup2完成后才答ready；`a3ef6372`改ready之后刷新状态，6配对diagnostic通过，保留原失败。 |
| loop90 | wrong-type upstream count红；class-any首轮红但最小重复通过。 | 严格owned syscall证明C先UDP/TCPbind后probe，Rustprobe早455μs/4.488ms；barrier后type18两侧实际forward/reply一致。真实启动接线race，dns-loop-detect重开；main初始check移到allbind之后且同步parent.local.config，保留sourcepool预分配，待新ELF完整族复跑。 |
| cache536 | 仅ptr-tcp-child-import / round-reverse-disabled cached TTL600对599；其它数据与真实upstream1一致。 | 0e4e78ed/195b20e8添加wall/monotonic有序且<900ms、两clock偏差≤5ms witness；仅两个fresh PTR600案例按实测整数floor计算599/600，缺clock/time-step/slow与TTL腐败负控仍拒绝，其他TTL严格。两侧真实probe都seed600/下一秒599，有15 controls；新freeze完整536待fresh。C PTR hash variation有8独立bank阳性，同进程repeat严格。 |
| relay174 | ordinary-reply arp-failure首轮C1/R0；选中15重跑转C0/R0，其他latepositive反转。 | 实际ip events/逐行snapshot与recv/send/ioctl witness定位自动IPv6 tentative→ready NEWADDR清认证relay状态。77080ea5仅禁IPv4fixture未来veth的自动LL生成，IPv6协议与故意地址generation场景保留；普通15两侧全wire/count相同，arp-failure两侧SIOCSARP=-EINVAL后send244B/downstream1。完整37/174重跑DAD缺包消失，出现actor跨FD假顺序；sender syscall与kernel入队两侧均1067→67/244B，35553f9f按SO_TIMESTAMPNS实际次序重建并独立重构校验，全部wire/count/source/dest不放宽；TS完整族复跑进行中。 |
| M2 | 7DNS＋4DHCPprofile通过；lifecycle-C exit1，Rust lifecycle未执行。 | 确认漏接actual_config_network.py；`830e1951`补br-lan/client/upstream实际namespace拓扑。C3.34s/R9.12s完整init/HUP/UCI/odhcpd/stop诊断通过，full archive002ec15d…f69e的91条metadata/54files核验后prune。新freeze完整M2须fresh。 |
| endpoint本地归档门 | syntax完整本地SHA+metadata与prune成功，scp proof到root parent权限失败；formal controller仍等待。 | 已有syntax proof不重打包；中转sudo安装、service首次pack本地核验/prune/plain恢复完成，门与191/191源行audit实际通过。 |

冻结source/tools没有原地修改。所有修复仅进入main及新的完整source archive。原失败、控制器命令、JSON和原始overlay已full-fidelity归档；核验SHA、类型、mode、uid/gid、nsmtime、symlink、deviceID、xattrs后才prune，原lockedJSON保留供后置门重新核验。旧绿不替代最终候选fresh结果。三个native instrumented fuzz当前仅build，90分钟实际窗口尚未完成；mixed/full-cache300s、ENOSPC/EMFILE、APK与生命周期尚未执行。物理路由器未触碰。

## 最终同ELF收尾与复跑

产品源码dc1b740d、ELF37f85d22…7f7b固定为1,929,256B；706库＋10main实际通过，20ignored不计。dc1b首次44族实际36通过/8夹具失败；tools-only6fb65冻结后44族fresh，43通过，仅日志fastretry需再修时序。修复工具与原产品分别有git archive/manifest，未改原源码/ELF。6d572edf单族修订保留整个6fb默认tree、每个原始receipt/projection/command/源和ELF身份，严格导入43不受影响绿与实际M2/fuzz，仅logging-all-scopes新tree全329重跑；34真实Git/进程负控通过。

| 新失败 | 实际因果与修复 | 复跑状态 |
| --- | --- | --- |
| local-service-bare TCP close errno | legacy探针不控制发送/accept入队，首次C reset104、Rust EOF；2e4a0da0把原16个deniedTCP输入改为实际SIGSTOP/完整RX41再resume，UDP/ID/count保持，仍强制104/reset而无宽容。 | bare18与4场景72actual通过；6fb完整next矩阵通过。 |
| scoped IPv6 local C校准 | global`::1%lo` UDP reply实际scope0，C util.c360–373要求与配置scope1相等；两侧都timeout，TCP均正常。旧C预期误写UDP response。 | 明确Ctimeout预期且要求实际upstream query+reply证据，完整third矩阵通过；属于共同C行为，不是故意差异。 |
| tag-if/local资格元数据 | old qualification_ready/eligible/known-gap保留了已实现完整族之前的状态，actual全cases0差异却仍拒绝闭合。 | 不删case/checks/inventory，校正元数据后完整tag-if/third通过。 |
| PXE/日志companion | shared actor新增received_ns被旧PXE evaluator当wire；companion旧sort还破坏真实kernel序。 | 4cb793af保留原raw/时钟界限/per-side重构，C/R仅剔received_ns且全包/endpoint/flags/count/order严格；完整PXE61syntax/260packet与companion50＋7actual通过。 |
| listeners长Unix路径 | fault helper自己的Syslog仍直接bind，路径156B导致32/side运行异常。 | a2ac99ac接shared helper；185/191B实际37observations＋3controls通过，6fb完整163/side、3534observations、130controls通过。 |
| ARP三Rust故障caller缺asset | allocator-map参数未从同次冻结link.map传入，75/78有效但三行未执行。 | 8f108609只加map绑定；6fb78/side、9controls通过，实际三calloc/realloc/helper-frame故障及恢复均到达，不恢复globalalloc。 |
| cache八整秒相位 | measuredwall/mono准确解释600/599、retained598/597、lease119/120；不是TTL内容/取值错误。 | 7b5c6ca1双侧真实phase0.2后仍保持原严格TTL/controls；536/536、1823controls和caller9全部通过，新8独立C reversebank保留。 |
| logging fastretry最后一例 | fixed .12s reply在C实际retry之前到达，C只有1upstream/Rust2；必需Cproducer与control正确拒绝。 | 8a9f09a5有界等真实第二个相同request后才释放唯一reply；三模式actualC/R日志/wire/count/clock全过、8mutation及真实UDP守卫有效；6d572edf全329正在fresh。 |
| 本地SSH延迟返回 | 远端M2/fuzz-build已完成并发布原锁定PASS，SSH通道仍等EOF。 | 独立重新读取原SHA/metadata/result/完成表，终止只剩本地通道，实际fuzz用独立通道启动；不把SSH255当daemon失败或漏跑。 |

实际fuzz三入口分别1801.3236/1801.2717/1801.4702秒，返回0、无artifact，共超过90target-minutes；native instrumented来自同一源，明确不同于交付musl ELF。两次实际完整M2均通过（7DNS、4DHCP、C/R init/HUP/UCI/odhcpd/stop）。旧失败不覆盖，全部raw完整SHA/mode/uid/gid/nsmtime/link/device/xattr本地核验后prune，锁定JSON恢复并再次核SHA。资源/压力/APK与最终报告继续，未操作物理路由器或M6正式性能。


## 资源、压力与取消清理：最终失败索引

以下补记只读核对本地证据，不修改任何旧失败。产品源码仍为 `dc1b740d7973838e2ae7f098d0726b0484e55074`，交付 ELF 仍为 `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b`，1,929,256B。9684 修订 manifest 为 `8da6dcf43dc585af54ffa89bf120dfc1b29d70ab0d9bec18469a09c1192a058f`。表内每份 archive 的 SHA 已与本地完整 metadata verification、prune receipt 相等，保留的 controller JSON 也与原 archive manifest 相等。

| 阶段与实际 attempt | 失败归因或成功范围 | 状态 | 原始本地证据 |
| --- | --- | --- | --- |
| resources / 6d572 / attempt 1 | 启动时window-before为空，随后独立日志query-phase诊断进入同一主机；exclusive门正确拒绝。取消pair留下不同session的C/R namespace worker。 | 拒绝，不能计为资源窗口 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-1/archive.tar.gz) · [原controller](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-1/plain/result.json) · [完整核验](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-1/local-verification.json) · [prune](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-1/prune.json) |
| resources / 6d572 / attempt 2 | 启动前发现attempt 1残留PID3702983/3702984及其init/daemon；commands为空，未执行任何新资源job。 | 正确拒绝，保留原结果 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-2/archive.tar.gz) · [原controller](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-2/plain/result.json) · [完整核验](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-2/local-verification.json) · [prune](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-2/prune.json) |
| resources / 6d572 / attempt 3 | 清场后两侧mixed及full-cache实际完整运行；controller分别305.0733s、356.8073s；两job accepted=true。 | PASS，原attempt 1/2不覆盖 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-final/archive.tar.gz) · [原controller](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-final/plain/result.json) · [完整核验](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-final/local-verification.json) · [prune](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-final/prune.json) |
| pressure / 6d572 / attempt 1 | argv漏接run_isolated.sh，0.09298s即exit 1，未进入要求的隔离namespace。5db5f049只补实际隔离接线。 | 夹具失败，保留原失败 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-missing-namespace/archive.tar.gz) · [原controller](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-missing-namespace/plain/result.json) · [完整核验](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-missing-namespace/local-verification.json) · [prune](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-missing-namespace/prune.json) |
| pressure / cbbe565 / attempt 1 | 补namespace后，关系快照与进程扫描之间出生的本job worker PID3712580被误判foreign；controller中断并清场。 | 夹具竞态，保留原失败 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-born-race/archive.tar.gz) · [原controller](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-born-race/plain/result.json) · [完整核验](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-born-race/local-verification.json) · [prune](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-born-race/prune.json) |
| pressure / 9684b010 / attempt 1 | 9684b010在初次busy之后再取真实ancestry快照，仅剔除确认属于本job的候选；真正foreign仍拒绝。ENOSPC/EMFILE两侧故障及恢复相同。 | PASS：有界故障/恢复，不称300s实际暴露 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-final/archive.tar.gz) · [原controller](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-final/plain/result.json) · [完整核验](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-final/local-verification.json) · [prune](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-final/prune.json) |

压力 controller 实际耗时 122.1653s，leaf 实际耗时 122.063s；`duration_note` 明确 300s 是每侧 deadline，并非实测故障暴露时长。ENOSPC 两侧均填满16,384B、满盘期间 ACK但无持久lease，恢复分别60.046s/60.042s；EMFILE实际触发，两侧均恢复47B/ID3201回复。该有界检查 `accepted=true`，不据此补写五分钟持续压力或M6性能资格。[压力原leaf](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-final/plain/enospc-emfile/result.json)。

取消清理原先只停止parent PGID，不能覆盖pair新建session的namespace workers。`5a2f476a`改controller记录本job及其descendant的PID/starttime，在TERM前及运行期间记录，停止时重新检查generation，跨session清理；默认6fb producer不变，也未将该后来工具修复回写为9684压力的生产资格。[真实guard/cleanup证据](/Users/USER/Developer/owrt-control-plane-rs/docs/dnsmasq/audits/20261006/controller-window-cleanup-proof-37f8.json)记录：guard两项实际测试接受出生于首快照之后的owned namespace child、拒绝真实foreign sibling；cleanup三项实际测试停止分离PGID及namespace workers、保留foreign sibling、拒绝错误PID generation。[guard完整archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-window-guard-20261006/proof-01.tar.gz) · [cleanup完整archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-job-cleanup-20261006/proof-01.tar.gz)。

## APK 原预算失败与生命周期资格

package attempt 1 的builder return 1，`status=failed`且仅`failure_boundary=size-target`；artifact身份核验、SDK recipe恢复均为true。APK为1,065,071B，原APK预算700,000B；ELF为1,929,256B，原ELF预算1,000,000B，两项budget_checks均false。Controller只保留同ELF的reviewable artifact并记录`pending-user-after-report`以继续隔离lifecycle，**未通过体积预算，也没有新增用户例外**。[原package manifest](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-9684b010256f/package-manifest.json) · [原package controller log](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-9684b010256f/package-controller-attempt-1.log)。

lifecycle attempt 1 实际return 0、status passed，完成8个安装/升级/重装/卸载/回滚/downgrade stages、实际变体互斥及cleanup；`cleanup.errors=[]`、`remaining_children=[]`，候选ELF SHA仍为37f85…7f7b。该资格与package预算失败分别保留，不能相互代替。[原lifecycle结果](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-9684b010256f/lifecycle-result.json) · [原lifecycle controller log](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-9684b010256f/lifecycle-controller-attempt-1.log)。Package/lifecycle整组归档及最终summary由Root处理；此索引不改变report或ledger，不称物理部署或M7验收。

## 最后归档恢复的基础设施错误

Selective tar恢复同时传了根目录和子路径，默认递归先恢复整树，之后重叠条目报Notfound/exit 2；原失败log保留。Root复核完整已恢复package树inventory与原manifest完全相等后，重新prune，以`--no-recursion`精确恢复所需JSON/log/APK；retry成功，两阶段`retained_full_metadata_verified=true`。此错误未改变产物或receipt bytes/metadata；不覆盖原失败，也不以该错误重跑功能。最终所有44族/8phase后置门由Root再次检查。[原失败log](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-9684b010256f/package-lifecycle-prune.log) · [retry log](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-9684b010256f/package-lifecycle-prune-retry.log) · [package原archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-package-final/archive.tar.gz) · [lifecycle原archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-lifecycle-final/archive.tar.gz) · [package prune](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-package-final/prune.json) · [lifecycle prune](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-lifecycle-final/prune.json)。

## 首轮失败 archive 定位补充

早先表中的“待fresh”属于当时快照；原始失败与后来绿分开保留。以下是具体本地完整archive入口，不使用诊断绿覆盖原失败。

| 原失败/阻塞 | 完整本地archive |
| --- | --- |
| logging长路径 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-logging-families/group-6fde0e8ca2c6-attempt-1.tar.gz) |
| cli-test | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-logging-families/group-216c52944de8-attempt-1.tar.gz) |
| cli-log-malloc | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-logging-families/group-240135ba79bc-attempt-1.tar.gz) |
| helper-init | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-logging-families/group-32a247874303-attempt-2.tar.gz) |
| helper-shutdown | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-logging-families/group-9da9f32c7dd8-attempt-1.tar.gz) |
| lease-recovery | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-logging-families/group-bd1d9a68437c-attempt-1.tar.gz) |
| foreground-file repro | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-logging-families/foreground-file-repro-attempt-1.tar.gz) |
| loop90 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-families/loop-detect-attempt-1.tar.gz) |
| cache536 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-families/m5_dns_cache-attempt-1.tar.gz) |
| listeners | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-families/m5_listeners-attempt-1.tar.gz) |
| endpoint归档门阻塞及恢复 | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-12b3-families/m5_dns_endpoints-attempt-1.tar.gz) |
| DHCP tags/options | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-fresh-12b3/dhcp-tags-options-8b7d-failed.tar.gz) |
| script-ARP | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-fresh-12b3/m5_script_arp-31937a72629a-failed.tar.gz) |
| relay | [archive](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M5/final-fresh-12b3/m5_relay-bd7e76db9883-failed.tar.gz) |

## 任务树退休：只读快照与保留门

审计基准为 main `129fc8f28a5f1405ffa718f890f95140b25c3c0c`，2026-10-06：54个worktrees，13个有branch、41个detached；10个有tracked/untracked变化（含Root用户prompts）。没有删除worktree/branch，没有创建退休ref；Git命令使用`GIT_OPTIONAL_LOCKS=0`。任务是否仍活跃由Root确认，clean不等于已退休。Root、自树、logging活跃树、TFTP/报告树保留；历史/未知detached本轮不删。

`git cherry` 的“+”只说明patch未匹配main，不推断它应进入最终产品。已有持久ref保留整条原始历史；缺ref的树退休前须先保存完整tip，dirty还须保存binary diff和全部untracked原文件及SHA。Git ref不覆盖ignored `private/`证据：含此目录的树先核验独立完整备份，不能把build cache或任务branch当证据备份。

| M5任务tree/branch | tip | 未匹配patch数 | 当前working tree | 已有持久tip ref / 退休前动作 |
| --- | --- | --- | --- | --- |
| `m5-device-binding` / `m5/device-binding` | `eac4985114b819d31eb9fa216ac6f2f95cb4f63e` | 1 | clean | `refs/archive/dnsmasq/M5-device-binding-20261006`；`refs/evidence/m5-device-binding-20261006` |
| `m5-endpoint-closeout` / `m5/endpoint-closeout` | `869d6e7d3bd6f76072d7f9657895658ec715f57c` | 0 | clean | `refs/archive/dnsmasq/M5-endpoint-closeout-20261006`；`refs/evidence/dnsmasq/M5-endpoint-extreme-closeout-20261006` |
| `m5-final-registry-recovery` / `m5/final-registry-recovery` | `69594f6771866e5a7c3e0bc82b4bf62f44b0dd41` | 0 | clean | 保留当前任务树；退休前新建`refs/archive/dnsmasq/task-retirement-20261006/m5-final-registry-recovery`，指向完整tip |
| `m5-final-validation-prep` / `m5/final-validation-prep` | `16aacf2bdaa82f1a7815ba6c33924cbde36647db` | 0 | dirty: 6paths | 先保存working patch/untracked；退休前新建`refs/archive/dnsmasq/task-retirement-20261006/m5-final-validation-prep`，指向完整tip |
| `m5-fixture-revision-tests` / `m5/fixture-revision-tests` | `1ba8c90540b752f9bd925d75b937d2364b13490e` | 0 | dirty: 2paths | 先保存working patch/untracked；退休前新建`refs/archive/dnsmasq/task-retirement-20261006/m5-fixture-revision-tests`，指向完整tip |
| `m5-interface-records` / `m5/interface-records` | `85c2953a508fcbd806cb203a5db587d71ff8552d` | 72 | dirty: 1paths | 先保存working patch/untracked；`refs/archive/dnsmasq/M5-interface-interrupted-20261006` |
| `m5-logging-cli-repair` / `m5/logging-cli-repair` | `113d41ec1c5a99d73645a0c9d297994c736d5e92` | 0 | clean | 保留当前任务树；退休前新建`refs/archive/dnsmasq/task-retirement-20261006/m5-logging-cli-repair`，指向完整tip |
| `m5-logging-contract` / `m5/logging-contract` | `fac7bc56eff37869318c375c62c41550f03b60dd` | 108 | clean；有ignored private证据 | 保留当前任务树；退休前新建`refs/archive/dnsmasq/task-retirement-20261006/m5-logging-contract`，指向完整tip |
| `m5-logging-fastretry-fixture` / `m5/logging-fastretry-fixture` | `58e390fa2f58d1c2f4576ae97a2bcdd5543a8e8c` | 0 | clean | 保留当前任务树；退休前新建`refs/archive/dnsmasq/task-retirement-20261006/m5-logging-fastretry-fixture`，指向完整tip |
| `m5-logging-health-repair` / `m5/logging-health-repair` | `7fbd2a89528fd93bdc0cf7ee90c9c2a8ac2b9de5` | 0 | clean | 保留当前任务树；退休前新建`refs/archive/dnsmasq/task-retirement-20261006/m5-logging-health-repair`，指向完整tip |
| `m5-report-draft` / `m5/report-draft` | `9667ce240042546129c7348009453c93b055401d` | 2 | clean | 保留当前任务树；退休前新建`refs/archive/dnsmasq/task-retirement-20261006/m5-report-draft`，指向完整tip |
| `m5-tftp-closeout` / `m5/tftp-closeout` | `5a1a0ba2230ef54e485038120ff67f6af45ddaa5` | 0 | clean | 保留当前任务树；`refs/archive/dnsmasq/M5-tftp-closeout-20261006`；`refs/evidence/dnsmasq/M5-tftp-closeout-20261006` |

明确可条件退休的非活跃M5候选：`m5-endpoint-closeout`（clean、无ignored证据、持久refs已有）；`m5-final-validation-prep`与`m5-fixture-revision-tests`（patch-equivalent，但dirty工具必须先完整保存）；`m5-device-binding`与`m5-interface-records`已有持久ref，但其ignored目录或dirty内容仍须先保留。全部logging树保守保留，避免在最后日志任务活跃时误删。

| dirty树：必须保留的本地内容 | binary diff SHA256（HEAD→working tree） |
| --- | --- |
| `/private/tmp/patchcheck2.yRud`：`components/dnsmasq/src/config/dns.rs`, `components/dnsmasq/src/dns/local.rs` | `a599b2a0294ed0d2424042d1a370c0047027e2d71991b168545702a191b7c0de` |
| `/private/tmp/patchcheck3.YLwj`：`components/dnsmasq/src/config/dns.rs`, `components/dnsmasq/src/dns/local.rs` | `cb5c636a0fa6f02b7f20236d7beb7c13b8ea3fc24190680f78b65227687c4893` |
| `/private/tmp/patchcheck4.YjQQ`：`components/dnsmasq/src/config/dns.rs`, `components/dnsmasq/src/dns/local.rs` | `cb5c636a0fa6f02b7f20236d7beb7c13b8ea3fc24190680f78b65227687c4893` |
| `/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/resume-send-retry-20261001`：`shared-upstream-before-integration.rs`, `upstream-draft.patch` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/stale-work`：`components/dnsmasq/src/dns/daemon.rs`, `components/dnsmasq/src/dns/daemon_cache_tests.rs`, `components/dnsmasq/src/main.rs`, `tools/dnsmasq/dns_stale_refresh_diff.py`, `components/dnsmasq/src/dns/daemon_stale_tests.rs` | `45d361309cccc3dd02471a57feee40d54bf71896a949011503649c3554125f6e` |
| `/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/worktrees/m5-final-validation-prep`：`tools/dnsmasq/m5_final_families.draft.json`, `tools/dnsmasq/m5_final_validation.py`, `tools/dnsmasq/m5_interface_records.json`, `tools/dnsmasq/m5_interface_records.py`, `tools/dnsmasq/test_m5_final_validation.py`, `tools/dnsmasq/m5_interface_records_qualify.py` | `2b79a5e3c0ac841e17cfe690d447f97c0afc61e2bb28898e97ab6dd952b12e86` |
| `/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/worktrees/m5-fixture-revision-tests`：`tools/dnsmasq/m5_final_validation.py`, `tools/dnsmasq/m5_fixture_revision.py` | `0fabceb8eb51495e2c988117eb401d836cf2840523d048e21dd2e06ec02bef85` |
| `/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/worktrees/m5-interface-records`：`components/dnsmasq/src/config/synth_domain.rs` | `e3b2cc890a155a2134c5c1527aea063dcd1dd6700ea3292cdea547a84418043b` |
| `/Users/USER/Developer/owrt-m2-integration`：`tools/dnsmasq/m2_lifecycle.py` | `055d5ae05060c7d904bcee325b8b51275a91d54a35721f646b90c1e69309febc` |

其中`resume-send-retry-20261001`的两个untracked文件SHA分别为`5af7d9b0ad13869de1e50154c3804681f9697b55e7d2da7555ce58215f7c31ad`（shared-upstream-before-integration.rs）、`473b2256c6638f0b5b4558497d956c6039d309fadb3b37785ca144f0dc40d42d`（upstream-draft.patch）。`patchcheck2`与`patchcheck3/4`的diff SHA不同，不能按目录名或base相同就合并丢弃。Root的所有`docs/prompts`修改/未跟踪文件原样保留。

## 随后获授权的三个 M5 任务树退休回执

Root随后明确授权清理已退休M5树，要求保留当前Root/本任务/logging/TFTP/报告树、历史detached及未知dirty工作。仅清理以下三个已结束旧树及同名task branch，54个worktrees降至51。首次保守预检发现ignored pyc缓存即停止、未删树；retry将这些缓存也全部保全。未访问Oracle，未改产品、report、ledger或用户prompts。

| 已退休task | durable tip ref | 原tip | 私有保全manifest |
| --- | --- | --- | --- |
| `m5/endpoint-closeout` | `refs/archive/dnsmasq/task-retirement-20261006/m5-endpoint-closeout` | `869d6e7d3bd6f76072d7f9657895658ec715f57c` | [完整文件/补丁SHA](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/worktree-retirement-20261006/batch-27fe4fd3-02/m5-endpoint-closeout/manifest.json) |
| `m5/final-validation-prep` | `refs/archive/dnsmasq/task-retirement-20261006/m5-final-validation-prep` | `16aacf2bdaa82f1a7815ba6c33924cbde36647db` | [完整文件/补丁SHA](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/worktree-retirement-20261006/batch-27fe4fd3-02/m5-final-validation-prep/manifest.json) |
| `m5/fixture-revision-tests` | `refs/archive/dnsmasq/task-retirement-20261006/m5-fixture-revision-tests` | `1ba8c90540b752f9bd925d75b937d2364b13490e` | [完整文件/补丁SHA](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/worktree-retirement-20261006/batch-27fe4fd3-02/m5-fixture-revision-tests/manifest.json) |

[私有总manifest](/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/worktree-retirement-20261006/batch-27fe4fd3-02/manifest.json)保存每树原status、working/staged binary diff SHA、原文件完整SHA/大小/mode/mtime及backup路径；共6个tracked变更原文件、2个untracked文件、27个ignored pyc缓存。删除前后均核对持久ref，备份文件SHA再次核验。原未提交内容仍在私有目录，未将其猜测合入最终产品。总manifest SHA256为`e9e758624e86552554deee4476a7d7ba6717c21748bb2ee712ca174f765a47f3`。其它树保持原状；当前任务树仍需等本回执合入后由Root决定退休。
