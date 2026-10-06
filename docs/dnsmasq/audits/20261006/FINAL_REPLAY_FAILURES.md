# M5 首轮统一回归失败记录

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
