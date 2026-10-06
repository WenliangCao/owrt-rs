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
| cache536 | 仅ptr-tcp-child-import / round-reverse-disabled cached TTL600对599；其它数据与真实upstream1一致。 | 添加实际时钟witness定位整秒相位，不作全局±1；C跨进程PTR hash variation有8独立bank阳性，同进程repeat严格。 |
| relay174 | ordinary-reply arp-failure首轮C1/R0；选中15重跑转C0/R0，其他latepositive反转。 | 实际ip events/逐行snapshot与recv/send/ioctl witness定位自动IPv6 tentative→ready NEWADDR清认证relay状态。77080ea5仅禁IPv4fixture未来veth的自动LL生成，IPv6协议与故意地址generation场景保留；普通15两侧全wire/count相同，arp-failure两侧SIOCSARP=-EINVAL后send244B/downstream1。完整37/174及syntax/binding/controls正在诊断重跑，不按count差异豁免。 |
| M2 | 7DNS＋4DHCPprofile通过；lifecycle-C exit1，Rust lifecycle未执行。 | 确认漏接actual_config_network.py；`830e1951`补br-lan/client/upstream实际namespace拓扑。C3.34s/R9.12s完整init/HUP/UCI/odhcpd/stop诊断通过，full archive002ec15d…f69e的91条metadata/54files核验后prune。新freeze完整M2须fresh。 |
| endpoint本地归档门 | syntax完整本地SHA+metadata与prune成功，scp proof到root parent权限失败；formal controller仍等待。 | 已有syntax proof不重打包；中转sudo安装、service首次pack本地核验/prune/plain恢复完成，门与191/191源行audit实际通过。 |

冻结source/tools没有原地修改。所有修复仅进入main及新的完整source archive。原失败、控制器命令、JSON和原始overlay已full-fidelity归档；核验SHA、类型、mode、uid/gid、nsmtime、symlink、deviceID、xattrs后才prune，原lockedJSON保留供后置门重新核验。旧绿不替代最终候选fresh结果。三个native instrumented fuzz当前仅build，90分钟实际窗口尚未完成；mixed/full-cache300s、ENOSPC/EMFILE、APK与生命周期尚未执行。物理路由器未触碰。
