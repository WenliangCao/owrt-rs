# M5 收尾报告

**草稿，2026-10-06。** 169项普通合同已关闭、剩余0；最终同ELF44功能族全部正式PASS，包括logging完整329场景。Linux706＋10、两次完整M2、三入口fuzz、两项五分钟资源窗口与ENOSPC／EMFILE已通过。APK已实际构建并绑定最终ELF，ELF/APK均超原预算；包生命周期待补真实结果，当前不宣布M5收尾完成或体积已获接受。物理路由器未操作；M6只保留[协议草稿](M6_PROTOCOL_DRAFT.md)，没有正式性能窗口。

## 交付身份与验收进度

产品源码`dc1b740d7973838e2ae7f098d0726b0484e55074`；AArch64 musl ELF SHA256 `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b`，1,929,256字节。构建为Rust1.98.1／固定SDK、opt-level3、static、strip、panic-abort、no-unwind，构建和产物复制在唯一Cargo锁内完成。镜像C为OpenWrt25.12.5 dnsmasq2.93／SHA256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。[完整冻结身份][identity]

工具6fb65独立git archive冻结后全44重新执行；最新fixture9684b010256f／manifest SHA256 `8da6dcf43dc585af54ffa89bf120dfc1b29d70ab0d9bec18469a09c1192a058f`保持原默认6fb65工具tree、产品ELF及43个原锁定receipt与argv，仅logging使用新tree。窗口guard修复只控制执行资格，没有删case/inventory或放宽wire/count。43个PASS及M2/fuzz的输入SHA/执行退出保存在[完成表][completed]；[最后logging资格][logging-final]加入后，[44族总门][families-aggregate]passed true、failures[]。[最终fixture身份][fixture]同时绑定本次压力验收。

| 验收门 | 实际结果与证据 |
| --- | --- |
| 169选项 | 已关闭169，部分/未实现均0；[逐项账本](DELIVERY_LEDGER.md#m5-盘点与工作顺序) |
| Linux单元 | 库706＋main10实际通过；20 ignored不计。[实际lib/main执行日志][tests-run]、[同源测试构建身份][tests]；测试ELF与交付release ELF分别绑定，不把build/no-run当作执行 |
| 同ELF44族 | 44/44正式PASS，logging329全量实际执行；[完整资格总门][families-aggregate]，逐族表如下 |
| 完整M2 | 两轮PASS：7 DNS、4 DHCP profile、C/R init/HUP/UCI/odhcpd/stop。[第一轮][m2a]、[第二轮][m2b] |
| native fuzz | dns_wire1801.324s、dhcp_packet1801.272s、config_line1801.470s，各exit0、artifacts空，累计5404.065 target-seconds；同源instrumented产物独立于交付musl ELF。[实际运行][fuzz] |
| 混合资源 | 300s实际采样／controller305.073s，C/R accepted true、failures[]；工作量及退出清理相同。[资源receipt][resources]、[实际采样][mixed-resource] |
| 满缓存资源 | inner实际300s／controller356.807s，双方4096条live A及首尾命中证明，accepted true、failures[]。[实际满缓存与负控][full-resource] |
| ENOSPC／EMFILE | PASS，C/R规范化观察完全相同、failures[]；leaf122.063s／controller122.165s，300s是每侧deadline。[压力receipt][pressure]、[故障、恢复与清理][pressure-leaf] |
| APK | 实际产物1,065,071B／SHA `bfed44eaf49703745a2c08a8ee1fbc5325b44f833d07baee2224a0084a6ee8aa`，payload等于最终37f85ELF，identity_verified/recipe_restored均true；**ELF/APK预算均失败，待用户体积决定**。[构建与预算manifest][package]、[执行controller][package-controller] |
| 包生命周期 | **待root补真实安装/升级/卸载/回滚/变体互斥及init激活结果；未记通过** |

## 44族逐项结果

“通过”是本交付ELF的实际完整步骤资格；各链接指向锁定receipt、结果SHA和完整检查。source-only控制不冒称live daemon；故意差异保持独立guard。所有原始数据在ignored/private全SHA、mode、uid/gid、nanosecond mtime、link/device/xattr核验后prune，controller与后置门JSON保留。

| 功能族（registry ID） | 结果／实际覆盖 | 证据 |
| --- | --- | --- |
| m5_option_matrix | 通过；40配置／278观察 | [锁定PASS][completed] |
| m5_option_matrix_next | 通过；40配置／613观察 | [锁定PASS][completed] |
| m5_option_matrix_third | 通过；56配置／590观察 | [锁定PASS][completed] |
| m5_option_matrix_tag_if | 通过；39配置／56观察 | [锁定PASS][completed] |
| m5_option_matrix_dhcp | 通过；65配置／131观察 | [锁定PASS][completed] |
| m5_option_matrix_dhcp_v4 | 通过；17配置／48观察 | [锁定PASS][completed] |
| m5_option_matrix_lease_names | 通过；47配置／200观察 | [锁定PASS][completed] |
| m5_local_records | 通过；418服务／102解析；3故意差异 | [锁定PASS][completed] |
| m5_boot | 通过；102观察＋6语法 | [锁定PASS][completed] |
| m5_helper | 通过；16场景、C/R32行 | [锁定PASS][completed] |
| m5_rr_filter | 通过；8组配对／8负控 | [锁定PASS][completed] |
| m5_config_inputs | 通过；51配置 | [锁定PASS][completed] |
| m5_lease_recovery | 通过；70场景／50边界／12负控 | [锁定PASS][completed] |
| m5_listeners | 通过；163配置/side、3534观察／130负控 | [锁定PASS][completed] |
| m5_tftp | 通过；30普通＋5reference＋6安全syntax | [锁定PASS][completed] |
| m5_dump | 通过；70配对；6普通＋8压力负控 | [锁定PASS][completed] |
| m5_script_arp | 通过；78/side、9负控；3Rust实际OOM caller | [锁定PASS][completed] |
| dhcp-proxy | 通过；13配对／4负控 | [锁定PASS][completed] |
| bridge-interface | 通过；13配对／4负控 | [锁定PASS][completed] |
| shared-network | 通过；17配对／4负控 | [锁定PASS][completed] |
| dhcp-reply-delay | 通过；25配对／4负控 | [锁定PASS][completed] |
| m5_relay | 通过；37配置／174报文＋40语法／15负控 | [锁定PASS][completed] |
| m5_pxe | 通过；61语法／260报文 | [锁定PASS][completed] |
| m5_leasequery | 通过；22配置／38查询 | [锁定PASS][completed] |
| dhcp-tags-options | 通过；全部1条冻结命令实际执行 | [锁定PASS][completed] |
| dhcp-identities | 通过；全部1条冻结命令实际执行 | [锁定PASS][completed] |
| dhcp-range | 通过；冻结147事件与完整caller | [锁定PASS][completed] |
| dhcp-files | 通过；82配置／330事件 | [锁定PASS][completed] |
| loop-detect | 通过；90required／670负控 | [锁定PASS][completed] |
| logging-all-scopes | 全329实际PASS／controller578.681s；44负控，phase true、leaf failures[] | [最终锁定PASS][logging-final]、[全部329与负控][logging-leaf] |
| cli-test | 通过；169×2＋7，345配对 | [锁定PASS][completed] |
| cli-log-malloc | 通过；15配对 | [锁定PASS][completed] |
| m5_edns | 通过；196required／21负控，7故意差异 | [锁定PASS][completed] |
| m5_dns_cache | 通过；536required／1823负控＋caller9 | [锁定PASS][completed] |
| m5_dns_endpoints | 通过；全部4条冻结命令实际执行 | [锁定PASS][completed] |
| m5_interface_records | 通过；全部6条冻结命令实际执行 | [锁定PASS][completed] |
| dns-files | 通过；107配置／556观察 | [锁定PASS][completed] |
| tftp-errors | 通过；95场景／17边界／10负控 | [锁定PASS][completed] |
| filterwin2k | 通过；19配置；严格上下游wire | [锁定PASS][completed] |
| helper-shutdown | 通过；13场景、C/R26行 | [锁定PASS][completed] |
| ubus-ordinary | 通过；350观察／2176检查／10负控 | [锁定PASS][completed] |
| logging-dhcp-companion | 通过；50场景＋7overflow caller | [锁定PASS][completed] |
| dhcp-device-binding | 通过；27required／195负控 | [锁定PASS][completed] |
| query-id-wrap-source-controls | 通过；SDK Os/O2×5 display值，10控制；非daemon计数耗尽 | [锁定PASS][completed] |

## 延后项、故意差异与代码健壮性

所有具体known-deferred已有明确修复或保留理由，冻结[source-bound处置审查][deferred]为complete，ordinary_unresolved/known_unresolved_deferred均空。泛化任意组合和只看源码的限制保留为覆盖说明，不改名成actual通过。

| 范围 | 完成的有限处置 |
| --- | --- |
| 缓存/forward | [cache极端处置](audits/20261006/CACHE_EXTREME_DISPOSITION.md)：安全signed容量/TTL边界匹配；巨型SOA首响应有效，拒绝u16窄化后的坏缓存回放 |
| domain/SRV/SYN | [endpoint处置](audits/20261006/ENDPOINT_EXTREME_DISPOSITION.md)：安全prefix wrap0、合法最长SRV及suffix错误退出匹配；负IPv6 prefix/不可编码PTR不进入C越界/坏包路径 |
| TFTP/boot/PXE/dump/CLI | [逐标签处置](audits/20261006/TFTP_DUMP_CLI_EXTREME_DISPOSITION.md)：VT/encoded dumpmask、reply-delay signed预算已修；零MTU、空predicate/menu/vendor、过长TLV和out-of-int配置明确拒绝；FIFO压力/退出保留有界进展取舍 |
| 日志/启动 | [日志收尾审计](M5_LOGGING_CLOSEOUT_AUDIT.md)：长/opaque路径、PID事件13、debug完整echo、真实serializer/菜单/企业option耗尽caller、合法大TXT/name已实际处置；counter wrap/私有IPC边界明确source-only范围 |

最终[与C行为差异总表](DELIVERY_LEDGER.md#与-c-的行为差异)逐条保留精确C源码位置、理由和actual/unsafe-excluded边界，包括FIFO等待时Rust继续DNS/TFTP、TFTP IPv6 scope、第二空conf-file、version实现归属、log-malloc不输出逐次分配trace，以及C的旧DATA/FD、损坏DNS/TLV与越界输入。没有把差异改名后声称零差异。

冻结[source-bound安全审查][safety]已完成：缺失SAFETY补齐FD唯一归属、FFI布局/长度、fork/passwd/capability和signal边界；网络/定时器可触达unwrap/expect改为已有Option/Result/显式错误，保留点逐条由固定长度或私有单owner不变量证明。ParentDns/ParentEvents/interface/DHCP provider/dump及logger改Rc/RefCell，生产无显式Mutex；只保留测试fixture锁。短借用在poll/fork前结束，重入用try_borrow与显式metrics快照。模块依据见[主审查](M5_ROBUSTNESS_REVIEW.md)、[DNS](audits/20261006/DNS_RUNTIME_SAFETY.md)、[config/interface](audits/20261006/config-interface-safety-review.json)、[TFTP/helper](M5_TFTP_HELPER_SAFETY.md)、[logging](M5_LOGGING_SAFETY_AUDIT.md)。静态审查没有替代上述实际复跑。

## ELF、APK与内存对M4

| 指标 | M4已接受基线 | M5最终opt3 | 增量 |
| --- | ---: | ---: | ---: |
| ELF字节 | 1,159,280 | 1,929,256 | +769,976（66.4%） |
| APK字节 | 633,984 | 1,065,071 | +431,087（68.0%） |
| 4096满缓存Q4 RSS（KiB） | 2,676 | 3,524 | +848（31.7%） |
| 同轮C满缓存Q4 RSS（KiB） | 1,652（M4） | 1,660 | 同轮Rust比C多1,864 |

M5 Rust空载RSS2,024KiB、填满3,460、命中验证后3,524，满缓存Q4同为3,524；C对应1,656/1,660KiB。双方满缓存Q4−Q3为0，C/R全程FD11/10、线程各1、子进程各0；4095命中缺一项负控正确拒绝，4096首尾命中时上游请求均0。混合窗口双方FD17、线程1、子进程0，20次DORA、41次renew、44次rebind、164次UDP与51次TCP查询完全相同；停机后daemon/ubusd均退出、socket关闭、lease行0。[RSS与满载证明][full-resource]、[混合采样及清理][mixed-resource]、[receipt][resources]均绑定最终ELF；[本地全SHA及metadata核验][resources-verification]通过后远端raw已prune。300秒结果只支持本次资源/回收门，不能推断M6收益或长期内存趋势；满载范围是4096条短名称动态A，不包含任意复杂RR或长名称。

ENOSPC在双方tmpfs实际填满16,384B，仍收到`127.0.0.15`的offer及ACK、满盘时没有durable lease，释放空间后分别60.046／60.042s恢复1条lease。EMFILE在双方实际施加FD压力，恢复后的DNS reply ID为`3201`、长度47B；规范化C/R观察完全相同。双方各场景退出后daemon/pid均无残留、lease行0、exit0。[实际故障与恢复][pressure-leaf]、[最终压力receipt][pressure]和[归档核验][pressure-verification]保存原始观察；leaf总122.063s，controller122.165s，参数300s只是每侧deadline，没有额外五分钟压力暴露的主张。

`dnsmasq-2.93-r2.apk`使用已验收的冻结ELF作为payload；不再次codegen/strip，SDK原recipe在构建后恢复，产物身份核验为true。[实际构建manifest][package]的status为failed、`failure_boundary=size-target`：1,929,256B ELF超过1,000,000B预算，1,065,071B APK超过700,000B预算。build returncode1只来自这两个预算检查；controller passed true只表示真实、可审查、身份正确的产物已生成，不能解释为预算通过或体积已被接受。生命周期结果仍待补齐。

[功能族体积归因](M5_SIZE_ATTRIBUTION.md)保留固定路径连续构建、首尾同字节控制及失败矩阵；混合阶段/共享泛型/链接布局不能冒称纯单族增量。下面是同次最终[link.map归属][size-map]的当前执行区存储：2,561输入sections覆盖1,674,984B，220B未归因；它不是+769,976B新增成本的因果拆分。

| 当前存储归属 | 执行区字节 |
| --- | ---: |
| DNS | 287,508 |
| DHCP | 214,972 |
| 配置解析 | 185,284 |
| main/root owner | 166,412 |
| helper | 38,312 |
| TFTP | 42,096 |
| logging/query | 23,972 |
| startup | 12,816 |
| neighbors/ARP | 10,576 |
| UBus组件＋服务 | 25,940 |
| dump | 5,400 |

已采用保持行为的source-pool选择简化，受控构建实测省16,384B并C回归；loop改固定31-byte probe消除每包Vec/format，混合阶段净0不声称独立节省。Mutex/Rc阶段省16,384B含main简化与布局，不冒称纯锁成本。log-malloc按用户要求撤掉globalallocator/128KiB实验缓冲和普通路径包装；143,360B的内联压缩只是已退役实验，不是当前产品额外收益。当前最大段run_inner29,832B、DNS config apply18,488、DHCP resolve_events16,380、helper child15,356；进一步拆分没有已证明行为不变的净节省，暂不改变调度/诊断合同。

| 可选构建 | ELF字节 | 比opt3少 | 资格与代价 |
| --- | ---: | ---: | --- |
| opt3交付候选 | 1,929,256 | — | 本报告的功能/资源候选 |
| opt-level s样本 | 1,613,864 | 315,392 | 仅同源size sample；尚未功能/资源/APK验收或M6，须重新冻结并验证 |
| opt-level z样本 | 1,503,272 | 425,984 | 同上；CPU/尾延迟影响未测，不能保证速度保持 |

M4的体积特许只属于M4 ELF；M5未自行接受新的ELF超标。原预算ELF1,000,000/APK700,000字节仍必须如实报告；s/z样本也都超过原ELF预算，APK压缩体积尚未测，不能保证满足700,000B。**待root填完生命周期后提交终版，才请用户决定接受opt3体积，或选择s/z并承担重冻结/功能资源包复测及后续M6测量成本。**

## 失败与重跑记录

完整失败链见[FINAL_REPLAY_FAILURES](audits/20261006/FINAL_REPLAY_FAILURES.md)，原12b3、dc1b首轮与各tools revision的红/未执行数据不覆盖。主要产品修复是masked-MAC错误文案和实际bind-before-loop-probe启动race；夹具修复涵盖长Unix path、helper init/ready边界、queued TCP、scope/资格元数据、ARP map资产、PXE时钟字段、relay DAD与跨FD真实kernel序、cache实际整秒phase。没有删除case、放宽wire/count或把基础设施异常归为已通过。

logging[原329失败及诊断][logging]只剩fastretry固定reply在C真实重传前返回；有界等实际第二个相同request再释放唯一reply的三模式diagnostic已过，随后[全329正式复跑][logging-final]完整PASS，不用诊断替代整族资格。最终logging归档SHA `be4f23357acf6b655f1974ca06802b9de2daa54354aa65b929097c7a362a3da1`，[5,583路径／4,559文件完整核验][logging-verification]通过后远端raw已prune。资源[attempt1][resources-rejected-1]因诊断负载污染在8.3005s被门拒绝，[attempt2][resources-rejected-2]因外部worker残留在采样前拒绝；按精确PGID清理后[attempt3][resources]完整PASS。压力[首轮][pressure-missing-namespace]因缺失`run_isolated`在0.0930s退出，[第二轮][pressure-born-race]因guard把自身新生子进程误当外部污染在5.0567s拒绝；9684修复own/foreign namespace资格及阳性/负控后[实际重跑][pressure]完整PASS。上述失败保留原receipt与执行边界，不记作产品通过。[APK首轮][package-controller]controller31.005s实际生成正确产物，build return1为显式预算失败；没有修改预算或删除失败。生命周期失败与复跑仍待实测补齐。

[identity]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/final-identity.json
[completed]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-6d572edf9ff0/completed.json
[tests]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-tests/plain/build.json
[tests-run]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/tests-run.log
[fixture]: ../../private/dnsmasq-rewrite/evidence/M5/final-9684-logging/gate/identity.json
[families-aggregate]: ../../private/dnsmasq-rewrite/evidence/M5/final-9684-logging/gate/families.aggregate.result.json
[m2a]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-m2/plain/result.json
[m2b]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-6fb65d96390e/archive-m2/plain/result.json
[fuzz]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-fuzz/plain/result.json
[logging]: ../../private/dnsmasq-rewrite/evidence/M5/final-6fb65-logging-families/regression-receipt.json
[logging-final]: ../../private/dnsmasq-rewrite/evidence/M5/final-9684-logging/logging-all-scopes-9684-attempt-1/logging-all-scopes.result.json
[logging-leaf]: ../../private/dnsmasq-rewrite/evidence/M5/final-9684-logging/logging-all-scopes-9684-attempt-1/logging-all-scopes/result.json
[logging-verification]: ../../private/dnsmasq-rewrite/evidence/M5/final-9684-logging/logging-all-scopes-9684-attempt-1.local-verification.json
[deferred]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/deferred-review.json
[safety]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/safety-review.json
[size-map]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/size-map-report.json
[resources]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-final/plain/result.json
[mixed-resource]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-final/plain/mixed-300/result.json
[full-resource]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-final/plain/full-cache-300/result.json
[resources-verification]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-final/local-verification.json
[resources-rejected-1]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-1/plain/result.json
[resources-rejected-2]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-resources-rejected-2/plain/result.json
[pressure]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-final/plain/result.json
[pressure-leaf]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-final/plain/enospc-emfile/result.json
[pressure-verification]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-final/local-verification.json
[pressure-missing-namespace]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-missing-namespace/plain/result.json
[pressure-born-race]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/archive-pressure-born-race/plain/result.json
[package]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-9684b010256f/package-manifest.json
[package-controller]: ../../private/dnsmasq-rewrite/evidence/M5/final-20261006/dc1b740d7973/fixture-9684b010256f/package-controller-attempt-1.log
