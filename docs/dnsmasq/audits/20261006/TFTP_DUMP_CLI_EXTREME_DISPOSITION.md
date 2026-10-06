# M5 TFTP / boot / PXE / dump / CLI 收尾处置

2026-10-06。具体已知极端输入已修复或明确保留；原泛化组合标签逐一改为有限覆盖或源码限制，不能算作实际测试通过。新证据完整身份、归档与执行数见[脱敏收据](tftp-dump-cli-extreme-disposition.json)。本报告的运行用于收尾校准；最终冻结后的全族仍须在同一 ELF 新跑，旧资格不复用。

| 实际运行 | 候选与结果 | 范围 |
| --- | --- | --- |
| dump 数值 / encoded 文件参数 | 2522e4a0，ELF7f256a35…ac67d，12配对，0差异，4负控拒绝 | CLI VT正负、LP64正负饱和、unsigned-long/hex溢出、octal停止；file VT、quoted7、quoted空格1、部分quote、quotedVT。原两轮VT红保持，实际PCAP修复后精确匹配；不是完整族资格。 |
| dump FIFO压力 | 同2522，4096-byte pipe，固定400 query | C第58请求在pipe_write停滞，DNS/TFTP/TERM不进展；排空后58记录完整且正常退出。Rust400请求均应答，后续DNS/TFTP正常，未排空TERM正常退出；57已写、256待写退出释放、88队列满错误。全部wire前缀独立认证，8差异负控拒绝。第二轮额外保存raw wchan；第一轮完整保留。 |
| boot | 同2522，102报文观察及6 syntax，0未分类差异 | 空tag / 256-byte file和sname只运行--test；不执行C未定义路径。其余tag、next-server、PRL、BOOTP和字段/容量边界严格配对。 |
| PXE syntax | 0dba599a，ELFecbf16f5…5992b，61配置，0未分类差异 | 原58包含8已知空值/长度安全拒绝；新增3个2147483648字段：CSA、service type、prompt timeout。所有拒绝只有--test实际C0/Rust1，不声称执行了危险runtime。 |
| TFTP reference | 同0dba，原3服务差异加6配置syntax | IPv4/IPv6同peer replacement精确旧/新DATA与C1/Rust0残留FD；安全根内parent组件精确C DATA/Rust ERR2。原32负控拒绝；6整数范围配置只--test C0/Rust1。 |
| TFTP zero-block MTU | 同0dba，2服务差异，24负控拒绝 | MTU32/52、blksize512、非空小文件，C OACK0后两次空DATA1重放；Rust完整ERR4。主动client ERR停止C状态，两侧owner健康、FD0、正常退出。原校准block2期望和错误V4peer失败完整保留。 |
| DHCP reply-delay | 同0dba，25完整配对，0差异、4负控拒绝 | 空、signed负、INTMAX预算、536870912预算wrap、2^32归零、2^32+1真实1秒六输入。恢复musl signed低32位和sec*4低32位。第一次普通fallback两侧因Side未传cli_flags而红；修复夹具并验证真实cmdline后完整25再过。 |

| 保留行为差异 | 精确 C 位置 | Rust 与理由 / 实际边界 |
| --- | --- | --- |
| 同peer single-port替换旧DATA与FD | tftp.c247–277/305–309重用struct且丢旧file；963–971/1020–1022按同指针和offset回放旧buffer；1029–1039只释放当前file | 返回当前请求文件数据并释放全部旧引用。V4/V6各两次普通RRQ和最终ACK，严格old/new wire与C1/Rust0FD；不复制陈旧数据或泄漏。 |
| bound IPv4 single-port源地址 | tftp.c63–66定义未初始化addra，100–119 branch未赋值；198–201只在另一branch初始化；320/522消费 | 采用已验证接收地址/pktinfo。C未初始化路径没有稳定参考期待；历史run06错误保留，本报告不再次运行该UB，普通wildcard single-port仍严格对照。 |
| 配置根下的parent路径组件 | tftp.c487–498拼接；547–553只判断第一次strstr("/..")，前面的..safe掩盖后面/../ | 拒绝每个..组件，仅有配置root时适用；无root正常路径合同不变。根内无害..safe/../boot.bin的C DATA/RustERR2有actual守卫，不需要逃逸或读取宿主文件。 |
| TFTP IPv6 link-local scope | tftp.c297–302清scope、336bind | 保留验证接口scope，避免原版dedicated link-local失败；精确scope现已在账本总表，最终listener族重新绑定，不能由本报告的globalV6替代link-local证据。 |
| MTU恰为IP/UDP/TFTP开销 | tftp.c385–395令blocksize0，930–933输出OACK0；964/970–971相同offset重放DATA | ERR4拒绝零块，避免非空传输无法前进；实际32/52各两空DATA1/C与完整RustERR4、健康/回收及24负控，不声称这是C内存漏洞。 |
| boot空tag与BOOTP空predicate | option.c1338–1344/1360–1368和4664–4701创建net=NULL；dhcp-common.c224–245解引用check->net；rfc2131.c2571–2579/615进入匹配 | 明确配置拒绝；boot空tag、BOOTP空predicate只有syntax新证据；BOOTP首次C SIGSEGV旧资格保留。不复制空指针运行崩溃。 |
| boot file/sname超过255 | option.c4347–4392未限长度；rfc2131.c2203–2213传fullsize到free_space；2184–2187长度窄化一个byte | 明确配置错误，避免选项TLV长度与拷贝长度不一致。256-byte file/sname实际C--test0/Rust1；固定field/255以内普通路径配对。 |
| PXE空menu/vendor | option.c4486/4723用opt_string_alloc生成NULL；rfc2131.c2477/2594 strlen(NULL) | 明确拒绝service-empty-menu、vendor-empty和empty-element；3syntax配对，C危险runtime不执行。 |
| PXE prompt252–255 | option.c4441–4443未检查payload上界；rfc2131.c2323–2339/2343–2354封装，free_space2187只写一byte外层长度 | prompt≤251；更长配置拒绝，避免外层option43窄化后的坏TLV；4个--test C0/Rust1，合法251边界普通合同保留。 |
| TFTP整数配置超过C int正域 | option.c750–765numeric_check+atoi；3624–3652消费max、mtu、port endpoint；tftp.c108–109/236–245混signedMTU、276int容量/385–395unsigned块限额 | config max/mtu/port拒绝超i32正域。6个syntax C0/Rust1保留；不执行C signedatoi overflow及负MTU/负容量caller。范围内及普通RRQ数字option的wrap/clamp已有独立真实资格。安全确定的domain/forward/reply-delay wrap另已修复，不能把这条当作泛化所有数字豁免。 |
| PXE整数配置超过C int正域 | option.c750–765、4448–4449、4480/4485/4497–4499，再窄化timeout byte/CSA/service type | 明确拒绝超i32配置。CSA/type/timeout各2147483648只--test C0/Rust1，保持source atoi UB范围限制；范围内65536/u16与256/u8窄化普通已对照。 |
| dump FIFO满/退出时记录保留 | dump.c70–76和287–300同步read_write会阻塞父owner | 非阻塞最多256条待写记录；满时报failed继续服务，TERM释放未写队列。4096B/400query实际C58完整记录后退出，Rust57已写/256未写释放/88满队列错误及8守卫。这是压力下进展和退出的明确取舍，普通排空消费者的全PCAP仍严格相同。 |

第二个空conf-file、version首行归属、log-malloc按用户更正的内容差异已在[账本总表](../../DELIVERY_LEDGER.md#与-c-的行为差异)，本报告不增加不同豁免。CLI169×2加7controls的完整测试仍是最终冻结后的独立运行门。

| 原延期标签 | 处置与有限边界 |
| --- | --- |
| dump integer-overflow mask grammar | 12具体输入已修/实际PCAP配对；没有继续延后。 |
| dump FIFO pressure beyond ordinary draining consumer | 具体4096B/400query实际分类如上，完整C来源/队列损失理由入差异表；没有继续延后。 |
| dump malformed or oversized wire/header combinations | 原标签没有对应已观察的差异输入，属于非穷尽覆盖说明。dump实际由有界服务caller提交；本族普通IP/UDP PCAP和TFTP503-byte/parser截断、DHCP固定header/最大buffer分别有冻结输入与最终重跑门。不能声称所有跨族wire组合都已通过。 |
| dump allocator and gettimeofday fault combinations | source-only限制：dump.c135–149使用栈header及caller buffer，不分配每条记录；287的gettimeofday有有效stack timeval及NULL zone，LinuxEFAULT需无效caller指针。没有实际组合故障输入/观测差异，故不伪造故障测试通过；Rust记录分配路径和SystemTime实现不同，任意双故障不属同一C分配site。固定actual-write-EIO/recovery仍是70-row全族required，final ENOSPC/EMFILE另是实际验收门。 |
| DHCP integer-overflow delay arithmetic | 六具体输入已修，同0dba25配对全过；没有继续延后。 |
| DHCP malformed relay/header combinations | 原标签无具体失败输入。冻结relay43边界/174报文与网络四族actual caller明确；任意组合仍是非穷尽覆盖限制，final DHCP packet定向fuzz须实际执行，不能把有限测试冒称组合穷尽。 |
| DHCP allocator fault combinations | 原标签无具体失败输入。已有逐caller失败输入、FD清理及final EMFILE/ENOSPC属于明确证据；任意allocator多故障组合没有执行证据，不写成故意行为差异。 |
| CLI allocation-log contents | 用户明确排除逐字分配trace；已从globalallocator普通路径撤除，接受/启动/--test仍要final replay。属于故意差异，非未完成极端功能。 |
| CLI extreme syntax numeric/malformed combinations | 原标签没有另附具体失败输入。已知domain/cache/forward/delay输入修复与9个TFTP/PXE安全range拒绝明确处置；第二空conf-file/version明确差异。169×2+7冻结CLI测试和最终config_line定向fuzz覆盖有限输入，不称任意语法穷尽。 |

报告仅承诺实际列明输入。所有失败、selected校准、source-only限制与unsafe-reference-excluded保留，不改名为zero-difference通过。最终registry应运行dump70、reply-delay25、PXE61syntax+260普通service、TFTP30普通+5reference+6配置syntax；TFTP不得带--case缩减final资格。
