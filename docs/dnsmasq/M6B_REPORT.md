# M6b 修复与优化报告

状态：执行中，尚未完成最终验收。性能结论仅代表 Oracle AArch64 构建机；物理路由器未操作。第1包已经按用户固定收尾点关闭，无方案A新基线27/27已经完成；方案A仍在独立分支，未取得新基线上的验收资格，未合入主线。本文提交不是本轮结束条件。

## 协议与身份

判定使用事前提交的 [M6B_PROTOCOL.md](M6B_PROTOCOL.md)。中间候选只跑9场景×3组×1轮，不能用单轮结果声称显著收益；最终候选仅执行一次9×3×5。方案A增量门另外固定为3个TCP场景×C/无A新opt3/A×5轮，CPU包括C子进程，不能重复加一次child CPU。A每正确请求CPU相对新opt3不劣于5%，且严格低于同配置C；吞吐和p95相对新opt3不劣于5%。任一硬门失败保留证据并按用户要求停止方案A，不拼不同候选最好的结果。

| 对象 | 源码 | ELF SHA256 | 字节 | 资格 |
| --- | --- | --- | ---: | --- |
| M6a opt3 | dc1b740d | 37f85d22…7f7b | 1,929,256 | 历史冻结基线，完整数据见M6A_REPORT |
| 镜像C | 精确OpenWrt 25.12.5 / dnsmasq 2.93 nodhcpv6 | 097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87 | 269,305 | 所有对照使用该镜像rootfs |
| 第1包无A opt3 | 70097c66 | 34b3b80a39ea619f616f9d003372640d6dc0af35d5941788ae15aa64c07a3050 | 1,949,736 | feature-off，742库/51入口/68UBus实际Linux通过；20 ignored不计 |
| 第1包无A s | 同70097c66 | b91d3f0ad8ab0759a1c447ed7029035cc2c6561d6a3a7e9e017f8c28c239c62a | 1,630,248 | feature-off，仅性能对照，不作功能验收 |
| 最终opt3 / s / APK | 尚未冻结 | 未测 | 未测 | 必须绑定同一最终源码及所有门 |

第1包opt3相对M5增加20,480B（1.06%）；s相对该opt3减少319,488B（16.39%）。这些只是体积，不能由此推断CPU代价或建议切换s。正式窗口不启用`m6b-diagnostics`、wake明细、perf或strace；计数诊断有独立companion身份。

新基线manifest为`adea1b55171b355be7c98ad87af03ab2156fdccfebe150ae43979499cd2b70dd`，证据在`private/dnsmasq-rewrite/evidence/M6B/baseline-70097c66/`。CPU0 daemon、CPU1 upstream、CPU2 generator、CPU3 controller；每窗fresh pilot后才正式测量，按C/R3/Rs交错，逐窗完整归档、本地逐文件SHA及元数据验证后才清远端raw。窗口内不运行其他构建、测试或fuzz。

## 第1包机制与归因边界

1. UDP接收缓冲改为owner复用，每轮固定有界批量；网络与文件fd统一等待，按最近实际timer到期计算timeout。包预算保留DHCP/TFTP/TCP/reload的运行机会。Linux旧代码已有网络fd，不能把非Linux的2ms park说成Linux实测根因。用户取消旧M5只加计数版本`df99d1f9`补测：**修复前的等待来源以读码和系统调用统计为证据，未做旧版本计数实测**。
2. 第1b初次调整metrics/UBus调用和fd backing数组复用效果很小。历史中间TCP CPU为Rust45.679µs、C27.434µs；UDP23.639/11.955、reload48.261/20.610、DHCP1550.191/456.072µs。这些属于旧候选，不是新70097基线。之后按每个fd的revents分派，保留内存已排完整输入、到期timer、错误/HUP、probe及关闭回收的逻辑工作。
3. readiness修后27个syscall诊断全部归档，scope为warmup+load+稳定排空，分母包括scope内全部正确回答。C/R3 calls/correct：UDP hit3.000/2.214、TCP local3.519/2.372、reload3.559/5.036、DHCP81.176/317.012；两TCP场景Rust EAGAIN为0。诊断有插桩，不能当CPU性能资格。DHCP额外57,120次名字/flags ioctl及14,025次周期snapshot解释诊断差距88.73%，详见[M6B_DHCP_SYSCALL_GAP.md](audits/M6B_DHCP_SYSCALL_GAP.md)。
4. 主循环变成实际事件等待后，helper队列、DNS文件请求等可能在consumer之后变为可运行。修复直接查询当前可运行状态，不依赖上一轮保存的runnable；可运行时通用poll0守卫，外部FIFO/transport背压仍等待其fd，绝不因队列非空而空转。HUP及普通小文件发布先于同wake的UDP/TCP新admission；大文件、FIFO/worker有界让出。22类来源、setter/consumer/wake及实际测试见[账本唤醒清单](DELIVERY_LEDGER.md#M6b-逻辑工作唤醒清单)。
5. Linux接口改为独立地址/路由事件，port0仍监视；只有unfinished DAD/迟绑或真实失败登记1秒重试，移除普通100ms全量扫描，保留每个DHCP请求fresh接口合同。ENOBUFS有界续读，不伪造地址/路由/resync；故障工具和后续新发现独立处理，不扩大第1包。
6. qualified kernel NEWROUTE按精确C先重发最后一次成功UDP，再请求非force resolver检查。保存exact wire、server、单调socket token和destination，仅一个复用Vec；不pin socket、不新建事务，不增加forward/log/dump/fastretry计数。真实UDP消费、本地/拒绝/无效输入、上游消费、HUP、debug/wildcard TCP及明确TFTP scratch构造使save失效；批次末尾额外WouldBlock探空不擦掉本批最新成功send。详见[库合同](audits/M6B_ROUTE_RESEND_FIX.md)和[owner合同](audits/M6B_ROUTE_RESEND_MAIN_CALLER.md)。

路由普通poll/no-poll在70097同ELF fresh镜像C/R均2包，wire/sourceport相同、forward action1、idleFD稳定；原7bdb只有1包的失败完整保留。169项因此复闭，不能把cleanup回答当resend通过。第1包已写唤醒测试全部实际通过；后续新发现独立修复、最终冻结前合入复测。

## 无A新基线已完成部分（单轮，未作显著分类）

70097c66的UDP-hit三组raw analyzer均方法有效、analysis_errors=[]。稳态90秒，饱和30秒；正确吞吐排除跨段完成和错误，CPU来自相应cgroup边界。全部九profile已完成27/27并全量本地SHA及metadata归档；以下均只作单轮归因，不拼旧候选结果。

| UDP-hit | 正确QPS | CPU µs/正确请求 | p50 ms | p95 ms | p99 ms | 限制 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| C 稳态 | 9,995.54 | 12.2798 | 0.019640 | 0.024880 | 0.055960 | 无generator限制；400次施加机会未发送，原计数保留 |
| R3 稳态 | 9,998.31 | 16.5592 | 0.023280 | 0.026800 | 0.060721 | 无generator限制 |
| Rs 稳态 | 9,998.32 | 17.9471 | 0.024601 | 0.027920 | 0.059121 | 无generator限制 |
| C 饱和 | 145,943.67 | 6.8464 | 0.135161 | 0.149961 | 0.163442 | generator_limited，不能冒称C真实服务上限 |
| R3 饱和 | 110,115.73 | 9.0706 | 0.179321 | 0.194442 | 0.208202 | 无generator限制 |
| Rs 饱和 | 95,233.70 | 10.4813 | 0.206122 | 0.227802 | 0.241162 | 无generator限制 |

三组均无timeout/wrong/transport error；60秒idle cgroup CPU增量均0。峰RSS/PSS：C1668/1660、R33532/3524、Rs3408/3400KiB；FD11/12/12、线程均1、子进程均0。R3稳态已达到实际施加约10k和亚毫秒目标，但相对C仍多4.2795µs/请求（34.85%）；Rs相对R3多1.3878µs（8.38%），饱和正确QPS低13.52%。这些是绝对代价/单轮归因，尚不能作显著变差或切换s的决定。三组完整源数据、raw latency分析及本地归档proof均在E/M6B/baseline-70097c66。

UDP-miss三组单轮亦方法有效、analysis_errors=[]、无普通错误、无generator限制：

| UDP-miss | 正确QPS | CPU µs/正确请求 | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| C 稳态 | 9,974.96 | 94.7367 | 0.164402 | 0.321922 | 1.080049 |
| C 饱和 | 11,792.17 | 84.0422 | 1.671654 | 1.830015 | 2.127817 |
| R3 稳态 | 9,984.44 | 84.3103 | 0.094121 | 0.146682 | 0.541164 |
| R3 饱和 | 15,920.40 | 62.0208 | 1.233530 | 1.391292 | 1.594054 |
| Rs 稳态 | 9,983.80 | 83.3466 | 0.092401 | 0.146281 | 0.558605 |
| Rs 饱和 | 16,441.90 | 60.0341 | 1.192610 | 1.352891 | 1.494533 |

R3稳态相对C少10.4264µs/请求（11.01%），p50少0.070281ms；Rs相对R3稳态少0.9637µs（1.14%）。与UDP-hit的s代价不同，必须逐场景报告，不能拿一项推断全部路径。仍是单轮归因，显著分类等待最终五轮。

DNS-mixed三组单轮方法有效、无错误、无generator限制：

| DNS-mixed | 正确QPS | CPU µs/正确请求 | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| C 稳态 | 9,993.93 | 32.1083 | 0.021080 | 0.134321 | 0.220882 |
| C 饱和 | 40,620.43 | 24.4779 | 0.485364 | 0.593965 | 0.696606 |
| R3 稳态 | 9,993.78 | 32.3364 | 0.027640 | 0.100801 | 0.169082 |
| R3 饱和 | 44,642.53 | 22.1554 | 0.437364 | 0.516964 | 0.581325 |
| Rs 稳态 | 9,993.83 | 33.6722 | 0.028761 | 0.104121 | 0.175882 |
| Rs 饱和 | 43,072.37 | 23.0671 | 0.456204 | 0.530244 | 0.582805 |

稳态R3与C CPU差0.2281µs（0.71%），p95少0.033520ms；Rs相对R3 CPU多1.3358µs（4.13%）。仍未作显著分类。UDP-miss用户/系统分项的旧syscall与新CPU账交叉核对见[M6B_UDP_MISS_KERNEL_ATTRIBUTION.md](audits/M6B_UDP_MISS_KERNEL_ATTRIBUTION.md)：socket/close两侧各一次，Rust多read4/FIONBIO/F_SETFD；mmap并非逐请求、minor fault极少，不能解释全部28–40µs系统CPU差。真正poll等待/跨核唤醒是待验证假设，不冒称已证实。

上游fault三组单轮均方法有效，冻结故障区间内600个预期timeout、wrong/transport error为0；没有正确回答的段不报CPU/正确请求或延迟分位，也不伪造p99。恢复段的跨界机会与正确数完整保留。

| fault | 正确QPS | CPU µs/正确请求 | p50 ms | p95 ms | timeout |
| --- | ---: | ---: | ---: | ---: | ---: |
| C 故障前 | 1,000.00 | 167.6975 | 0.203641 | 0.273322 | 0 |
| C 故障中 | 0.00 | — | — | — | 600 |
| C 恢复 | 992.82 | 265.3814 | 0.306402 | 0.382203 | 0 |
| R3 故障前 | 1,000.00 | 122.4698 | 0.158321 | 0.220802 | 0 |
| R3 故障中 | 0.00 | — | — | — | 600 |
| R3 恢复 | 992.85 | 196.8709 | 0.217322 | 0.304243 | 0 |
| Rs 故障前 | 1,000.00 | 107.3238 | 0.136402 | 0.164521 | 0 |
| Rs 故障中 | 0.00 | — | — | — | 600 |
| Rs 恢复 | 993.12 | 176.6167 | 0.187561 | 0.234922 | 0 |

仍只为无A单轮归因；恢复时间、请求间最大间隙和原始计数在相应analyzer JSON，不拿仅恢复后平均数掩盖故障期间。

TCP-local三组单轮方法有效、无普通错误、无generator限制：

| TCP-local | 正确QPS | CPU µs/正确请求 | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| C 稳态 | 9,995.79 | 27.2349 | 0.031600 | 0.130881 | 0.426364 |
| C 饱和 | 37,325.07 | 26.7378 | 0.261242 | 0.830647 | 3.087746 |
| R3 稳态 | 9,998.07 | 25.5756 | 0.030480 | 0.056600 | 0.365883 |
| R3 饱和 | 73,083.27 | 13.6603 | 0.198962 | 0.528884 | 0.719926 |
| Rs 稳态 | 9,997.81 | 27.8912 | 0.031920 | 0.059481 | 0.391284 |
| Rs 饱和 | 63,526.50 | 15.7201 | 0.239602 | 0.583165 | 0.811087 |

| TCP-local资源 | 峰RSS / PSS KiB | 峰FD（进程族求和） | 线程 / 子进程 | 完整FD稳定排空秒 | 0 / 1 / 5 / 60s PSS KiB |
| --- | ---: | ---: | ---: | ---: | --- |
| C | 30948 / 4016 | 641 | 21 / 20 | 0.040924 | 1660 / 1660 / 1660 / 1660 |
| R3 | 11492 / 11484 | 32 | 1 / 0 | 0.040966 | 2292 / 2292 / 2292 / 2292 |
| Rs | 11372 / 11364 | 32 | 1 / 0 | 0.041127 | 2168 / 2168 / 2168 / 2168 |

C RSS是父子进程求和，重复包含fork共享页，应结合进程族PSS比较内存，不能由较大RSS说Rust更省内存。三组idle60s CPU均0。R3稳态CPU较C少1.6593µs（6.09%），p95少0.074281ms；Rs较R3多2.3156µs（9.05%），饱和CPU多约15.08%。这些限定于本单轮，A硬门仍须新的完整5轮C/R3/A增量矩阵。

TCP-cache三组单轮方法有效、无错误、无generator限制：

| TCP-cache | 正确QPS | CPU µs/正确请求 | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| C 稳态 | 9,995.53 | 32.7343 | 0.038121 | 0.175641 | 0.496284 |
| C 饱和 | 30,069.50 | 33.1390 | 0.425443 | 1.162009 | 3.542669 |
| R3 稳态 | 9,959.39 | 32.3678 | 0.027840 | 0.723166 | 1.471972 |
| R3 饱和 | 47,718.10 | 20.9192 | 0.143281 | 1.481212 | 1.925976 |
| Rs 稳态 | 9,969.12 | 33.9835 | 0.028120 | 0.700806 | 1.376532 |
| Rs 饱和 | 45,409.00 | 21.9835 | 0.154041 | 1.544252 | 1.994976 |

| TCP-cache资源 | 峰RSS / PSS KiB | 峰FD（进程族求和） | 线程 / 子进程 | 完整FD稳定排空秒 | 0 / 1 / 5 / 60s PSS KiB |
| --- | ---: | ---: | ---: | ---: | --- |
| C | 30392 / 8814 | 636 | 21 / 20 | 0.040952 | 1664 / 1664 / 1664 / 1664 |
| R3 | 24932 / 24924 | 32 | 1 / 0 | 0.061876 | 3832 / 3832 / 3832 / 3832 |
| Rs | 24804 / 24796 | 32 | 1 / 0 | 0.061578 | 3704 / 3704 / 3704 / 3704 |

R3稳态CPU只较C少0.3665µs（1.12%），p95却多0.547525ms、p99多0.975688ms；共享方案须过尾延迟门，不能只报p50或CPU。无A峰PSS24,924KiB，排空后3,832KiB确认M6a更正量级，不能称峰值为长期保留。Rs较R3稳态CPU多1.6157µs（4.99%）；当前未作显著分类。

TCP-miss三组单轮方法有效、无错误、无generator限制：

| TCP-miss | 正确QPS | CPU µs/正确请求 | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| C 稳态 | 4,396.52 | 227.2472 | 1.042848 | 3.459549 | 32.801312 |
| C 饱和 | 4,643.30 | 215.1574 | 1.112409 | 3.605310 | 18.832796 |
| R3 稳态 | 8,227.03 | 118.9840 | 0.208681 | 3.749312 | 5.384245 |
| R3 饱和 | 9,189.33 | 108.5106 | 1.545933 | 4.775119 | 5.955090 |
| Rs 稳态 | 8,009.04 | 122.5910 | 0.218162 | 4.128194 | 5.682568 |
| Rs 饱和 | 8,749.23 | 114.0082 | 1.582054 | 5.271244 | 6.385693 |

| TCP-miss资源 | 峰RSS / PSS KiB | 峰FD（进程族求和） | 线程 / 子进程 | 完整FD稳定排空秒 | 0 / 1 / 5 / 60s PSS KiB |
| --- | ---: | ---: | ---: | ---: | --- |
| C | 23208 / 5564 | 326 | 16 / 15 | 0.040809 | 1660 / 1660 / 1660 / 1660 |
| R3 | 33728 / 33720 | 52 | 1 / 0 | 0.061888 | 8812 / 8812 / 8812 / 8812 |
| Rs | 33600 / 33592 | 52 | 1 / 0 | 0.062128 | 8680 / 8680 / 8680 / 8680 |

R3稳态CPU较C少108.2632µs（47.64%）、正确QPS高87.13%，p50低0.834167ms、p99低27.417067ms，但p95高0.289763ms。无A峰PSS33,720KiB、排空后8,812KiB；三组idle60s CPU均0。Rs较R3稳态CPU多3.6070µs（3.03%）、p95高0.378882ms（10.11%）；仍仅单轮，完整数值不能替代最终波动分类或A45窗口硬门。

DHCP-lease三组单轮方法有效、各2400个正确DORA/renew/release循环、无错误/无generator限制；真实leasefile release末态已过。每正确循环包含冻结的完整事务序列，不把CPU改称每个DHCP包。

| DHCP-lease | 正确循环/秒 | CPU µs/循环 | p50 ms | p95 ms | 峰PSS KiB | idle60s CPU秒 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| C | 20.00 | 581.7800 | 2.775583 | 3.432348 | 1672 | 0.000000 |
| R3 | 20.00 | 775.7079 | 2.839383 | 3.390148 | 2452 | 0.000000 |
| Rs | 20.00 | 832.0071 | 2.858383 | 3.378988 | 2196 | 0.000000 |

样本2400不足10000，不报p99。R3较C多193.9279µs/循环（33.33%），较历史第1b1550.191µs明显下降，但不能据跨源码/时点直接作显著分类。Rs较R3多56.2992µs（7.26%）。去除普通周期扫描后idle CPU归零，每packet fresh接口语义保持，剩余CPU差不靠复用陈旧接口或省安全检查掩盖。

Reload-concurrent三组单轮方法有效、各120000个正确DNS回答、无错误/无generator限制，冻结HUP发布及TFTP并发独立守卫过：

| reload-concurrent | 正确QPS | CPU µs/正确请求 | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| C | 1000.00 | 21.2552 | 0.040481 | 0.071841 | 0.154762 |
| R3 | 1000.00 | 36.9664 | 0.052760 | 0.090401 | 0.157162 |
| Rs | 1000.00 | 39.0623 | 0.054040 | 0.093841 | 0.167442 |

R3较C多15.7112µs/请求（73.92%）、p95多0.018560ms；Rs较R3多2.0959µs（5.67%）。这些差距保留，不以低于旧48.261µs的中间候选掩盖相对新C余差。完整无A27窗已结束，逐窗回拷SHA+metadata验证和prune全完成；汇总`E/M6B/baseline-70097c66/no-a-27-analysis.{json,windows.csv,comparisons.csv}`每profile每组三组各1轮，工具标formal_complete=false表示不足最终135五轮，并非此27窗任务未完成。各组case/源/所有attempt不挑选，显著分类仍未证明。

## TCP方案A及内存

按[M6B_TCP_MEMORY_DESIGN.md](M6B_TCP_MEMORY_DESIGN.md)第5节执行，推荐A仍只在独立worktree。内容块/名字索引分片共享，连接保留私有小型LRU；每个mutator先detach，S1–S8语义及逐query导回不能改变。旧分支的原语/布局数字不冒充新70097基线上fresh资格；新原语、视图隔离、服务、资源/生命周期、压力与CPU门尚未完成。

独立初版5f3d42b4仍使用`HashMap<Arc<[u8]>, Vec<usize>>`，没有已实现的inline/Many共享；旧 all64 shard detach实测368,000B/4,224次分配，包含4096个singleton Vec（32,768B）和64 HashMap backing＋64 shard Arc（335,232B）；content detach296,960B/128分配。设计§4要求的有序Empty/One内联＋Many共享helper与高位shard正在独立补齐，随后重新跑全部fresh门，不把初版或旧测量当最终A资格。

当前结构模型为4096 snapshot 66,560B（65KiB）、3次分配，20 views约1.27MiB；这是requested结构账，不是整体PSS，不是原先约32KiB的预测。generation仍u64。S8释放DNS状态不提前释放日志占有的slot，不在stale refresh结束前释放视图；不加入额外Box或accept分配。最终须给实际parent/view/content/index/pinned/live requested、峰PSS及0/1/5/15/60秒排空余额。

M6a报告的TCP12–29MiB原“after-drain”值保留原始数据并已加更正：runner当时仅检查C child=0，Rust仍有18–23/36–42 FD，尚未排空。设计复测实际排空后60s PSS约cache3840KiB、miss8660KiB；视图/缓冲已释放，余量含allocator驻留。新测量必须确认计数归零或完整空闲FD集合持续稳定，不能复用这两个诊断值代替最终结果。

## 正式结果与切换s

新基线、A增量及最终135窗口尚在执行/准备中。完整九场景结果、每轮成功/错误、p50/p95及CPU/正确请求、峰RSS/PSS、FD/thread/child、60秒idleCPU及波动分类将由冻结窗口填入。没有五轮证据不作“有收益/无显著差异/变差”结论；错误回答不算吞吐，不能平均掉尾延迟。是否值得切换s尚未有本轮结论。

## 失败、重跑与保全

| 记录 | 结果及处理 | 完整证据 |
| --- | --- | --- |
| 原UDP-only135 | 用户改为中间27后停止；已完成C窗与中止Rust窗保留，最终135仅最后候选一次 | E/M6B/formal-udp-only-386fa821 |
| 首超大wake窗口 | 作废；重复派生数组未完整保留，摘要/原SHA/sidecar保留，不能算通过 | E/M6B/controller-failures/retention-limitations.json |
| 早期baseline日志/误SHA日志 | 曾覆盖部分日志，有保全缺口，不能隐瞒或当新资格 | 同retention-limitations.json |
| service-4816 ARP立即FD | extra为瞬时/proc/net/if_inet6；改为完整FD集合3×20ms/最多2秒稳定守卫，fresh ARP过；未只sleep放宽数量 | E/M6B/full-archives/service-4816-03 |
| service-4816 DNSfiles | 107中21失败；修当前runnable后3e全过，7bdb再次107过 | E/M6B/full-archives/service-4816-04、service-3e1b-05/06、owner-7bdb-runtime |
| 旧同wake HUP | C新43/Rust旧42；117优先级修复后7bdb六caller全部过 | E/M6B/full-archives/same-wake-3e1b-01、owner-7bdb-runtime |
| startupFIFO测试fixture | Init首步是cache/hosts barrier，不是opened FIFO；修fixture到真实等待态后实际过，不改产品来迎合断言 | E/M6B/full-archives/wake-linux-7dc3-failed，b16b8d0c… |
| TCP transport错误断言 | C NoReply→EDE23→flags0 local answer为REFUSED5；修期望后43main全过，不放宽为2或5 | E/M6B/full-archives/owner-linux-2c28-failed，c51b7c33… |
| route保存缺口 | C2/Rust1真实失败；70097 basic两profile C/R2、forward1/稳定FD复闭 | E/M6B/full-archives/route-resend-7bdb-01，762fb38b…；route-7009-runtime，870c1ead… |
| route-clears C debug TCP | 前5执行，第6UBus metric Not found。精确C debug非fork也drop父UBus，旧UBUS_CONTRACT_PHASE已记；独立修统计fixture，最终前fresh重跑，不阻塞新基线/A | E/M6B/full-archives/route-7009-runtime；原失败不改为通过 |
| 被取消旧M5计数 | 准备/中止记录保留、未完成计数实测，不作根因资格，进程/namespace/cgroup清理 | E/M6B/full-archives/old-loop-failed-01、old-loop-cancelled-02及archive tag |

E=`private/dnsmasq-rewrite/evidence/`。所有列出的完整归档按SHA、类型、mode、uid/gid、纳秒mtime、symlink、device/whiteout和xattr核验后才prune。历史保全缺口单独列出，不降低后续标准。诊断scope内C TCP miss57普通timeout及fault各组60预期timeout也保留，不声称所有旧回答零错误。

## 最终验收、差异与待决策

最终固定链为44canonical族/68步骤→M2→perf guard→资源→压力→package→lifecycle；配方与未执行边界见[M6B_FINAL_ACCEPTANCE_RECIPE.md](audits/M6B_FINAL_ACCEPTANCE_RECIPE.md)。perf guard将冻结20客户端UDP p50≤1ms、60秒idleCPU与真实hold20 TCP峰PSS的具体cap/basis；当前cap尚未取得最终实测，不称通过。最终交付强制opt3/feature-off，同一ELF验证所有受影响M5、M2、满4096缓存RSS/300秒资源、ENOSPC/EMFILE与APK安装升级卸载回滚。

既有故意差异见[账本差异总表](DELIVERY_LEDGER.md#与-C-的行为差异)及[M5_BEHAVIOR_DIFFERENCES.md](M5_BEHAVIOR_DIFFERENCES.md)。169项不能有M6b新增差异。最终ELF/APK、满载RSS与M4/M5比较、逐族体积归因和全部fresh资格尚未完成，不能请求体积或M7决定；完成最终报告后再请用户决定是否切换s、是否接受本轮增量及是否进入M7。

## 独立方案 A 已完成的前置门

独立A源码为 `d8ddb22b3dcd3cce2eae44b0941f5c4095800b3c`，仍未合main。Oracle复制测试ELF的实际日志为库751通过、20 ignored（不计通过）；main首次51通过/1失败，使用独立TMPDIR重跑同复制ELF后52通过；UBus68通过。feature-off opt3产品ELF为1,957,928B，SHA `924bdfc240f1ef811c8eacb4035a7476f8581166469144b6e4a22a01449a2c71`，比无A 70097c66 opt3增加8,192B（0.42%）。这些结果仅确认构建和上述测试，不代表镜像服务门、资源门或CPU门通过。

实际Rust crate基础原语已完成：core21场景/22,571条命令、policy29场景/471条命令、EDNS155条命令（143 queries）、lease70场景/1,876条命令比较，均零差异/失败。core只归一化不同generic RR类型之间的相对次序；类型内顺序、值、expiry、negative、TTL、stale精确比较。完整raw result.json已核实70场景，初始日志打印剔除cases时未冒称该场景数。四组原语明确没有镜像C守护进程资格：core使用精确hash的C函数提取和ASan/UBSan；其余组为新编译driver链接匹配源版本的既有native C对象，没有重建全部C对象。

目标机layout探针实际执行1个指定ignored测试、exit0，同复制ELF前后SHA相同，collector再次核验所得JSON逐字节相同。4096条snapshot为66,560 requested B/3 allocations；全部名字索引分片detach为243,264B/128 allocations，全部内容块detach为296,960B/128 allocations，child drop为−606,784B，三个净值平衡。singleton零分配、Many clone零分配、首次共享rotation72B/2 allocations、unique rotation/remove零分配。视图隔离正控33/33；五负控均触发指定真实测试失败：discard content/index各4、禁rotation3、保留expired reverse2、reuse generation3。探针与负控是诊断门，不是产品PSS/CPU资格，不能替代内部余额10批、S1–S8镜像服务、资源/生命周期、压力或45窗CPU门。


完整身份及失败记录见[独立A证据核对](audits/M6B_A_D8_EVIDENCE_REVIEW.md)。以上是阶段资格，全部门过之前不合主线。

fresh transfer已通过36个case、307个状态；fresh native C半pipe EOF171检查通过，但Rust旧`dns::tcp_transfer::partial_eof_tests`入口已经随单owner直传退休，误用此测试器得到0 tests并因缺输出报FileNotFound，红证据保留。现产品每query使用完整`CacheTransaction`同步capture/import，无byte Receiver；不得为通过旧工具重新引入废弃transport。C cache.c952–1056的父子pipe半截读失败仍保留原始C观察，不当成现A存储的可注入故障；实际网络上游EOF及fail-prefix/import合同分别由服务和现Cache原语验证。

fresh answer补充对照实际764条命令、164个query、382个metric snapshots零差异。最初build-reference仅构建C未跑比较，fresh-answer-03把配置当positional参数导致C exit1；fresh-answer-04用真实-C配置入口重跑通过，全部失败保留。初始门全量归档tar `1ac1eee5a1b259c66929e928b017da36008fae59bbf45a32409408eea332663f`，10515路径/9753文件SHA及全部元数据已本地通过，snapshot staging已删除，活跃产品源/ELF保留。reverse首次探针仍用旧Slot.entry/usize链接，编译报3处错误；仅工具4938efad改为现Cache::entry/slot_index，新private cfg(test)源码和统一probe-tests正在重建，不是产品功能失败。

## fresh reverse 导入发现的既存缺陷（处理中）

fresh C reverse21case/126进程完成，20稳定case184观察、ordering12观察；A copied lib的稳定观察181匹配/3差异，全在PTR target恰为父配置CNAME。ordering12全匹配。root以70097无A冻结ELF在同镜像补真实caller：UDP C/R均1上游、插入1、后两请求缓存续答；TCP C只需1上游并插入1，Rust首次父插入0、下一UDP再次上游，累计2次。这是当前基线也存在的普通导入方向错误，不归因为A共享存储，不改变ordered comparator或列作故意差异。cache-rr选项资格暂重开1项（cache-size容量资格保留），修复与fresh服务复闭后恢复169。

无A的70097完整27窗口原始数据保持历史；A增量45窗口将给无A和A同时带相同方向修复，保证共享存储增量独立归因，不重新扩中间27窗口。新的source/ELF与门收据在修复freeze时登记。计数companion04方法六tests实际通过、目标机布局相符，SHA937a06612edbfd25e37972496bd3d90046cbcf53c5590f6e643ff4ee0c47db84；仅方法控制，不代表10批余额/产品资源/CPU门。其build SSH -n通道同样在远端实际结束后滞留，本地核对无匹配build进程及完整收据后终止owned15785，wrapper255单列保留，不能冒充runtime失败。

方向修复main1bd9436c、独立A ae1cdba6只在Cache::import_counted跳过reverse的forward-local callback，新增IPv4/IPv6及forward冲突精准测试，尚待新ELF镜像复闭。新pair第一准备因controller在scp结束前读source tar触发Unexpected EOF，首次raw和controller保留；第二fresh目录先逐tar SHA核对，再解包/构建，不覆写首失败或放宽验证。
