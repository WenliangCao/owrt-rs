# 九组件优化收尾索引（2026-09-28）

本索引汇集已有工程结案，不重新运行前八项。每项的接受取舍、未通过旧性能门及缺测仍由对应原报告保留；隔离验证不等于九组件组合部署验收。生产仍是精确 OpenWrt 25.12.5 镜像，未部署、刷写、重启或替换生产进程。

> 编辑状态：前八项索引已核对；reload-config 正式构建和最终四側门完成后，由本轮主报告补齐末行与正式来源，再明确关闭整轮。

这里的“本体定版”是组件研究保留的源码提交；其后共享 UCI/ubus 的重建使用整个仓库的正式源码快照。下表正式产物暂列最新已完成 UCI 的 [canonical run 36485630189](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36485630189)，源 `feb7a4ee2265a8e7207094764f1c8b41d69fe3bb`，完整身份由[验证JSON](uci-20260928-validation.json)核验。它们不能覆盖各研究原实机 ELF 的身份或把历史成绩迁到新 ELF。

| 组件／保留方案 | 本体定版源码 | 最新正式ELF SHA256／字节 | 报告与证据入口 | 已接受取舍和明确缺口 |
|---|---|---|---|---|
| ubusd R136 | `195e45f2ef32efa734bfa33b0b5ae7109a747b3f` | `494c5c0a37fbbaa766bff7c52233927189528bfff74e71a8faec375552a87c92`<br>516,072 B | [结果](R136_UBUSD_COMPLETION_RESULT.md)、[正确性](R136_CORRECTNESS_RESULT.md)、[构建差异](R136_BUILD_IDENTITY.md) | 注册/对象事件4项慢尾仍为负；1 KiB扇出匿名增量+12 KiB、断开保留+16 KiB。原 completion-01 FAILED 保留。实机研究ELF为 `ce3d1aa…de2330`，当前正式重建不能继承该ELF逐字身份；源码绝对路径也会改变布局。 |
| netifd H10 | `dc055aee2d576599699c52479bd58c0566584626` | `b37b80e19d26e5ef5d47a43f02ce4a5727d9957b992d299121d81e359dcf95b9`<br>1,069,120 B | [工程结案](NETIFD_20260927_ENGINEERING_RESULTS.md)、[全指标](NETIFD_20260927_ALL_METRICS.md)、[UCI共享回归](UCI_20260928_SHARED.md) | 9项 UNRESOLVED、44项单对越门、3项资源 FAIL 保留。事件cycle对R89 p95 +72.205 ms/+10.385%、p99 +131.308 ms/+17.764%；原严格门未全过。研究实机canonical为 `4c042050…c41ad`；最新UCI只补实际消费者回归，不重做原矩阵。 |
| httpd H12 | `ba37d2c557a3d695a5c3bbce931732ed9f1aa0f7` | `1ed3ed327f967dd920a33bea79322d5ceb1b60de48eb51c9ec4aef8bb86e42d2`<br>1,608,447 B | [工程结案](HTTPD_20260928_RESEARCH.md)、[候选与不利项](httpd-20260928-candidates.json) | CGI对R89 CPU +9.30 µs/+1.31%、mean +56.14 µs/+2.60%；关闭后RSS对C/R89 +72/80 KiB。密集转义微基准对H2 +20.32 µs/+14.36%；设备未测该专项。三侧实机不是整栈或全部TLS分布性能证据。 |
| fw4 H13 | `a88e443a7a521e489bfb42154ee6d07ffe1a7354` | `b591092ca432813452917a84d7c858fa8604a9171bfbb8523b9e3681b5c6d8f1`<br>1,034,963 B | [工程结案](FW4_20260928_RESEARCH.md)、[候选与不利项](fw4-20260928-candidates.json)、[UCI共享回归](UCI_20260928_SHARED.md) | Oracle普通check树CPU +1.08%、p99 +5.12%，一窗p99 +10.80%；print最大RSS +4 KiB。设备fw4/nft CPU未分离、树并发RSS峰值缺测；tmpfs不代表flash。原研究ELF `dce40da2…9a614` 与最新UCI重建分开。 |
| rpcd H1 | `7a005811497b34a14bff9f64c3fcdf6fd5798ea2` | `270cb15153173843efcc55fdc0a8e6735103ca38b27c6ee4c75417380666ac71`<br>1,256,211 B | [工程结案](RPCD_20260928_RESEARCH.md)、[全指标](RPCD_20260928_BENCHMARKS.md)、[UCI共享回归](UCI_20260928_SHARED.md) | 24项中并非全胜；LuCI devices对C CPU约+0.171 ms、mean约+0.189 ms；十轮销毁后RSS对R89 +80 KiB/+6.56%。PSS/USS、部分readiness wait缺测；原正式研究ELF `158031f2…cc309`，后续UCI重建另有门。 |
| procd H1 | `349d42a13d360ca84708190528c11f0e45b115db` | `8eb463b484e4e646e7ea1b1d140a1ea8ccd5bcc0a5e838fcef54e5058c0980bf`<br>876,536 B | [工程结案](PROCD_20260928_RESEARCH.md)、[四侧指标](PROCD_20260928_METRICS.md) | 真实实例字段查询CPU对C/R89 +59.479 µs/+10.65%、+25.815 µs/+4.36%；list32/128四并发部分等待增加。大于约2 TiB的meminfo既有数值边界；无真实硬件watchdog、生产PID1或冷启动验收。 |
| LOGD | `386771659d127c20386b59614d3a82e0406f1e84` | `c45ad7d8e69e66b81f833330597e4ffb8cdce0c0b42ba416b0a820bd3a8a2f75`<br>432,827 B | [工程结案](LOGD_NEXT_RESEARCH.md)、[候选索引](LOGD_NEXT_CANDIDATES.md) | 设备syslog CPU未证实超出R94的稳定新增收益；历史follow_8对C CPU反例保留。pipe实际容量/物理页缺测，RSS不能代替；本轮未将既有多读者Oracle证据冒充新设备实验。 |
| UCI | `feb7a4ee2265a8e7207094764f1c8b41d69fe3bb` | `336164c7b49908a356eccf934e40528398811ff2595e2b926170278a15c5c506`<br>486,155 B | [工程结案](UCI_20260928_RESEARCH.md)、[四侧指标](UCI_20260928_BENCHMARKS.md)、[验证](uci-20260928-validation.json) | batch_read16对R89树CPU +208.158 µs/+2.47%，四轮均增；相对R94 set_commit_get/get/batch +0.50/+0.30/+0.51%。非UTF-8 rename明确拒绝为既有差异；短命maxrss不是整树并发峰值，commit只测tmpfs。 |
| reload-config | 待本轮正式源码 | 待本轮正式APK实际提取ELF | 本轮研究／四侧／验证报告待补 | 待正式候选门完成；不得把未完成门写为通过 |

历史实测与当前产物不同时，保留两份身份。netifd、fw4、rpcd 的后续 UCI 正式重建已经通过定向共享功能及 Oracle 增量回归，详见[共享消费者报告](UCI_20260928_SHARED.md)；未重新开启三者设备全量矩阵。HTTPD 共享 ubus 修改后的其他消费者合同子集见其结案报告，部分门明确为选择运行。UBUSD R136 的路径敏感构建身份及原 SDK ELF仍由原报告保存。

工程结案允许已量化且可接受的局部性能代价；不豁免事件、权限、隔离、恢复或身份错误。本轮研究结果不授权后续生产切换。
