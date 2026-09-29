# 九组件优化收尾索引（2026-09-29）

时点说明：下文记录组件优化研究结案时的状态。后续经用户授权完成了[最终九组件整栈实测](STACK_20260929_ASSESSMENT.md)：C₁/Rust 完整有效，两个 C₂ 窗口在输出校验处中止，现已恢复原 C 运行状态。新增整栈证据及其限制以该报告为准，历史专项成绩和缺口仍保留。

后续复核：这五次启动均为软件重启，断电恢复尚未测试；内存与 AES p99 的“已确认退步”判断已更正。netifd 前缀顺序的兼容问题已修复源码并补充回归测试，尚未重建部署；下列正式 ELF 身份和历史性能仍指原试验产物。

本索引汇集已有工程结案，不重新运行前八项。每项的接受取舍、未通过旧性能门及缺测仍由对应原报告保留；隔离验证不等于九组件组合部署验收。生产仍是精确 OpenWrt 25.12.5 镜像，未部署、刷写、重启或替换生产进程。

[reload-config 总验证清单](reload-config-20260929-validation.json) 已汇总通过的正式四侧设备窗口、功能/恢复/健康门和新共享库消费者回归。本轮九组件优化到此结束。未通过的旧性能门、接受的局部退步和缺测仍按下表保留，不扩大为部署或新一轮研究。

这里的“本体定版”是组件研究保留的运行时代码提交；最新正式产物统一来自 [canonical run 36491554447](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36491554447)，仓库源码 `43b98a138bea2b37713634c012a37a9d7186a20b`。七个 APK 和三个 core 产物中的实际静态 AArch64 ELF 身份列在下表；APK manifest SHA256 为 `b7b1ad3e3a906b18a1734eb248c79f7ccf76a187530c6f0dcb93a9df68ce3261`，core manifest 为 `a21aa7e179a595d24f72015c1e3ff350d86670feefa02e3a640f7f9b29b558ad`。各研究历史实测 ELF 的身份仍单独保留，历史成绩不转记到重新链接的产物。

| 组件／保留方案 | 本体定版源码 | 最新正式ELF SHA256／字节 | 报告与证据入口 | 已接受取舍和明确缺口 |
|---|---|---|---|---|
| ubusd R136 | `195e45f2ef32efa734bfa33b0b5ae7109a747b3f` | `494c5c0a37fbbaa766bff7c52233927189528bfff74e71a8faec375552a87c92`<br>516,072 B | [结果](R136_UBUSD_COMPLETION_RESULT.md)、[正确性](R136_CORRECTNESS_RESULT.md)、[构建差异](R136_BUILD_IDENTITY.md) | 注册/对象事件4项慢尾仍为负；1 KiB扇出匿名增量+12 KiB、断开保留+16 KiB。原 completion-01 FAILED 保留。实机研究ELF为 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`，当前正式重建不能继承该ELF逐字身份；源码绝对路径也会改变布局。 |
| netifd H10 | `dc055aee2d576599699c52479bd58c0566584626` | `0f9814c608e85dd863002007c967cebcce696fbcba624bbb5a33fe23e6637ec4`<br>1,069,120 B | [工程结案](NETIFD_20260927_ENGINEERING_RESULTS.md)、[全指标](NETIFD_20260927_ALL_METRICS.md)、[UCI共享回归](UCI_20260928_SHARED.md) | 9项 UNRESOLVED、44项单对越门、3项资源 FAIL 保留。事件cycle对R89 p95 +72.205 ms/+10.385%、p99 +131.308 ms/+17.764%；原严格门未全过。研究实机canonical为 `4c0420503a93dd33bd98ad9197bb8da156578fd012dda346507bff54645c41ad`；后续共享库重建只补相应消费者回归，不重做原矩阵。 |
| httpd H12 | `ba37d2c557a3d695a5c3bbce931732ed9f1aa0f7` | `76e8f50a8615c81d7b9827d4542d9fbdd72bdfff93326602f701cf04de42afaa`<br>1,612,543 B | [工程结案](HTTPD_20260928_RESEARCH.md)、[候选与不利项](httpd-20260928-candidates.json) | CGI对R89 CPU +9.30 µs/+1.31%、mean +56.14 µs/+2.60%；关闭后RSS对C/R89 +72/80 KiB。密集转义微基准对H2 +20.32 µs/+14.36%；设备未测该专项。历史实测ELF为 `1ed3ed327f967dd920a33bea79322d5ceb1b60de48eb51c9ec4aef8bb86e42d2`；三侧实机不是整栈或全部TLS分布性能证据。 |
| fw4 H13 | `a88e443a7a521e489bfb42154ee6d07ffe1a7354` | `f75a2c2a4c5b0579836a02607e4db0ac9b6e8938ae3a893a38d7cc2a531503ee`<br>1,034,963 B | [工程结案](FW4_20260928_RESEARCH.md)、[候选与不利项](fw4-20260928-candidates.json)、[UCI共享回归](UCI_20260928_SHARED.md) | Oracle普通check树CPU +1.08%、p99 +5.12%，一窗p99 +10.80%；print最大RSS +4 KiB。设备fw4/nft CPU未分离、树并发RSS峰值缺测；tmpfs不代表flash。原研究ELF `dce40da22acb56678010261a060e09b81e626494a92ebad0d40501a6a1e9a614` 与后续共享库重建分开。 |
| rpcd H1 | `7a005811497b34a14bff9f64c3fcdf6fd5798ea2` | `c798ea0dc6c7cdb9b408d2cef7f4e748a20987f576ba5f128c559bf568f9e841`<br>1,252,115 B | [工程结案](RPCD_20260928_RESEARCH.md)、[全指标](RPCD_20260928_BENCHMARKS.md)、[UCI共享回归](UCI_20260928_SHARED.md) | 24项中并非全胜；LuCI devices对C CPU约+0.171 ms、mean约+0.189 ms；十轮销毁后RSS对R89 +80 KiB/+6.56%。PSS/USS、部分readiness wait缺测；原正式研究ELF `158031f2382c832fc067f2d20e2a2683a877b8ff491723f4df869301f37cc309`；后续共享库重建另有门。 |
| procd H1 | `349d42a13d360ca84708190528c11f0e45b115db` | `3d4bfdfaa0e4ea035339b17d5ade1c14fcc59fff9d014b6aacc9e4a0dcff7f62`<br>876,536 B | [工程结案](PROCD_20260928_RESEARCH.md)、[四侧指标](PROCD_20260928_METRICS.md) | 真实实例字段查询CPU对C/R89 +59.479 µs/+10.65%、+25.815 µs/+4.36%；list32/128四并发部分等待增加。大于约2 TiB的meminfo既有数值边界；历史实测ELF为 `8eb463b484e4e646e7ea1b1d140a1ea8ccd5bcc0a5e838fcef54e5058c0980bf`；无真实硬件watchdog、生产PID1或冷启动验收。 |
| LOGD | `386771659d127c20386b59614d3a82e0406f1e84` | `24e3eccfc485f098e192e18ac5bc3ef8a4d6b7b91998a5db1e75956773bb53ec`<br>428,731 B | [工程结案](LOGD_NEXT_RESEARCH.md)、[候选索引](LOGD_NEXT_CANDIDATES.md) | 设备syslog CPU未证实超出R94的稳定新增收益；历史follow_8对C CPU反例保留。pipe实际容量/物理页缺测，RSS不能代替；历史实测ELF为 `c45ad7d8e69e66b81f833330597e4ffb8cdce0c0b42ba416b0a820bd3a8a2f75`；既有多读者Oracle证据不是新设备实验。 |
| UCI | `feb7a4ee2265a8e7207094764f1c8b41d69fe3bb` | `336164c7b49908a356eccf934e40528398811ff2595e2b926170278a15c5c506`<br>486,155 B | [工程结案](UCI_20260928_RESEARCH.md)、[四侧指标](UCI_20260928_BENCHMARKS.md)、[验证](uci-20260928-validation.json) | batch_read16对R89树CPU +208.158 µs/+2.47%，四轮均增；相对R94 set_commit_get/get/batch +0.50/+0.30/+0.51%。非UTF-8 rename明确拒绝为既有差异；UCI历史实测与本次正式ELF完整SHA相同；短命maxrss不是整树并发峰值，commit只测tmpfs。 |
| reload-config | `e106123f9e4121d56adb9f3ed83336181b7a9ebc`；canonical仓库源码为上列 `43b98a1` | `f8ab20df721780239fdcffe15e9d96950738623e490cbe531fe42cdb8d149553`<br>465,643 B | [工程结案](RELOAD_CONFIG_20260929_RESEARCH.md)、[四侧指标](RELOAD_CONFIG_20260929_BENCHMARKS.md)、[总验证](reload-config-20260929-validation.json)、[Oracle协议与恢复](reload-config-20260928-functional-validation.json) | 保留规范化缓冲/摘要小改动与顺序进程内投递、连接复用；每事件重新查找对象，失败/超时不重试，取消保留旧基线。实际单包/多包变更CPU对R94 −34.15%/−58.41%。首次/无变化/注释minor faults +3/+2.5/+3.5；首次/无变化依赖CPU +3.739/+1.355µs；首次p95/p99首对窗口增加。保留SDK pilot无变化CPU不利结果。R94原SDK ELF `e22deec64229a94745dbe30c8815368889b84061f9cc936ba829c4561551d9a4` 只作历史性能参考。基线位于tmpfs，保留sync_all/原子rename，不外推flash；接收器确认不代表下游服务完成重载。 |

与 UCI 收尾的 [run 36485630189](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36485630189) 对比，**UCI 和 UBUSD 两个正式 ELF 的完整 SHA256、字节数均相同**。这里的 UBUSD `494c5c0a…` 与 R136 原实测 SDK ELF `ce3d1aa2…` 是两个不同身份，不能混为同一产物；路径敏感构建说明仍适用。

NETIFD、HTTPD、FW4、RPCD、PROCD、LOGD 六个 ELF 在本轮共享 ubus 变更后重新构建，身份发生变化。表中的组件本体定版保持原结案选择，新链接 ELF 的定向功能/恢复回归由 [本轮总验证](reload-config-20260929-validation.json) 和 [七消费者11门结果](RELOAD_CONFIG_20260929_SHARED_GATE_PLAN.md) 记录；后者保留一次控制中断，功能门最终全部通过；它们没有重跑各自原来的完整性能矩阵，不能据功能门声明旧性能数字仍逐字适用于新 ELF，也不声称性能完全不变。reload-config 的本轮四侧成绩则绑定本次正式 `f8ab20df…` ELF。

更早的共享库变化仍按原证据解释：NETIFD、FW4、RPCD 在 UCI 收尾时实际重建并通过定向共享功能及 Oracle 增量回归，见 [UCI共享消费者报告](UCI_20260928_SHARED.md)；HTTPD 更改共享 ubus 后的其他消费者合同子集见其结案报告。该历史回归与本轮新库回归分别列证，不合并成一次整栈验收。

工程结案允许已量化且可接受的局部性能代价；不豁免事件、权限、隔离、恢复或身份错误。本轮研究结果不授权后续生产切换。
