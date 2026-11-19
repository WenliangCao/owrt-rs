# audit110 round3 release candidate · 发版说明草稿 · 2026-11-19

**`release_qualified=false`。候选发布门槛尚未通过。**

本候选以v0.3.3（`1e25d61dc707833f97afa5a56148f4dbceb50ed3`）为行为基线，升级到Rust1.100.0与更新后的锁定依赖，保持OpenWrt内核、硬件驱动与执行面。最终产品为`1f9de983757880c14133998a5befcfdf1d4fafe5`；干净历史重组前后完整Git tree相同，components tree也与最终Oracle门禁受测树一致。完整逐项台账见`docs/reviews/AUDIT110_ROUND3_20261119.{md,json}`。

拟交付内容：

- HTTP请求体及CGI遇到短暂I/O错误时保留处理状态；parked TLS不会因空readiness丢连接。兼容测试继续覆盖PATH_INFO。
- DNS修正fatal startup日志、local ownership、label内分隔符、non-QUERY回复策略、relay出接口选择及hostsdir推断刷新。配置CNAME缓存链、relay hostname及N1 stale过滤标记/N2 UDP DO修复均已集成，最终DNS内容组为`f3c98f1b`。
- netifd修复reload自启动、协议IP过期与inactive状态、typed UCI、设备消失和自管桥清理；补齐offlink失败恢复、IPv6 assignment路由所有权和class。无线非有限数据不再在teardown abort，编码遵循ucode；删除排队radio后仍执行旧setup再推进后继。
- odhcpd分离refresh与reply容量，并使混合/0、/32、/60来源产生全部有效PD前缀。C/base/fixed的前缀数为3/2/3；修复的合同是前缀、长度及寿命集合等价，**不承诺包字节或同preferred时的排列相等**。
- logd满环历史读取不再使Rust abort；正常stream、lines参数与后续恢复保持合同。**有意不仿造C被正文覆盖的损坏历史头，因此该损坏状态下默认history与C并不严格相等。**
- fw4、uci、procd与rpcd保留已有C合同测试；这些测试不是新增产品故障修复。唯一保留的性能改动是iwinfo重复查询去重及首次调用顺序修订，perf内容已归入`1f9de983`。

本轮决策已收齐：39个候选提交均有盲审映射，其中25项最初只读源码、14项有有界执行；19项旧待定最终采纳/修订采纳4项、关闭其余15项，剩余0。9项任务均有处理；DNS TCP65536与重复DHCP选项未观察到用户规定的abort/非法发送条件，决定不修。RA零lifetime、-S docroot、HEAD错误正文、CLOEXEC/rpcd信号顺序和netifd强杀旧helper依既定取舍不做。

最终Oracle全部门禁已通过（Linux aarch64、Rust1.100）：`make test check-rust fmt-check check-benchmark check-toolchain check-toolchain-negative check-tools check-harnesses`。原组件证据包括netifd 193测试及36次namespace运行、DNS最终分片883通过和23 ignored、ring公共接口及PD解码对照。**23项ignored未执行；源码推导、组件门禁与整机验收分开记载。** N1/N2由`95ce2040`、`8a3f2390`修复，经`4fb8a8cf`集成并重组至DNS组`f3c98f1b`；两项新测试在前修订均失败、最终均通过。N1仅验证Stale owner边界，没有新增真实上游刷新实验。最终DNS报告HEAD`54740216`及net报告已原样保全到主证据`closeout/`；详见台账S09/S10/S25/S26。

<!-- BEGIN round3-evidence -->

兼容边界包括 logd 有意保留的损坏历史差异、odhcpd PD 的集合等价及报文字节差异，以及已有的 netifd typed 配置和 DNS 负缓存过滤差异。

**正式配方 A/A。** 通过，3 组 45 窗。 CPU、时延、吞吐量、RSS、匿名内存和空闲指标的已测区间全部重叠。 见 `device/aa-result.json`。

| 负载 | 窗数 | CPU 中位变化 | P50 中位变化 | 吞吐量中位变化 |
| --- | ---: | ---: | ---: | ---: |
| 低负载 DNS | 15 | +0.592% | +2.882% | +0.000% |
| 饱和 DNS | 15 | +1.944% | +1.071% | -2.873% |
| 6 个 DHCPv4 客户端 | 15 | -4.034% | -2.920% | +3.605% |

A/A PGO 生成 [44603802652](https://github.com/WenliangCao/owrt-rs/actions/runs/44603802652)，训练覆盖 11 个场景、50 份原始 profile。

| PGO 产物 | Transport CI | Use CI | Profile SHA256 | ELF SHA256 |
| --- | --- | --- | --- | --- |
| aa | [44607652850](https://github.com/WenliangCao/owrt-rs/actions/runs/44607652850) | [44607990145](https://github.com/WenliangCao/owrt-rs/actions/runs/44607990145) | f6a8dfed8230a70522d22ba2a3c38a2404c97c24b6d38a97bac7fa13037bbed1 | f6bd7dc0906a61a44ab82dd1cf5e91a168b41cd3db02ea9b7c69bc68718a6c53 |
| toolchain | [44613768533](https://github.com/WenliangCao/owrt-rs/actions/runs/44613768533) | [44613984164](https://github.com/WenliangCao/owrt-rs/actions/runs/44613984164) | a3914aa437b23c929fc16c5ad4adec7a8284c9523288bbca79340c53d8595149 | 1c894234ad2b88f57f8193fd53571867b76444fa98535299e50786120d49b6c8 |
| final | [44614899005](https://github.com/WenliangCao/owrt-rs/actions/runs/44614899005) | [44615067016](https://github.com/WenliangCao/owrt-rs/actions/runs/44615067016) | e01a17fbb1796809826be8d5b7155addfab777f58fa7d006b184cbbf61103550 | 882ce65bc5a1e4c192424a4c4e04daf10ef9b92acf096953a9c43005cf3a7048 |

**四方 ELF 体积（字节）。**

| 组件 | 线上 v0.3.3 | CI 重建 | 仅工具链 | 最终候选 | 工具链相对重建 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `dnsmasq` | 2,321,243 | 2,321,243 | 2,313,179 | 2,317,275 | -8,064 |
| `fw4` | 1,051,347 | 1,051,347 | 1,043,283 | 1,043,283 | -8,064 |
| `httpd` | 1,620,727 | 1,620,727 | 1,629,047 | 1,629,047 | +8,320 |
| `logd` | 432,819 | 432,819 | 424,755 | 424,755 | -8,064 |
| `netifd` | 1,105,976 | 1,105,976 | 1,097,920 | 1,118,400 | -8,056 |
| `odhcpd` | 807,032 | 807,032 | 803,064 | 803,064 | -3,968 |
| `procd` | 897,016 | 897,016 | 888,960 | 888,960 | -8,056 |
| `reload-config` | 465,643 | 465,643 | 465,771 | 465,771 | +128 |
| `rpcd` | 1,280,803 | 1,280,803 | 1,285,027 | 1,276,835 | +4,224 |
| `ubusd` | 524,280 | 524,280 | 512,120 | 512,120 | -12,160 |
| `uci` | 490,251 | 490,251 | 482,187 | 482,187 | -8,064 |

最终 `reload-config` 为 465,771 字节，512 KiB 门槛通过，余量 58,517 字节。

**四方真机结果。**
证据未齐。完成 9/17 项，已分析 180/340 窗。 使用全部窗的最小值和最大值，区间相接视为重叠。发版门槛比较最终候选与线上。

数值为中位数 [最小值, 最大值]。`dhcp6` 表示 6 个 DHCPv4 客户端。

| 负载与指标 | 单位 | 线上 v0.3.3 | CI 重建 | 仅工具链 | 最终候选 | 工具链对重建 | 最终对线上 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| fourway-uci `export_64.p50_us` | µs | 2209.55 [2172.92, 2299.03] | 2224.86 [2186.54, 2244.56] | 2205.93 [2153.76, 2225.86] | 2216.63 [2176.31, 2322.27] | -0.851% | 重叠 +0.320% |
| fourway-uci `export_64.throughput` | ops/s | 420.182 [410.458, 429.875] | 417.13 [410.918, 423.398] | 425.684 [414.767, 428.39] | 422.722 [345.315, 425.393] | +2.051% | 重叠 +0.605% |
| fourway-fw4 `check.p50_us` | µs | 50067.6 [50018.2, 60019.7] | 50092.1 [50036.5, 59921.1] | 50126.5 [50065.7, 59661.3] | 57807.6 [50042.4, 59948] | +0.069% | 重叠 +15.459% |
| fourway-fw4 `check.throughput` | ops/s | 18.8856 [16.2664, 19.2524] | 18.3615 [17.7184, 18.71] | 18.2075 [18.035, 19.0464] | 18.0413 [16.678, 18.3703] | -0.839% | 重叠 -4.471% |
| fourway-reload-config `unchanged_config.p50_us` | µs | 3686.61 [3662.76, 3810.02] | 3750.01 [3648.37, 3875.11] | 3762.93 [3560.04, 3812.41] | 3721.54 [3517.64, 3770.7] | +0.345% | 重叠 +0.948% |
| fourway-reload-config `unchanged_config.throughput` | ops/s | 249.535 [236.714, 265.728] | 248.191 [233.898, 258.524] | 255.906 [237.214, 269.8] | 260.292 [240.769, 275.425] | +3.109% | 重叠 +4.311% |
| fourway-ubusd `invoke.p50_us` | µs | 98.178 [97.178, 98.409] | 97.717 [97.255, 99.178] | 97.947 [97.485, 98.486] | 98.64 [98.332, 99.64] | +0.235% | 重叠 +0.471% |
| fourway-ubusd `invoke.throughput` | ops/s | 9486.26 [9239.05, 9746.05] | 9486.75 [9011.98, 9549.04] | 9479.59 [9149.37, 9654.13] | 9379.55 [9110.29, 9510.26] | -0.075% | 重叠 -1.125% |
| fourway-logd `log_read_100.p50_us` | µs | 500.278 [487.967, 510.511] | 485.274 [484.504, 501.124] | 491.43 [481.735, 506.741] | 482.659 [479.965, 484.505] | +1.269% | 改善 -3.522% |
| fourway-logd `log_read_100.throughput` | ops/s | 620.506 [581.346, 635.076] | 633.119 [625.543, 642.867] | 623.245 [612.818, 642.795] | 633.382 [616.211, 647.718] | -1.560% | 重叠 +2.075% |
| fourway-rpcd `file_stat.p50_us` | µs | 171.119 [165.734, 171.581] | 176.198 [173.12, 198.665] | 179.967 [176.737, 188.739] | 172.658 [169.658, 186.507] | +2.139% | 重叠 +0.899% |
| fourway-rpcd `file_stat.throughput` | ops/s | 4814.65 [4664.97, 5228.63] | 4651.1 [3305.96, 4710.78] | 4517.51 [3990.78, 4673.4] | 4766.49 [4526.83, 4868.2] | -2.872% | 重叠 -1.000% |
| fourway-httpd `cgi.p50_us` | µs | 2552.02 [2516.09, 2604.95] | 2550.17 [2526.78, 2583.33] | 2557.25 [2528.93, 2595.18] | 2548.09 [2524.47, 2687.82] | +0.278% | 重叠 -0.154% |
| fourway-httpd `cgi.throughput` | ops/s | 381.045 [315.773, 384.435] | 379.898 [369.105, 381.897] | 379.404 [369.893, 382.031] | 380.186 [352.706, 383.926] | -0.130% | 重叠 -0.225% |
| fourway-procd `service_list_32.p50_us` | µs | 183.969 [182.353, 187.97] | 186.661 [182.584, 200.05] | 180.506 [178.275, 193.663] | 181.891 [178.891, 217.9] | -3.297% | 重叠 -1.130% |
| fourway-procd `service_list_32.throughput` | ops/s | 2170.25 [2029.75, 2239.49] | 1978.15 [1960.23, 2216.98] | 2223.32 [2000.92, 2268.94] | 2096.3 [1834.02, 2240.78] | +12.394% | 重叠 -3.408% |
| fourway-netifd `device_status.p50_us` | µs | 609.459 [603.611, 625.771] | 612.921 [606.843, 620.154] | 610.074 [607.766, 635.311] | 615.153 [612.306, 624.001] | -0.464% | 重叠 +0.934% |
| fourway-netifd `device_status.throughput` | ops/s | 1255 [1203.39, 1274.31] | 1186.74 [1163.85, 1265.24] | 1198.89 [1168.3, 1211.49] | 1223.56 [1205.92, 1258.81] | +1.024% | 重叠 -2.506% |

待补负载：`fourway-odhcpd`、`fourway-iwinfo`、`fourway-uci-memory`、`fourway-fw4-memory`、`fourway-reload-config-memory`、`fourway-dns200`、`fourway-dns-saturation`、`fourway-dhcp6`。各项缺证原因见 JSON。

**工具链影响。** 仅工具链与 CI 重建 v0.3.3 相比，单独估计 Rust 和依赖升级的变化。
已比较 150 个指标，10 个不重叠改善，7 个不重叠回退，133 个区间重叠。 JSON 记录每项中位变化，回退逐项列于下表。

**不重叠回退。** 最终候选对线上的回退阻塞发版。

| 对照 | 负载 / 指标 | 单位 | 新值中位 [min, max] | 基准中位 [min, max] | 变化 |
| --- | --- | --- | ---: | ---: | ---: |
| final_vs_shipped | fourway-logd `syslog_128.throughput` | ops/s | 54230.9 [49221.8, 55137.3] | 57977.5 [56783.9, 58504.2] | -6.462% |
| final_vs_shipped | fourway-httpd `static_16k.p95_us` | µs | 472.502 [442.109, 623.77] | 395.483 [368.399, 411.025] | +19.475% |
| final_vs_shipped | fourway-httpd `static_16k.subject_cpu_us_per_op` | µs/op | 149.694 [140.763, 167.647] | 132.18 [130.497, 134.765] | +13.251% |
| final_vs_shipped | fourway-procd `idle.VmRSS` | KiB | 940 [940, 944] | 880 [880, 880] | +6.818% |
| final_vs_shipped | fourway-procd `resident.VmRSS` | KiB | 940 [940, 944] | 880 [880, 880] | +6.818% |
| final_vs_shipped | fourway-netifd `idle.RssAnon` | KiB | 200 [200, 200] | 196 [192, 196] | +2.041% |
| final_vs_shipped | fourway-netifd `idle.VmRSS` | KiB | 1252 [1252, 1252] | 1248 [1244, 1248] | +0.321% |
| final_vs_shipped | fourway-netifd `idle.cpu_us_per_s` | µs/s | 39.2613 [35.0385, 42.8002] | 33.2153 [32.5616, 34.6614] | +18.202% |
| final_vs_shipped | fourway-netifd `resident.RssAnon` | KiB | 200 [200, 200] | 196 [192, 196] | +2.041% |
| final_vs_shipped | fourway-netifd `resident.VmRSS` | KiB | 1252 [1252, 1252] | 1248 [1244, 1248] | +0.321% |
| toolchain_vs_aa | fourway-fw4 `check.children_cpu_us_per_op` | µs/op | 13696 [13580.1, 14167.1] | 13466.1 [13413.5, 13532.7] | +1.707% |
| toolchain_vs_aa | fourway-logd `syslog_128.subject_cpu_us_per_op` | µs/op | 8.36377 [7.90173, 8.69879] | 7.81857 [7.71605, 7.88318] | +6.973% |
| toolchain_vs_aa | fourway-logd `syslog_128.throughput` | ops/s | 53448.7 [44976.1, 55143.3] | 58224.3 [57166.9, 59123.6] | -8.202% |
| toolchain_vs_aa | fourway-httpd `jsonrpc.p50_us` | µs | 933.385 [931.846, 936.771] | 926.384 [917.073, 930.847] | +0.756% |
| toolchain_vs_aa | fourway-procd `idle.VmRSS` | KiB | 944 [944, 944] | 880 [880, 880] | +7.273% |
| toolchain_vs_aa | fourway-procd `resident.VmRSS` | KiB | 944 [944, 944] | 880 [880, 880] | +7.273% |
| toolchain_vs_aa | fourway-netifd `interface_dump.subject_cpu_us_per_op` | µs/op | 68.0962 [67.5116, 68.7896] | 65.7417 [65.0087, 66.3929] | +3.581% |
| toolchain_vs_shipped | fourway-logd `syslog_128.throughput` | ops/s | 53448.7 [44976.1, 55143.3] | 57977.5 [56783.9, 58504.2] | -7.811% |
| toolchain_vs_shipped | fourway-rpcd `file_stat.p50_us` | µs | 179.967 [176.737, 188.739] | 171.119 [165.734, 171.581] | +5.171% |
| toolchain_vs_shipped | fourway-rpcd `file_stat.subject_cpu_us_per_op` | µs/op | 87.6447 [85.3063, 94.3388] | 80.6006 [74.7634, 82.8892] | +8.740% |
| toolchain_vs_shipped | fourway-procd `idle.VmRSS` | KiB | 944 [944, 944] | 880 [880, 880] | +7.273% |
| toolchain_vs_shipped | fourway-procd `resident.VmRSS` | KiB | 944 [944, 944] | 880 [880, 880] | +7.273% |
| final_vs_toolchain | fourway-uci `export_network.children_cpu_us_per_op` | µs/op | 752.46 [749.26, 755.45] | 733.49 [726.99, 739.68] | +2.586% |
| final_vs_toolchain | fourway-uci `export_network.p50_us` | µs | 1161.21 [1151.82, 1173.83] | 1140.13 [1131.97, 1144.21] | +1.849% |
| final_vs_toolchain | fourway-logd `syslog_128.p50_us` | µs | 17.004 [16.773, 17.158] | 16.62 [16.619, 16.697] | +2.310% |
| final_vs_toolchain | fourway-httpd `static_16k.p95_us` | µs | 472.502 [442.109, 623.77] | 396.714 [374.093, 408.101] | +19.104% |
| final_vs_toolchain | fourway-httpd `static_16k.subject_cpu_us_per_op` | µs/op | 149.694 [140.763, 167.647] | 130.047 [127.166, 135.511] | +15.108% |
| final_vs_toolchain | fourway-httpd `static_16k.throughput` | ops/s | 2540.71 [2185.46, 2778.59] | 2876.14 [2843.91, 2979.56] | -11.663% |
| final_vs_toolchain | fourway-netifd `idle.RssAnon` | KiB | 200 [200, 200] | 192 [192, 196] | +4.167% |
| final_vs_toolchain | fourway-netifd `idle.VmRSS` | KiB | 1252 [1252, 1252] | 1180 [1180, 1184] | +6.102% |
| final_vs_toolchain | fourway-netifd `resident.RssAnon` | KiB | 200 [200, 200] | 192 [192, 196] | +4.167% |
| final_vs_toolchain | fourway-netifd `resident.VmRSS` | KiB | 1252 [1252, 1252] | 1180 [1180, 1184] | +6.102% |
| final_vs_toolchain | fourway-netifd `wireless_status.p50_us` | µs | 104.026 [103.488, 115.644] | 103.102 [101.718, 103.179] | +0.896% |

**正式 CI 和固件。**

| Workflow | CI run | Runner SHA | 结果 |
| --- | --- | --- | --- |
| `ci.yml` | [44611708642](https://github.com/WenliangCao/owrt-rs/actions/runs/44611708642) | `8da8997053259ddaebf3f44b371e734393816087` | success |
| `core-safe-check.yml` | [44611704436](https://github.com/WenliangCao/owrt-rs/actions/runs/44611704436) | `8da8997053259ddaebf3f44b371e734393816087` | success |
| `dnsmasq-target-check.yml` | [44611713580](https://github.com/WenliangCao/owrt-rs/actions/runs/44611713580) | `8da8997053259ddaebf3f44b371e734393816087` | success |
| `dnsmasq-pgo-candidate.yml` | [44615067016](https://github.com/WenliangCao/owrt-rs/actions/runs/44615067016) | `b9f37d87b6c8016cb21fe3b0d426eabeb80d31a3` | success |
| PGO generate | [44611700552](https://github.com/WenliangCao/owrt-rs/actions/runs/44611700552) | `8da8997053259ddaebf3f44b371e734393816087` | success |
| `release-image.yml` | [44616018468](https://github.com/WenliangCao/owrt-rs/actions/runs/44616018468) | `db34b429d03be3130360cd39d848f49a4023edc2` | success |

固件 `openwrt-25.12.6-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin`（14,192,928 字节），CI artifact `owrt-image-25.12.6-db34b429d03be3130360cd39d848f49a4023edc2`（ID `14576066991`）。
SHA256 `5ba5d461c39939108346e9c15bc6154c3c8980d36e13be18a25ac28ee333b156`。镜像内 11 个 ELF 的摘要与四方最终输入一致。

**路由器最终验收。** 最终身份或健康收据缺失或未通过。

固件物理启动和刷机仍未执行。

待通过的门槛为 `four_way_complete`、`four_way_no_final_regressions`、`router_final_identity`。

发版说明草稿，未创建 GitHub Release。

<!-- END round3-evidence -->
