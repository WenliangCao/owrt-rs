# R86：所有高于原版、低于原版或持平的事实清单

数据源：`R86_parts/results.json`、`summary.json`、`httpd_memory_router.json`。组件和整机数值为四舍五入前的中位数；百分比为 `(Rust/原版−1)×100`。

## 汇总计数

- 组件 74 项：mean 73 降低、1 上升；吞吐 73 提高、1 降低；墙钟时间 73 降低、1 上升。
- p50：71 降低、3 上升；p95：66 降低、8 上升；p99：66 降低、8 上升。
- 被测主体 CPU：73 降低、1 持平。依赖 CPU：30 降低、30 持平、14 上升。客户端 CPU：62 降低、2 持平、10 上升。

成功数、预热数和 TLS CPU 计数是协议相同的采集控制量：组件逐项 100% 成功，TLS 每项 1,000/1,000 成功（fresh-c1/c4 CPU 分母分别 1,010/1,040）；它们不作为性能回退。

## component 中较差或持平的逐项中位数

| 组件/负载 | 指标 | 原版 | Rust | 变化 |
|---|---|---:|---:|---:|
| `fw4/check` | `client_cpu_us_per_op` (持平) | 500 | 500 | +0.000000% |
| `fw4/check` | `dependency_cpu_us_per_op` (回退) | 600 | 850 | +41.666667% |
| `fw4/print` | `dependency_cpu_us_per_op` (回退) | 650 | 850 | +30.769231% |
| `httpd/static_1m_dat_c4` | `client_cpu_us_per_op` (回退) | 8545 | 8655 | +1.287303% |
| `logd/log_read_100` | `dependency_cpu_us_per_op` (回退) | 167.5 | 174.5 | +4.179104% |
| `netifd/device_status` | `dependency_cpu_us_per_op` (回退) | 86 | 89 | +3.488372% |
| `netifd/device_status_all` | `dependency_cpu_us_per_op` (回退) | 99 | 103 | +4.040404% |
| `netifd/device_status_all_c4` | `dependency_cpu_us_per_op` (回退) | 133.432539683 | 136.904761905 | +2.602230% |
| `netifd/device_status_c4` | `dependency_cpu_us_per_op` (回退) | 119.047619048 | 120.03968254 | +0.833333% |
| `netifd/interface_dump_32` | `dependency_cpu_us_per_op` (回退) | 152.5 | 176.5 | +15.737705% |
| `netifd/interface_dump_32_c4` | `client_cpu_us_per_op` (回退) | 1980 | 2000.5 | +1.035354% |
| `netifd/interface_dump_32_c4` | `dependency_cpu_us_per_op` (回退) | 191.468253968 | 200.892857143 | +4.922280% |
| `netifd/interface_named_32` | `client_cpu_us_per_op` (回退) | 110.5 | 113.5 | +2.714932% |
| `netifd/interface_named_32` | `p95_us` (回退) | 206.244 | 232.481 | +12.721340% |
| `netifd/interface_named_32` | `p99_us` (回退) | 338.623 | 361.09 | +6.634812% |
| `netifd/interface_named_32_c4` | `client_cpu_us_per_op` (回退) | 128.5 | 131.5 | +2.334630% |
| `netifd/interface_named_32_c4` | `p95_us` (回退) | 689.325 | 695.173 | +0.848366% |
| `netifd/interface_named_32_c4` | `p99_us` (回退) | 874.294 | 906.6865 | +3.704989% |
| `netifd/lan_status` | `client_cpu_us_per_op` (回退) | 117 | 118 | +0.854701% |
| `netifd/lan_status` | `dependency_cpu_us_per_op` (持平) | 51.5 | 51.5 | +0.000000% |
| `procd/service_list_128` | `client_cpu_us_per_op` (回退) | 1341 | 1354 | +0.969426% |
| `procd/service_list_128` | `dependency_cpu_us_per_op` (回退) | 109 | 121 | +11.009174% |
| `procd/service_list_128_c4` | `dependency_cpu_us_per_op` (持平) | 135.416666667 | 135.416666667 | +0.000000% |
| `procd/service_list_32` | `dependency_cpu_us_per_op` (回退) | 62 | 65.5 | +5.645161% |
| `procd/service_list_32_c4` | `p95_us` (回退) | 1336.6015 | 1355.9525 | +1.447776% |
| `procd/service_list_32_c4` | `p99_us` (回退) | 1788.6365 | 1818.798 | +1.686284% |
| `procd/service_list_named_128` | `client_cpu_us_per_op` (回退) | 41 | 42 | +2.439024% |
| `procd/system_info` | `client_cpu_us_per_op` (回退) | 143 | 143.5 | +0.349650% |
| `procd/system_info` | `dependency_cpu_us_per_op` (回退) | 56 | 63 | +12.500000% |
| `procd/system_info_c4` | `dependency_cpu_us_per_op` (持平) | 74.4047619048 | 74.4047619048 | +0.000000% |
| `rpcd/file_stat` | `client_cpu_us_per_op` (回退) | 53.7 | 53.9 | +0.372439% |
| `rpcd/session_access` | `p95_us` (回退) | 117.221 | 118.222 | +0.853943% |
| `rpcd/session_access` | `p99_us` (回退) | 209.552 | 210.4365 | +0.422091% |
| `rpcd/session_access_64` | `p95_us` (回退) | 112.6815 | 123.223 | +9.355129% |
| `rpcd/session_access_64` | `p99_us` (回退) | 212.8605 | 218.0155 | +2.421774% |
| `rpcd/session_access_c4` | `p99_us` (回退) | 471.079 | 474.8485 | +0.800184% |
| `rpcd/session_access_granted_c4` | `p50_us` (回退) | 254.371 | 256.41 | +0.801585% |
| `rpcd/session_access_granted_c4` | `p95_us` (回退) | 391.2125 | 396.945 | +1.465316% |
| `rpcd/session_access_granted_c4` | `p99_us` (回退) | 494.546 | 503.048 | +1.719153% |
| `rpcd/uci_configs` | `p95_us` (回退) | 215.5155 | 224.2865 | +4.069777% |
| `rpcd/uci_get_64_c4` | `client_cpu_us_per_op` (回退) | 1116 | 1146 | +2.688172% |
| `rpcd/uci_get_authorized` | `dependency_cpu_us_per_op` (回退) | 61.2 | 62.9 | +2.777778% |
| `rpcd/uci_get_network` | `dependency_cpu_us_per_op` (回退) | 59 | 61.4 | +4.067797% |
| `ubusd/lookup` | `p95_us` (回退) | 63.8625 | 66.247 | +3.733803% |
| `ubusd/lookup` | `p99_us` (回退) | 110.566 | 125.839 | +13.813469% |
| `ubusd/lookup_all_128` | `mean_us` (回退) | 1461.45088965 | 1465.3317466 | +0.265548% |
| `ubusd/lookup_all_128` | `ops_per_s` (回退) | 648.420132253 | 646.521280227 | -0.292843% |
| `ubusd/lookup_all_128` | `p50_us` (回退) | 1367.07 | 1373.341 | +0.458718% |
| `ubusd/lookup_all_128` | `wall_s` (回退) | 15.4221663585 | 15.467401485 | +0.293312% |
| `ubusd/lookup_c4` | `p50_us` (回退) | 142.189 | 143.113 | +0.649839% |
| `ubusd/lookup_c4` | `subject_cpu_us_per_op` (持平) | 23.3134920635 | 23.3134920635 | +0.000000% |
| `uci/set_commit_get` | `client_cpu_us_per_op` (持平) | 380 | 380 | +0.000000% |

## whole 中较差或持平的逐项中位数

| 组件/负载 | 指标 | 原版 | Rust | 变化 |
|---|---|---:|---:|---:|
| `all/log` | `client_cpu_us_per_op` (回退) | 1002 | 1052.5 | +5.039920% |
| `all/network` | `client_cpu_us_per_op` (回退) | 608 | 616.5 | +1.398026% |
| `all/procd` | `mean_us` (回退) | 467.35256205 | 472.10480885 | +1.016844% |
| `all/procd` | `p50_us` (回退) | 424.568 | 430.8905 | +1.489161% |
| `all/procd` | `server_cpu_us_per_op` (回退) | 298 | 354.5 | +18.959732% |
| `all/uci` | `client_cpu_us_per_op` (持平) | 400 | 400 | +0.000000% |

## mixed-lane 中较差或持平的逐项中位数

没有较差或持平的性能指标；4 个并发 lane 的吞吐、均值、p50、p95、p99 均提高。

## TLS 性能回退判定

相同 AES256-GCM 套件的四项均无回退。默认套件的 fresh-c4 吞吐/墙钟微小差异来自 20/s 限速器，精确值已在整机启动段列出。

## 单组件常驻采样中 Rust 数值更高的字段

这些字段是独立进程的 `/proc/status`/探针采样；RssShmem 从 0 增加代表映射口径变化，不等于同量独占物理内存。温度是同一设备窗口的环境读数，列出差值但不能据此归因于组件。

| 组件 | 字段 | 原版 | Rust | 变化 |
|---|---|---:|---:|---:|
| `httpd` | `RssAnon` | 126 | 128 | +1.587302% |
| `httpd` | `RssShmem` | 0 | 928 | n/a (原版为0) |
| `httpd` | `Threads` | 1 | 2 | +100.000000% |
| `httpd` | `VmHWM` | 1032 | 1310 | +26.937984% |
| `httpd` | `VmPTE` | 32 | 42 | +31.250000% |
| `httpd` | `VmRSS` | 1032 | 1060 | +2.713178% |
| `httpd` | `fds` | 8 | 8 | +0.000000% |
| `httpd` | `temperature_millic` | 62756 | 62984 | +0.363312% |
| `logd` | `RssShmem` | 0 | 328 | n/a (原版为0) |
| `logd` | `Threads` | 1 | 1 | +0.000000% |
| `logd` | `temperature_millic` | 61388 | 61540 | +0.247605% |
| `netifd` | `RssShmem` | 0 | 920 | n/a (原版为0) |
| `netifd` | `Threads` | 1 | 1 | +0.000000% |
| `netifd` | `temperature_millic` | 62072 | 62148 | +0.122438% |
| `procd` | `RssShmem` | 0 | 784 | n/a (原版为0) |
| `procd` | `Threads` | 1 | 1 | +0.000000% |
| `rpcd` | `RssShmem` | 0 | 1052 | n/a (原版为0) |
| `rpcd` | `Threads` | 1 | 1 | +0.000000% |
| `rpcd` | `temperature_millic` | 62072 | 62224 | +0.244877% |
| `ubusd` | `RssAnon` | 144 | 154 | +6.944444% |
| `ubusd` | `RssShmem` | 0 | 456 | n/a (原版为0) |
| `ubusd` | `Threads` | 1 | 1 | +0.000000% |
| `ubusd` | `temperature_millic` | 62148 | 62148 | +0.000000% |

## HTTPD 64 保持连接内存

| 字段 | 原版 | Rust | 变化 |
|---|---:|---:|---:|
| `before.VmPTE` | 32 | 32 | +0.000000% |
| `before.Threads` | 1 | 2 | +100.000000% |
| `held.VmRSS` | 1478 | 2940 | +98.917456% |
| `held.RssAnon` | 566 | 2008 | +254.770318% |
| `held.VmHWM` | 1478 | 2940 | +98.917456% |
| `held.VmPTE` | 34 | 294 | +764.705882% |
| `held.Threads` | 1 | 66 | +6500.000000% |
| `after_close.VmHWM` | 1278 | 2848 | +122.848200% |
| `after_close.VmPTE` | 34 | 36 | +5.882353% |
| `after_close.Threads` | 1 | 2 | +100.000000% |

## 整机空闲前/后资源中 Rust 较差字段

两侧各两次启动；以下是按实现合并后的中位数。

| 阶段/字段 | 原版 | Rust | 变化 |
|---|---:|---:|---:|
| `idle_before.MemFree` | 148546 | 135650 | -8.681486% |
| `idle_before.memory_available_kib` | 137912 | 132050 | -4.250537% |
| `idle_before.system_memory_kib.Cached` | 21920 | 35732 | +63.010949% |
| `idle_before.system_memory_kib.Mapped` | 5524 | 8014 | +45.076032% |
| `idle_before.system_memory_kib.SReclaimable` | 6610 | 6628 | +0.272315% |
| `idle_before.system_memory_kib.SUnreclaim` | 20956 | 21270 | +1.498378% |
| `idle_before.system_memory_kib.KernelStack` | 1608 | 1696 | +5.472637% |
| `idle_before.system_memory_kib.PageTables` | 840 | 864 | +2.857143% |
| `idle_after.MemFree` | 142810 | 130498 | -8.621246% |
| `idle_after.memory_available_kib` | 132214 | 126940 | -3.988988% |
| `idle_after.temperature_millic` | 60020 | 60172 | +0.253249% |
| `idle_after.system_memory_kib.Cached` | 26186 | 39934 | +52.501337% |
| `idle_after.system_memory_kib.Mapped` | 5540 | 8014 | +44.657040% |
| `idle_after.system_memory_kib.SReclaimable` | 6686 | 6706 | +0.299133% |
| `idle_after.system_memory_kib.SUnreclaim` | 20562 | 20880 | +1.546542% |
| `idle_after.system_memory_kib.KernelStack` | 1592 | 1664 | +4.522613% |

## 整机空闲前进程诊断中 Rust 较高的字段

以下是 120 秒空闲采样、按实现两窗口合并的中位数；低基数 CPU、进程映射和线程数用于诊断，不能与组件隔离主体 CPU 或独占物理内存混用。

| 进程/字段 | 原版 | Rust | 变化 |
|---|---:|---:|---:|
| `procd.cpu_one_core_pct` | 0.008333333333 | 0.041666666667 | +400.000000% |
| `httpd.RssAnon` KiB | 240 | 380 | +58.333333% |
| `httpd.VmPTE` KiB | 36 | 52 | +44.444444% |
| `httpd.Threads` | 1 | 5 | +400.000000% |

## 整机启动、存储与运行兼容事实

- 客户端首次 SSH：原版两窗 40.254267916、50.258638209 s；Rust 两窗 50.257931500、50.270089375 s。按侧中位数为 45.256453062→50.264010438 s（+11.064847%）。这是约 10 秒轮询观测。
- 健康确认总耗时按侧中位数：原版 271.568146312 s，Rust 273.777201230 s（+0.813444%）；四窗均连续健康至少180 s并追加30 s。
- overlay 启动前存储：原版 used 20,408 KiB / available 38,424 KiB 与 20,408 / 38,428；Rust 21,664 / 37,172 与 21,672 / 37,160。对应 Rust 多占 1,256/1,264 KiB，可用少 1,252/1,268 KiB。
- 九个入口文件总大小：原版 520,451 bytes，Rust 7,598,474 bytes；增加 7,078,023 bytes（+1,359.978749%）。此比较不含原版共享库/ucode/TLS依赖闭包，也不表示可删除空间。
- 最终 APK/部署归档大小 7,357,210 bytes；原 R84 包和原件保留用于自动回退。
- HTTPD 资源耗尽门：限制期原版接受 3/3 个请求，Rust 接受 0/3；解除限制后两者各成功 4 个请求，连接槽和 fd 均恢复；两侧进程均存活。
- HTTPD fuzz 133 个案例：Rust 无新增相对最终基线的候选变化；但相对原版仍保留 22 个既有差异（见下一节）。

整机 HTTPD 的四项默认 TLS 受同一 20/s fresh 限速器约束；该项 Rust 吞吐比原版低 0.002790%（19.9993102067 vs 19.9998681329/s）、墙钟时间高 0.002790%（50.001724604 vs 50.000329708 s），属于限速计时诊断。相同 AES256-GCM 套件的四项没有回退。

## HTTPD 与原版的 22 个既有协议/畸形输入差异

这些是精确行为差异；有些是 Rust 更早拒绝畸形输入，不能全部称为性能回退。

| 案例 | 原版 | Rust |
|---|---|---|
| `cgi-pathinfo-nul` | HTTP/1.1 500 Internal Server Error; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `chunked-bad-size` | HTTP/1.1 200 OK; closed=True | HTTP/1.1 400 Bad Request; closed=True |
| `chunked-huge-size` | HTTP/1.1 200 OK; closed=True | empty/no response, closed=False |
| `connect` | HTTP/1.0 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `header-ctrl` | empty/no response, closed=False | HTTP/1.1 200 OK; closed=True |
| `header-no-colon` | empty/no response, closed=False | HTTP/1.1 400 Bad Request; closed=True |
| `header-obs-fold` | empty/no response, closed=False | HTTP/1.1 400 Bad Request; closed=True |
| `http09` | HTTP/0.9 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `http12` | HTTP/1.0 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `http2` | HTTP/1.0 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `httpx` | HTTP/1.0 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `json-deep-array` | HTTP/1.1 200 OK; closed=True | HTTP/1.1 200 OK; closed=True |
| `lf-only` | empty/no response, closed=False | HTTP/1.1 200 OK; closed=True |
| `long-path-8k` | ConnectionResetError: [Errno 104] Connection reset by peer | HTTP/1.0 413 Request Entity Too Large; closed=True |
| `lowercase-method` | HTTP/1.0 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `method-only` | HTTP/0.9 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `percent-nul` | HTTP/1.1 200 OK; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `pipelined-bad-second` | HTTP/1.1 200 OK; closed=True | HTTP/1.1 200 OK; closed=True |
| `raw-space-in-path` | HTTP/1.0 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `tab-separated` | HTTP/0.9 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `trace` | HTTP/1.0 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |
| `unknown-method` | HTTP/1.0 400 Bad Request; closed=True | HTTP/1.0 400 Bad Request; closed=True |

## 统计口径与结论边界

- 依赖 CPU 和客户端 CPU 是诊断分项，不是被测主体 CPU；整机 procd 的 CPU 是六个守护进程 own counter 合计口径，不能直接与隔离 procd 单进程夹具比较。
- TLS 默认协商套件不同（原版 CHACHA20-POLY1305，Rust AES256-GCM）；相同 AES256-GCM 补测才是严格同套件比较。fresh 请求限速 20/s，因此默认 fresh-c4 吞吐 −0.002790% / 墙钟 +0.002790% 是限速器计时噪声，不是可归因的服务回退。
- MemAvailable、Cached、Mapped、RSS、RssShmem、VmHWM、温度、启动时间受文件缓存、背景活动、轮询和采样口径影响；不等价于独占物理内存、PSS 或握手吞吐上限。
- 组件、整机、TLS 和兼容性证据均为有限场景；这些数据不证明所有输入无 bug。
