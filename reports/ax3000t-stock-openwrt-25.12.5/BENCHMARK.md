# Benchmark：Rust 实现 vs 原 C/ucode/shell 实现（AX3000T，2026-09-03）

> 同一台设备、同一时刻、同样输入。一次性程序并排跑（原版在 `/rom`），daemon 用 `owrt-*-switch` 短窗口切换。
> 脚本：`tools/bench_device_side_by_side.sh`（设备上）、`tools/bench_httpd.sh` + `tools/bench_http_client.py`（Mac 发压）、
> `tools/bench_swap_windows.sh`（logd/rpcd 切换）。原始输出 `private/bench/`。MT7981B 双核 A53，busybox `time` 计时。

## 1. 先说结论

- **fw4 规则生成快 10 倍**（205 → 19.5 ms）：原版是 ucode 解释器跑脚本，Rust 是原生二进制。这是唯一有"量级"差别的地方。
- **httpd 全面更快**：静态 +18–24%，`/ubus` JSON-RPC +18%，TLS +80%（rustls vs mbedtls），CGI 持平（瓶颈在 LuCI 本身）。
- **uci / rpcd 核心对象 / logd 写入：持平**。每次调用 3–5 ms，绝大部分是进程启动与 ubus 往返，两边一样。
- **Rust 慢的地方（第三轮时）**：rpcd 的 `iwinfo info`（28 vs 19 ms）与 `luci-rpc getWirelessDevices`（73 vs 49 ms），`logread` 全量输出
  （60 vs 26 ms），`uci export` 全量（8.0 vs 5.9 ms）。第四轮后全部消失：logread 是测量假象，其余由决策 0017（opt-level 3 + 静态）与 netlink 缓冲复用解决，见 §11。
- **reload_config 一开始慢 5.4 倍**（404 vs 75 ms）——benchmark 找出的真 bug：子进程等待用 10 ms 轮询，38 个子进程各吃掉
  一个时钟片。已改为阻塞等待（提交 bfc0645，owrt-reload-config r3），修复后数据见 §3。
- **体积**：Rust 二进制大一个量级（rpcd-rs 781 KB vs rpcd 62 KB + 6 插件 + libiwinfo ≈ 250 KB；httpd-rs 1.1 MB vs uhttpd 78 KB；
  fw4-rs 744 KB vs 3 KB 脚本 + ucode 运行时）。overlay 共用 2.4 MB / 60 MB，不是约束。
- **内存**：daemon RSS 同量级：rpcd-rs 1.46 MB **小于** rpcd 2.03 MB；httpd-rs 1.98 vs uhttpd 1.77 MB；logd-rs 1.16 vs logd 0.95 MB。

## 2. 一次性程序（N=100，fw4 N=20；per_op = 墙钟 / N）

| 用例 | 原版 | Rust | 比值 |
|---|---|---|---|
| `uci -S -n export network` | 2.60 ms | 2.80 ms | 1.08× |
| `uci -S -n export`（19 包） | 5.90 ms | 8.00 ms | 1.36× |
| `uci show firewall` | 3.50 ms | 4.00 ms | 1.14× |
| `uci get network.lan.ipaddr` | 2.80 ms | 2.80 ms | 1.00× |
| `uci set` + `commit`（scratch 目录） | 5.30 ms | 5.90 ms | 1.11× |
| `fw4 print` | 205.0 ms | 19.5 ms | **0.10×** |
| `fw4 check` | 263.5 ms | 74.0 ms | **0.28×** |
| `reload_config`（无变更，r1：10 ms 轮询） | 74.6 ms | 404.0 ms | 5.42× |

## 3. reload_config 修复后（owrt-reload-config r3，2026-09-03 已部署）

| 用例（N=100） | 原版 shell 脚本 | r1（10 ms 轮询） | r3（阻塞等待） |
|---|---|---|---|
| `reload_config` 无变更 | 78.5 ms | 404.0 ms | 96.1 ms |

r3 上线方式：`owrt-reload-config-switch disable` → `apk add` → `enable`；上线前后用 C 脚本与 r3 各跑一次无变更 run，
`/var/run/config.md5` 逐字节相同，trace 显示 19 个包比较、0 变更。剩余 18 ms 差距是 19 次 `uci show` + 19 次 `md5sum`
的 fork/exec 由 Rust 进程逐个等待（C 脚本同样 fork，但 shell 内建的管道少一次拷贝）；可以在进程内算 MD5 消掉 19 个 fork，
但那会偏离"与原脚本同一路径"的原则，暂不做。

## 4. httpd（Mac 发压，4 并发 × 400 请求，keep-alive；uhttpd 临时起在 8080/8443，参数与 httpd-rs 完全相同）

| 用例 | uhttpd req/s | httpd-rs req/s | uhttpd p50 | httpd-rs p50 |
|---|---|---|---|---|
| 静态 44 KB CSS | 1124 | 1326 | 3.41 ms | 2.74 ms |
| 静态 `/`（index） | 3355 | 4165 | 1.14 ms | 0.87 ms |
| CGI `/cgi-bin/luci/`（登录页 403） | 31.5 | 31.9 | 127 ms | 124 ms |
| `/ubus` JSON-RPC（getBoardJSON） | 987 | 1163 | 3.93 ms | 3.28 ms |
| TLS 静态 CSS | 528 | 949 | 7.08 ms | 3.63 ms |

macOS 自带的 `ab` 对这台设备每请求卡 140 ms（客户端问题），故改用 `tools/bench_http_client.py`。

## 5. logd（切换窗口）

| 用例 | C logd | logd-rs |
|---|---|---|
| 500 条 `logger` 写入 | 1.11 s | 1.12 s |
| `logread` 全量（约 750 行） | 26 ms | 60 ms |
| `ubus call log read lines=100` | 5.4 ms | 5.2 ms |
| RSS | 952 kB | 1156 kB |

## 6. rpcd（切换窗口，N=50；`ubus` CLI 往返约 3.8 ms 是下限）

| 方法 | C rpcd | rpcd-rs |
|---|---|---|
| `session list` | 3.8 ms | 3.8 ms |
| `uci get network` | 4.2 ms | 4.6 ms |
| `uci configs` | 3.8 ms | 4.2 ms |
| `file stat` / `file read board.json` | 4.0 / 3.8 ms | 4.0 / 4.0 ms |
| `luci getFeatures`（spawn 外部程序） | 227 ms | 204 ms |
| `luci-rpc getBoardJSON` | 4.0 ms | 4.0 ms |
| `luci-rpc getNetworkDevices` | 11.8 ms | 13.2 ms |
| `luci-rpc getDHCPLeases` | 4.6 ms | 5.6 ms |
| `luci-rpc getWirelessDevices` | 48.8 ms | 73.0 ms |
| `iwinfo info phy0-ap0` | 19.0 ms | 28.2 ms |
| `iwinfo assoclist phy0-ap0` | 6.8 ms | 7.2 ms |
| `network.rrdns lookup` | 4.0 ms | 4.0 ms |
| `rc list`（跑 31 个 init 脚本） | 1127 ms | 1137 ms |
| RSS | 2028 kB | 1464 kB |

## 7. 待办（性能，不是正确性）

- iwinfo/nl80211 路径每次调用多花约 9 ms：对照 C 的 netlink 请求次数，找多余的 dump（怀疑 phy 查询未复用）。
- `uci export` 全量慢 36%：19 个文件的读解析，看是否有多余的拷贝或未缓冲写（uci r3 后重测仍在，见 §9）。

## 8. 第四轮修复后（2026-09-03 晚，rpcd r6 / logd r3 / reload-config r4 上线）

| 用例 | 原版 | 修复前 Rust | 修复后 Rust | 改动 |
|---|---|---|---|---|
| `reload_config` 无变更（N=100） | 77.6 ms | 404 → 96 ms | **64.9 ms** | 一次 `md5sum` 处理全部文件（C 脚本也是一次，但 Rust 少一层 shell） |
| `ubus call file exec /bin/true`（N=50） | — | 轮询 10 ms 粒度 | 6.0 ms（≈ ubus CLI 3.8 ms + fork/exec） | 阻塞等待 |
| `ubus call iwinfo info`（N=50） | 19.0 ms | 28.2 ms | **24.0 ms** | 每线程复用 netlink 接收缓冲（原来每次 recv 分配并清零 64 KiB） |
| `ubus call luci-rpc getWirelessDevices` | 48.8 ms | 73.0 ms | **60.0 ms** | 同上 |
| `logread -l 400`（两边环内各 500 行，N=20） | 22 ms | — | **22 ms（相同）** | 原 60 vs 26 ms 是环内行数不同造成的假差距（每行约 50 µs 全在 logread 客户端自身）；沙箱 strace 帧长/系统调用相同。socketpair + BlobBuf 复用（logd r3）保留 |

进程内逐 op 对照（`rpcd-rs --iwinfo-bench` vs 同机 C libiwinfo 计时程序 `private/bench/iwbench.c`）：24 个 op 总计 Rust 28.1 / C 26.1 ms
（phy0），32.0 / 29.2 ms（phy1）；请求数相同（42 次 netlink），剩余差距集中在 `htmodelist`（1.25 vs 0.53 ms）与 `noise`（2.0 vs 1.5 ms）。

**顺带发现的非性能 bug**：apk 升级 owrt-rpcd 时，包的 postinst（设计为"安装即惰性"的 `switch disable`）被 apk 当作 post-upgrade
再次执行，设备静默切回 C rpcd、rpcd-rs 进入 crash loop（对象重复注册）。已用 `owrt-rpcd-switch enable` 恢复，并把六个包的 postinst
改为"boot-enable 打开时保持接管并重启/重挂载"（提交 9259153）。

## 9. uci r3（字节保真改造）上线后重测（2026-09-03 夜，N=100，含进程启动）

| 用例 | `/rom/sbin/uci` | `uci-rs` r3 | r2 时 |
|---|---|---|---|
| `export network` | 2.7 ms | 2.9 ms | — |
| `export`（19 包） | 5.9 ms | 8.0 ms | 8.0 ms |
| `show firewall` | 3.2 ms | 4.6 ms | — |
| `get network.lan.ipaddr` | 2.6 ms | 2.8 ms | — |

字节保真改造没有改变性能。`get` 显示进程启动开销两边相同（+0.2 ms），差距全在解析/导出：export 全量的工作量 5.2 vs 3.3 ms，
`show firewall` 1.8 vs 0.6 ms（show 路径整包 clone）。这是计划 A5 的剩余项。

## 10. A5 的答案：构建配置，不是解析器（2026-09-03 夜）

构建机上同源的静态 cargo 构建与 C uci 持平；设备上的差距来自 `opt-level = "z"` 与 `-crt-static` 关闭（动态链接）。
改为 opt-level 3 + 静态后（决策 0017），SDK 产出的 uci r4 在设备上从 `/tmp` 实测（N=100，含进程启动）：

| 用例 | C | r3（现网） | **r4** |
|---|---|---|---|
| `export`（19 包） | 5.9 ms | 7.2 ms | **5.5 ms** |
| `show firewall` | 3.1 ms | 4.0 ms | **2.7 ms** |
| `export network` | 2.7 ms | 2.9 ms | **1.9 ms** |
| `get network.lan.ipaddr` | 2.6 ms | 2.8 ms | **1.9 ms** |

输出哈希与 C 相同。六个组件同一改法重建，等待部署窗口。

## 11. 决策 0017 六件上线后的全量重测（2026-09-03 22:36–22:45，设备）

一次性程序（`tools/bench_device_side_by_side.sh`，N=100，fw4 N=20，含进程启动）：

| 用例 | 原版 | Rust（0017 前） | **Rust（0017 后）** |
|---|---|---|---|
| `uci export network` | 2.70 ms | 2.9 | **2.00** |
| `uci export`（19 包） | 6.00 ms | 7.2 | **5.30** |
| `uci show firewall` | 3.10 ms | 4.0 | **2.70** |
| `uci get network.lan.ipaddr` | 2.60 ms | 2.8 | **1.80** |
| `uci set` + `commit`（scratch 副本） | 5.20 ms | — | **3.90** |
| `fw4 print` | 203 ms | 19.5 | **17.0** |
| `fw4 check` | 261 ms | — | **72** |
| `reload_config` 无变更 | 55.7 ms | 64.9 | **36.2** |

httpd（`tools/bench_httpd.sh`，400 请求 ×4 并发，同参数 uhttpd 镜像在 8080/8443；两次运行取第二次）：

| 用例 | uhttpd req/s | httpd-rs r2 req/s | uhttpd p50 | httpd-rs p50 |
|---|---|---|---|---|
| 静态 44 KB CSS | 1436 | 1384 | 2.62 ms | 2.64 ms |
| 静态 `/` | 3390 | 4364 | 1.11 ms | 0.85 ms |
| CGI LuCI 登录页 | 30.4 | 31.8 | 131.8 ms | 125.8 ms |
| `/ubus` JSON-RPC | 1005 | 1153 | 3.91 ms | 3.35 ms |
| TLS 静态 CSS | 531 | 1005 | 7.04 ms | 3.42 ms |

大 CSS 一项两边持平（两次运行 1312/1384 vs 1519/1436，第三轮记的 +18% 里 C 那次偏低）；其余不变或更快。

rpcd（`tools/bench_swap_windows.sh`，N=50，同一会话内切到 C rpcd 再切回）：

| ubus 调用 | C rpcd | rpcd-rs r7（0017 前） | **rpcd-rs r8** |
|---|---|---|---|
| `session list` | 4.0 ms | — | 3.8 |
| `uci get network` | 4.2 | — | 4.4 |
| `file stat` / `read board.json` | 3.8 / 3.8 | — | 3.8 / 4.0 |
| `luci getFeatures`（fork opkg/apk 探测） | 227.8 | — | **202.6** |
| `luci-rpc getNetworkDevices` | 12.2 | — | 12.4 |
| `luci-rpc getDHCPLeases` | 4.6 | — | 5.0 |
| `luci-rpc getWirelessDevices` | 50.2 | 60.0 | **46.0** |
| `iwinfo info phy0-ap0` | 18.4 | 24.0 | **16.8** |
| `iwinfo assoclist` | 6.4 | — | **5.8** |
| `rc list`（3 次，跑全部 init 脚本） | 1137 | — | 1253 |
| RSS | 2016 kB | — | 1224 kB |

A4（iwinfo）随 0017 一并关闭：剩余的 +25% 也是 opt-level z 的代价。logd 窗口里 `logread` 全量 54 vs 26.5 ms 又是环内行数不同
（rs 环里多了部署与 500 条 logger 消息），§8 的等行数对照仍然成立；`ubus call log read` 5.0 vs 5.4 ms，RSS 568 vs 952 kB。
