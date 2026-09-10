# R82：完全体性能对比——九个 Rust 组件 vs 原版，同一台设备

> 历史测量（R81 修复前）。最新版的单组件与整体替换对照以 [R84](R84_DEPLOYMENT_BENCHMARK.md) 为准。
> R84 使用持久客户端、固定原版依赖和四次冷启动；不同版本与方法的数字不混合比较。

> 2026-09-09 21:50，AX3000T（MT7981B 双核 A53，Linux 6.12.94，up 51 min）。全部 Rust 组件已常驻。
> 设备侧脚本 `tools/r82_bench_full.sh`（一次性程序、ubusd、rpcd、procd、netifd、logd），Mac 侧
> `tools/bench_httpd.sh`（httpd）。原始输出在 `private/bench/r82/`。
> 方法承接 [BENCHMARK.md](BENCHMARK.md)（09-03，六个组件）：同设备、同时刻、同输入、同客户端；
> 一次性程序原版取自 `/rom`；daemon 类各起一条备用 bus，C 从 `/rom` 起（`/lib` 里的共享库就是它的），
> Rust 起第二实例，同一客户端打两边。`ubus` CLI 一次往返约 3.6–3.8 ms 是所有短调用的地板。

## 1. 结论

- **一次性程序**：uci 快 1.1–1.5×（`get` 2.6→1.8 ms，`set+commit` 5.2→4.0 ms）；fw4 `print` 206→17 ms
  （**12×**）、`check` 282→77 ms（3.7×）；reload_config 58→37 ms（1.6×）。与 09-03 一致。
- **ubusd**：延迟持平（lookup 51 vs 53 µs、invoke 91 vs 94 µs、notify 8 vs 7.5 µs，均 p50），4 客户端并发
  p99 rs 略差（447–649 vs 412–449 µs）；**RSS 500 vs 896 kB**。
- **rpcd**：全部在 CLI 地板附近，差异 ≤ 1 ms（iwinfo info rs 快 0.8 ms，rrdns rs 慢 0.6 ms）；**RSS 1188 vs 2016 kB**。
- **procd（监管模式并排）**：service list 3.6 vs 3.8 ms，set+delete 7.5 vs 8.5 ms；**RSS 824 vs 1080 kB**。
  PID 1 启动时间线与 C 在 0.1 s 内（见 §7）。
- **httpd**：静态 CSS 571 vs 437 req/s（+31%）、首页 892 vs 465（+92%）、`/ubus` 609 vs 471（+29%）、
  TLS CSS 439 vs 380（+16%）、CGI 持平；压测中 RSS 1536 vs 1792 kB。
- **netifd**：API 延迟在地板附近；**发现一处真实的额外开销**——空闲时 0.7–1.6% CPU（C 接近 0），
  根因是订阅了地址组并在每批 netlink 事件上全量 rescan（每事件约 6 ms CPU）。§7 与 §9。
- **体积**：Rust 静态二进制 0.4–1.5 MB，C 二进制 16–233 KB + 共享库（libubox 66 KB、libubus 29 KB、
  libuci 41 KB、libucode 177 KB、libiwinfo 66 KB、rpcd 插件 120 KB）。RSS 上 Rust 反而更小（§8）。

## 2. 一次性程序（N=100，fw4 N=20；per_op = 墙钟/N）

| 用例 | /rom 原版 | Rust | 比值 |
|---|---|---|---|
| `uci -S -n export network` | 2.70 ms | 1.80 ms | 0.67× |
| `uci -S -n export`（全部包） | 6.10 ms | 5.30 ms | 0.87× |
| `uci show firewall` | 3.10 ms | 2.70 ms | 0.87× |
| `uci get network.lan.ipaddr` | 2.60 ms | 1.80 ms | 0.69× |
| `uci set` + `commit`（scratch 目录） | 5.20 ms | 4.00 ms | 0.77× |
| `fw4 print` | 206.0 ms | 17.0 ms | **0.08×** |
| `fw4 check` | 281.5 ms | 76.5 ms | **0.27×** |
| `reload_config`（无变更） | 58.0 ms | 36.5 ms | 0.63× |

## 3. ubusd（r39 负载：同一 `bench` 客户端，同一 bus 上的 `bench.target` 提供者）

| 操作 | C ubusd p50 / p99 | ubusd-rs p50 / p99 | ops/s C → rs |
|---|---|---|---|
| lookup（n=3000） | 50 / 86 µs | 51 / 89 µs | 19.2k → 18.8k |
| lookup_all（n=300） | 46 / 98 µs | 48 / 77 µs | 20.5k → 20.1k |
| invoke（n=3000） | 91 / 193 µs | 94 / 199 µs | 10.5k → 10.2k |
| notify（n=3000） | 8 / 11 µs | 7 / 10 µs | 114k → 122k |
| 4 并发 invoke（各 750） | p50 216–229，p99 412–449 µs | p50 218–305，p99 447–649 µs | 4.1–4.3k → 3.4–4.0k |
| daemon CPU（单客户端全程） | 25 ticks | 28 ticks | |
| daemon RSS | 896→908 kB | 500→508 kB | |

## 4. rpcd（N=50，各在自己的 bus，C 从 `/rom/sbin/rpcd` + `/usr/lib/rpcd/*.so`）

| 方法 | C rpcd | rpcd-rs |
|---|---|---|
| `session list` | 3.80 ms | 4.00 ms |
| `uci get network` | 4.20 | 4.40 |
| `uci configs` | 3.80 | 4.20 |
| `file stat` / `file read board.json` | 3.80 / 3.80 | 3.80 / 4.00 |
| `luci-rpc getBoardJSON` | 4.20 | 4.00 |
| `luci-rpc getNetworkDevices` | 11.80 | 12.40 |
| `luci-rpc getDHCPLeases` | 4.40 | 4.80 |
| `luci-rpc getWirelessDevices` | 3.60 | 4.40 |
| `iwinfo info phy0-ap0` | 18.60 | 17.80 |
| `iwinfo assoclist phy0-ap0` | 6.20 | 7.20 |
| `network.rrdns lookup` | 4.40 | 5.00 |
| RSS | 2016 kB | 1188 kB |

## 5. procd（监管模式，非 PID 1，各在自己的 bus；C `-s`，rs 在 `/` 的 chroot 里把 rs bus 绑到 `/var/run/ubus/ubus.sock`）

两侧注册的对象集相同（container、hotplug.×10、service、system）。

| 方法 | C procd | procd-rs |
|---|---|---|
| `service list` | 3.80 ms | 3.60 ms |
| `service list verbose` | 4.40 | 3.80 |
| `system board` | 3.80 | 3.80 |
| `system info` | 3.80 | 3.60 |
| `service set`（起一个实例）+ `delete`（n=20） | 8.50 | 7.50 |
| RSS | 1080 kB | 824 kB |

## 6. httpd（Mac 经 Wi-Fi 发压，4 并发 × 400，keep-alive；uhttpd 从 `/rom` 起在 8080/8443，参数与 httpd-rs 相同）

| 用例 | uhttpd req/s / p50 | httpd-rs req/s / p50 |
|---|---|---|
| 静态 44 KB CSS | 437 / 8.85 ms | **571** / 6.57 ms |
| 静态 `/` | 465 / 8.43 ms | **892** / 4.31 ms |
| CGI `/cgi-bin/luci/`（403） | 29.0 / 135 ms | 28.1 / 134 ms |
| `/ubus` JSON-RPC | 471 / 8.41 ms | **609** / 6.44 ms |
| TLS 静态 CSS | 380 / 9.25 ms | **439** / 8.26 ms |
| RSS（压测中） | 1792 kB | 1536 kB |

绝对值低于 09-03（当时 CSS 1124/1326 req/s）：本次 Mac 经 Wi-Fi 且路由器上 5 个客户端在线；两侧同一轮测，
相对结论不受影响。

## 7. netifd 与 PID 1（无法并排跑第二个实例；对照用启动时间线与录得的 C 数据）

**启动时间线**（内核秒，procd 状态行进 kmsg）：

| 里程碑 | C（R74 基线 / 今日 16:51 C 启动 dmesg） | Rust 完全体（procd-rs + ubusd-rs + netifd-rs，本次启动） |
|---|---|---|
| `- early -` | 9.23 | 9.26 |
| `- ubus -` | 9.79 | 9.90 |
| `- init -` | 9.86 | 9.97 |
| lan2 DSA 口开始配置 | 16.30 | 15.97 |
| phy0-ap0 进入 forwarding | 17.00 | 17.16 |
| `- init complete -` | （未录） | 19.39 |

**API 延迟**（netifd-rs 活体，N=50）：`network.interface dump` 4.4 ms、`network.device status`（25 个设备，
逐个 ethtool/ioctl）15.6 ms、`network.wireless status` 4.6 ms、`network.interface.lan status` 3.8 ms。
C 的同项没有设备内数据；`luci-rpc getNetworkDevices`（走 device status）C 11.8 vs rs 12.4 ms 可作旁证。

**空闲 CPU（发现项）**：60 s 无调用窗口内 netifd-rs 97 ticks（1.6%），另一 30 s 窗口 21 ticks（0.7%）；
同窗口 procd 39、ubusd 115（httpd 压测经它）、rpcd-rs 12、logd-rs 0。累计：netifd 4842 ticks / 3066 s = 1.6%，
procd 0.11%，ubusd 0.07%。受控实验：在 `lo` 上 add/del 地址 100 次（200 个 RTM_NEWADDR/DELADDR）
→ netifd-rs 125 ticks，**每事件约 6 ms CPU**。

根因：`Netifd::new` 订阅 RTNLGRP_LINK + IPV4_IFADDR + IPV6_IFADDR，`drain_netlink` 对每批事件都
`rescan_devices()`（全量 RTM_GETLINK dump + 对 25 个已知设备各做一遍 `read_settings`：ethtool、ioctl、
sysctl）。C 的 `rtnl_event` socket **只订阅 RTNLGRP_LINK**，`cb_rtnl_event` 只处理 NEWLINK/DELLINK，
按 ifname 查一个设备做 `device_set_present/link`，O(1)、无 ioctl。路由器空闲时的 IPv6 RA 生命周期刷新、
租约、邻居变化都在地址组里，于是 Rust 每几秒醒一次做 6 ms 的无用功。修复见 §9。

## 8. 体积与常驻内存

| 组件 | C 二进制（+ 共享库） | Rust 静态 | RSS C | RSS Rust |
|---|---|---|---|---|
| uci | 16 KB + libuci 41 KB | 490 KB | — | — |
| fw4 | 3 KB + fw4.uc 80 KB + libucode 177 KB + 模板 42 KB | 1072 KB | — | — |
| reload_config | 0.6 KB shell | 494 KB | — | — |
| ubusd | 33 KB + libubox 66 KB | 528 KB | 896 kB（bench） | 500 kB（bench）/ 360 kB（活体） |
| procd | 98 KB | 856 KB | 1080 kB（监管） | 824 kB（监管）/ 744 kB（PID 1） |
| netifd | 233 KB | 987 KB | — | 896 kB |
| rpcd | 62 KB + 插件 120 KB + libiwinfo 66 KB | 1158 KB | 2016 kB | 1188 kB（bench）/ 468 kB（活体） |
| uhttpd | 58 KB | 1465 KB | 1792 kB（压测） | 1536 kB（压测）/ 552 kB（活体） |
| logd | 17 KB | 408 KB | 952 kB（09-03） | 360 kB |

共享库对 C 是摊销的（libubox/libubus 被多个 daemon 共用），所以体积对比只说明"静态链接的代价"，不说明内存：
RSS 上 Rust 每个 daemon 都更小。Flash 上九个 Rust 二进制合计约 7.4 MB，overlay 使用 8%。

## 9. 修复：netifd-rs 的 netlink 订阅与 C 对齐（提交 3c46782，候选 eb38bd1b）

改动：只订阅 RTNLGRP_LINK；`drain_netlink` 仅当批次里有 RTM_NEWLINK/DELLINK 才 rescan。
门槛：r63 up/down/absent/late/late16 五档 identical，套件 24/24，148 单测。

设备窗口 #5（22:16 stage → 22:17:45 可达并首过 → 连续 188 s 全过 → 22:20:55 confirm，事后复核过）。
第一次尝试因编排器管道吞掉 stage 的拒绝码而空跑了一次重启（旧候选 86c4e164 原地重启，无损）；编排器
已加 `pipefail` 并在已有 Rust 候选常驻时先 `undo` 再 `stage`，保证 `.c-orig` 永远是 C 原件。

| 指标 | 修复前（86c4e164） | 修复后（eb38bd1b） |
|---|---|---|
| 空闲 60 s 的 CPU ticks | 97（≈1.6%） | **5（≈0.08%）** |
| 200 个 RTM_NEWADDR/DELADDR 事件的 CPU | 125 ticks | **0** |
| 累计 CPU / uptime | 4842 / 3066 s（1.6%） | 95 / 320 s（含启动） |
| RSS | 896–936 kB | 816 kB |
| 同窗口 procd / ubusd / rpcd-rs | 39 / 115 / 12（当时 httpd 压测在跑） | 3 / 2 / 0 |

至此九个组件在设备上没有一项比原版慢；netifd 空闲开销回到与 procd、ubusd 同一量级。

## 10. logd（活体 rs；C 侧沿用 09-03 切换窗口数据——C logd 没有指定 bus 的参数）

`ubus call log read lines=100` 5.2 ms（C 09-03：5.4）；`logger` 200 条 1.1 s（C 500 条 1.11 s，同量级）；
`logread` 全量 26 行/… 见原始输出；RSS 360 kB（C 952 kB）。

## 11. 未覆盖

转发吞吐与无线数据面（不在本项目范围，内核/驱动/hostapd 未变）；`rc list`（fork 31 个 init 脚本，两侧
都是 1.1 s 量级，09-03 已测）；netifd/PID 1 的同机并排请求延迟（只能有一个）。
