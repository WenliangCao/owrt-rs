# 九组件之后：系统分层与下一阶段取舍

2026-09-29。建议下一阶段以**整机网络性能和固件维护**为主线。先定位用户实际经过的慢路径，再决定是否增加 Rust 实现。当前没有证据支持立刻完整重写 DNS/DHCP、无线认证或另一套系统基础设施。

本页记录开始测量前的调查与规划；随后三步工作的实际结果见[整机网络性能与固件维护报告](DATAPATH_20260929_RESULTS.md)。

## 依据与当前状态

- 当前固定版本：[AX3000T Rust9 v0.1.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/ax3000t-rust9-v0.1.0)，源码 `a4053dd5d4b4b2dbed3ff8a56d595aeabd33e0d0`，OpenWrt 25.12.5，Linux 6.12.94。
- 17:27:38 UTC 只读核对 `/lib/apk/db/installed`：**164 个包的名称和版本与原生镜像部署记录完全相同，其中 53 个是 kmod 包**。包不等于独立进程；BusyBox 一个程序包含多种工具，LuCI 多个包只是界面模块或资源。
- 功能来源使用精确镜像的 [package manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/packages.json)、[源码身份](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json)和[九入口替换清单](../../packaging/image/native-25.12.5.json)。原生部署已完成，历史研究文档中的“待部署”不代表现在仍待部署。
- 实机本次只读取包数据库、进程、有限配置键、sysfs 与规则摘要。没有变更设备配置、运行压测或部署采集器。

| 只读观察 | 当前值 | 能说明什么 |
|---|---|---|
| WAN 协议 / 链路 | DHCP / 1000 Mb/s 全双工 | PPPoE 当前不是上网路径；端口速率给吞吐设定上限 |
| 软件流量卸载 | `flow_offloading=1`，运行规则有 flowtable 和 `flow add` | 软件快路径已配置；本次未统计每条连接的实际命中率 |
| 硬件流量卸载 | `flow_offloading_hw=0`，规则无 `flags offload` | 是值得评估的候选，不能由关闭状态推断存在性能故障 |
| MediaTek WED | `mt7915e` 的 `wed_enable=N` | 无线卸载未启用；与通用硬件流量卸载分开评估 |
| Packet steering | `network.globals.packet_steering=1` | 已有配置；未测负载下两核是否均衡 |
| 无线配置 | 2.4 GHz HE20 / 5 GHz HE80 | 只是配置，不能替代吞吐、重传和信道占用测量 |
| dnsmasq / odhcpd / odhcp6c RSS | 1256 / 1084 / 908 KiB | 单个时点的驻留页，不是独占内存或峰值 |
| hostapd / wpa_supplicant RSS | 3408 / 2916 KiB | 两个进程共享 wpad 等页，不能把和当独占内存 |
| 可选流量服务 | 未安装 SQM、WireGuard、OpenVPN、常见代理包 | 不应把这些算成当前生产性能问题的来源 |

## 分层点评

“本项目不重写”是工程范围判断，不表示世界上不能实现；仍应跟进上游修复和正常版本更新。下表按职责划分，横跨多层的软件包在附录按主职责归组。

| 层级 | 剩余部分 | 职责与评价 | 建议 |
|---|---|---|---|
| 硬件与引导 | Bootloader、启动固件、板级校准数据 | 引导和硬件适配基础；重写没有已知生产性能收益。启动固件不一定属于 rootfs 包，本次没有读取闪存分区或重新鉴定 bootloader 版本 | 本项目不重写、不改分区或校准数据 |
| 内核与驱动 | Linux、mt76/mac80211/cfg80211、以太网/交换机驱动、MTD/UBI、文件系统 | 调度、内存、无线、存储和包转发的基础 | 保留上游实现；只基于具体证据配置、升级或修复 |
| 内核数据路径 | IP 转发、bridge、conntrack、NAT、nftables 内核模块、硬件快路径 | 用户的下载、视频和游戏数据主要走这里 | 高优先级测量和配置优化；不重写网络栈 |
| 用户态基础 | musl libc、libgcc、BusyBox/ash | 运行环境和命令工具。BusyBox 还提供 WAN 的 udhcpc、ntpd、crond 等 | 保留；没有为语言统一而替换整套工具的收益依据 |
| 启动与存储 | 原 `/sbin/init`、preinit、mount_root/fstools、ubihealthd、fitblk | Rust procd 接管不等于早期启动、挂载和 NAND 维护也已重写 | 保留；修具体缺陷，不作为提速项目 |
| 刷写与恢复执行 | sysupgrade、upgraded、mtd、ubi-utils、fwtool、FIT 检查、uboot-envtools | 低频但决定镜像写入和下次启动 | 本项目不重写；继续使用既有工具 |
| 隔离与密码基础 | ujail/seccomp、mbedTLS、随机数和签名工具、CA/keyring | 服务隔离、认证和信任基础；ujail 的 RSS 不是可随意去掉的“浪费” | 保留并跟进修复；不自制密码学实现 |
| 共享库 | libubus/libubox/libuci、libnl-tiny、libmnl、JSON 库等 | 现存 C 服务与 ucode 模块仍依赖 C ABI；Rust 的同协议实现不等于可以卸载这些库 | 保留；体积裁剪前验证全部使用方 |
| 网络协议服务 | dnsmasq | DNS 转发/缓存和 LAN DHCPv4。可能影响首次解析等待，但不是持续下载转发路径 | 条件候选：先拆分缓存命中、未命中和上游等待；完整替换暂不立项 |
| 网络协议服务 | odhcpd | LAN IPv6 RA、DHCPv6、相关中继/NDP 等语义 | 保留；范围复杂且不是逐包吞吐瓶颈，重写优先级低 |
| 网络协议服务 | odhcp6c / udhcpc | WAN 获取 IPv6 地址/前缀和 IPv4 租约，与 netifd 协同 | 保留；续租、生命周期正确性比计算速度重要 |
| 网络协议服务 | ppp / ppp-mod-pppoe | PPP/PPPoE 接入，当前 DHCP WAN 未使用 | 不重写；是否从以后镜像裁剪取决于是否仍需该接入能力 |
| 无线协议服务 | wpad 的 hostapd / wpa_supplicant | AP/STA 管理、认证、密钥协商等；不负责在用户态搬运每一份普通 Wi-Fi 数据 | 保留成熟实现；无线性能先看信道、重传、驱动和卸载 |
| 无线编排 | wifi-scripts、无线 ucode、iw/iwinfo | 生成/应用无线配置、查询能力、连接 netifd 与 wpad/驱动 | 默认保留；只有具体启动/重载热点才考虑小范围改写 |
| 规则执行工具 | nft 用户态、libnftables/libnftnl | 把规则提交给内核；fw4-rs 已负责生成规则。nft 命令速度不等于每个包转发速度 | 保留；巨大规则集重载若确有瓶颈再剖析 |
| 已完成控制面 | 九个 Rust 组件及共享 Rust ubus 库 | 配置、进程、消息总线、网络编排、规则生成、日志和 HTTP/RPC | 维护兼容和真实热点；不再以每项微基准全胜为常态目标 |
| 剩余控制工具 | C ubus CLI、原 logread、jshn、jsonfilter、验证工具 | 主要服务 shell/调试/输出转换；有些成本来自反复启动和跨进程调用 | 条件候选：优先消除热调用链的重复工作；单独换语言未必有收益 |
| 系统脚本 | rc.common、procd.sh、init.d、hotplug、proto handlers、首启配置生成 | OpenWrt 服务与板级适配的接口，调用频率和耗时各异 | 不全量重写；只改有剖析证据且边界明确的小段 |
| 系统小服务 | ntpd、crond、urngd、LED/按钮逻辑 | 校时、定时任务、熵和基础设备行为 | 保留；无已知高频瓶颈 |
| 管理访问 | Dropbear SSH、uclient-fetch | 管理登录、文件传输和下载 | 保留；它们通常不承载家庭设备的日常转发流量 |
| Web/UI | LuCI JS、ucode、lucihttp、cgi-io、主题/翻译 | 浏览器管理界面、页面分发、上传下载等 | 本轮不重做界面和解释器；具体请求慢再定位 |
| 镜像与升级（跨层） | APK、包配方、owut/ASU、CI、Release 清单 | 把运行良好的组件持续构建成可追溯的固件 | 值得继续做产品工程；保留现有包管理与刷写引擎 |

原包名 `procd`、`ubusd`、`netifd`、`uci`、`rpcd`、`uhttpd`、`firewall4`、`logd` 仍出现在包数据库里：它们提供依赖、脚本、辅助程序和配置。九个标准入口由 `owrt-control-plane` 原位提供，不应由包名推断正在运行 C 主程序。

## 下一阶段的顺序

1. **建立真实网络路径的性能画像。** 区分 LAN 内部、LAN→WAN、有线、无线；记录吞吐、同时下载/上传时的延迟、丢包、CPU 分布和重传。宿舍上游拥塞与本机处理成本分开。已有控制面吞吐数字不是 IP 转发吞吐证据。
2. **根据瓶颈选一项优化。** CPU 被转发吃满时评估硬件流量卸载及命中率；无线成为瓶颈时检查重传、信道和 WED；链路满载延迟明显上升时评估 SQM/CAKE。SQM 与硬件流量卸载不是一组默认全开的开关，取舍依据是带宽、延迟和 CPU 的实际目标。
3. **维护完整镜像。** 固定上游源码与依赖、支持下一次整镜像更新、核对配置兼容和九入口所有权、验证 Release 来源及校验。现成 owut/ASU 是否能构建带自定义包的下一版镜像需单独验证，当前只确认安装了客户端，未验证服务端能提供该私有包。
4. **按依赖裁剪体积。** 只选择确实不用的功能/资源，分别报告压缩镜像字节、overlay 可用容量、运行内存。不能把删除只读文件的 overlay 白化当成回收 ROM 空间，也不能由“已重写一个入口”推断整个原包无用。保留九组件分进程的职责边界。
5. **最后决定是否新增 Rust 项目。** DNS 是剩余用户态中较有实际使用频率的研究候选；如果主要耗时来自上游，继续重写价值低。其次是热脚本链的重复解析/启动成本。DHCP/IPv6、无线认证、SSH 和 BusyBox 的全量替换不列入下一阶段。

如果选择 DNS 研究，第一份交付应是当前 dnsmasq 的调用方、DNS/DHCP 联动、配置/租约合同及缓存命中/未命中成本报告。然后才能决定局部改进、复用现成实现或完整替换；现在不预先设计 dnsmasq-rs。

九组件本身仍保留已量化的局部代价，见[整栈评估](STACK_20260929_ASSESSMENT.md)与[组件结案索引](NINE_COMPONENT_20260928_CLOSEOUT.md)。这些文档的性能数字绑定当时产物；当前已发布镜像的部署状态以[原生部署结果](NATIVE_DEPLOYMENT_20260929_RESULT.md)为准。本规划不把历史所有数字转写成当前镜像的新测量。

## 外部参考的用途

- [Linux 6.12 flowtable 文档](https://docs.kernel.org/6.12/networking/nf_flowtable.html)：软件与硬件快路径、NAT、命中状态和限制；用于解释为什么转发性能要研究数据路径。
- [OpenWrt SQM](https://openwrt.org/docs/guide-user/network/traffic-shaping/sqm)：满载排队延迟、CPU 开销和硬件卸载的取舍。通过官方页面搜索结果及 Context7 官方文档索引复核。
- [hostapd 官方说明](https://w1.fi/hostapd/)：认证与 AP 管理职责；不由进程名称推断普通数据转发都经过该进程。
- [dnsmasq 官方说明](https://dnsmasq.org/doc.html)、[odhcpd 上游](https://github.com/openwrt/odhcpd)：用于核对职责广度；具体部署功能仍以精确包变体为准，例如此机是 `odhcpd-ipv6only`。

## 完整包归类

以下按主职责列出 164 个包，每个包只出现一次。版本来自部署记录，已与当前设备逐项核对。分组供选题和依赖检查使用，不是卸载清单。

| 分组 | 包数 |
|---|---:|
| 内核、驱动与 kmod 固件 | 54 |
| SoC 配套固件 | 2 |
| 基础文件系统与存储 | 4 |
| 底层刷写与镜像检查工具 | 4 |
| 基础运行环境与工具箱 | 5 |
| 隔离辅助程序 | 2 |
| 密码、随机数与信任材料 | 9 |
| 共享 IPC/配置/JSON/Netlink 库及文本辅助工具 | 12 |
| 九组件原生包与原有配套包 | 16 |
| DNS、DHCP、IPv6 与 PPP | 5 |
| 无线协议、编排与查询 | 7 |
| nft 规则提交 | 2 |
| 管理命令与下载 | 4 |
| ucode 解释器及模块 | 13 |
| LuCI 界面、Web 辅助库与 CGI | 22 |
| 包管理与升级客户端 | 3 |
| **合计** | **164** |

### 内核、驱动与 kmod 固件

| 包 | 版本 |
|---|---|
| `kernel` | `6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1` |
| `kmod-cfg80211` | `6.12.94.6.18.26-r1` |
| `kmod-crypto-aead` | `6.12.94-r1` |
| `kmod-crypto-authenc` | `6.12.94-r1` |
| `kmod-crypto-ccm` | `6.12.94-r1` |
| `kmod-crypto-cmac` | `6.12.94-r1` |
| `kmod-crypto-crc32c` | `6.12.94-r1` |
| `kmod-crypto-ctr` | `6.12.94-r1` |
| `kmod-crypto-des` | `6.12.94-r1` |
| `kmod-crypto-gcm` | `6.12.94-r1` |
| `kmod-crypto-geniv` | `6.12.94-r1` |
| `kmod-crypto-gf128` | `6.12.94-r1` |
| `kmod-crypto-ghash` | `6.12.94-r1` |
| `kmod-crypto-hash` | `6.12.94-r1` |
| `kmod-crypto-hmac` | `6.12.94-r1` |
| `kmod-crypto-hw-safexcel` | `6.12.94-r1` |
| `kmod-crypto-manager` | `6.12.94-r1` |
| `kmod-crypto-md5` | `6.12.94-r1` |
| `kmod-crypto-null` | `6.12.94-r1` |
| `kmod-crypto-rng` | `6.12.94-r1` |
| `kmod-crypto-seqiv` | `6.12.94-r1` |
| `kmod-crypto-sha1` | `6.12.94-r1` |
| `kmod-crypto-sha256` | `6.12.94-r1` |
| `kmod-crypto-sha3` | `6.12.94-r1` |
| `kmod-crypto-sha512` | `6.12.94-r1` |
| `kmod-gpio-button-hotplug` | `6.12.94-r5` |
| `kmod-hwmon-core` | `6.12.94-r1` |
| `kmod-i2c-core` | `6.12.94-r1` |
| `kmod-leds-gpio` | `6.12.94-r1` |
| `kmod-lib-crc-ccitt` | `6.12.94-r1` |
| `kmod-lib-crc32c` | `6.12.94-r1` |
| `kmod-mac80211` | `6.12.94.6.18.26-r1` |
| `kmod-mt76-connac` | `6.12.94.2026.03.19~39c960c3-r2` |
| `kmod-mt76-core` | `6.12.94.2026.03.19~39c960c3-r2` |
| `kmod-mt7915e` | `6.12.94.2026.03.19~39c960c3-r2` |
| `kmod-mt7981-firmware` | `6.12.94.2026.03.19~39c960c3-r2` |
| `kmod-nf-conntrack` | `6.12.94-r1` |
| `kmod-nf-conntrack6` | `6.12.94-r1` |
| `kmod-nf-flow` | `6.12.94-r1` |
| `kmod-nf-log` | `6.12.94-r1` |
| `kmod-nf-log6` | `6.12.94-r1` |
| `kmod-nf-nat` | `6.12.94-r1` |
| `kmod-nf-reject` | `6.12.94-r1` |
| `kmod-nf-reject6` | `6.12.94-r1` |
| `kmod-nfnetlink` | `6.12.94-r1` |
| `kmod-nft-core` | `6.12.94-r1` |
| `kmod-nft-fib` | `6.12.94-r1` |
| `kmod-nft-nat` | `6.12.94-r1` |
| `kmod-nft-offload` | `6.12.94-r1` |
| `kmod-ppp` | `6.12.94-r1` |
| `kmod-pppoe` | `6.12.94-r1` |
| `kmod-pppox` | `6.12.94-r1` |
| `kmod-slhc` | `6.12.94-r1` |
| `kmod-thermal` | `6.12.94-r1` |

### SoC 配套固件

| 包 | 版本 |
|---|---|
| `eip197-mini-firmware` | `20260221-r1` |
| `mt7981-wo-firmware` | `20260221-r1` |

### 基础文件系统与存储

| 包 | 版本 |
|---|---|
| `base-files` | `1711~f5dae5ece4` |
| `fitblk` | `2` |
| `fstools` | `2026.05.23~16718b6e-r1` |
| `ubi-utils` | `2.3.0-r1` |

### 底层刷写与镜像检查工具

| 包 | 版本 |
|---|---|
| `fit-check-sign` | `2025.10-r2` |
| `fwtool` | `2025.10.03~04cd252e-r1` |
| `mtd` | `27` |
| `uboot-envtools` | `2025.10-r2` |

### 基础运行环境与工具箱

| 包 | 版本 |
|---|---|
| `busybox` | `1.37.0-r6` |
| `libc` | `1.2.5-r5` |
| `libgcc1` | `14.3.0-r5` |
| `ubox` | `2025.10.30~6f78fa49-r1` |
| `zlib` | `1.3.1-r1` |

### 隔离辅助程序

| 包 | 版本 |
|---|---|
| `procd-seccomp` | `2026.03.13~58eb263d-r1` |
| `procd-ujail` | `2026.03.13~58eb263d-r1` |

### 密码、随机数与信任材料

| 包 | 版本 |
|---|---|
| `ca-bundle` | `20260601-r1` |
| `getrandom` | `2025.10.30~6f78fa49-r1` |
| `libmbedtls21` | `3.6.6-r2` |
| `libustream-mbedtls20201210` | `2026.03.01~99f1c0db-r1` |
| `openwrt-keyring` | `2025.12.10~f0670054-r1` |
| `px5g-mbedtls` | `11` |
| `urandom-seed` | `3` |
| `urngd` | `2025.10.03~f17e33d9-r1` |
| `usign` | `2025.10.03~c4c72b1b-r1` |

### 共享 IPC/配置/JSON/Netlink 库及文本辅助工具

| 包 | 版本 |
|---|---|
| `jansson4` | `2.14.1-r1` |
| `jshn` | `2026.06.19~7dd12784-r1` |
| `jsonfilter` | `2026.03.16~b9034210-r1` |
| `libblobmsg-json20260213` | `2026.06.19~7dd12784-r1` |
| `libjson-c5` | `0.18-r1` |
| `libjson-script20260213` | `2026.06.19~7dd12784-r1` |
| `libmnl0` | `1.0.5-r1` |
| `libnl-tiny1` | `2025.12.02~40493a65-r1` |
| `libubox20260213` | `2026.06.19~7dd12784-r1` |
| `libubus20251202` | `2026.06.28~24864e78-r2` |
| `libuci20250120` | `2025.12.02~66127cd7-r1` |
| `libudebug` | `2026.01.16~875e1a7a` |

### 九组件原生包与原有配套包

| 包 | 版本 |
|---|---|
| `firewall4` | `2025.03.17~b6e51575-r2` |
| `logd` | `2025.10.30~6f78fa49-r1` |
| `netifd` | `2026.02.26~cbb83a18-r1` |
| `owrt-control-plane` | `0.1.0-r2` |
| `procd` | `2026.03.13~58eb263d-r1` |
| `rpcd` | `2026.06.04~28faf640-r1` |
| `rpcd-mod-file` | `2026.06.04~28faf640-r1` |
| `rpcd-mod-iwinfo` | `2026.06.04~28faf640-r1` |
| `rpcd-mod-luci` | `20240305-r1` |
| `rpcd-mod-rpcsys` | `2026.06.04~28faf640-r1` |
| `rpcd-mod-rrdns` | `20170710` |
| `rpcd-mod-ucode` | `2026.06.04~28faf640-r1` |
| `ubusd` | `2026.06.28~24864e78-r2` |
| `uci` | `2025.12.02~66127cd7-r1` |
| `uhttpd` | `2026.06.16~7b1bec45-r1` |
| `uhttpd-mod-ubus` | `2026.06.16~7b1bec45-r1` |

### DNS、DHCP、IPv6 与 PPP

| 包 | 版本 |
|---|---|
| `dnsmasq` | `2.93-r1` |
| `odhcp6c` | `2026.06.20~07d324ee-r1` |
| `odhcpd-ipv6only` | `2026.06.29~5d7be43f-r1` |
| `ppp` | `2.5.2-r3` |
| `ppp-mod-pppoe` | `2.5.2-r3` |

### 无线协议、编排与查询

| 包 | 版本 |
|---|---|
| `hostapd-common` | `2025.08.26~ca266cc2-r1` |
| `iw` | `6.17-r1` |
| `libiwinfo-data` | `2026.01.14~f5dd57a8-r1` |
| `libiwinfo20230701` | `2026.01.14~f5dd57a8-r1` |
| `wifi-scripts` | `1.0-r1` |
| `wireless-regdb` | `2026.05.30-r1` |
| `wpad-basic-mbedtls` | `2025.08.26~ca266cc2-r1` |

### nft 规则提交

| 包 | 版本 |
|---|---|
| `libnftnl11` | `1.3.1-r1` |
| `nftables-json` | `1.1.6-r2` |

### 管理命令与下载

| 包 | 版本 |
|---|---|
| `dropbear` | `2025.89-r3` |
| `libuclient20201210` | `2026.06.07~daad21fa-r1` |
| `ubus` | `2026.06.28~24864e78-r2` |
| `uclient-fetch` | `2026.06.07~daad21fa-r1` |

### ucode 解释器及模块

| 包 | 版本 |
|---|---|
| `libucode20230711` | `2026.01.16~85922056-r1` |
| `ucode` | `2026.01.16~85922056-r1` |
| `ucode-mod-digest` | `2026.01.16~85922056-r1` |
| `ucode-mod-fs` | `2026.01.16~85922056-r1` |
| `ucode-mod-html` | `1` |
| `ucode-mod-log` | `2026.01.16~85922056-r1` |
| `ucode-mod-math` | `2026.01.16~85922056-r1` |
| `ucode-mod-nl80211` | `2026.01.16~85922056-r1` |
| `ucode-mod-rtnl` | `2026.01.16~85922056-r1` |
| `ucode-mod-ubus` | `2026.01.16~85922056-r1` |
| `ucode-mod-uci` | `2026.01.16~85922056-r1` |
| `ucode-mod-uclient` | `2026.06.07~daad21fa-r1` |
| `ucode-mod-uloop` | `2026.01.16~85922056-r1` |

### LuCI 界面、Web 辅助库与 CGI

| 包 | 版本 |
|---|---|
| `cgi-io` | `2026.06.28~7314451c-r1` |
| `liblucihttp-ucode` | `2023.03.15~9b5b683f-r1` |
| `liblucihttp0` | `2023.03.15~9b5b683f-r1` |
| `luci` | `26.180.75667~128a781` |
| `luci-app-attendedsysupgrade` | `26.180.75667~128a781` |
| `luci-app-firewall` | `26.180.75667~128a781` |
| `luci-app-package-manager` | `26.180.75667~128a781` |
| `luci-base` | `26.180.75667~128a781` |
| `luci-i18n-attendedsysupgrade-zh-cn` | `26.180.75667~128a781` |
| `luci-i18n-base-zh-cn` | `26.180.75667~128a781` |
| `luci-i18n-firewall-zh-cn` | `26.180.75667~128a781` |
| `luci-i18n-package-manager-zh-cn` | `26.180.75667~128a781` |
| `luci-lib-uqr` | `26.180.75667~128a781` |
| `luci-light` | `26.180.75667~128a781` |
| `luci-mod-admin-full` | `26.180.75667~128a781` |
| `luci-mod-network` | `26.180.75667~128a781` |
| `luci-mod-status` | `26.180.75667~128a781` |
| `luci-mod-system` | `26.180.75667~128a781` |
| `luci-proto-ipv6` | `26.180.75667~128a781` |
| `luci-proto-ppp` | `26.180.75667~128a781` |
| `luci-ssl` | `26.180.75667~128a781` |
| `luci-theme-bootstrap` | `26.180.75667~128a781` |

### 包管理与升级客户端

| 包 | 版本 |
|---|---|
| `apk-mbedtls` | `3.0.5-r3` |
| `attendedsysupgrade-common` | `10` |
| `owut` | `2026.04.09~5d6760b5-r1` |
