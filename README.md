# owrt-control-plane-rs

在一台**真实运行**的 OpenWrt 路由器上，把控制面逐个换成 Rust 实现。目标设备是 Xiaomi Mi Router
AX3000T（MT7981B，双核 A53），部署规格是 OpenWrt 25.12.5 `r33051-f5dae5ece4` 官方 `sysupgrade.bin`，
内核 6.12。每一步都以三类依据为准：精确镜像里的内容、该镜像对应的上游源码、脱敏后的设备实测行为。
保留精确 C 原件与离线恢复材料。

**现状（2026-10-17）：[v0.2.2](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.2.2) 十组件固件已保留配置上线，业务 unsafe 从 545 处降到 0，目标编译警告清零。**
本版统一整理系统调用与安全封装，业务 crate 禁止 unsafe，CI 遇到编译警告即失败。
完整正确性及用户指定的 24 个流量窗口、10 次启动检查通过；短检查未见可辨退化，
UDP 命中的小幅不利趋势和瞬时 FD 审查保留，不宣称严格等效或提速。
同一正式 CI 镜像只刷写一次，连续健康确认与 600 秒资源观察通过，没有额外重启。
详见[部署记录](docs/reviews/DEPLOYMENT_V0_2_2_20261017.md)、[发布说明](docs/reviews/RELEASE_V0_2_2_20261017_NOTES.md)
及[统一验收报告](docs/reviews/CORE_SAFE_20261017.md)。当次配置和精确 v0.2.1 回滚镜像已离机保存。

**历史里程碑（2026-09-29）：完整九组件 Rust 固件已保留配置刷入，客户端验收与用户物理断电复测通过，试验工具已清理。**
固定回溯节点：[AX3000T Rust9 v0.1.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/ax3000t-rust9-v0.1.0)，
构建源码 `a4053dd`；Release 保存实际刷入镜像、完整组件身份和校验资料。
见[部署记录](docs/reviews/NATIVE_DEPLOYMENT_20260929_RESULT.md)与[镜像验收](docs/reviews/NATIVE_IMAGE_20260929.md)。
前一次分层部署的断电修复和清理见
[修复记录](docs/reviews/POWER_RECOVERY_20260929_FIX.md)与[清理记录](docs/reviews/POWER_RECOVERY_20260929_CLEANUP.md)。
统一安装布局、配置迁移和 C 恢复方式见[发布说明](docs/RELEASE.md)。

**历史状态（2026-09-20）：当时路由器运行精确 C 原版；R95 只做隔离测试。**
[R94 审计](docs/reviews/R94_COMPLETION_AUDIT.md)发现四项实际缺陷及性能/内存证据缺口；
[R95 修复](docs/reviews/R95_DEFECT_FIXES.md)已逐项提交并在路由器验证。
九组件“全面胜 C、尽可能胜 R89”的目标尚未完成，后续遵循
[实机研究与验收规则](docs/R95_PERFORMANCE_RESEARCH.md)。

**历史里程碑（2026-09-15）：R92 九组件曾通过 Wi-Fi 部署，原计划第 2–5 批和该轮实机验收完成。
内核、驱动、数据面和无线 handler 脚本保留，本轮没有刷写固件。**
运行时固定为 `ca1a9121df0380448a19d474e29796066b6734e8`，
[正式构建 34874442503](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34874442503)；
后续工具、注释和报告提交没有替换这份运行时。
[R92 验收](reports/ax3000t-stock-openwrt-25.12.5/R92_REMAINING_BATCHES.md)包含异常恢复、兼容修复、
R91 日志、插件与无线复核：68 道必需门、四个冷启动、74 负载×三侧×四轮的 888 条测量通过。
每个剩余问题的修复或保留理由见 [逐项处置](reports/ax3000t-stock-openwrt-25.12.5/R92_COVERAGE.md)。

相对本轮精确 C，固定整批 CPU 低 23.39%，mixed 吞吐高 12.05%，idle-before 守护进程 RSS
中位数之和为 9606→5320 KiB。相对历史正式 R89，HTTP lane CPU **+9.38%**、log **+29.49%**、
mixed **+4.35%**，mixed 吞吐 **−3.73%**；不能宣称全面无回退。MemAvailable 少 6.31 MiB，
副本缓存控制不支持把全部差额归于静态二进制。[性能报告](reports/ax3000t-stock-openwrt-25.12.5/R92_PERFORMANCE.md)
保留各轮范围、同机 HTTP 控制、尾延迟、停放成本及内存边界。

该轮保留精确 C、正式 R89、已接受 R90 和 R92；诊断文件在当时核验清理。
[回退与包保留](docs/R92_RELEASE_AND_ROLLBACK.md)、[续接说明](docs/R92_RESUME.md)记录该轮身份与复核入口。
[R90](reports/ax3000t-stock-openwrt-25.12.5/R90_BATCH1_LIFECYCLE.md)记录已经完成的第一批生命周期修复。

历史 [R86 报告](reports/ax3000t-stock-openwrt-25.12.5/R86_PERFORMANCE_REVIEW.md)（发布提交 `f612e30`）记录了信号唤醒、HTTPD资源耗尽和
netifd子进程回收检查的修复。九组件代表负载的平均延迟和CPU均下降；完整74项负载中，平均延迟
73项下降、1项上升，CPU73项下降、1项持平。整机混合吞吐较原版高9.49%，控制面CPU/次低9.90%，
固定整批CPU低20.29%。

这些结果不表示全面提升：整机独立服务列表查询CPU高18.96%，HTTPD保持64连接RSS增量为原版452→Rust2096 KiB，
部分尾延迟仍上升。每侧只有两次整机启动；有限测试也不能证明任意输入无bug。
[部署证明](reports/ax3000t-stock-openwrt-25.12.5/R86_parts/deployment.json)、
[完整表格与图](reports/ax3000t-stock-openwrt-25.12.5/R86_parts/rendered/system_results.md)及
[所有回退与持平事实清单](reports/ax3000t-stock-openwrt-25.12.5/R86_REGRESSIONS_COMPLETE.md)以及
[R85优化日志](reports/ax3000t-stock-openwrt-25.12.5/R85_OPTIMIZATION_LOG.md)保留全部有效样本和历史失败。

[R87算法复核](reports/ax3000t-stock-openwrt-25.12.5/R87_ALGORITHM_REVIEW.md)（2026-09-12）把整机CPU回退定位到
ubusd事件循环每条消息轮询全部客户端（实机约18个），把HTTPD保持连接内存定位到每连接一线程，并提交了
ubusd就绪集合、HTTPD空闲连接停放和rpcd ACL匹配快路径三项改动；构建机上64连接RSS增量1944→100 KiB、
ubusd CPU不再随客户端数增长；正式构建随后走完隔离矩阵与四个冷启动窗口，整机13条lane全部快于原版
（procd lane −12.5%、活动CPU −27.6%，64连接RSS增量+260 KiB对原版+452）。

[R88完整审计](reports/ax3000t-stock-openwrt-25.12.5/R88_FULL_AUDIT.md)（2026-09-13）用9个只读子代理逐组件对照原版源码审计，
根代理复核：唯一的P1出在R87自己的procd节拍优化里（总线持续可读时维护饿死，看门狗不喂），连同13项P2/P3在R89修复轮
（提交d9c1048，release-image 34724293710）修掉并重走全部流水线；报告给出逐组件正确性/性能/资源/稳定性结论、
未修复的已知差异清单与“可整体替代、附条件”的判定。

## 分层与边界

| 层 | 内容 | 处置 |
|---|---|---|
| 内核与驱动 | Linux 6.12、mt798x-wmac/mt76 无线、an8855 DSA 交换机、nftables、netlink | **保留** |
| 数据面 / 执行面 | hostapd（wpad）、dnsmasq、odhcpd、udhcpc/odhcp6c、dropbear、busybox、apk、sysupgrade stage2（`upgraded`） | **保留**——成熟、失败边界清楚、与本项目无接口冲突 |
| 脚本层（被控制面调用） | `/lib/netifd/proto/*.sh`（dhcp/dhcpv6/ppp）、`/lib/netifd/wireless/mac80211.sh`（ucode wifi-scripts）、`/etc/init.d/*`、`/etc/hotplug.d/*`、`/etc/board.json` | **保留**——Rust daemon 按上游的调用合同（argv、环境、notify 协议）驱动它们 |
| **控制面（管理层）** | procd、ubusd、netifd、rpcd、uci、firewall4 生成器、uhttpd、logd、reload_config | **全部 Rust**（下表） |
| UI | LuCI（ucode，经 CGI 与 `/ubus`） | **保留**——跑在 httpd-rs + rpcd-rs 上 |

分层的判据不是"能不能用 Rust 写"，而是接口面是否清楚、失败边界是否可控、以及有没有办法在
一台唯一的生产设备上验证并回退。数据面组件一律不碰；控制面组件按爆炸半径从小到大逐个接管。

## 控制面组件

下表的安装形态记录首次分层上线。当前九个标准入口均由统一 `owrt-control-plane` 包原位提供。

| 组件（crate） | 替代 | 上游参考 | 首次上线形态 | 首次上线 | 报告 |
|---|---|---|---|---|---|
| `components/reload-config` | `/sbin/reload_config`（procd 配置变更分发） | procd 触发链 | apk `owrt-reload-config`，bind mount | 2026-09-02 | R05_GO_LIVE |
| `components/logd` | logd | ubox | apk `owrt-logd`，服务替换 | 2026-09-02 | R15_LOGD |
| `components/httpd` | uhttpd（静态、CGI、`/ubus` JSON-RPC、TLS） | uhttpd 7b1bec45 | apk `owrt-httpd`，服务替换 80/443 | 2026-09-02 | R14_HTTPD |
| `components/fw4` | firewall4 规则生成器（`fw4.uc` + 模板） | firewall4 b6e51575 | apk `owrt-fw4`，bind mount `/sbin/fw4` | 2026-09-02 | R09_FW4 |
| `components/rpcd` | rpcd 全部对象：session/uci/rc、file/luci、luci-rpc/iwinfo/rpc-sys/network.rrdns | rpcd 28faf640 | apk `owrt-rpcd`，服务替换 | 2026-09-02 | R13/R17/R18 |
| `components/uci` | libuci + `/sbin/uci` | uci 66127cd7 | apk `owrt-uci`，bind mount `/sbin/uci` | 2026-09-02 | R16_UCI |
| `components/procd` | procd：服务监管、trigger、PID 1、rcS、hotplug/coldplug、watchdog、sysupgrade 移交 | procd 58eb263d | 直接替换 `/sbin/procd`，原件在 stock `/rom` | 2026-09-09 | R65–R75 |
| `components/ubusd` | ubusd（系统消息总线） | ubus 24864e78 | 直接替换 `/sbin/ubusd`，原件在 stock `/rom` | 2026-09-09 | R36–R42、R76 |
| `components/netifd` | netifd：设备/接口/协议/路由/DHCP 生命周期 + 无线编排状态机 | netifd cbb83a18、wifi-scripts f0a60eee | 直接替换 `/sbin/netifd`，原件在 stock `/rom` | 2026-09-09 | R45–R64、R77–R80 |
| `components/ubus` | libubus/libubox 客户端与对象服务器、blobmsg、json_script | ubus 24864e78 | 库，被上述 crate 使用 | — | — |

前六个通过 apk 包安装，`owrt-<name>-switch enable|disable|boot-enable` 显式切换，`owrt-switch status`
一处查看；后三个是"失效即失联"的组件，在 bind mount 生效之前就已运行，所以改为在 overlay 上直接
替换 `/sbin/<x>`。冗余 `.c-orig` 已在 2026-09-29 清理，stock `/rom` 原件与离线备份保留。
这段描述的是此前的分层部署；当前集成固件中九个程序均原位安装，C 救援原件另存于 `/usr/libexec/owrt-stock/`。

第三方直接依赖保留 httpd 的 rustls/ring（TLS），v0.2.2 新增固定 rustix 1.1.5。
业务 crate 强制 `forbid(unsafe_code)`；必要的系统 ABI、信号、fork 和 FD 边界集中在
platform 封装内，UCI/fw4 保留极薄的 libc 启动入口。目标平台编译警告为零，CI 有编译
警告即失败。具体范围见[统一验收报告](docs/reviews/CORE_SAFE_20261017.md)。发布构建 opt-level 3、
静态 musl（决策 0017），正式发布由 GitHub Actions `release-image` 生成（决策 0018）。

整体基线 [R84 实机对照](reports/ax3000t-stock-openwrt-25.12.5/R84_DEPLOYMENT_BENCHMARK.md) 使用四次冷启动和
72 次单组件隔离运行，基线是精确原版 OpenWrt。整体替换后的四客户端混合吞吐下降约 3.9%，控制面
CPU/请求增加约 12.4%；fw4 规则生成、UCI 命令及 HTTPS 则有明显收益。六个常驻进程 RSS 合计约
9.18→4.61 MiB，但共享页重复计数及文件缓存差异使其不能等同于整机独占内存节省。内核转发吞吐未测量。
R84 版本的逐组件、CPU、延迟、内存、存储和测量边界以该报告为准；[R82](reports/ax3000t-stock-openwrt-25.12.5/R82_BENCHMARK_FULL.md)
及 [09-03 六组件数据](reports/ax3000t-stock-openwrt-25.12.5/BENCHMARK.md) 保留为历史记录。

## 方法：每个组件怎么被证明可以上线

1. **合同**（`docs/contracts/<组件>.md`）：从上游源码和设备实测里写下要复刻的语义，包括不显然的
   怪癖（有符号/无符号、truthiness、avl 排序、通知顺序……）和**有意偏离**（每条都写明理由）。
2. **差分门槛**（`tools/r*_*.sh`）：在 aarch64 构建机上，把设备的精确 rootfs 复制两份，在各自的
   mount/net/pid namespace 里跑 C 原件和 Rust 候选，同一客户端打同一串调用，逐字节比对输出、
   内核状态、写出的文件。每个门槛都有**红证**——注入故障（换成 `/bin/false`、改掉一行）必须判红，
   否则这个门槛不算存在。netifd 31 例（`tools/netifd_suite.sh`）、procd 272 标记（`r65`）、
   ubusd（`r36`–`r42`）、rpcd/uci/fw4/httpd/logd 各有自己的套件。
3. **设备窗口**：stage → 重启 → **站在客户端**验收（本机租约、经路由器解析、经路由器出网、
   运行中二进制 = 候选）→ 连续观察 ≥ 3 分钟 → confirm；设备侧带自动回退（无人 confirm 则还原 C 并重启）。
   窗口编排器（`tools/p6_window.sh`）脱离聊天会话运行——控制机就在被测路由器的 Wi-Fi 上。
4. **报告**（`reports/…/R<nn>_*.md`）：每次窗口和每轮审计的证据、失败与修法。失败也写：P6 跑了
   四次窗口，两个只有真机才暴露的缺口（DSA 口晚 16 秒注册、`resolv.conf.auto` 没写）都在 R78–R80。
5. **外部审计**：R68/R70（procd）、R73（全量）由不同会话/模型对抗审计；每条发现先复现再修，
   复现不了的连理由一起写回。[R81 冷审计](docs/reviews/R81_COLD_AUDIT.md) 的逐项修复与最终验证见
   [R83 报告](reports/ax3000t-stock-openwrt-25.12.5/R83_R81_FIXES.md)。

## 回退

当前 v0.2.2 使用 `owrt-recover-c` 成套准备十个 C 程序及 dnsmasq 原 init/ACL，共十二份文件，再单独重启；failsafe 中先 `mount_root`。
原件位于 `/usr/libexec/owrt-stock/`，当前 `/rom` 内对应入口已是 Rust，不能作为 C 原件。
这不等同于回退版本；v0.2.2 的版本回滚使用已核验的 v0.2.1 镜像和当次独立配置备份。
详见[当前恢复说明](docs/RELEASE.md#恢复路径)及[硬件救援手册](docs/RUNBOOK_AX3000T_RECOVERY.md)。

下表仅记录历史 stock + overlay 部署的恢复方式，已删除的 `/root/r84` 工具需要从离线备份恢复后才可使用。
历史 [R92 整栈冷回退流程](docs/R92_RELEASE_AND_ROLLBACK.md)不适用于当前原生镜像。

| 组件 | 回退 |
|---|---|
| uci / fw4 / reload_config / logd / httpd / rpcd | `owrt-<name>-switch disable`（立即）；`boot-enable off`（开机不再接管） |
| procd / ubusd / netifd | `/bin/sh /root/r84/stack-switch.sh stage stock` 后冷启动，按身份与客户端健康门核验 |
| 全部 | failsafe（mesh 键 + lan4）→ `/rom` 原封系统；再不行走 [救援手册](docs/RUNBOOK_AX3000T_RECOVERY.md) |

## 仓库结构

```
components/      十个 crate（上表），各自 README/Cargo.toml；工作区 rust-toolchain 1.98.1
docs/contracts/  每个组件的语义合同与有意偏离
docs/decisions/  编号决策（0001–0018），过时的带"现状"横幅
docs/reviews/    外部审计原文与复审
docs/RELEASE.md  发布流水线；docs/RUNBOOK_AX3000T_RECOVERY.md 救援手册
reports/         按设备 (ax3000t-stock-openwrt-25.12.5/) 的全部证据报告，R<nn> 递增
tools/           差分门槛、探针、bench、设备窗口脚本（r*_*.sh 与 netifd_suite.sh 是回归入口）
tests/reference/ 合同 C1 的参考用例
packaging/       OpenWrt SDK 打包配方（owrt-* apk）
manifests/       发布与验证的机器记录
archive/         已完成/已被推翻的计划与 I0 过程文档（只供追溯）
private/         镜像、rootfs、设备备份、bench 原始输出——不进 Git
```

## 构建与验证

```sh
# 构建（任一 crate）：pinned 1.98.1，静态 musl
cargo +1.98.1 build --release --bins --examples --target aarch64-unknown-linux-musl

# 差分门槛需要 Linux + sudo + 设备精确 rootfs（不在仓库内），例如：
sudo bash tools/netifd_suite.sh <rootfs> <netifd-rs> <outdir> <examples-dir>
sudo sh   tools/r65_procd_diff.sh <rootfs> <procd-rs> <outdir> <examples-dir>
```

一条项目内反复验证过的纪律：**构建、门槛、提交必须出自同一棵树的同一瞬间**（注释也算改动），
引用哪份二进制就记录它的 SHA256；开发构建、正式构建和实机身份分别核验。

## 明确不做

不重写内核、驱动、hostapd、dnsmasq/odhcpd、sysupgrade stage2、无线 handler 脚本和 LuCI。不做
ubusd 的**热**切换（客户端 odhcpd/dnsmasq/netifd 的重连语义不允许，决策 0015；上线走的是随重启的
冷切换）。不在没有回退路径的情况下碰设备。

## 历史

I0（镜像与源码基线、职责边界）→ 阶段 1–5（reload_config、logd、httpd、fw4、rpcd 插件层，2026-09-02，
[FINAL_REPORT](reports/ax3000t-stock-openwrt-25.12.5/FINAL_REPORT.md)）→ 第二至五轮（uci、rpcd 核心、
开机路径、找 bug、模糊测试，09-03）→ 发布流水线（09-04–06）→ P3–P6（procd、sysupgrade、ubusd、
netifd，09-07–09，R63–R80）→ R81 冷审计修复与部署/对照测试（09-10，R83–R84）→
R85–R89 性能与审计 → R90 生命周期 → R91 日志 → R92 第 2–5 批修复、部署与整体验收（09-15）。
被推翻的计划与结论在 [archive/](archive/README.md)。
