# 2026-10-08 体检跟进与 r3 热修复验收

本轮基于线上 `a4053dd5d4b4b2dbed3ff8a56d595aeabd33e0d0`，在
`hotfix/health-20261008-r3` 独立工作树完成。没有导入 main 的 dnsmasq 或
`components/ubus/src/{conn,sys}.rs` 改动。固件、原始地址、配置、转储和构建
产物只保存在忽略目录。物理路由器未安装、清理、修改配置、重启或刷写。

## 结论与证据范围

**GO：建议重发 `0.1.0-r3` 候选。** 已修复实际观测到的 fw4 abort、
盘点出的同类 CLI 输出错误、两个 netifd 内核兼容遗漏，并补齐新规则所需
的 PD 自然到期清理。正式 CI 二进制的 9 组功能/集成门首轮通过，32 轮相关基准
均完成且内容校验通过。频繁 fw4 core 的具体根因已有原版对照与定向回归，值得重发。

WAN6 抖动的具体上游触发与真实反馈仍列为证据不足；既有 LAN 桥生命周期
差异继续单列。部署需另行明确授权及当次恢复门，本轮未执行。

原版行为以精确 OpenWrt 25.12.5 镜像及匹配源码为准；历史报告只用于定位
原始证据。2026-10-09 本轮 SSH 只读身份检查返回 `No route to host`，没有
取得新的生产观测。Linux oracle 上的隔离实验使用精确原版文件和私有
rootfs 副本，不连接生产总线或网络。

## 逐项判定

| 项目 | 分类 | 判定边界 |
|---|---|---|
| fw4 查询 stdout 断管道导致 abort | 我们的缺陷 | 原版忽略 SIGPIPE 时查询安静返回；Rust 打印宏 panic，release 配置将其变为 SIGABRT。 |
| shell `cat: write error: Broken pipe` | 原版行为 | procd 的 SIGPIPE 忽略状态传给子进程，不能把这条 shell 错误作为 Rust 缺陷。 |
| WAN6 公网地址撤回又恢复 | 证据不足，倾向上游网络 | 13 次原始输入中 5 次本就没有公网地址；全 C 历史窗口也有在→无→有。 |
| offlink 子网不可达路由 / PD 下游源策略规则缺失 | 我们的缺陷 | 同输入 netns 红差分四次一致，匹配 C 源码明确安装；本轮补齐，不把遗漏直接当成上游抖动根因。 |
| PD 无新通知时自然到期仍残留 | 我们的缺陷 | 仅增加 source rule 会在旧 timer 缺口上形成新残留；六秒 PD 后停止通知的四轮对照确认，因此补齐最小 PD 到期处理。 |
| LAN 前缀顺序 ULA 优先 | r2 已修复的历史缺陷 | `a4053dd5` 已有匹配 C `list_add` 的头插语义和四项回归，不重复修改。 |
| `/tmp` 转储积累 | 我们的缺陷的后果 | 修 fw4 根因；不新增转储轮转，不清理设备文件。 |
| IPv4 TCP/53 超时 | 上游网络方向；具体位置证据不足 | 三个直接外部 IPv4 TCP 查询超时，本地 TCP 和直接上游 IPv6 TCP 成功；无九组件修复依据。 |
| 60 秒 DHCP 租期 | 上游网络 | 原版 udhcpc 日志明确收到 60 秒租期，288 次续租；没有九组件缩短租期的证据。 |
| 2.4 GHz 某终端 TX failed | 证据不足 | 只有单终端累计驱动计数，无增量或同负载 C 对照；不能归责九组件。 |
| 启动 mt7530 探测超时 | 原版行为 | 保留的内核/驱动探测阶段失败，随后实际 AN8855 初始化和 WAN 1Gbps 成功；不修控制面。 |
| 日志保存窗口短 | 原版配置行为 | 仅建议远程有界保存；当前日志不足以回溯此前重启或证明长期稳定。 |

### 需要纠正或收窄的原报告/任务前提

- 原生九组件镜像中的 `/rom/sbin/fw4` 也是 Rust；C oracle 应取固定原始
  镜像的 `/sbin/fw4` 或经哈希验证的 `/usr/libexec/owrt-stock/sbin/fw4`。
- 本地保存的完整 core 是两份；90 份的统计来自当时列表与批量签名扫描。
  不把两份独立 ELF 复核写成重新解析了全部 90 份。
- C2 原始快照证明全 C 栈发生公网地址撤回/恢复，但失败的那次 fw4 调用
  没有保留 stdout，不能严格归因该次字节门失败；C2 重试的差异只是集合
  顺序变化，不能把所有失败都称为同一个撤回事件。
- odhcp6c 终止上一脚本是解释读端关闭的源码路径；缺少当次逐进程信号
  轨迹，不能断言每一份 core 都由这个路径触发。
- 旧 APK 重装测试可在 `APK unavailable, skipped` 后误报通过。本轮移植
  后续历史修正并加入成功空操作负控，见[验证器报告](HEALTH_20261008_NATIVE_PACKAGE_VALIDATION.md)。

原始材料、匹配源码位置、逐项 SHA-256 与复算命令见
[独立证据审计](health-20261008-evidence.md)及[派生 JSON](health-20261008-evidence.json)。

## 修复、oracle 与回归

| 热修复提交 | 修改 | 已完成的 Linux / C oracle 证据 |
|---|---|---|
| `42608b5a`（原分支 `10e98e63`） | fw4 信号/输出和子进程边界；uci 输出错误；其余一次性诊断非 panic 写出 | fw4/uci 37 场景 × 6 输出/信号条件 × 4 轮 = 888 行全绿；正式 r2 同矩阵 128 行差分均四轮复现。另 15 个诊断 × 6 × 4 = 360 行通过，r2 断管 abort 120 次、修复后 0 次。 |
| `84b0f7a5`（原分支 `1cabb7fc`） | offlink 子网不可达路由、PD 下游源策略不可达规则，以及这些规则的生命周期 | 172 项 Linux netifd 单测通过；基线红差分四轮相同；当时默认 DAD 的 14 个稳定状态及 13 个即时地址快照与 C 逐值相同。最终 timer 版复测允许 1 秒 uptime 起点差异，其余内容仍相同。 |
| `d72928c9` | 无协议更新时仍按每秒定时清理自然过期 PD、assignment、source rule 和相关路由 | 六秒 PD 后停止通知，四轮红 `0→1→1`，修复后四轮与 C 同为 `0→1→0`；完整状态相同。172 项 Linux 单测及原 13 输入/DAD 回放再次通过。 |
| `fb3a3ec3` | 离线 APK 验证器要求实际恢复载荷 | 正式 r2 副本真实重装通过；stock/native 各四次成功空操作均被拒绝。 |

CLI 详细盘点和信号/退出码矩阵见[CLI 报告](health-20261008-cli.md)及
[结果 JSON](health-20261008-cli.json)。没有引入新的输出抽象或依赖。
fw4 查询在 SIGPIPE=IGNORE 时与原版相同地返回 0、stderr 为空；默认处理
时 shell 可见退出码均为 141。原版 shell wrapper 的 raw wait 为 141，
单 ELF 候选为 −13，两种形式分别保存，未掩盖。

Rust 专用诊断没有 C 对等命令：这些路径以 r2 正常字节/退出码为兼容
基线，单列 C 诊断参考，不能把它们算作 C help 文本完全相同。fw4 的
usage/check 保留原版写失败文本及非零退出码，不是一律吞错后成功。

冻结源码 `42608b5a` 随后在 oracle 一次批量通过 600 项组件/库 Rust 测试、
14 项 benchmark Rust 测试、五项仓库检查和所需基准/helper 构建，共 17 个
检查入口全部返回 0。完整命令、计数、耗时和日志哈希见
[源码批测记录](HEALTH_20261008_SOURCE_VALIDATION.json)。macOS 只运行纯 Python
比较器检查，不充当 Linux 组件验收。

netifd 详细证据见[回放报告](health-20261008-netifd.md)和
[派生结果](health-20261008-netifd.json)。`9774b10b` 仅修正测试工具对路由
转储顺序的处理：比较完整路由多重集合，保留所有字段和重复数；不改变
ubus 前缀或策略规则顺序。五项比较器测试确认内容变化和重复项仍会失败。
该工具修正未改变 CI 的组件源码或二进制构建输入。

独立审查扩大到了 PD 撤回/重授、移除/恢复 `ip6assign`、LAN down/up、
WAN down、PD 到期和 DAD。原始输入比较覆盖真实地址、flags、生命周期、
全部 IPv6 路由/rules、sysctl、WAN/LAN ubus 内容与 hotplug；有限生命周期
只容许采样时间偏差。netlink 日志保留作诊断，不把稳定快照相同当成任意
内核瞬态或真实 RA 交互完全等价的证明。

扩展场景中，初版修复的完整比较保留九条旧差分（四次 r2 基线均存在），
涉及 PD timer 与 LAN 桥生命周期。这些历史红结果保留。最后独立审查
区分了显式 `valid=0` 和静默自然到期，发现新增 rule 会被旧 timer 缺口
留下；因此补入 `d72928c9`，关闭 PD 到期项。原始 13 条输入的 PD valid
最小 6263 秒，不触发这一补充场景。

**仍未关闭的是既有 LAN down/up 桥生命周期差异**：C 删除 br-lan，Rust
保留，重建 ifindex 和 WAN prefix assigned 投影也不同。它不由本轮修改
引入，不在原始 WAN6 捕获输入的触发范围内；本轮不扩大为桥管理重写。
不能把原扩展场景的规则子断言通过写成整体完全一致。

## 正式 r3 候选与 r2 逐组件比较

r2 正式来源为 [release-image 36592957923](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36592957923)。
已重新下载 artifact，核验其 `SHA256SUMS` 全部 26 项；manifest 九组件身份
与 2026-10-08 保存的生产 `release.json` 完全一致。

首轮 [release-image 37900803281](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/37900803281)
在 SDK 的 fw4 链接阶段失败：配方的 `Build/Prepare` 漏拷新增 `build.rs`，
因此没有 `-Wl,-u,getauxval`。失败日志与产物保留，不计为候选成功。
`022a8545` 只补配方这一行，重新通过正式工作流构建；`components/` 与
已通过完整 Linux 批测的 `42608b5a` 逐文件一致，未重新占 oracle 编译。

修配方后的 [37901579949](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/37901579949)
已成功，但尚未包含最终 PD 自然到期修复，保留为中间构建证据。

最终 r3 构建为 [37902724239](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/37902724239)，
源码 `d72928c9a7d9ed28a9aa2c8d749d31e2a9ed6d33`，包版本 `0.1.0-r3`。
CI 已成功，下载后逐文件核验 `SHA256SUMS` 的 26 项全部一致；九个
组件的 manifest 与二进制清单一致。镜像为 12,759,328 字节，SHA-256：

`bd6db93f2a7eb5efab226f882d25baa6740b04f6548ee9d051ef2a0ccccfcc68`

| 组件 | r3 ELF SHA-256 | 与 r2 的差异（字节） |
|---|---|---|
| fw4 | `77e2a33ead41736ce313780adf92473765d008f9137165a39ae94bf97028582e` | 已变化；-4096 |
| httpd | `bf7b29260f008622b1157bb39bcd969ae39932c534828be8429c50343670e904` | 已变化；-8 |
| logd | `e1d29e61f2a1c6d5242747156a215e0a7d934a3079f17bd5ea582b2dccb73151` | 已变化；4088 |
| netifd | `7ce3a64d094e05484721ec68855eff5f4d68a484a6ce5f073bd013d2fbb79eb1` | 已变化；4088 |
| procd | `3d4bfdfaa0e4ea035339b17d5ade1c14fcc59fff9d014b6aacc9e4a0dcff7f62` | 逐字节相同 |
| reload-config | `c96823a2e4b8ea3b5dd79ad375220514ae1ac2357e7f61714a722c4a2269dc7a` | 已变化；0 |
| rpcd | `c65491f434f35b6771b3fa9e0336a3580bf88522dfd222d3cc6cc45a8c6227c1` | 已变化；4088 |
| ubusd | `ab3bff56b6ba5d798701d0e73d20469a36cf1ea0773fdd64a0eb9411ec1fc42d` | 已变化；0 |
| uci | `50ba9ed8f5cf5686313be3e1d32a281278daf3d17c319b71211fb96a4dbd76a7` | 已变化；0 |

完整 r2/r3 双向哈希、尺寸、APK 哈希和 CI 内容验收见
[发布身份对照 JSON](HEALTH_20261008_RELEASE_IDENTITIES.json)。procd 未改，
最终二进制也与 r2 完全相同。其余八项对应本轮 CLI 输出修改，netifd
另有路由/规则及自然到期修复；不存在带入 main 的其它组件实现。
固定官方镜像、九份 C 救援身份、原包版本、LuCI/翻译源和内核身份均未变。

### 正式产物最终批次

在 oracle 的独立 namespace 中运行最终 CI 二进制，**9 组顶层功能/集成
检查首轮通过，32/32 轮基准完成且内容校验首轮通过**。详细命令、身份、
时间、日志哈希与每项结果见[正式产物验收报告](HEALTH_20261008_FORMAL_VALIDATION.md)
和[机器记录](HEALTH_20261008_FORMAL_VALIDATION.json)。其中：

- fw4/uci 断管道 888 行及其它一次性诊断 360 行，实际 stdout/stderr 内容
  与退出状态检查通过；包含读端在 spawn 前关闭的确定性回归。
- fw4 upstream corpus/defaults、uci 字节/文件状态、reload-config 协议内容
  通过；r56 真实 DHCPv6、r62 PD 生命周期通过。旧 r56 不比较 updated/
  ifupdate，该部分由新 13 输入回放另行比较，不能把两者覆盖混为一谈。
- 原 13 输入且 DAD 开启的完整状态/通知回放、短 PD 后不再发送通知的自然
  到期回归通过，测试中的真实地址、flags、sysctl、route/rule 和输出内容
  都参与比较。
- native 配置迁移/保留、错误恢复身份拒绝、九份 C 恢复、真实 APK 载荷
  重装通过；九组件从标准路径启动，HTTP/HTTPS 内容、日志、UCI/reload、
  fw4 原版字节对照和 nft check、隔离 PID1 重启均通过。

基准覆盖 fw4、uci、reload-config、netifd，每项 C/Rust 各四轮，顺序平衡；
成功还包含实际内容校验，不能只靠 exit=0 记绿。详细结果见[基准 JSON](HEALTH_20261008_BENCHMARKS.json)。共 32 个完整 run、
120 个负载结果、433,600 次成功测量。下表为各侧四轮“每轮平均延迟”的
中位数；负数表示本次主机上耗时更少：

| 负载 | C（µs） | r3（µs） | 相对 C |
|---|---:|---:|---:|
| fw4 / print | 20103.81 | 993.97 | -95.06% |
| fw4 / check | 32069.50 | 11991.64 | -62.61% |
| uci / export_network | 577.45 | 301.23 | -47.83% |
| reload-config / unchanged_config | 7861.58 | 808.29 | -89.72% |
| netifd / reload_unchanged | 762.79 | 941.98 | +23.49% |

15 种负载中 14 种 Rust 比 C 快；**netifd unchanged reload 比 C 慢 23.49%**，
四轮数据保留。这里是同一构建主机的 C/r3 比较，没有做 r2/r3 同窗口性能
对照，也没有测物理路由器性能；不能把这一差距归因于本轮修改，不能声称
“无性能回退”。本轮以修复可重复的 abort 和内核兼容遗漏为重发依据，
保留这一已测性能限制，不为追求性能绿而改写结果或再占用 oracle。


第一次正式 driver 误用含设备节点的 rootfs 触发 Python copytree 阻塞，
尚未启动任何 CLI 实例或测量。只停止该测试 driver，保留失败记录，改用
同镜像的普通文件提取目录并重新核对九个 C 身份；有效批次不含该次预备
失败，没有重构建组件。

有效批次开始于 `2026-10-09T08:14:43.651044Z`，结束于
`2026-10-09T08:27:09.811512Z`。每个测试入口前检查 `cpu-a-79e`；本批次无
冲突。所需原始证据已取回本机，oracle 计算及取证连接均已结束，立即通知
用户可开始 dnsmasq 独占 CPU 窗口。之后的报告汇总只在本机进行。



## 部署计划与恢复门（不执行）

只有候选 go、另行取得用户明确部署授权，且以下恢复门重新通过后，才能
把 r3 安装到物理设备。Wi-Fi 管理有效，不以 LAN 网线作为部署前提。

1. 恢复设备连通后先做约三分钟只读基线：九组件实际运行/磁盘身份、
   WAN/WAN6、LAN DHCP、双频 AP、LuCI HTTP/HTTPS、IPv4/IPv6 DNS 和外网
   访问，以及客户端健康。保全新的故障证据。
2. 在电脑离线保存并校验当前配置备份、必要 overlay/恢复资料、r2 已验收
   镜像、固定官方救援镜像和九份 C 原件；验证可读取、可解包、哈希一致。
   旧备份不能代替当次部署前备份。
3. 逐项核对 r3 CI run、源码提交、固件 SHA-256、APK 与九个 ELF，确认
   `native-nine`、配置保留清单和空间余量。使用完整固件升级流程；统一
   APK 是镜像装配输入，不用于在线替换 PID1/总线。
4. 先在同一候选镜像的隔离环境验证适用于 native 布局的自动回退：错误
   恢复身份拒绝写入、健康超时和未确认重复启动触发恢复、恢复后不循环
   重启、显式健康确认解除当次试验。C 恢复源必须是已核验的
   `/usr/libexec/owrt-stock/`；不可沿用把 `/rom/sbin/*` 当 C 的旧假设。
   在该门通过前，不把历史 layered guard 当作现成保护。
5. 授权部署后按既定配置保留策略升级，回连后核验全部实际运行身份与
   配置保持，并连续检查至少三分钟客户端和路由器健康。只有自动回退
   已就绪且客户端 DHCP、双频 AP、管理页面、DNS、IPv4/IPv6 外网检查均
   通过，才确认部署；失败保留证据并走已验证的回退路径。
6. 部署确认后继续观察 fw4 转储是否新增及 WAN6 输入变化。上游 RA 抖动
   不以屏蔽 `ifupdate` 或去重隐藏。日志建议送到带容量/保留期限的远程
   接收端；本轮不改变日志配置。

这些是后续部署准入条件，不表示本轮已对物理设备执行或通过恢复门。

## 工作分支与证据保留

整合热修复工作树为 `/Users/USER/Developer/owrt-health-r3`。原 `main` 的
并发工作和未提交文件保持不动。已完成的 CLI/netifd 任务分支与工作树已
清理；原实验提交分别保留在 `archive/health-20261008-cli`、
`archive/health-20261008-netifd` 标签，私有本地材料搬到本工作树
`private/health-20261008/{cli-local,netifd-local}`。原主仓库及 oracle 中的
大体量原始证据仍在各分报告记录的位置。
