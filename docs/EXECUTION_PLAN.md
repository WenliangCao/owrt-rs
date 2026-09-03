# Rust-native OpenWrt Control Plane：执行计划

> 版本：5.0，2026-09-02
> 状态：第一轮（阶段 1–5）**完成**（2026-09-02），R05、logd、uhttpd、fw4、rpcd 插件层由 Rust 实现接管并开机启动，收官综合窗口通过，见 [FINAL_REPORT](../reports/ax3000t-stock-openwrt-25.12.5/FINAL_REPORT.md)。第二轮（阶段 6–9，§11）进行中：§11.0 自检、阶段 6（uci-rs 接管 `/sbin/uci`）、阶段 7（rpcd-rs 接管 `session`/`uci`/`rc`）与阶段 8（rpcd-rs 接管全部 rpcd 对象，原 rpcd 停止）已完成 2026-09-02；阶段 9（ubusd）经前置检验判定不执行（决策 0015）。第二轮收官见 [REPORT_ROUND2](../reports/ax3000t-stock-openwrt-25.12.5/REPORT_ROUND2.md)。 第三轮（§11.8，2026-09-03 起）：用户放宽设备边界（有线可达、接受崩溃、要求完整备份与救援机制），决策 0016 允许一次受控重启验证开机路径；ubusd 排最后。
> v4→v5 变更：只新增 §11；§0–§10 保持第一轮原文，作为已完成工作的记录。
> 历史：v2（1066 行）见 [archive/stage-gates/EXECUTION_PLAN_v2_2026-09-02.md](../archive/stage-gates/EXECUTION_PLAN_v2_2026-09-02.md)

## 0. 终点是什么，以及能否在五个阶段内到达

**终点的定义**：在这台 Xiaomi AX3000T 上，凡是"失效后不会切断唯一管理路径、也不会让设备无法
启动"的控制面职责，全部由 Rust 实现并作为开机默认路径运行；其余职责保留 C 实现，并有书面理由。
按 I0 的 17 项职责分类，这意味着：

| 去向 | 职责 | 理由 |
|---|---|---|
| Rust，五阶段内完成 | R05 配置变更分发、R15 logd、R14 uhttpd、R09 firewall4 生成、R13 rpcd | 失效面分别是：事件漏发、日志、Web UI、规则生成（有字节级 oracle）、管理 API；都能靠 SSH 或断电恢复 |
| 保留 C，明确不做 | R01 procd、R03 启动编排、R07 netifd、R08 无线、R12 ubusd、R17 升级 | 失效即失去 SSH 或无法启动；本机是唯一设备且无 UART/拆机（决策 0006），没有恢复路径 |
| 保留，无价值替换 | R02 init 框架、R06 首启生成、R10 dnsmasq、R11 odhcpd、R16 hotplug | 属于执行面或一次性脚本 |
| 视阶段 5 证据决定 | R04 UCI 库 | 只在 rpcd 的 `uci` 对象需要时以最小方式触及 |

**能否做到**：阶段 1–4 我有把握，每一阶段都有可字节比对或可并排运行的 oracle，都有"disable
即恢复"的退路，也都不碰上表第二行。阶段 5（rpcd）是唯一不确定的一段：范围取决于阶段 3 实测到的
LuCI 调用集，可能是完整替换，也可能收在 `session`/`file`/`luci` 三族而把 `uci` 对象留给原实现。
两种落点都算终点，区别只是最终报告里 Rust 覆盖的对象数。

**做不到的事要说清**：第二行的六项在只有一台生产路由器、没有恢复路径的条件下不会去做。若将来有
第二台同型号设备作为实验机，netifd 与 ubusd 可以重新评估；这不需要 UART，只需要一台坏了也不影响
家里网络的机器。

## 1. 工作方式（对此前积弊的直接纠正）

1. **每完成一个任务 commit 一次**，不积压。
2. **阶段 = 结果**，不是仪式。每阶段只产出四样东西：一份决策记录（`docs/decisions/`）、代码、一份
   验证报告（`reports/`）、一份 manifest JSON（`manifests/`）。不再写 preflight/review/gate 脚本，
   不在 README、runbook、计划、报告之间复写状态；README 只做索引。
3. **验证强度按爆炸半径定**。规则生成器用字节 diff；daemon 用并排运行；接管路径必须先证明
   `disable` 能回到原状，再证明 `enable`。
4. **设备窗口的固定形式**：只读 precheck（hash、pid、mount）→ 操作 → postcheck（同一组 hash）→
   drift 复核。原始输出留在 Git 外的 `private/`，报告只写脱敏结论。
5. **授权粒度**：每阶段向用户要两次授权——"安装但不启用"和"启用/开机接管"。只读探针不再逐次
   申请。任何重启、刷机、拆机永久不在路径上。
6. **依赖策略**：R1 做到零第三方 crate。后续允许少量成熟 crate（TLS 无法自研），每引入一个都在
   决策记录里写明理由和二进制体积影响；overlay 剩余 57 MB，RAM 可用 120 MB，体积不是硬约束但要记账。
7. **不做的事**：不建通用框架，不提前设计"控制面总线"，不为未排期的职责写接口草稿。

## 2. 已完成（不再重做）

| 阶段 | 结论 | 记录 |
|---|---|---|
| I0 | 17 项职责分类；唯一替换候选 R05 | [I0_FINAL_REPORT](../reports/ax3000t-stock-openwrt-25.12.5/I0_FINAL_REPORT.md)、[REPLACEMENT_BOUNDARY](../reports/ax3000t-stock-openwrt-25.12.5/REPLACEMENT_BOUNDARY.md) |
| C1 | 合同 C1-01，11 个参考用例 | [config-change-dispatch](contracts/config-change-dispatch.md) |
| R1 | Rust 候选 11/11 合同、6/6 故障与原实现一致，零依赖，432 KB 静态 | [R1_IMPLEMENTATION](../reports/ax3000t-stock-openwrt-25.12.5/R1_IMPLEMENTATION.md) |
| V1 | 官方 SDK package，默认 disabled，reboot 即失的 bind mount | [V1_VALIDATION](../reports/ax3000t-stock-openwrt-25.12.5/V1_VALIDATION.md) |
| H1.4 | 实机 `/tmp` shadow 通过 | [H1_4_SHADOW](../reports/ax3000t-stock-openwrt-25.12.5/H1_4_SHADOW.md) |
| H1.5 | APK 已安装，disabled | [H1_5_DISABLED_INSTALL](../reports/ax3000t-stock-openwrt-25.12.5/H1_5_DISABLED_INSTALL.md) |
| drift | `network` drift 成因与收口 | [H1_6_DRIFT_PROBE](../reports/ax3000t-stock-openwrt-25.12.5/H1_6_DRIFT_PROBE.md) |
| H1.6 | 候选真实接管、真实 ubus 投递、切回静默 | [H1_6_CANARY](../reports/ax3000t-stock-openwrt-25.12.5/H1_6_CANARY.md) |
| 阶段 1 | R05 0.2.0 转正：syslog trace、S11 开机重新接管、boot-enable on | [R05_GO_LIVE](../reports/ax3000t-stock-openwrt-25.12.5/R05_GO_LIVE.md)、[决策 0007](decisions/0007-r05-boot-enable-and-syslog-trace.md) |
| 阶段 2 | Rust ubus 库 + logd 替换，并排比对 10/10，boot-enable on | [R15_LOGD](../reports/ax3000t-stock-openwrt-25.12.5/R15_LOGD.md)、[合同 C2](contracts/logd.md)、[决策 0008](decisions/0008-replace-logd-with-rust-and-own-ubus-library.md) |
| 阶段 3 | httpd 替换（静态/CGI/ubus 桥/TLS），并排 38/38，设备并排+canary 一致，boot-enable on | [R14_HTTPD](../reports/ax3000t-stock-openwrt-25.12.5/R14_HTTPD.md)、[合同 C3](contracts/httpd.md)、[决策 0009](decisions/0009-replace-uhttpd-with-rust-httpd.md) |
| 阶段 4 | fw4 生成器 Rust 化，上游 31/31 逐字节，设备 print 门禁相同后接管 `/sbin/fw4`，经候选 reload 规则集不变，boot-enable on | [R09_FW4](../reports/ax3000t-stock-openwrt-25.12.5/R09_FW4.md)、[合同 C4](contracts/fw4.md)、[决策 0010](decisions/0010-port-firewall4-to-rust.md) |
| 阶段 5（rpcd） | rpcd 插件层 `file`/`luci` Rust 化，沙箱 63/63 相同，裁剪插件目录 + rpcd-rs 服务上线，boot-enable on；session/uci/rc 保留 C | [R13_RPCD](../reports/ax3000t-stock-openwrt-25.12.5/R13_RPCD.md)、[合同 C5](contracts/rpcd-plugins.md)、[决策 0011](decisions/0011-rpcd-plugin-layer-in-rust.md) |
| 阶段 6（uci） | libuci 语义 + `uci-rs` CLI，上游 112/112，rootfs 差分 175/175，设备门禁 export/show/changes 相同后 bind mount 接管 `/sbin/uci`，reload_config 经候选 0 差异，boot-enable on（S00） | [R16_UCI](../reports/ax3000t-stock-openwrt-25.12.5/R16_UCI.md)、[合同 C6](contracts/uci.md)、[决策 0012](decisions/0012-uci-library-and-cli-in-rust.md) |
| 阶段 7（rpcd 核心） | `session`/`uci`/`rc` 迁入 rpcd-rs（`uci` 对象基于阶段 6 库），rootfs 双沙箱差分 272/272，设备只读门禁 51 项相同，enable 顺序"停 rpcd → 起 rpcd-rs → 起 rpcd（只剩插件）"，boot-enable on（S11） | [R17_RPCD_CORE](../reports/ax3000t-stock-openwrt-25.12.5/R17_RPCD_CORE.md)、[合同 C7](contracts/rpcd-core.md)、[决策 0013](decisions/0013-rpcd-core-objects-in-rust.md) |
| 阶段 8（rpcd 插件 + netlink 读侧） | `rpc-sys`/`network.rrdns`/`luci-rpc`/`iwinfo` 迁入 rpcd-rs，libiwinfo nl80211 后端与 rtnetlink 读侧纯 Rust 复刻；沙箱 r18 74/74、并排 r19 11/11；设备只读门禁 49 项相同；原 rpcd 停止、S12 移除 | [R18_RPCD_PLUGINS](../reports/ax3000t-stock-openwrt-25.12.5/R18_RPCD_PLUGINS.md)、[合同 C8](contracts/rpcd-plugins-stage8.md)、[决策 0014](decisions/0014-rpcd-plugin-objects-and-netlink-read-side.md) |
| 阶段 9（ubusd，有条件） | 不执行：r22 沙箱显示 odhcpd/dnsmasq/netifd.wireless 在 ubusd 重启后不恢复，在线切换需重启 netifd 等禁区组件 | [决策 0015](decisions/0015-ubusd-replacement-not-executed.md)、`tools/r22_ubus_clients_reconnect.sh` |

设备实测事实（2026-09-02 只读探针）：uhttpd 监听 80/443，`/ubus` 由 `uhttpd-mod-ubus` 提供，LuCI
以 CGI 方式运行 `/www/cgi-bin/luci`（ucode，无 Lua）；rpcd 插件 file/iwinfo/luci/rpcsys/rrdns/ucode，
ubus 共 40 个对象；fw4 生成 203 行 ruleset，含一个默认 include；logd 以 `-S 128` 运行，未配置远程
syslog；候选 R05 package 已安装且 disabled。

## 3. 阶段 1：R05 收官——Rust dispatcher 成为开机默认路径（已完成 2026-09-02）

**目标**：每次启动后，`/sbin/reload_config` 的所有调用都由 Rust 候选处理；原实现文件保留为
`disable` 后的回退；一个约 3 分钟的启用窗口内零投递失败。

**工作项**
1. 候选 0.2.0：trace 从 stderr 改为写 syslog（`/dev/log`，tag `reload_config`），stderr 与原实现一样
   静默；保留 `--trace-stderr` 供手工调试。这是接管默认路径前唯一必要的行为修正。
2. 在服务器精确 rootfs harness 重跑 11 个合同用例与 6 个故障用例（工具已有：`r1_candidate_check.py`、
   `v1_package_check.py`），确认与 0.1.0 仅差 trace 去向。
3. package 增加 `/etc/init.d/owrt-reload-config`（START=11，紧跟 `boot` 的 S10）：开机时执行
   `switch enable`。S10 那一次仍由原实现处理，因此候选出错不会影响启动；同时增加一条 uci-defaults
   之外的显式 `enable-on-boot` 开关，默认关闭，安装后不改变行为。
4. 设备：升级到 0.2.0（disabled），窗口内 `enable` 复跑 H1.6 三批；然后打开 `enable-on-boot`。
   下一次用户自然重启后（不为此重启）复核 mount、trace 进 logread、baseline 一致。
5. 约 3 分钟监测窗口：启用后一次只读探针（mount、baseline drift、logread 中的 delivery 失败计数）。
6. 仓库瘦身：README 收成索引；`tools/` 只留可重复运行的脚本。

**爆炸半径**：事件漏发（原实现同样静默）。**退路**：`switch disable` 或关闭 `enable-on-boot`；
最坏断电重启回到原实现。

**退出条件**：开机接管已发生一次；窗口内 `delivery_failures` 总计 0；drift 复核 0；报告
`R05_GO_LIVE.md`。

**规模**：Rust 改动约 100 行；package 改动约 60 行 shell；两个设备窗口。

## 4. 阶段 2：R15 logd 替换，并建立 Rust ubus 库（已完成 2026-09-02）

**目标**：`logd` 由 Rust 实现替代并开机运行；`logread`、`logread -f`、`logger`、`log.read`/`log.write`
行为与原实现一致；产出可复用的 `components/ubus` 库（连接、lookup、invoke、注册对象、回复、
notify/subscribe、fd 传递）。

**为什么先做它**：logd 只有两个 ubus 方法，失效只影响可观测性；但它把"注册 ubus 对象 + 通过 ubusd
ACL + 作为 procd instance 运行"三条契约一次跑通。阶段 3、4、5 全部依赖这套 ubus 库。

**工作项**
1. 证据：读 ubox/logd 与 logread 源码、libubus 线协议（`ubusmsg.h`、blobmsg）、`/usr/share/acl.d`
   中 `log` 的 ACL、设备 `system` 配置的 log 选项（已知：size 128，udp，无远程地址）。冻结合同
   C2：环形缓冲区语义、`read` 的 oneshot/stream 与 fd 传递、`write` 的 priority/source 字段、
   `/dev/log` 与 kmsg 的接入、`logread -e/-l/-f/-t` 输出格式。
2. `components/ubus`：不依赖 libubus，纯 Rust 实现 unix socket 上的 ubus 报文。用 ubusd 在精确
   rootfs harness 中做对照测试：同一调用在 `ubus` CLI 与本库下的 blob 逐字节一致。
3. `components/logd`：单线程 + poll，环形缓冲区、`/dev/log`、`/dev/kmsg`、远程 syslog（udp/tcp）、
   文件输出，按 `system` 配置。通过 `uci -q get` 读配置，不引入 UCI 库。
4. package `owrt-logd`：自带 init 脚本，默认 disabled；`enable` = 停原 `log` 服务并启动本实现；
   `disable` 反向。开机顺序与原 `log`（START=12）相同。
5. 设备：安装 disabled → 5 分钟窗口并排验证（`logger` 写入、`logread` 读出、`logread -f` 流式、
   `ubus call log read`）→ disable → 打开开机启用 → 约 3 分钟监测窗口。

**爆炸半径**：切换瞬间丢失环形缓冲区内容（原实现重启同样如此）；失效时无日志但设备与 SSH 正常。
**退路**：`disable` 回到原 `log` 服务。

**退出条件**：C2 全部用例通过；开机由 Rust logd 服务；窗口内 `logread` 无缺失、无崩溃重启；
`components/ubus` 有对照测试。报告 `R15_LOGD.md`。

**规模**：ubus 库约 800 行，logd 约 700 行；两个设备窗口。

## 5. 阶段 3：R14 uhttpd 替换——Rust HTTP/TLS 前端与 `/ubus` 桥（已完成 2026-09-02）

**目标**：80/443 由 Rust 服务提供：静态文件、CGI（`/www/cgi-bin/luci` 与 cgi-io 四个入口）、
`/ubus` JSON-RPC 桥（会话与 ACL 判定走 `session.access`，复用阶段 2 的 ubus 库）、TLS。LuCI 全部
页面可用。同时记录每一次 `/ubus` 调用的对象与方法，作为阶段 5 的范围依据。

**工作项**
1. 证据：uhttpd 与 uhttpd-mod-ubus 源码；`/ubus` JSON-RPC 2.0 请求/响应/错误码、批量调用、
   `list`/`call` 语义；session cookie 与 `ubus_rpc_session` 的传递；CGI 环境变量集合；LuCI 依赖的
   header 与 MIME 行为；证书路径与 px5g 生成规则。冻结合同 C3。
2. 决策 0007：TLS 实现选择（rustls + 一个 crypto backend），记录体积与交叉编译验证。若用户确认
   只在 LAN 用 HTTP，可先不做 TLS，把 443 留给原 uhttpd。
3. `components/httpd`：单进程、非阻塞、无通用 Web 框架；CGI 用 fork/exec；`/ubus` 桥直接用
   ubus 库；访问日志写 syslog（进阶段 2 的 logd）。
4. 对照测试：在精确 rootfs harness 中用同一组 HTTP 请求（LuCI 登录、状态页、网络页、防火墙页、
   `/ubus` 批量调用、静态资源、404、大文件）比较原 uhttpd 与本实现的状态码、关键 header、body 哈希。
5. 设备：安装 disabled → 窗口内先在 8080/8443 并排运行，用真实浏览器走完 LuCI 主要页面 →
   disable → 再一次窗口交换端口（停 uhttpd、本实现占 80/443）→ 开机启用 → 约 3 分钟监测窗口；`/ubus` 调用清单在
   窗口内走完 LuCI 主要页面后导出。

**爆炸半径**：LuCI 不可用；SSH 不受影响。**退路**：`disable` 恢复 uhttpd。

**退出条件**：C3 通过；LuCI 主要页面在本实现下可用；开机由 Rust 服务监听；窗口内无崩溃；产出
`/ubus` 调用清单（对象 × 方法 × 次数）。报告 `R14_HTTPD.md`。

**规模**：约 2500 行（含 TLS 集成）；三个设备窗口。

## 6. 阶段 4：R09 firewall4 生成器 Rust 化

**目标**：Rust 实现的 `fw4` 从 `/etc/config/firewall`、`/etc/nftables.d/` include 与 ubus
`network.interface dump` 生成 nftables ruleset，与原 fw4 输出**字节相同**；`start/reload/print/check`
子命令一致；开机由 Rust 版本生成规则。

**为什么可控**：fw4 是一次性 ucode 程序，输出是完整文本，I0 已判定"只差一个差分测试"。上线条件
就是 diff 为空，因此上线那一刻应用的规则与原实现完全相同。

**工作项**
1. 证据：firewall4 的 `main.uc` 与 `fw4.uc`、上游仓库自带测试用例（作为额外 oracle）、设备当前
   203 行 ruleset 与 include 文件、`/etc/init.d/firewall` 与 hotplug 20-firewall 的调用方式。
   冻结合同 C4：输入集合、输出规范、include 处理顺序、`check` 语义。
2. `components/fw4`：解析 UCI（复用 `uci show` 规范化输出，与 R1 同一做法）、区域/规则/转发/
   NAT/ipset 建模、生成 nft 文本。不调用 ucode。
3. 差分：设备当前配置 + 上游测试用例 + 若干合成配置，`fw4 print` 与本实现逐字节比较；
   `nft -c -f` 检查。
4. package：bind mount 到 `/sbin/fw4`（与 R05 同一切换机制），默认 disabled。
5. 设备：安装 disabled → 窗口内 `print` 差分为空 → `enable` 后执行一次 `fw4 reload`（规则不变，
   `nft list ruleset` 前后哈希一致）→ 开机启用 → 约 3 分钟监测窗口（每次 `reload` 后 ruleset 哈希）。

**爆炸半径**：若 diff 不为空则不上线，因此上线不改变规则。理论最坏是运行时崩溃导致 reload 失败，
此时旧规则仍在内核中生效。**退路**：`disable`；断电重启由原 fw4 重建规则。

**退出条件**：C4 通过；设备配置差分为空；开机由 Rust fw4 生成；窗口内 reload 哈希不变。报告
`R09_FW4.md`。

**规模**：约 2000 行；两个设备窗口。

## 7. 阶段 5：R13 rpcd 替换与收官

**目标**：管理 API 由 Rust 提供，范围以阶段 3 记录的真实 LuCI 调用清单为准；所有 Rust 组件开机
默认运行并通过一次综合窗口；写出最终报告：哪些职责已是 Rust、哪些保留及理由、后续条件。

**两种落点**
- **A（完整）**：Rust rpcd 提供 `session`、`file`、`uci`、`rpc-sys`、`iwinfo`、`luci`、`luci-rpc`
  与 ucode 插件对象。`uci` 对象的 changes/apply/rollback 语义要求接近 UCI 库层面的实现，这里会
  触及 R04；只在调用清单确实需要时做，并以 `uci` CLI 为规范化后端。
- **B（收敛）**：Rust 提供 `session`、`file`、`rpc-sys`、`luci`、`luci-rpc`；`uci` 与 `iwinfo` 对象由
  裁剪后的原 rpcd 继续提供（移除对应插件即可分离）。若阶段 3 数据显示 `uci` 对象方法面大而 LuCI
  依赖深，选 B。

**工作项**
1. 证据：rpcd 源码（session 存储、ACL 合并规则、超时）、`/usr/share/rpcd/acl.d` 全部 ACL、
   阶段 3 调用清单、LuCI 对返回字段的精确依赖。冻结合同 C5。
2. `components/rpcd`：基于 ubus 库注册对象；`file` 的 exec/read/write 严格按 ACL；`session` 的
   login/access/set/get/destroy 与超时。
3. 对照：同一组 JSON-RPC 请求在原 rpcd 与本实现下响应一致（字段、顺序不敏感的结构比较、错误码）。
4. 设备：安装 disabled → 窗口内并排（本实现以临时对象名注册，或停原 rpcd 5 分钟）→ 开机启用。
5. 收官：合并五个 package 的启用开关为一处；约 3 分钟综合监测窗口；最终报告 `FINAL_REPORT.md`；更新
   README 为最终索引。

**爆炸半径**：LuCI 登录或操作失败；SSH 不受影响。**退路**：`disable` 恢复原 rpcd。

**退出条件**：C5 通过；LuCI 全部页面在 Rust rpcd 下可用；五个组件开机运行且综合窗口内无回退；最终报告。

**规模**：A 约 3500 行，B 约 2000 行；两到三个设备窗口。

## 8. 阶段间依赖与顺序

```text
阶段 1 R05 收官 ──┐
阶段 2 logd + ubus 库 ──► 阶段 3 httpd/ubus 桥 ──► 阶段 5 rpcd + 收官
                        └► 阶段 4 fw4（只用 ubus 库的 invoke，可与阶段 3 并行）
```

阶段 1 与阶段 2 的证据工作可以并行；阶段 4 可以与阶段 3 并行推进。

## 9. 每阶段固定要求

| 项 | 要求 |
|---|---|
| 决策记录 | 一份，说明为什么做、边界、依赖选择 |
| 合同 | `docs/contracts/` 一份，附参考用例 |
| 代码 | `components/<name>`，无通用框架；`packaging/openwrt/owrt-<name>` |
| 验证 | 精确 rootfs harness 对照 + 设备窗口；报告一份，manifest 一份 |
| 上线形态 | 默认 disabled 安装；显式 enable；开机启用有独立开关；`disable` 先于 `enable` 被证明 |
| 监测 | 用户要求每次约 3 分钟：启用后一个只读探针窗口，不做多日 soak |
| 提交 | 每个任务一次 commit |

## 10. 仍然禁止

拆机、UART、TFTP/U-Boot、raw NAND、固件写入；替换或修改 procd、ubusd、netifd、无线栈、sysupgrade
路径。这些不随"继续"解除。**2026-09-03 决策 0016 修订**：为验证开机路径的受控重启、OpenWrt failsafe、
恢复出厂三项从禁止项移出（前置条件与失败处置见该决策）；raw NAND 只读转储作为备份允许；TFTP 原厂
救援只作为用户操作的最后手段，不是计划步骤。

## 11. 第二轮（v5）：管理层全 Rust，执行层全保留

**出发点**：用户的原始愿景是"不重写 OpenWrt，做 Rust-native control plane"：kernel、驱动、nftables、
hostapd、dnsmasq、package/build system 全部保留，重新实现其上的管理层（ubus 库、UCI 库、网络状态、
服务管理、管理 API），最后再逐步替换 netifd/procd/ubusd 的一部分，始终保持 `/etc/config` 格式与
软件生态兼容。第一轮完成后，愿景里的前两项已各有一半：

- ubus client/server 库：`components/ubus`，四个组件共用（对象注册、invoke、notify、fd 传递）。
  缺 ubusd 侧的注册表、ACL、事件广播。
- UCI 解析器：fw4 与 rpcd 各有一份只读文本解析，没有 delta、commit、序列化。
- 强类型配置：fw4 的 firewall 配置模型已是强类型，可作模板。

**第二轮终点**：LuCI 之下从配置（UCI 读写）到状态（netlink）到管理 API（rpcd 全部对象）全是 Rust；
procd/netifd 的写路径、无线栈、sysupgrade 继续保留 C（§10 不变）。到达这一点后，"新的管理 API"
才有实体可架，在此之前不做 API 层。

### 11.0 前置：第一轮代码自检（不接触设备）——已完成 2026-09-02

结论见 [AUDIT_ROUND1](../reports/ax3000t-stock-openwrt-25.12.5/AUDIT_ROUND1.md)：修复 20 处行为差异（含 rpcd file.write 的 umask 模式、ubus 有符号整数、logd read 类型策略、httpd 413/MIME、fw4 ipset 空白与 %.14g），全部按 `cargo check → 单元 → 上游 31/31 → release → differential（rpcd 63/63+16、httpd 38/38、logd 10/10）` 重验通过；其余为不触发本设备且高风险的边缘行为，记录待阶段 6–9 收口。


按用户给出的 15 项迁移自检清单对 `components/` 全部代码做一次对抗式审查：架构/数据结构是否擅改、
是否有 stub/`unwrap()`/绕过逻辑、共享类型是否一致、`unsafe` 边界、整数与边界语义、异常行为、测试
是否被削弱、release 行为、跨 crate 接口漂移、可审计性、重构与迁移是否分离、重复错误模式、测试
执行路径。发现即修，按 `cargo check → smoke → 上游 regression → release → differential` 重验。
产出：一份报告 `reports/ax3000t-stock-openwrt-25.12.5/AUDIT_ROUND1.md`，列出行为差异、修复、
未能确认的风险、为 Rust 化而改变原行为之处。

### 11.1 阶段 6：`components/uci` 库 + `/sbin/uci` CLI——已完成 2026-09-02

结论见 [R16_UCI](../reports/ax3000t-stock-openwrt-25.12.5/R16_UCI.md)。合并 fw4/rpcd 内嵌解析器（下文"合并"项）推迟到阶段 7 与 rpcd `uci` 对象一起做。

- **替换**：libuci 的读、写、delta（`/tmp/.uci` savedir）、commit、revert、`export`/`show` 序列化；
  `/sbin/uci` CLI 以 bind mount 接管，形态同 fw4。
- **为什么先做**：是愿景"字符串配置变强类型"的根，也是阶段 7 `uci` 对象的前提；CLI 有字节级 oracle。
- **oracle**：同一组命令序列（get/set/add/delete/rename/reorder/commit/revert/changes/show/export，
  含 `-P /var/state`、`-c`、`-q`、`-S`、`-n` 等选项）跑在精确 rootfs 的设备配置上，比较 stdout、
  stderr、退出码、落盘文件与 savedir 内容；上游 libuci 的 tests/ 作只读 oracle。
- **退路**：`disable` 卸载 bind mount；门禁是 `uci show` 全库逐字节相同。
- **合并**：fw4、rpcd 里的两份解析器改为依赖本 crate（属迁移后的重构，单独 commit，单独重验）。rpcd 侧随阶段 7 完成；fw4 侧 2026-09-02 完成（上游 31/31、设备差分 203 行相同、owrt-fw4 r2 上线，见 R09 补记）。
- **规模**：约 2500 行；一份决策记录、合同 C6、报告、manifest。

### 11.2 阶段 7：rpcd 核心对象（session/uci/rc）——已完成 2026-09-02

结论见 [R17_RPCD_CORE](../reports/ax3000t-stock-openwrt-25.12.5/R17_RPCD_CORE.md)。§11.6 的 rpcd 内嵌解析器合并已随本阶段完成（沙箱 r13 63/63、r17 272/272）；fw4 的合并留待阶段 8。

- **替换**：`session`（登录经 `/etc/shadow` + libc `crypt`、ACL 合并 `/usr/share/rpcd/acl.d`、
  超时、冻结/解冻与 SIGHUP 再执行）、`uci` 对象（get/state/add/set/delete/rename/order/changes/
  commit/revert/apply 回滚计时器/confirm/rollback/reload_config，基于阶段 6 的 uci crate）、`rc`；
  并入现有 rpcd-rs 的 `file`/`luci`（ACL 检查改为进程内）。运行时状态放 `/var/run/rpcd-rs`。
- **混合形态**（决策 0013）：原 rpcd 的 `main.c` 忽略核心对象注册失败，因此 rpcd-rs 先注册
  （S11），原 rpcd 后启动（S12）只剩插件 `luci-rpc`/`iwinfo`/`rpc-sys`/`network.rrdns`；这四个
  对象与原 rpcd 进程的退出归阶段 8。
- **oracle**：`tools/r17_rpcd_core_check.py`，精确 rootfs 双沙箱（原：完整 rpcd；候选：rpcd-rs +
  插件裁剪的 rpcd），会话 id/expires 遮罩，272 步。
- **退路**：`owrt-rpcd-switch disable` 停 rpcd-rs、卸载裁剪目录、重启原 rpcd。enable/disable 都会
  使 LuCI 会话失效（需重新登录），窗口内告知。
- **依赖**：阶段 6 的 uci crate；crypt 直接用 musl libc 的 `crypt()`（无新 crate）。

### 11.3 阶段 8：netlink 客户端（只读）+ `luci-rpc`/`iwinfo`——已完成 2026-09-02（决策 0014，两步）

结论见 [R18_RPCD_PLUGINS](../reports/ax3000t-stock-openwrt-25.12.5/R18_RPCD_PLUGINS.md)。

- 8a 完成于 2026-09-02（沙箱）：`rpc-sys`、`network.rrdns` 移植，r18 58/58；`luci-rpc` 非无线方法
  （rtnetlink getifaddrs/邻居表、租约、主机提示、DUID、board）以测试名并排差分 r19 11/11。
- 8b 完成于 2026-09-02：nl80211 后端（libiwinfo f5dd57a8 复刻，5.8k 行）→ `iwinfo` 对象 + `getWirelessDevices`
  → 打包 r4 → 设备只读门禁 49 项相同（`tools/r20_go_live_device.sh`）→ 原 rpcd 停止并移除 S12。
- rpcd-rs 的 ubus 断连处理与 C rpcd 一致（退出，procd respawn），不另做重连；阶段 9 的前置以此计。

- **替换**：`luci-rpc`（getNetworkDevices/getWirelessDevices/getHostHints/getDHCPLeases/
  getBoardJSON/getDUIDHints/getConntrackHelpers）与 `iwinfo` 对象；这是"网络状态 daemon"的读侧：
  设备、地址、路由、邻居、无线状态的强类型模型。
- **oracle**：与 `ip -j link/addr/route/neigh`、`iwinfo`、原 luci-rpc 输出结构比较；只读，无爆炸半径。
- **规模**：rtnetlink + nl80211 约 2500 行；不引入 netlink crate（协议面小且需与内核头精确对应）。

### 11.4 阶段 9（有条件）：ubusd——不执行，2026-09-02（决策 0015）

前置条件检验未通过：`tools/r22_ubus_clients_reconnect.sh` 显示 ubusd 重启后 odhcpd 永不恢复、dnsmasq 空闲时不恢复、netifd 丢失 `network.wireless`；补救须重启 netifd/dnsmasq/odhcpd，触及 §11.5 的禁区。理由与解除条件见 [0015](decisions/0015-ubusd-replacement-not-executed.md)。

原文：

- **替换**：`/sbin/ubusd`（对象注册表、`/usr/share/acl.d` ACL、事件、monitor、invoke 转发）。
- **前置条件**：先在精确 rootfs 沙箱验证每个 libubus 客户端（procd、netifd、hostapd、dnsmasq、
  odhcpd、rpcd-rs、logd-rs、httpd-rs 桥）在 ubusd 消失后确实重连并重新注册对象；我们自己的三个
  daemon 目前不重连，须先补上。条件不满足则本阶段不做，理由写入决策记录。
- **退路**：重启 C ubusd，客户端重连。dropbear 不依赖 ubus，SSH 不受影响。
- **规模**：约 2000 行。

### 11.5 继续不做，以及解除条件

- netifd 写路径、procd（PID 1 与实例管理）、无线栈启停：单台生产路由器无恢复路径。有第二台
  同型号实验机即可开始，顺序是先 `network.interface` 状态读侧（阶段 8 已铺路），再 proto handler。
- sysupgrade、kernel、驱动、nftables、hostapd、dnsmasq、odhcpd：与愿景一致，保留。

### 11.6 两个收口（随阶段 6–9 顺带完成）

- 六个 crate 收成一个 Cargo workspace，抽出共享的 `uci`、`json`、`netlink`；合并 logd/httpd/fw4/
  rpcd 中的重复解析器。每次合并单独 commit，重跑该组件的 oracle。
- 给 logd-rs、rpcd-rs、httpd-rs 的 ubus 连接补重连逻辑（阶段 9 的前置）。进展 2026-09-02：logd-rs 已按
  libubus `ubus_auto_connect` 语义重连（每秒重试、重新注册 `log`、环形缓冲与流客户端保留），沙箱
  `tools/r21_logd_reconnect_check.sh` 验证 ubusd 重启后 2 秒内恢复；httpd-rs 每次请求新建连接，无需改动；
  rpcd-rs 待阶段 8b 收尾后加。顺带发现：ubusd 只加载 root:root 属主的 acl.d 文件，oracle 上的 rootfs
  副本属主是 ubuntu，之前所有沙箱都在无 ACL 状态下运行（root 客户端不受影响；harness 已改为 chown，
  r17/r18/r19 重跑结果不变）。

### 11.8 第三轮（2026-09-03 起）：开机路径验证与收口

**触发**：用户 2026-09-03 提出可用网线直连、接受崩溃、要求完整备份与救援机制，并问"下一步是 ubusd 吗"。
回答：不是；先验证从未跑过的开机路径。边界修订见 [决策 0016](decisions/0016-reboot-verification-and-rescue-boundary.md)，
救援手册见 [RUNBOOK_AX3000T_RECOVERY](RUNBOOK_AX3000T_RECOVERY.md)。

| 步 | 内容 | 状态 |
|---|---|---|
| 1 | 备份：`sysupgrade -b`、overlay 全量、mtd0–7 只读转储、fw_printenv、系统事实 → `private/backup/2026-09-03/`；官方 25.12.5 镜像与 RD03 原厂 1.0.47 固件下载校验 → `private/images/` | 完成 2026-09-03 |
| 2 | 预检：bootloader 选槽逻辑核实（只看 `flag_last_success`/`flag_try_sys2_failed`，计数不参与）；uci-rs 与 `/rom/sbin/uci` 的开机路径 export/show/get 19 包相同；`tools/r23_reboot_gate.sh pre` 参考态 | 完成 2026-09-03 |
| 3 | 受控重启一次：用户在设备旁、网线接 `lan4`、电脑另有上网途径；`reboot` → `r23 post` 逐文件 diff → 约 3 分钟观察；失败按 0016 §5 处置 | **完成 2026-09-03**：SSH 39 s 恢复，15/15 结构化状态相同，标志仅 sys1 计数 +1，4 分钟无 respawn；[R23_BOOT_PATH](../reports/ax3000t-stock-openwrt-25.12.5/R23_BOOT_PATH.md) |
| 4 | 部署 logd-rs r2（ubus 重连）；补 REPORT_ROUND2 §4 遗留 | **完成 2026-09-03**：r21 以同一二进制重跑通过，设备升级并重启 logd，3 分钟稳定；[R15 附录](../reports/ax3000t-stock-openwrt-25.12.5/R15_LOGD.md) |
| 5 | ubusd：仅在 1–4 全部通过后单独评估；0015 技术结论不变，默认建议不做 | **用户 2026-09-03 决定不做**；项目进入收尾 |
| 6 | 收尾·仓库：GitHub 私有仓库 `WenliangCao/owrt-control-plane-rs`，124 个历史提交作者/提交者邮箱重写为 noreply（tag `pre-rewrite` 保留原历史）；根 `Makefile`（test/check-tools/apk/image）+ GitHub Actions host 测试 | 完成 2026-09-03，CI 绿 |
| 7 | 收尾·Benchmark：一次性程序并排、httpd 并排（uhttpd 临时 8080）、logd/rpcd 切换窗口；发现并修复 reload_config 10 ms 轮询（r3 上线） | 完成 2026-09-03，[BENCHMARK](../reports/ax3000t-stock-openwrt-25.12.5/BENCHMARK.md) |
| 8 | 收尾·发布流水线：`tools/release.sh fetch/apk/image` + ImageBuilder（本地包索引、`DISABLED_SERVICES`、`FILES` 标记），对 25.12.5 产出自定义 sysupgrade 镜像并离线验证，不刷写 | [RELEASE](RELEASE.md)、`manifests/release-25.12.5.json` |

### 11.9 第四轮（2026-09-03 起）：找 bug，追性能

**用户目标**：① 找出已存在或可能存在的 bug；② 性能输给原版的地方查找、打磨，追平或超过。
两条线并行，每项都要有"发现 → 修复 → 沙箱差分不变 → 设备窗口重测"的闭环；修复合并进各包的下一个 release。

**A. 性能（以 [BENCHMARK](../reports/ax3000t-stock-openwrt-25.12.5/BENCHMARK.md) 为基线）**

| # | 项 | 嫌疑/根因 | 处置 |
|---|---|---|---|
| A1 | rpcd `file exec` 每次多至 10 ms、`rc list` 每脚本多至 5 ms | `try_wait` + `sleep` 轮询（与 reload_config r1 同一类） | **完成**：`procwait`（阻塞等待 + 超时线程），rpcd r6 上线，`file exec /bin/true` 6.0 ms |
| A2 | reload_config 96 vs 79 ms | 19 次 `md5sum` fork，C 脚本只 fork 一次 | **完成**：r4 上线，64.9 vs 77.6 ms，已快于原脚本 |
| A3 | `logread` 全量 60 vs 26 ms，且与条数线性（约 50 µs/条） | 环缓冲 `list()` 或每条 frame 构造的 O(n) 开销；管道 64 KB vs C 的 socketpair | **完成（无差距）**：控制环内行数后（各 500 行，`logread -l 400` ×20）C 0.44 s、logd-rs 0.44 s 相同；沙箱 strace 帧长与客户端系统调用相同。原差距是环内行数不同的测量假象。socketpair + BlobBuf 复用（logd r3）保留 |
| A4 | `iwinfo info` 28 vs 19 ms、`getWirelessDevices` 73 vs 49 ms；CPU 时间≈0，纯等待 | 每个 op 独立 netlink/固件往返，可能比 C 多发请求（重复 wiphy dump / survey） | **大部分完成**：逐 op 对照（`--iwinfo-bench` vs 同机 C 计时程序）显示请求数相同（42 次）；每次 recv 分配并清零 64 KiB 是主因，改为每线程复用后 24.0 / 60.0 ms（C 19.0 / 48.8）；剩余差距在 `htmodelist`/`noise`。**决策 0017 后关闭**：rpcd r8 `iwinfo info` 16.8 vs C 18.4、`getWirelessDevices` 46.0 vs 50.2 ms |
| A5 | `uci export`（19 包）8.0 vs 5.9 ms、`show` 4.0 vs 3.5 ms | show 路径整包 clone；解析器每 token 分配 | **根因找到并修复（决策 0017）**：构建机上同源静态构建与 C 持平；差距来自 `opt-level z` + 动态链接。改 opt-level 3 + 静态后 uci r4 设备实测 `export` 5.5 vs 5.9、`show firewall` 2.7 vs 3.1、`get` 1.9 vs 2.6 ms，全部快于 C。六组件同改并已上线（第三个窗口），全量重测见 BENCHMARK §11：uci 五项、fw4、reload_config、iwinfo、getWirelessDevices 全部快于原版 |

**B. bug**

| # | 项 | 方法 |
|---|---|---|
| B1 | 时序类缺陷普查 | **完成**：rpcd file.rs / rc.rs 轮询已改（r6）；其余 sleep 均对应 C 的原有 sleep（rpc-sys 延迟重启、passwd 管道、uci apply 回滚） |
| B2 | clippy | 已跑（uci 9、logd 2、httpd 1、fw4 21、rpcd 23 条）：全部为风格类，无真 bug；清零待做 |
| B3 | panic 面 | **复核完成**：125 处 unwrap/expect 中非测试代码的每一处都有前置守卫（fw4 sections.rs 10 处、rpcd rtnl/lucirpc/luci、ubus blob.rs）；真正的 panic 来自 B4 的字符边界索引，已修 |
| B4 | 非 UTF-8 | **uci 修复并上线（r3，设备 export 哈希前后不变）**：uci-rs 把非 UTF-8 字节替换成 U+FFFD 且遇到行首高位字节会 panic（abort，波及 rpcd-rs 的 `uci` 对象与 fw4-rs 开机）；值改为字节保真，CLI argv 走 `args_os`；rpcd/fw4 在 blobmsg/JSON 边界有损转换（DEVIATION 注释）。其余 `read_to_string` 点（ethers/board.json/resolv.conf 等）待改为按字节读 |
| B5 | 差分模糊 | **uci 完成**：`tools/r24_uci_fuzz.py`（150 例/种子）找到 B4 的 panic 与字节替换，其余 144 例与 C 逐字节相同；fw4/rpcd/httpd/logd 的模糊待做 |
| B6 | 资源 | daemon 在压测前后 fd 数、RSS 不增长；rpcd 会话过期、logd 环大小上限 |

**边界不变**：设备窗口仍是 disable/enable 切换 + 约 3 分钟探针；不刷机、不动 nvram；每个修复一次 commit。

### 11.7 顺序与依赖

```text
11.0 自检 ──► 阶段 6 uci 库/CLI ──► 阶段 7 rpcd 完整 ──► 阶段 9 ubusd（有条件）
                                └► 阶段 8 netlink/luci-rpc/iwinfo（可与阶段 7 并行）
```

§1 工作方式、§9 每阶段固定要求、§10 禁止事项全部沿用；每阶段两次设备授权（安装不启用 / 启用与
开机接管），监测窗口约 3 分钟。

### 11.10 第五轮（2026-09-03 夜起）：字节读取、差分模糊、clippy 清零

用户指令："rpcd 里 read_to_string 读 ethers/board.json/resolv.conf 改按字节读；fw4/rpcd/httpd/logd 的差分模糊；clippy 清零；做完了直接替换到路由器里。"
报告 `reports/.../R25_ROUND5.md`。

| # | 项 | 状态 |
|---|---|---|
| C1 | 字节读取：rpcd 7 处（shadow/passwd/group/ethers/board.json/resolv.conf/ACL/`luci` 读文件）、fw4 include 与 /proc /sys 读、logd passwd | **完成**（`util::read_lossy`） |
| C2 | clippy 清零（七个 crate，含 1 个 deny 级 `while_immutable_condition`——与 C 同义的 `while (ready)`，改 `if ready { loop }`） | **完成**：全部 0 |
| C3 | 差分模糊 fw4（`r29`）：ucode fw4 vs fw4-rs 同一变异配置 | **完成**：找到并修 2 处——列表值在警告里的字符串化、非 ASCII 值的 char-boundary panic（abort → 无防火墙）；ucode 自身在 defaults/include 非法时崩溃（每 200 例约 25 次）记为不复刻的 DEVIATION |
| C4 | 差分模糊 rpcd（`r26`）：63 方法 × 随机参数 | **完成**：4 种子 × 615 步 0 差异 |
| C5 | 差分模糊 logd（`r28`）：原始 syslog 报文 + 坏 ubus 参数 | **完成**：0 差异 |
| C6 | 差分模糊 httpd（`r27`）：畸形请求 133 例 | **完成**：修 6 处（`%00` 与坏 chunk 长度不再静默断开、错误状态行版本与正文按 uhttpd、请求行空格折叠、JSON 尾部垃圾）；其余 ~25 例是有意的错误路径偏差（R25 §3.3） |
| C7 | 重建并部署 uci r5、fw4 r5、logd r5、rpcd r9、httpd r3（reload-config 无改动） | **完成**（2026-09-03 23:22，全部门禁通过，3 分钟探针干净） |
