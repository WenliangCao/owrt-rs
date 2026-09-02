# Rust-native OpenWrt Control Plane：五阶段执行计划

> 版本：4.0，2026-09-02
> 状态：R05 实机验证完成（H1.4 shadow、H1.5 disabled install、H1.6 canary 全部通过）；进入阶段 1
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

设备实测事实（2026-09-02 只读探针）：uhttpd 监听 80/443，`/ubus` 由 `uhttpd-mod-ubus` 提供，LuCI
以 CGI 方式运行 `/www/cgi-bin/luci`（ucode，无 Lua）；rpcd 插件 file/iwinfo/luci/rpcsys/rrdns/ucode，
ubus 共 40 个对象；fw4 生成 203 行 ruleset，含一个默认 include；logd 以 `-S 128` 运行，未配置远程
syslog；候选 R05 package 已安装且 disabled。

## 3. 阶段 1：R05 收官——Rust dispatcher 成为开机默认路径

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

## 4. 阶段 2：R15 logd 替换，并建立 Rust ubus 库

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

## 5. 阶段 3：R14 uhttpd 替换——Rust HTTP/TLS 前端与 `/ubus` 桥

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

拆机、UART、TFTP/U-Boot、raw NAND、固件写入、为本项目主动重启设备；替换或修改 procd、ubusd、
netifd、无线栈、sysupgrade 路径。这些不随"继续"解除。
