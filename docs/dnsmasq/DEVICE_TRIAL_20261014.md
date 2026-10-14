# AX3000T 真机临时试运行：2026-10-14

**结论：Rust 版在本次约 15 分钟的家庭 Wi-Fi 试运行中承接了实际 DNS 和 DHCP 请求。候选运行期间，已测本地 DNS/DHCP、Mac 重连、IPv4/IPv6 上网及 LuCI 路径未见新增失败。可以进入下一阶段部署验收，但本次不足以批准无条件正式替换 C。** 公网 TCP DNS 尚未通过现场验收，首次地址获取和自然定时续租未覆盖，完整安装包的 init/ACL 也没有安装验证。

**试运行已结束，路由器已自动恢复原 C 版。** 没有执行刷写、安装包、持久配置改写、路由器重启、产品代码修改或 GitHub push。用户最后确认 Mac 重连后一切正常，随后不再要求用户参与；后续检查和收尾均自动完成。

## 范围与身份

设备为 Xiaomi Mi Router AX3000T，现场系统 OpenWrt **25.12.5 r33051-f5dae5ece4**、Linux **6.12.94**。通过家用 Wi-Fi 管理，真实客户端为管理用 Mac；iPhone/iPad 未参与。家庭其他设备保持日常使用，没有主动断开它们或模拟新的家庭客户端。

| 对象 | 精确身份 |
| --- | --- |
| 试运行时 main | `2b1e5cb63c552e4450e2ca17be6ad12144ff329a` |
| 已验收产品/包源码冻结 | `b587282081b72ea0f96cf909e0f70b0bc8de9372`；main 对应产品和包输入一致 |
| 实际上传并运行的 SDK APK 内 ELF | 2,124,571 B；SHA256 `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c` |
| stock C：试前、ROM、恢复后实际进程 | SHA256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 使用的 main 试运行脚本 | SHA256 `dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74` |
| 原 stock init / ACL | SHA256 `610f043921f86083ef8e28f34acc2f853145469c6ae4f2994670916bb4062a7f` / `2d412bf29ea25d9dd51dcdc77884e3fe21b91e4ce3e0125ec8749d1799aca39d`；前后未变 |

ELF 从已核验的最终 SDK 归档提取，上传后再次核哈希，并核对实际 `/proc/<pid>/exe`。仅将 tmpfs 中的候选临时 bind 到 `/usr/sbin/dnsmasq`，保留原 stock init 与 ujail，由现场既有 Rust procd 管理，使用现场生成的配置、租约、hosts 和上游信息。**r4 APK 未安装，其新 init/ACL 不在本次真机覆盖范围内。** 先前实验室资格见 [main 合并验收](MERGE_READINESS_20261014.md) 和 [最终 SDK 收据](audits/full-20261014/SDK_FINAL_B587.md)，不把它们替作本次现场结果。

## 准备与恢复门

替换前将 `/etc` 备份及生成配置、hosts、resolver、租约和 helper 等运行输入拷回电脑 `private/device-trial-20261014/`。配置归档含 261 个条目，覆盖当次 `sysupgrade -l` 清单；运行输入归档含 10 个条目。私有目录权限为 0700，配置、客户名称、MAC、地址、完整日志和二进制均未提交 Git。

- 配置备份 SHA256：`7fa606784bcc8e8454506d5bc75d6663d3d9bf1825c446eeda7e6e222d83a183`。
- 运行输入备份 SHA256：`e1befa00f92811f53c9ccd8c5678a5aa41267c92d295c48d9eeb4f5b78baa724`。
- 确认原 C 实际进程和 ROM 身份、本地 DNS、WAN 和管理路径，再启动 **900 秒自动回退**。deadline 在替换前创建，Rust 启动后另有健康 watch；现场核验两者的进程组、候选实际身份和本地答复。全程未执行 `confirm`。

时间统一为 UTC（现场日志原时区为 UTC+02）：15:54:48 开始替换，15:54:54 候选健康检查完成；16:09:48 到达期限；16:09:54 日志确认 C 已运行并能回答，16:09:57 独立 SSH 验证恢复身份；16:15:57 完成最终核对和临时文件清理。

## 客户端和网络检查

| 检查 | 实际结果及证据 | 判定范围 |
| --- | --- | --- |
| 真实 Wi-Fi 重连与 DHCP | 用户关闭 Wi-Fi 约 10 秒后重新连接，回复“连上了，看起来一切 OK”；Rust 计数及日志记录 **2 REQUEST、2 ACK、0 NAK**，ACK 与管理 Mac 身份匹配；Mac 保存的 DHCP 包更新为 ACK，租期 43,200 秒 | 既有租约重连时的请求/确认通过；不是新客户完整 DORA，也不是自然 T1/T2 定时续租 |
| IPv4 / IPv6 上网 | C 试前、Rust、C 恢复后，Mac 分别强制 IPv4 和 IPv6 HTTPS，均 HTTP 200；用户在 C 和 Rust 阶段均报告 test-ipv6 **10/10** | 真实双栈使用通过；保留现有 odhcpd/RA，不据此声称 Rust 独立承接 DHCPv6/RA |
| 本地 DNS UDP/TCP | 三阶段各 6 个查询均 NOERROR、有答案；Rust 另测两条真实租约名 UDP/TCP 共 4 答案，与租约匹配 | 已测本地名字通过；不披露客户名称和地址 |
| TCP 连接复用 | Rust 同一 TCP 连接连续 3 个问题，ID 匹配、NOERROR、预期单条 A 答案 | 已测本地持续 TCP 会话通过 |
| 公网 DNS UDP | 三个公网域名的 A/AAAA，各阶段 **6/6** 正常 | 已测公网 UDP 通过 |
| 公网 DNS TCP | **试前 C 0/6、Rust 0/6、恢复后 C 6/6**；失败为 2 秒查询超时。试前 C 的额外 2 个再次查询也在 3 秒内未答 | **未通过 Rust 现场验收，原因未定**；详见下文 |
| LuCI / 管理通道 | 自动请求 LuCI 未认证入口，三个阶段均为相同的 HTTP 403；SSH、管理地址 ping 正常。用户对含网页/LuCI 的重连检查整体回复正常 | 管理路径与用户所见页面正常；403 是未认证基线响应，不当作登录功能测试 |
| WAN | IPv4/IPv6 均保持 up，uptime 递增。候选阶段对照的地址/上游 DNS 相同，路由变化仅见 IPv6 有效期倒计时；最终收尾时 WAN6 地址列表缩短，保留为独立观察，详见下文 | 未观察到 WAN 重启或已测双栈访问失败；不声称全部最终 IPv6 状态原样，也不以网站显示的出口 IPv4 变化推断 WAN 被重置 |

客户端自动检查原记录为 `c-before-client.json`、`rust-first-client.json`、`c-after-client.json`，真实租约证据为 `dhcp-user-evidence.json`、`mac-dhcp-reconnected.txt`，追加本地协议证据为 `rust-local-contract.json`，均保留在 private。用户没有找到手动“续租”按钮，因此没有把该步骤写成已完成。

### 公网 TCP DNS 的未闭合问题

问题在切换 Rust 前已经存在。基线期间，从 **Mac 经家庭网络**直接查询当时的上游：两个 IPv4 resolver 均为 UDP 成功、TCP 超时；两个 IPv6 resolver 的 UDP/TCP 均成功。这不是路由器网络命名空间内的直连实验，不能定位到 ISP，也没有抓包证明某次 daemon 查询具体走了哪条上游路径。

恢复 C 后同组公网 TCP 查询全部成功，说明先前失败不能描述成持续不变的网络条件。时间、上游选择、缓存/进程状态等因素没有在这次现场试运行中隔离；**既不能把它认定为新发现的 Rust 独有缺陷，也不能因试前 C 同样失败而宣布两版等价或豁免 Rust。** 没有为了得到成功结果而再次替换或重跑 Rust。

对实际使用的影响：本轮用户网页与双栈访问正常，但依赖公网 DNS TCP 的请求可能超时；要求 TCP 的客户端和部分回退场景仍有资格缺口。正式替换前需要在独立授权的窗口内完成可归因、匹配条件的公网 TCP 验收。

### 收尾期间的 WAN6 状态变化

16:10:17 已恢复 C 时，WAN6 仍为试前的 6 个地址（5 个 ULA、1 个 global），扣除寿命字段后的路由集合也与试前相同。16:15:24 首次观察到地址剩 2 个（1 个 ULA、原 global），16:15:57 清理核对保持该状态。delegated global prefix、上游 DNS 未变；路由总数仍为 18，但归一化集合有 12 项移出、12 项移入，涉及 ULA 目标/源选择，**不只是倒计时或排序变化**。

这项变化的观测区间位于 C 恢复之后。没有证据把它归因于 Rust、C、自然到期或较早的 TCP 超时；报告保留为尚未归因的现场变化。WAN/WAN6 uptime 均继续增加，清理后另补测强制 IPv4/IPv6 HTTPS 均为 HTTP 200，未见已测公网访问影响；未另测消失的 4 个原 ULA 地址路径，后续现场验收应继续跟踪。

## 与现有九个组件的配合

现场核验的是路由器当时的实际文件及运行进程，不套用 Oracle 上另一套 Rust9 的哈希。九个文件的前后身份均一致；详细 SHA 见 [派生收据](audits/device-trial-20261014/summary.json)。

| 组件 | 本次覆盖 | 未覆盖 |
| --- | --- | --- |
| ubusd、procd | 既有 Rust 进程保持运行；原 stock init/ujail 与 Rust procd 启动候选、到期恢复 C；`dnsmasq` 与 `dnsmasq.dns` 双对象存在 | 没有重启 ubusd 或注入注册/ACL 故障 |
| netifd | WAN/WAN6 状态和 uptime 持续正常，未改接口配置 | WAN 断线重拨、接口重建 |
| logd | 收集启动、租约、恢复及系统日志 | 日志洪泛、轮转/故障注入 |
| rpcd、uhttpd | 管理路径保持可达，用户所见 LuCI 正常 | LuCI 全部 RPC 功能与配置写入 |
| uci、reload_config、fw4 | 实际文件身份保持；原配置和防火墙环境下运行 | 三者是按需命令，未主动改配置、reload 或重建防火墙，不声称完成各自全部合同测试 |

六个常驻支撑 daemon 的最终 PID/实际可执行文件身份与试前一致；现有 odhcpd 也保持原 PID/身份。由此支持“在当前实际系统中正常共存”，不支持“九个组件所有接口和故障路径均已真机验证”。

## 资源与日志

约每 2 秒读 `/proc`，并订阅日志和 DHCP 事件。Rust 有 **397 个样本**，首末跨度 **873.25 秒**，同 PID/starttime；两个采样批次之间有 **69 秒资源采样空档**，因此不称全程无间断采样。该空档不抹去，现场身份检查及自动恢复 owner 另有记录。

| 指标 | 试前 C | Rust |
| --- | --- | --- |
| 采样窗口 | 40 点，79.59 秒 | 397 点，873.25 秒 |
| 主进程 RSS 中位数 / 峰值 | 1,284 / 1,292 KiB | 2,324 / 2,424 KiB |
| 主进程匿名 RSS 中位数 / 峰值 | 272 / 280 KiB | 416 / 464 KiB |
| CPU 累计增量 | 自身 3 + 已回收子进程 1 tick | 自身 48 ticks，无已回收子进程计数增量 |
| FD | 44 → 44，峰 46 | 46 → 42，峰 52 |

Rust 实测 RSS 约多 1 MiB，但执行文件来自 tmpfs，RssShmem 为 1,904–1,968 KiB，不能当作全部额外堆内存；C 的 TCP 子进程共享页也不能直接相加作 PSS。没有现场 PSS/CLK_TCK 数据，不编造 PSS、CPU 秒或速度提升。两个窗口是家庭自然流量混合负载，不能据 tick 数作性能排名。

Rust 采样期间系统 MemAvailable 最低 114,316 KiB，未观察到 OOM、进程重启或持续累积 FD，采样窗口未显示异常 CPU 累积。RSS 从 2,280 增到 2,424 KiB，短时样本不能证明长期无泄漏。恢复后的 C 单独统计，未混入 Rust 计数。

日志未发现 dnsmasq/UBus 错误、panic、OOM 或崩溃模式。保留两类需解释的输出：

- stock init 启动时的 `udhcpc ... no lease, failing` 来自 `dhcp_check()` 防重复 DHCP 服务器探测（`-n -q -s /bin/true`），不能当作真实 Mac 分配地址失败；真实客户另有 ACK 证据。
- netifd WAN6 的 `cat: write error: Broken pipe` 在试前归档已有 18 条，启动后至最终日志收集范围内有 3 条，WAN 保持 up。两个观察窗不同，不比较发生率，不将这条既有警告抹去或直接断言无害。

## 实际自动恢复与最终状态

本轮没有 `confirm`，deadline 到期实际执行恢复；健康 watch 也确认恢复完成。两条成功日志对应并发恢复 owner 的确认，不当作两次独立网络故障。

回退前后以约每秒一次本地 DNS 查询监测，共 65 次，**61 次正确、4 次连续超时（TCP 1、UDP 3）**。前一成功完成于 16:09:49.069582，后一成功完成于 16:09:54.095199，相距 **5.03 秒**。这是重启切换期间可观测的 DNS 间隙，不是精确测得全网连续断网 5.03 秒；每个探测期限为 1 秒，TCP 每五次抽样一次。正式操作应预期重启切换会造成短暂 DNS 不可用。

最终核对已完成：

1. 实际 C 进程 PID 664、磁盘 `/usr/sbin/dnsmasq` 和 `/rom/usr/sbin/dnsmasq` 哈希完全一致；原 Rust PID 已退出。
2. 没有候选 bind mount，C 的 mountinfo 无试运行目录；deadline/watch 及其原进程组后代均不存在。
3. 双 ubus 对象、本地 DNS、WAN/WAN6 正常；恢复后客户端 22 项自动检查均完成，所有 DNS 查询有正常答案，IPv4/IPv6 HTTPS 200、LuCI 保持原未认证响应、ping 无丢包。
4. 前后 `/etc` 压缩归档 **逐字节一致**，261 个条目的内容和元数据未变；原 init/ACL、九个组件文件身份未变。运行租约正常更新，不回写旧租约覆盖客户新状态。
5. 将临时状态归档回电脑后，删除仅由本次创建的 `/tmp/device-trial-20261014/` 和 `/tmp/dnsmasq-trial/`，验证均不存在；停止本次日志订阅和采样连接。

未实测重启，但临时 bind 已卸载、候选已清理、stock 文件保持 ROM 身份且启动配置未改；没有留下重启后启用 Rust 的机制。

## 正式替换前仍需完成

- 公网 TCP DNS 在匹配上游、缓存/进程状态和时间条件下的 C/Rust 对照，必要时保留包级证据；本次不判原因已解决。
- 真实新客户端完整 DISCOVER/OFFER/REQUEST/ACK，以及自然 T1/T2 续租。此次 12 小时租期无法在 15 分钟窗口内覆盖；睡眠、漫游、多客户端差异也未验证。
- 较长正常使用窗口，覆盖负载变化和内存趋势。本次没有压力/断网/断电或重启试验。
- 如要正式部署 APK，另行授权验证 r4 init/ACL、安装激活、总线重连及包级恢复。此次保留 stock init/ACL，不能借实验室结果宣称这些已在真机完成。

这些是现场验收范围和一个尚未归因的 TCP 问题，不等于已证实产品存在同样数量的新 bug，也不构成“零 bug”承诺。当前决定为：**保留 main 的已验收版本，现场继续运行 C；暂不转为永久替换。**

## 证据索引

公开脱敏派生收据：[summary.json](audits/device-trial-20261014/summary.json)、[资源/恢复统计](audits/device-trial-20261014/runtime-analysis.json)、[原始材料 SHA 清单](audits/device-trial-20261014/evidence-manifest.json)。原始材料均位于本机忽略目录 `private/device-trial-20261014/`；报告不复制现场地址、客户名称、MAC 或配置内容。

主要证据包括 `identity.json`、`backup-identity.json`、`start.txt`、前后状态/配置归档、三个客户端阶段 JSON、上游对照、真实 DHCP 包及事件、资源采样、自动回退期间 DNS 轨迹、最终日志、`final-cleanup.sh` 与 `final-cleanup.txt`。完整保留失败与未覆盖项，没有把超时删除后重新计算通过率。
