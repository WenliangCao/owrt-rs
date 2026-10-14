# 上线前审计 A：DNS / DHCP 行为

日期：2026-10-14。审计产品快照：main
`58365e8c8ebe1805573baa02543baf1c9d45be68`。之后本审计的提交只增加工具和报告。

## 结论：当前不能上线替换

**按本次行为标准，不通过。** DHCPv4 的多客户端获取、续租、到期、重启和
C 租约接管，以及多数日常 DNS / 重载流程均通过了精确镜像 C 对照；但原配置
启用的本地域规则与缓存 CNAME 交互仍有两项已复现的客户端可见错误：

1. C 能本地完成的 TCP 查询，Rust 继续问上游；上游不可用时客户端超时。
2. C 能从缓存解析的 CNAME 本地终点 A 记录，Rust 返回 NXDOMAIN。

这两项不需要启用额外冷门选项，也不依赖畸形 DNS 报文。已有审计曾允许相关
增量合并，不等于符合本次替换标准。没有发现本次测试导致的 daemon 自身崩溃，
也没有发现实际配置下 DHCP 客户端拿不到地址的反例。

**触发范围要准确理解：**这些反例需要上游 CNAME 链指向实际 `local` 规则覆盖的
名字，例如合成的 `.lan` / `.invalid` 终点；不是普通公网 CNAME 的普遍失败，
也不是所有 A/AAAA 查询失效。本次没有采集家庭实时流量，无法给出触发频率。
预热回答使用公网地址，绕过了原配置本来就应执行的 rebind 过滤；不能将结果
直接外推到会先被该过滤拒绝的私网地址回答。阻断依据是**当前启用配置可达、
有效报文、确定的解析失败**，不是未经测量的发生率。

## 对照基准、输入与方法

以 [ACTUAL_CONFIG_STAGE.md](ACTUAL_CONFIG_STAGE.md) 指向的离线捕获为准。
实际生成配置为 737 字节，SHA-256：
`273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`。
没有用手写简化配置代替主体实验。保持 include、接口、53/67 端口、resolver
文件路径和四个端点（两个 IPv4、两个 IPv6）；上游服务由隔离环境里的可控
DNS 应答器替代，以便制造失败和核对转发次数。

| 对象 | 本轮身份 |
| --- | --- |
| 部署规格 | 小米 AX3000T，OpenWrt 25.12.5 / `r33051-f5dae5ece4`，镜像内 dnsmasq 2.93-r1 nodhcpv6 |
| 精确镜像 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 本轮 fresh Rust release ELF | `5931b2d114ae5c3e911775e8fd529dcf83ef8718e2c11b50916ce1164dab0966`，2,056,672 B |
| Rust 构建 | Rust 1.98.1、镜像 SDK linker、AArch64 musl、opt3/LTO、feature-off、static PIE |
| C 实现参考 | OpenWrt recipe revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`；148 个 patched source files 本轮重新核验 |

**行为 oracle 实际执行的是镜像 C ELF，使用镜像自身 musl / 库；不是宿主
重编译 C。** native matching-source 构建只提供主实验的 UBus fixture 和源码
验证。冻结归档的 639 个文件逐项匹配 Git、本地工作区和 Oracle；构建、参考树、
输入键名及文件散列见 [identity.json](audits/20261014/predeploy_behavior/root/identity.json)。

所有服务在 `ssh oracle` 的独立 network/mount/PID namespace 中运行。
服务端、LAN 客户端、上游各自隔离；捕获遗漏的 `/etc/passwd`、`group`、
`hosts`、`ethers` 从精确镜像补齐。为测试 IPv6 客户端传输，增加了合成 LAN
ULA；新增客户端、租约和故障场景查询为合成数据，另回放已有 hosts 的名字，
其真实内容保留在 private。Oracle 内核为
`6.17.0-1020-oracle`，不是路由器的 6.12.94。

审计从接口和源码入手，再用实际 daemon 实包差分，不以 Rust 自生成期望值。
DNS 比较 ID、问题、flags、记录顺序、类型、TTL 和内容，并核对受控上游日志。
DHCP 比较完整 payload；续租随机 T1/T2 先独立验证 C 的共享偏移规则，再只
屏蔽对应 8 字节。租约过期比较相对时间；所有容差都在分项报告明确列出。
主审另写了不依赖产品或原探针 decoder 的
[检查器](audits/20261014/predeploy_behavior/root/check_dns.py)，重新解码原始
DNS 包并验证请求关联、完整包消费、超时及上游次数；TTL、超时、计数变异均
被拒绝，见 [校准](audits/20261014/predeploy_behavior/root/checker-calibration.json)。

## 发现清单

P1：普遍服务中断、崩溃或常规地址获取失效；P2：条件触发但有实质客户端
错误；P3：低影响兼容差异。是否阻断由实际配置和客户端影响决定，不能仅看
等级。本轮没有 P1；以下 P2 为窄触发的上线阻断。

| ID | 级别 / 上线影响 | 状态 | 发现 |
| --- | --- | --- | --- |
| B01 | P2，阻断 | 已复现，源码解释确认 | TCP 缓存 CNAME 终点落入本地域时仍转发；上游无响应使客户端超时 |
| B02 | P2，阻断 | 已复现；内部根因尚未隔离 | 从 CNAME 学到的本地终点 A，C 可解析而 Rust 返回 NXDOMAIN |
| B03 | P3，不阻断 | 已复现 | 两种超长异常 TCP 请求，C EOF、Rust RST；正常服务继续 |

没有把仅凭源码猜测、没有复现的风险列成确定缺陷；本轮也没有独立未解决的
疑似阻断项。未覆盖项另列，不算通过。

### B01 — 本应本地结束的 TCP CNAME 查询依赖上游

最小步骤（不改原配置）：

1. 客户端通过 TCP 查询 `local-chain.outage.audit.example A`。
2. 受控上游返回 TTL 120 的
   `CNAME audit-outage-terminal.lan` 和该终点的 `A 8.8.4.4`。
   两版给客户端的预热响应完全一致。
3. 保留同一 TCP 连接，使四个上游不回应，查询同一 alias 的 AAAA。

| 观察 | 精确 C | Rust |
| --- | --- | --- |
| AAAA 客户端结果 | 立即 NOERROR、空 Answer | 2 秒客户端截止时超时 |
| 该场景上游请求类型 | `[A]` | `[A, AAAA]` |
| 进程状态 | 存活，正常退出 0 | 存活，正常退出 0 |

两秒是复现器的客户端 deadline，不是断言 Rust 永远不返回。错误是 C 本可
立即完成的操作被加入上游依赖，已经越过该客户端正常等待窗口。

上游正常应答时，同连接预热后查 AAAA/TXT/ANY，C 均空 NOERROR 且不再
转发，Rust 继续转发并返回上游答案；实际 `rfc6761.conf` 的 `.invalid`
终点也复现。UDP A 预热后再建 TCP 查询的控制同样表明问题不只限于长期
保留原连接。未预热的新 TCP 与相应 UDP 控制单独保留，不能将 C 的 UDP
行为拿来替代 C 的 TCP 标准。

源码原因：匹配 C `rfc1035.c` 的缓存 CNAME 遍历更新 `namebuff`，
`forward.c` 的 TCP 路径在缓存未命中后用终点名选路。Rust
[`cache_engine.rs`](../../components/dnsmasq/src/dns/cache_engine.rs#L748)
返回 `packet: None` 时没有保留该终点信息；
[`tcp_service.rs`](../../components/dnsmasq/src/dns/tcp_service.rs#L463)
重新解析原问题名选路，绕过了终点本地域规则。Rust 发给上游的是原 alias，
本实验不能证明向上游泄漏了 `.lan` 终点查询名。

主审独立核验原始包的结果见
[focused-independent.json](audits/20261014/predeploy_behavior/root/focused-independent.json)；
另用保留的同一工具在新 namespace 独立复跑，43 个响应经新 decoder 核验，
再次确认同预热答案、C 本地完成及 Rust 超时，见
[root-repeat-checked.json](audits/20261014/predeploy_behavior/root/root-repeat-checked.json)。
完整差分、控制、运行工具身份见
[DNS 分项](audits/20261014/predeploy_behavior/dns/review.md)。
这是历史 O1 在本轮原配置下的新复现，不以历史增量合并结论豁免。

### B02 — 已学到的 CNAME 本地终点不能直接解析

同样在原配置下，通过 TCP 预热外部 alias，得到
`CNAME audit-terminal.lan + A 8.8.4.4`，再执行 B01 的同连接 AAAA/TXT/ANY
序列，关闭连接后直接查询终点：

- `audit-terminal.lan A`，UDP 与新 TCP：C 返回缓存的 `8.8.4.4`；
  Rust 均返回 NXDOMAIN。
- `audit-terminal.lan AAAA`：C 返回 NOERROR/NODATA；Rust 返回 NXDOMAIN。
- 预热前的 AAAA 控制两版都是 NXDOMAIN，排除了原来 hosts 就有该名字。

这不是 TTL 或压缩表示差异：A 查询已经从可解析变成名字不存在；NXDOMAIN
还可能被客户端负缓存。后一句是协议后果推断，本轮没有测量真实客户端的
负缓存时长。它与 B01 使用同类 CNAME / 本地域交互，但这里**上游正常时
直接 A 查询就失败**。尚未区分缓存导入、发布或本地查询选择哪一层导致此
行为，也未证明它和 B01 有独立根因，不把未定位的内部原因写成事实；行为
本身已复现，不标成疑似。尚未把上述序列缩减为“仅 A 预热就会失败”。

另起进程的普通公网终点控制通过：TCP 预热 `cname.public.audit.example →
target.audit.example + A` 后关闭四个上游，直接查询终点 A 的 UDP/TCP 两版
都能从缓存回答，没有新上游请求。
[控制证据](audits/20261014/predeploy_behavior/dns/public-cache-control/observations.json)
排除了“所有 TCP CNAME 终点缓存都失效”的泛化。

完整步骤、原始结果散列与直接 A/AAAA 控制见
[focused/observations.json](audits/20261014/predeploy_behavior/dns/focused/observations.json)
和 [DNS 分项](audits/20261014/predeploy_behavior/dns/review.md)。主审另从最终
原始包独立解码 51 个响应，核实两种传输的 C A 答案与 Rust NXDOMAIN，见
[最终包核验](audits/20261014/predeploy_behavior/root/focused-final-checked.json)。

### B03 — 超长异常 TCP 查询的连接关闭表示不同

将普通 `robustness-audit.lan A` 查询在 question 后补零至 4096 或 65507
字节，再加 DNS-over-TCP 长度前缀发送。C 客户端读到 EOF，Rust 得到
`ConnectionResetError`；两者都拒绝该异常请求，进程继续服务，后续 UDP/TCP
健康查询和完整 DORA 成功。没有正常家庭请求因此失败的证据，不阻断上线。

复现工具为 `predeploy_audit_robustness.py --quick`；详细输入、原始记录散列及
范围见 [健壮性报告](audits/20261014/predeploy_behavior/robustness/REPORT.md)。
完整 corpus 的初轮缺少镜像 hosts/ethers，后来补齐四个文件再跑短控制，
仍复现该差异；没有把短控制说成完整 corpus 重跑。

## 通过了什么

计数是各自实验单位，不相加成“全部协议场景”，也不重复累计准备失败和中间版本。

| 实际使用场景 | 新执行结果 / 证据 |
| --- | --- |
| 多客户端获取、续租与迁移 | 12 个合成 MAC/client-id 成批 DORA；单播 renew、广播 rebind、INIT-REBOOT、NAK 后恢复、稳定 client-id 换 MAC、INFORM、RELEASE 均一致 |
| 租约名字和持久化 | 短名/FQDN A、AAAA、PTR、重名/改名、bogus-hostname、option 81、IoT 名字；HUP、正常/主动 SIGKILL 重启；接管同一份 C 写出的 11 租约文件。四组共 134 对完整 DHCP、657 对 DNS 零差异；[DHCP 报告](audits/20261014/predeploy_behavior/dhcp/review.md) |
| 无流量自然到期 | 不改 range，用客户端请求取得 120 秒最短租约；离线不 RELEASE，真实等待到期后、发任何新查询前两版已主动清理；A/PTR 撤销及再次获取一致 |
| DHCP 与 DNS 同时工作 | 12 客户端获取及地址探测期间，两版各 232 次本地 DNS 查询成功，无 3 秒超时；不是路由器性能数据 |
| 日常 DNS 矩阵 | 71 组、每版 452 次客户端交换：IPv4/IPv6 UDP/TCP、A/AAAA、普通公网 CNAME、TXT/HTTPS、正负缓存、TTL 到期、rebind、EDNS、截断后 TCP、流水/分片、并发请求；客户端语义一致，上游每阶段总数一致，逐问题/端点映射差异保留；[DNS 对照](audits/20261014/predeploy_behavior/dns/comparison.json) |
| 上游故障与恢复 | 单地址族可用、首选 drop/SERVFAIL/REFUSED、全上游失败及恢复均与 C 一致。不是承诺任意 SERVFAIL 都自动选到成功答案；以实际 C 返回为准 |
| 转发表压力 | 176 个请求遇上游全丢包时的超时/REFUSED 与 C 相同；缓存继续工作，等待失效后新查询及 48 并发查询恢复。共同的上游不可用不是 Rust 独有故障 |
| hosts / resolver / 主配置变更 | 实际配置 60/60 比较一致，含 hosts 原子替换/删除、resolver 四端点轮换/空/删除/恢复、缓存行为、bind-dynamic 新地址；24 次 HUP 期间 160/160 双栈 UDP/TCP 查询成功；[重载报告](audits/20261014/predeploy_behavior/reload/review.md) |
| UCI reload 调用链 | 镜像 init/procd/rpcd/odhcpd 的合成 UCI 流程结果一致；配置 apply 后真实内层 ELF PID 变化、新配置生效，odhcpd DHCPv6 租约名字能经 DNS AAAA 查询。此组使用合成 UCI，非原 737 字节配置；旧工具的 PID 布尔字段不算生命周期证据 |
| 有界报文健壮性 | 每版 316 个 DNS、31 个 DHCP 边界输入，20 个健康观察；除 B03 的 2 项关闭表示外相同，正常退出。补齐文件后的短控制另列；不是长期 fuzz |
| Fresh 普通单测 | 780 lib + 77 bin 通过，0 失败；23 ignored 未运行。[日志身份](audits/20261014/predeploy_behavior/root/tests.json)。单测通过不抵销 B01/B02 |

重载的一项重要边界：**单独 HUP 不重读主配置，两版都如此。** 实际 init
reload 先重新生成配置并经 procd 提交，再发 HUP；配置变更需要的重启路径
已另测，不能把 HUP 的正常限制误报为 Rust 缺陷。既有 TCP 连接跨 HUP 保留
旧 hosts 视图，两版相同；新连接看到新视图。

常规矩阵的上游请求总数两版都是 420，各阶段总数也相同，但选优及周期探测
落在哪个具体问题/端点上并非逐项相同，JSON 明确记录
`endpoint_query_counts_equal=false`。这些观察没有改变本轮客户端答案或
成功/失败结果；响应/到达顺序造成该分配差异是与现有日志和实现相符的解释，
不是逐交错形式证明。没有把端点计数不一致隐藏为“所有网络行为完全相同”。

## 复跑与证据位置

Oracle 本轮根目录：`/home/ubuntu/dnsmasq-predeploy-behavior-20261014/`。
`source/` 是冻结归档，`private/release/dnsmasq-rs` 为被测 Rust；镜像来自
`/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`。
实际捕获来自 `dnsmasq-dhcp-network-actual-20261001/private/runtime-source/rootfs`；
LAN CIDR 从旧 `dnsmasq-northstar-dns-20261002/private/c-network-07/topology.json`
的 `router` 字段读取，避免在 Git 公开展开。

主体复跑结构均为：

```text
run_isolated.sh
  → actual_config_network.py --source-root RUNTIME --router-cidr CIDR --output FRESH_PRIVATE_NETWORK
  → actual_config_rootfs.py --source-root RUNTIME
  → predeploy_audit_{dns,dhcp,reload,robustness}.py ...
```

各层用 `--` 分隔，使用 `sudo -n`，每轮给新目录。B01/B02 使用 DNS 工具
`--focused`，C 侧使用 `--image-elf` 和精确镜像 ELF，Rust 侧使用上述冻结
release；完整参数及各组结果路径在相应分项报告。C 的行为记录与 Rust 记录
始终分开保留，比较器不把双方共同超时误说成成功解析。

准备失败保留在 private：缺失账户、Oracle `protected_regular` 对人为预置
租约的限制，均在进入业务前失败，不计产品缺陷。初轮 SERVFAIL 竞速差异在
固定上游响应时序后消失，原始记录保留，没有证据将其另列为 Rust 缺陷。
旧 lifecycle 工具用 jail 内 PID=1 判断重启存在观察错误；本轮用已校验 ELF
的外层可见 `inner_pid` 证明重启，不采用 `uci_apply_restarted`；同类的
`sighup_keeps_pid`、`init_reload_keeps_pid` 也不用于证明进程保持不变。

## 没有覆盖的范围

- 未接触物理路由器，未测试射频/漫游/真实手机电脑 DHCP 实现、硬件 offload、
  目标内核差异、断电及 flash 写入。12 个客户端是一个独立 namespace 中的
  12 个合成身份，不是 12 台实体设备。
- 未做长期运行、长期 fuzz、OOM/FD 耗尽、完整 TCP 资源上限、实际路由器
  内存/CPU/存储预算验收；这是行为审计，不代替资源和部署集成审计。
- 未等待实际 12 小时租期自然结束；用合法客户端短租期验证真实时间到期。
  未穷尽满池、所有 ICMP 地址冲突、双 DHCP server、重载与 DHCP 收包的全部
  竞态、包丢失/重排组合、修改配置重启期间的丢包窗口。
- IPv6 DNS、AAAA 和 odhcpd 名字发布有覆盖；目标 dnsmasq 是 nodhcpv6，
  不负责替代 odhcpd 的 DHCPv6/RA。未宣称完整 IPv6 网络栈验收。
- 未启用的 PXE/TFTP/relay、所有自定义 option、静态预约/tag 组合、DNSSEC
  验证和其它冷门配置未作全面资格化；不因其未覆盖而额外阻止本次上线。
  历史报告中的选项/parser 边界也没有在本轮全部复验，不宣称已经消失。
- 没有重采当天物理路由器的配置；结论绑定本报告记录的离线捕获。如果实际
  配置已改变，这份原配置实验不能自动替新配置作保。

修复 B01/B02 后应保留原配置、原包序列和本轮 C 结果重跑，再检查 UDP/TCP、
本地名字、负缓存和重载交互；不要求以未使用冷门选项的完全等价为前提。
本轮没有修改产品代码、访问或修改物理路由器、部署、刷机或推送 GitHub。
镜像、ELF、完整配置、原始客户端数据和报文均留在 private，Git 仅保存审计
工具、无秘密身份信息和派生报告。

收尾重新核验了 675 个 Oracle 源码、工具及原始证据文件的散列，产品目录与
冻结快照无差异；本任务无残留进程或宿主挂载。
[收尾记录](audits/20261014/predeploy_behavior/root/closeout.json)
