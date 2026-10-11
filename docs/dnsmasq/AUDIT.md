# dnsmasq 独立替代审计

审计日期：2026-10-11。产品快照：`perf/udp-dhcp-reload` 的
`3e7df6c1cc45b74f0430e5460379713900172cb4`。本报告之后的审计提交不改变产品。

## 结论

**当前不能完整替代镜像中的 C dnsmasq。性能分支可以作为尚未通过替代验收的实验组件改进
合入 main；不能因此启用 C→Rust 替换或宣布重写已完成。**

这不是因为尚未完成所有测试，而是已经复现了正常受支持操作中的服务中断和行为错误：
标准诊断信号杀死整个服务，多 MAC 静态预约无法交接租约，Rapid Commit 漏掉名称策略，
以及原版可运行配置令 Rust 启动失败。它已经能处理大量常规业务，但尚不满足同名、同配置、
同运维接口替换的要求。部署替代前应修复下面的 P1/P2 功能缺陷，保留这些独立 daemon
差分作为回归，并单独接受资源预算；性能收益不能抵销行为错误。

**合并性能增量与替代资格需要分别判断。** 审计时 `main` 为
`f00ad61680f271305367187411f2be2edc1b046c`，其 dnsmasq/ubus 产品源码与
`889fe4f5` 相同。本轮对该旧产物重跑信号、DHCP、配置三组，观察与当前候选完全一致。
具体是 A01–A05、A09 已在旧 main 等价产物上复现，属于既有缺陷；A10 也完成了单独的
旧 main 复核。其余项目的归属不能仅由这几组结果推定。
[旧 main 对照](audits/20261011/main_baseline.json)及
[DNS 对照](audits/20261011/dns.json)记录了这一区分。

本轮未发现应阻止这组性能增量合并的新增确定性回归。分支相对 main 没有改动 packaging、
镜像定义或 CI；[常规镜像组件清单](../../packaging/image/native-25.12.5.json#L8)和
[镜像构建脚本](../../tools/ci_build_image.sh#L19)均不将 dnsmasq-rs 作为替换组件，
main push 的 [CI](../../.github/workflows/ci.yml#L3)只运行 host-tests。
因此允许合入研究／性能改进的判断不会自动把 Rust 安装为生产 DNS/DHCP 服务。
此合并建议以保持该启用边界、公开保留本报告缺陷为前提；不扩展为对未来默认替换配置的批准。

本轮未修改产品代码、未接触物理路由器、未推送 GitHub。只提交复现工具、合成输入的
派生结果和本报告。没有可据本报告执行真实路由器部署的结论。

## 证据与审计方法

目标是 AX3000T OpenWrt 25.12.5 镜像中的 **dnsmasq 2.93-r1 / nodhcpv6**，
不是任意上游默认构建，也不是 `dnsmasq-full`。匹配 OpenWrt 配方 revision 为
`f0a60eee2fe051741c643ea6118718aae1ef17fb`，源码 archive SHA256 为
`0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19`。
DHCPv4、BOOTP/PXE、relay、TFTP、IPv6 DNS、AD 代理和 UBus 在目标范围内；
DHCPv6/RA 服务、DNSSEC 验证、auth DNS、DBus、conntrack、ipset/nftset 不在编译能力内。
未编译引擎不等于所有相关配置入口都可以拒绝，见 A05。

| 产物 | SHA256 / 身份 |
| --- | --- |
| 镜像原版 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 本轮从冻结源码构建的 Rust ELF | `331177ba5d2b7d4d1e8fbb65152b7721475a03782e6c629131db719ef7b63448` |
| matching source 的 native C 辅助 oracle | `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431` |
| 旧 main Rust 对照 | `791a7c33987fbb21887c51041f27722b9cc1bd8bd4cffab0fc03a292517fb10f` |

Rust 使用 Rust 1.98.1、镜像对应 SDK linker、`aarch64-unknown-linux-musl`、
release opt3、LTO、feature-off。所有服务实验在 `ssh oracle` 的独立网络／mount／PID
namespace 中运行。主要差分直接运行镜像 C 与镜像 musl/libraries；配置组还使用隔离
image-root overlay。Oracle 是 AArch64、Linux `6.17.0-1020-oracle`，不是目标路由器内核。
本轮重新验证 matching C 的 148 个 patched files、42 个编译对象、特性开关和
libubox/ubus revision；未重新从固件 archive 开始提取镜像。
[身份和构建记录](audits/20261011/identity.json)包含源码 tree、ELF 结构和测试记录。

审计先阅读现有接口与匹配 C 调用链，然后分开检查 DNS、DHCP、运行生命周期、配置与包，
对可疑路径编写独立真实 daemon 差分。发现依据是外部行为及最小代码路径，不是 Rust
自生成的期望结果。测试保留正常 REQUEST、option 50 有／无、信号 HUP/USR2 等控制组；
另由不同审查者复核 DHCP、配置和内存实验的前提及结果。

本轮普通单测：**lib 757 通过、bin 74 通过，0 失败；23 个 ignored 未运行**。
这些通过结果不覆盖已复现的边界。历史“44 族通过”也没有推翻本轮反例。

独立 DNS 对照重复两轮，每轮 368 个 profile／transport／EDNS 组合，359 个结果一致；
其中 252 个转发、过滤和 rebind 组合全部字节一致。差异为 A10 的七类异常 TCP 输入和
两项 C 压缩错误。DHCP 为 9 组、18 个 daemon、24 次报文交换、90 次 DNS 查询；
配置为 43 个输入，信号 12 例，hosts 内存 6 例，TFTP 24 组。组合数不等于独立语义数，
也不将重跑计成额外覆盖。

## 发现清单

严重度按影响而非代码行数划分：P1 为正常受支持操作导致服务终止或客户端无法获得租约；
P2 为特定配置、协议路径或资源条件下的实质错误／成本／防护退步；P3 为局部较低影响的
兼容差异。没有发现或声称已经证明的 P0 远程执行漏洞。

| ID | 级别 | 发现 | 证据状态 |
| --- | --- | --- | --- |
| A01 | P1 | SIGUSR1 / SIGALRM 直接终止 daemon | 本轮精确镜像 C、native C、Rust 复现 |
| A02 | P1 | 多 MAC 静态预约交接时 OFFER 后无 ACK | 本轮 wire、租约文件复现 |
| A03 | P2 | Rapid Commit 漏掉按地址池标签的名称策略 | 本轮 wire、租约、A/PTR 复现 |
| A04 | P2 | Rapid Commit 不采用 hosts 权威名 | 本轮租约、A/PTR 复现 |
| A05 | P2 | 11 个 C 可运行的配置入口令 Rust 启动失败 | 本轮启动与实际 DNS 复现 |
| A06 | P2 | hosts 全文件临时分配造成额外内存门槛，重载漏载记录 | 本轮受控内存实验 |
| A07 | P2 | 当前 ELF 为非 PIE，丢失 C 的主映像地址随机化属性 | 本轮 ELF 结构确认；未做利用实验 |
| A08 | P2 | 更大的常驻／峰值内存和文件体积，部分场景 CPU 仍高于 C | 文件体积本轮确认；运行成本为已复核历史同源数据 |
| A09 | P3 | Rapid Commit ACK 漏发客户端 hostname option 12 | 本轮 ACK wire 复现 |
| A10 | P3 | 异常 TCP DNS 查询直接 EOF，绕过已有 REFUSED 应答路径 | 本轮重复差分，旧 main 同样复现 |

### A01 — 诊断信号终止服务

[`main.rs:867`](../../components/dnsmasq/src/main.rs#L867)只注册 INT、TERM、HUP、USR2，
没有注册 USR1/ALRM。匹配 C `dnsmasq.c:99,1398–1399,1601–1603` 将 USR1 转成
统计／缓存 dump 事件，ALRM 则驱动租约维护。

在 DNS 已可回答后发送 `kill -USR1 PID`：两个 C 都继续回答并输出统计；Rust
exit status 为 `-10`，后续 DNS 超时且 pidfile 遗留。发送 ALRM 时 Rust 为 `-14`，
C 继续服务。HUP、USR2 控制组全部继续回答。共 12 例。
[证据](audits/20261011/runtime_signals.json)

这会把原来的例行诊断变成 DNS/DHCP/TFTP 同进程服务中断，并非仅缺少一项统计。
触发需要能给进程发信号的本地操作，不是无认证远程崩溃。ALRM 缺失也不能直接推导成
“内部租约过期永不执行”，Rust 另有 timer 维护路径，本轮没有作此结论。

### A02 — 多 MAC 静态租约交接失败

配置一个包含两块网卡 MAC、同一 IPv4 的 `dhcp-host`。先由第一 MAC 正常获得该地址，
再由第二 MAC 进行 DISCOVER/REQUEST。C 给第二 MAC ACK 并更新租约；Rust 给出 OFFER，
随后两次 REQUEST 都无回答，租约仍属于第一 MAC，daemon 本身存活。
[证据：`multi-mac-static-handoff`](audits/20261011/dhcp.json)

[`state.rs:370`](../../components/dnsmasq/src/dhcp/state.rs#L370)识别可接管 occupant 后
只设置 `existing_id`；[`state.rs:397`](../../components/dnsmasq/src/dhcp/state.rs#L397)
仍以 `existing.is_none()` 判断需要新分配，进入
[`lease.rs:385`](../../components/dnsmasq/src/dhcp/lease.rs#L385)的 `AddressInUse` 错误。
这是代码确认的原因，**不是日志里观测到了该错误字符串**。C `rfc2131.c:1540` 直接复用
旧 lease。典型有线／无线网卡切换会失败，直到旧租约释放或过期；这是支持内的配置。

### A03 — Rapid Commit 可绕过按地址池配置的名称规则

启用 `dhcp-rapid-commit`，地址池带 `set:pool`，配置
`dhcp-ignore-names=tag:pool`。客户端发带 option 80、hostname=`untrusted`、
**不带 requested-address option 50** 的 DISCOVER。C ACK 但不保存／发布该名字；
Rust 保存并实际发布 `untrusted` 的 A/PTR。换成 `dhcp-generate-names=tag:pool`，
C 生成 MAC 名，Rust 没有生成。给 DISCOVER 加 option 50 后，两者策略恢复一致。
[证据](audits/20261011/dhcp.json)

[`daemon.rs:2135`](../../components/dnsmasq/src/dhcp/daemon.rs#L2135)在最终选址前按
requested-address/ciaddr 计算 range tags；此时为 `0.0.0.0`，快速分配后的池标签没有
重新参与 ignore/generate 决策。影响是明确配置的名字政策被绕过，不能扩大描述成已经
证明任意域名劫持。

### A04 — Rapid Commit 的租约名偏离 hosts 权威名

hosts 为分配地址设置 `authoritative`，客户端快速提交时声称 `claimed`。
C 的租约只采用 `authoritative`；Rust 租约采用 `claimed` 并额外发布该名字的 DNS
记录。普通 REQUEST 控制组均使用权威名。
[证据](audits/20261011/dhcp.json)

[`daemon.rs:2186`](../../components/dnsmasq/src/dhcp/daemon.rs#L2186)只为消息类型 3
计算 `reverse_address`，遗漏 DISCOVER 在 Rapid Commit 下直接变为 ACK 的分支。
C 则在统一 ACK 路径执行 `host_from_dns(yiaddr)`。这与 A03 是不同的遗漏条件。

### A05 — 原版合法配置导致整体拒绝启动

逐项追加以下配置时，C `--test` 成功、`port=0` 能运行，并在开启 DNS 后实际回答
`audit.test A = 192.0.2.42`；Rust 均以退出码 1 报
`option is not implemented by dnsmasq-rs`，没有 DNS 服务：

`quiet-ra`、`quiet-dhcp6`、`no-dhcpv6-interface=lo`、`enable-ra`、`auth-ttl=60`、
`auth-soa=1`、`auth-server=ns.audit.test,lo`、`auth-sec-servers=ns.audit.test`、
`auth-peer=192.0.2.1`、`dnssec-debug`、`dnssec-no-timecheck`。

正控制 `no-ident` 两边均正常。全组 43 个输入的结果在
[config.json](audits/20261011/config.json)。最小配置：

```ini
port=15353
listen-address=127.0.0.1
bind-interfaces
no-hosts
no-resolv
host-record=audit.test,192.0.2.42
quiet-ra
```

运行 `dnsmasq -C FILE -k --user=root --group=root --pid-file= --log-facility=-` 即可。
[`main.rs:616`](../../components/dnsmasq/src/main.rs#L616)的统一 fallback 把这些
入口全部拒绝了。默认 nodhcpv6 UCI 不一定生成它们，所以不是所有默认安装必现；
但同名替换应兼容既有合法手写配置。修复需要逐项保留 C 语义，不能未经检查全部作 noop。

`auth-zone`、`dnssec`、`conntrack`、`enable-dbus` 的 `--test` 拒绝时机也不同，
但双方实际运行都拒绝，**不将它们计入这 11 项服务回归**。

### A06 — hosts 临时内存按整个文件大小增长

合成合法 hosts 文件仅含一条 `192.0.2.1 audit.test` 和 48 MiB 的 128 字节短注释行。
无内存限制时双方回答正确；C 峰值 RSS 为 **1,116 KiB**，Rust 为 **50,476 KiB**。
Rust 最终 RSS 回落到 1,856 KiB，问题是临时峰值，不是持续占用 50 MiB。

只给 daemon 设置 `RLIMIT_AS=32 MiB` 后，C 仍可加载；Rust 启动时漏掉整个文件，
回答 REFUSED。小 hosts 启动正常后再加入同样注释并 HUP，C 仍回答，Rust 丢失原先记录
并返回 REFUSED／零答案。全部进程仍活着并正常 TERM 退出。
[六组实验](audits/20261011/hosts_memory.json)

[`main.rs:6583`](../../components/dnsmasq/src/main.rs#L6583)先 `std::fs::read` 分配
全文件，读失败就省略该来源；[`main.rs:3127`](../../components/dnsmasq/src/main.rs#L3127)
将这一结果发布为新 hosts。匹配 C `cache.c` 的 `read_hostsfile/gettok` 流式处理。
注释也必须支付完整临时内存成本，是不必要的设计差异。

这是受控**虚拟地址空间限制**，不是目标设备 OOM 复现；未声称 C 自身发生所有读失败时
都会保留旧数据。正常 `-k` 模式重定向 stderr 后，这个 `eprintln!` 也不进入配置的日志
通道；本次 reload 日志没有对应加载失败提示。

### A07 — 主 ELF 丢失 PIE 属性

本轮 `readelf -h/-l` 及独立 ELF 解析：镜像 C 为 AArch64 `ET_DYN` PIE，Rust 为
static `ET_EXEC`、无 interpreter。Rust ELF 含 GNU_RELRO 程序头，GNU_STACK 无执行
标志，未见 WX LOAD；本轮未验证 RELRO 的运行时映射保护。静态非 PIE 主映像不获得
C PIE 的代码地址随机化属性。
[程序头证据](audits/20261011/identity.json)

默认 [package 编译规则](../../packaging/openwrt/owrt-dnsmasq/Makefile#L85)未显式选择
PIE/static-PIE，本轮构建实际为 static ET_EXEC。此前 DYN1 只是候选，未成为默认构建，不能用它的成功结果替代
当前 ELF 的实际属性。这是防护退步；本轮没有证明能利用它进行攻击，也不将 Rust 的
其他内存安全收益折算成相互抵销。

### A08 — 资源成本仍不是 C 的等价替换

当前 ELF 为 **1,970,216 B**，C 为 **269,305 B**，增加 1,700,911 B、为 C 的 7.316 倍。
这是 ELF 文件大小，不是当前 APK、squashfs、完整 flash 或 RAM 的倍数。

运行成本使用已存在的 54 窗同源证据：旧 ELF `98ac292a…`，与本轮 `331177ba…` 不同，
但本轮核对其 157 个产品输入文件与当前相同。重新检查 324 个 raw 文件身份，并重算
54 窗 CPU 算术、资源峰值及中位数；另独立解码 8 窗 latency，结果与历史分析一致。
**本节不是 fresh ELF 的重新压测。**
[来源、三轮汇总和校验结果](audits/20261011/performance_evidence.json)

| 稳态场景 | C CPU μs/单位 | Rust CPU μs/单位 | C PSS KiB | Rust PSS KiB |
| --- | ---: | ---: | ---: | ---: |
| UDP cache hit | 11.865 | 12.403 | 1,660 | 3,360 |
| DHCP DORA+renew+release 周期 | 473.749 | 525.038 | 1,660 | 2,244 |
| 并发 reload | 19.771 | 27.246 | 1,632 | 2,444 |
| TCP miss | 226.172 | 95.395 | 5,484 | 18,728 |

DHCP/reload 的 CPU 分别高 10.83%/37.81%，达到该三轮比较协议的退步判定；UDP hit
高 4.54%，未达到 10% 幅度门槛。这三项 p95 **没有**达到延迟退步判定，不能将 CPU
差异称为延迟差异。其余六场景主要阶段 Rust CPU 更低，不能概括成“Rust 全面更慢”。

TCP miss PSS 稳态为 C 的 3.415 倍，饱和为 4.571 倍；排空 60 秒后中位 PSS 仍为
**12,020 KiB 对 1,660 KiB**。这是 RAM 余量成本，未证明持续泄漏。相同 10k QPS
目标下实际 C/Rust 约 4,417/9,988 QPS，不是等完成吞吐的内存比较；TCP cache 的稳态
PSS 反而 Rust 更低。C 子进程 RSS 会重复计算共享页，跨进程比较使用 PSS。

已优化掉的重复接口查询有价值，但余下内存、存储与 CPU 代价仍需要明确的目标预算。
本轮没有在实际设备上证明这些成本会导致过载，也不把历史真机研究当作本轮设备验收。

### A09 — Rapid Commit ACK 缺少 hostname option 12

客户端提供 `claimed`，快速提交后两边租约／DNS 均使用该名，但 C ACK 携带 option 12，
Rust ACK 没有。普通 REQUEST 控制组一致。
[证据](audits/20261011/dhcp.json)

[`daemon.rs:2162`](../../components/dnsmasq/src/dhcp/daemon.rs#L2162)仍把 DISCOVER
当作普通 OFFER，提前清空应答名称，遗漏 Rapid Commit 实际发送 ACK 的事实。
影响仅能确认到客户端收到的选项差异；没有证据证明本例客户端因此丢失租约。

### A10 — 错误 TCP 查询的应答路径未接通

零 question、两个 question（普通／压缩编码）、自指针、越界压缩指针、bitstring label、
超长 name 共七类输入，C 返回 flags=`0x8185` 的 REFUSED，Rust 不发 DNS frame 而直接
关闭该 TCP 连接。当前产物重复两轮，旧 main 等价产物再做 18 个组合的定向控制，行为
相同；daemon 及其他客户端后续健康检查均正常。
[请求／回答字节与归因](audits/20261011/dns.json)

[`daemon.rs:1735`](../../components/dnsmasq/src/dns/daemon.rs#L1735)的
`tcp_view_answer` 提前传播 `Question::parse` 失败，经
[`main.rs:2783`](../../components/dnsmasq/src/main.rs#L2783)退出当前连接，实际未到达
[`tcp_service.rs:529`](../../components/dnsmasq/src/dns/tcp_service.rs#L529)已经实现的
`query_error` REFUSED 应答。这说明原语有错误应答实现，不能代表 daemon 调用链已接通。

两个 question 虽可编码，但不在 dnsmasq 单 question 请求接口内；其余是空请求、非法
名称或不支持的旧标签编码。这里只确认错误处理兼容差异，不是普通受支持查询失败、
安全绕过或 daemon DoS；保留直接关闭行为也需要明确记为有意差异。

## 其他差异与没有列为缺陷的候选

大整数配置的接受范围不同：例如 `cache-size=2147483648`、
`local-ttl=4294967356`，C 的目标 musl `atoi` 表现为回绕，Rust
[`scalar.rs:66`](../../components/dnsmasq/src/config/scalar.rs#L66)拒绝超出 i32 范围。
十个输入的 `--test` 差分见 [config.json](audits/20261011/config.json)。这是确认的
边界差异，但严格拒绝溢出输入有合理依据，不要求为替代而复制 C 的溢出行为；
没有把它算作正常配置阻断，也未宣称测过这些值的完整运行语义。

首个繁忙 UDP listener 可能压住后续 listener 的静态候选撤回：精确 C 的
`dnsmasq.c:1982–1987` 同样处理首个 ready listener 后 return。本轮没有复现并证明
Rust 比 C 更差，不把它列为新增回归。

DNS 的 forward-pointer 请求把 question 指向 offset 18 的尾随名称。C 回答时将
answer 放在该位置，形成 question `c012` → answer owner `c00c` 的指针环；Rust
展开 question 后返回可解码的 A 回答。UDP/TCP 两个观察见
[dns.json](audits/20261011/dns.json)。不把 Rust 的重新编码判为缺陷，也不要求复刻坏包。

TFTP 独立实际 daemon 对照共 24 组：22 组逐字段一致，Rust 全部完成期望的传输／拒绝。
覆盖 octet/netascii、空文件／整块终止／多块、窗口 4/32、OACK、选项大小写、首 DATA
重传、IPv4/IPv6、单端口、missing/traversal/WRQ/非法 mode/短包等边界。
[TFTP 证据](audits/20261011/tftp.json)中的两项不一致是：

- `netascii-one-byte-block`：以 LF 开头、协商 blksize=1，C 重复 DATA 1 后客户端超时，
  Rust 完成 9 字节及终止块。C 的 `tftp.c:802,972–973` 在文件 offset 未前移时复用旧块，
  是解释重复包的源码依据。
- `bound-ipv4-single-port`：绑定接口的 IPv4 单端口模式，C 报 `Network unreachable`
  且无答包，Rust 完成；正常 wildcard 单端口和 IPv6 单端口控制组均一致。C 的接收／
  源地址选择路径为解释依据，本轮没有证明任意环境均会触发该错误。

两项都有实际差异，但没有证据表明 Rust 在这里更差，不要求复制 C 的失败行为。
48 个 daemon 全部正常 TERM 退出。此组不是完整 TFTP 故障注入或性能验收。

## 可重复运行

下列路径均在 Oracle 的隔离实验树。`SOURCE` 是冻结的产品源码加本报告附带的审计工具，
工具不会改变产品构建输入。`OUT` 必须换成不存在的新目录；本轮已清理测试进程。
Git 中只保存合成结果，ELF、镜像、完整日志和
历史 raw 性能资料留在 ignored/private。

```sh
AUDIT=/home/ubuntu/dnsmasq-independent-audit-20261011
SOURCE=$AUDIT/source
RUST=$AUDIT/private/release/dnsmasq-rs
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files

# 当前产品构建（必须新建输出目录）
sh "$SOURCE/tools/dnsmasq/oracle_build.sh" "$SOURCE" "$AUDIT/private/release-new" release

sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$SOURCE/tools/dnsmasq/audit_20261011_runtime_signals.py" \
  --rust "$RUST" --image-root "$IMAGE" \
  --c-native /home/ubuntu/dnsmasq-rewrite-20260929/c-native-01/dnsmasq/dnsmasq \
  --out "$AUDIT/private/signals-new"

sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$SOURCE/tools/dnsmasq/audit_20261011_dhcp.py" \
  --rust "$RUST" --image-root "$IMAGE" --out "$AUDIT/private/dhcp-new" \
  --report "$AUDIT/private/dhcp-new-result.json"

sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$SOURCE/tools/dnsmasq/audit_20261011_config.py" \
  --rust "$RUST" --image-root "$IMAGE" --out "$AUDIT/private/config-new"

sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$SOURCE/tools/dnsmasq/audit_20261011_hosts_memory.py" \
  --rust "$RUST" --image-root "$IMAGE" --out "$AUDIT/private/hosts-new"

sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$SOURCE/tools/dnsmasq/audit_20261011_tftp.py" \
  --rust "$RUST" --image-root "$IMAGE" --out "$AUDIT/private/tftp-new" \
  --report "$AUDIT/private/tftp-new-result.json"

sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$SOURCE/tools/dnsmasq/audit_20261011_dns.py" \
  --rust "$RUST" --image-root "$IMAGE" --out "$AUDIT/private/dns-new"

readelf -h -l "$RUST"
readelf -h -l "$IMAGE/usr/sbin/dnsmasq"
```

完整复现脚本链接：
[信号](../../tools/dnsmasq/audit_20261011_runtime_signals.py)、
[DHCP](../../tools/dnsmasq/audit_20261011_dhcp.py)、
[配置](../../tools/dnsmasq/audit_20261011_config.py)、
[hosts 内存](../../tools/dnsmasq/audit_20261011_hosts_memory.py)、
[TFTP](../../tools/dnsmasq/audit_20261011_tftp.py)、
[DNS](../../tools/dnsmasq/audit_20261011_dns.py)。

A08 的复核可在现有 Oracle 资料上运行
`python3 /home/ubuntu/dnsmasq-independent-audit-20261011/private/audit_performance_20261011.py`；
输入分析／raw 路径、SHA256、复核脚本 SHA 和输出路径见
[performance_evidence.json](audits/20261011/performance_evidence.json)。完整窗口方法与
重跑工具见 [性能研究记录](PERF_RESEARCH_UDP_DHCP_RELOAD.md)和
[M6B 协议](M6B_PROTOCOL.md)，不能用正在并行审计的负载窗口替代独占性能测量。

## 覆盖边界

本轮主要检查和执行了 DNS 本地／转发／过滤／rebind／错误输入、配置／启动、信号、
DHCP 静态预约与 Rapid Commit、hosts 重载、
TFTP 传输与错误边界、ELF 身份／布局以及单元回归；复核了历史同源性能证据。
包的 10 个 init/UCI/helper/
hotplug/ACL/default-data 文件与精确配方逐字节一致，未发现新的确定性包装缺陷。

以下不能据本报告宣称通过：

- 物理路由器部署、Wi-Fi/LAN 客户端健康、真实升级回滚、目标内核与驱动交互。
- 当前 fresh ELF 的 APK 构建、apk solver、安装／升级／卸载／rollback、完整 procd/ujail
  生命周期；旧 M6 包验证是历史记录，未自动继承到本轮产物。
- 全部 195 个配置入口的组合、include/conf-script 复杂进程树、所有权限/capability
  失败次序及所有 UCI 生成配置。
- DHCP relay、BOOTP/PXE、真实 bridge/interface 拓扑、租约文件断电／磁盘满／I/O
  注入，以及 DHCP 大规模负载。
- 独立 DNS corpus 使用 `cache-size=0` 和隔离 stub 上游，没有重新验证完整动态缓存
  aging/coalescing/resend、真实 WAN resolver、TCP 多帧流水线／half-close；这些路径的
  部分单测及历史材料不能扩大成这次独立 daemon 实验的覆盖。
- 新的长时 soak、覆盖引导 fuzz、OOM killer、全部 FD/内存故障注入、helper 被杀后的
  恢复、UBus 高压断连恢复。部分路径做了静态检查，不能等同黑盒验证。
- fresh ELF 的全部吞吐／CPU／延迟性能重跑，以及 Oracle 结果向 Cortex-A53 设备的外推。

这些未覆盖项限制“已经没有其他问题”的判断，不影响由现有可重复反例得出的
“当前不能完整替代”结论。
