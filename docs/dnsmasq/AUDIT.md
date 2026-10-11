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

## 2026-10-11 修复与验证补记

本节记录 `fix/audit-20261011` 从 `main=be531cee` 开始的修复。上文及原始 JSON 保留为历史审计证据；修复后的状态以本节及 `audits/20261011/fixes/` 为准。范围为 A01–A06、A09、A10，加 A07 的独立取舍；没有进行 A08 优化。没有合并 main、推送 GitHub 或接触物理路由器。

### 行为修复

| 项目 | 修法 | 最终产物验证 |
| --- | --- | --- |
| A01 | 信号处理器只记录事件并唤醒既有 owner；USR1 输出实际 cache/queries/server/TCP HWM；debug 或 log-queries 开启时还输出当前 hosts、租约及缓存记录，ALRM进入现有 prune→leasefile→DNS 维护队列。 | 原 12 例继续服务；两次 dump 的缓存／查询／上游／NXDOMAIN 计数与 C 一致；受控 EFBIG 写失败恢复后，ALRM 在自动重试时间到来前恢复租约文件；随后 dump 可见该租约。 |
| A02 | 以 `existing_id` 判断是否还需分配，已允许接管的多 MAC 静态预约复用旧 lease。 | 第二 MAC 获得 ACK，租约交接与 C 相同。 |
| A03 | DISCOVER 的选址和提交分开，Rapid Commit 用最终地址／context 获取地址池 tag 后执行名称策略。 | 无 option 50 也正确应用 ignore/generate；option 50 有／无对照均一致。 |
| A04 | REQUEST 与 Rapid Commit 共用 ACK 名称决策，先采用 hosts 权威名，再处理客户端名称、ignore/generate。 | 租约及 A/PTR 与 C 一致，不再额外发布 claimed。 |
| A05 | 恢复 11 个配置入口及 C 的语法校验；保留 auth-server 对接口、local-service、TFTP/whichdevice、请求日志的仍有效语义；保留 no-dhcpv6-interface 的相关接口标志。 | 原 11 项加 no-ident 正控制，语法、启动、退出及实际 DNS wire 全部一致。 |
| A06 | 普通 hosts 以 8 KiB 块读取，普通／hostsdir 共用最多 502 字节 token 的流式解析器；不再保留全文件或整行。打开／目录错误进入现有日志通道；普通坏 token 仍只累计统计，没有新增无界诊断队列。 | 48 MiB 注释＋一条记录，普通启动及 RLIMIT_AS=32 MiB 的启动／HUP 全部正确，C/R应答一致；Rust取消按48MiB文件长度分配的临时输入缓冲；最终峰值RSS为2652–2660KiB。 |
| A09 | 只在普通 OFFER 抑制客户端 option 12；快速 ACK 保留按 ACK 规则选定的名字。 | Rapid Commit ACK hostname option 与 C 一致。 |
| A10 | 缓存入口不再因问题解析失败提前关闭 TCP，交由既有请求错误处理；本次七类异常／不受支持输入恢复 REFUSED。 | 七类异常输入及正常控制共16个UDP/TCP组合，C/R答包全部一致且服务健康。 |

USR1 不输出 C blockdata allocator 池数字或内部 non-terminal 占位，记录顺序不承诺一致；它们不代表 Rust 的内存结构。原始日志保留，差分校验真实业务计数、可见记录与维护副作用，不以进程未崩溃代替诊断功能实现。

完整 DHCP/DNS 回归另抓到旧 main 已有的 debug TCP 问题：旧 NXDOMAIN 会遮住后来发布的 DHCP A 记录，初修版和旧 main 对照 ELF 各自与 matching-native C 比较均为33/34，两者都在 `ack-fqdn-tcp` 返回旧 NXDOMAIN。TCP现在与UDP一样先执行了解缓存语义的本地名称查询，再查转发缓存；debug缓存查询使用当前本地视图。最终冻结产物与精确镜像 C 的该完整回归已转为34/34。这是受影响回归实际暴露的补修，不是放宽旧期望。

### 冻结产物与结果

运行代码冻结于 `4a72e24544bc50ef2a71d0e05032fbd9b3dd9721`（后续为验证工具、构建默认选择及报告）。Oracle目录 `/home/ubuntu/dnsmasq-audit-fix-20261011/source-02`；feature-off、opt3、Rust1.98.1、匹配SDK。

- PIE ELF：`bf0eb539b5bc788b635376ab1480b5cfb7e7b56bae838fa0c964794ab9be67d3`。
- 同源静态对照：`2c475f83983596d2a4e7dd7927f2116bf1fa41e0d8ac6fe6ab66f98950f72549`。
- C仍为精确镜像 `097a9e21…`；信号组额外保留 matching native C 正控制。
- 最终单测：lib757、bin74通过，0失败，23个ignored未执行。测试运行体为静态musl harness；实际daemon差分和完整功能族使用上述PIE release ELF。
- 本轮纳入修复的 A01–A06、A09、A10 定向复现全部通过。补充完整族：DHCP/DNS34、reverse-name28、TCP15检查/116回答、reload23、hosts generation两轮各102查询/侧、DHCP range76服务场景，全部通过。
- [原复现与补充回归](audits/20261011/fixes/reproductions.json)、[构建／单测／运行时防护](audits/20261011/fixes/build_and_unit.json)。

按预先选定的注册命令及既有例外判据，**22/22 个受影响完整功能族、43/43 个逻辑命令通过**。包含配置与名称选项、DHCP tags／identities／range／files／lease recovery／device binding、listeners、TFTP、日志、CLI、EDNS、DNS cache／interface records／files 及 UBus。最终 logging 为329个场景；UBus完整族通过，350项paired observations、失败为0。每个命令的结果路径、SHA、导出检查项及可用场景清单见 [完整功能族结果](audits/20261011/fixes/families.json)，完整明细见其中指向的原始结果。

闭合记录保留最初43命令中的20个完整通过族，以两次**整个族**重跑替换logging与UBus结果；没有仅重跑失败单例来宣布整个族通过。原始失败文件及SHA仍在同一证据中。这里的“完整”指预先选定的22个受影响族，既有明确记录的C缺陷／溢出输入差异仍按原规则保留；没有宣布全部44族、M5/M6归档程序或部署生命周期通过。

### A07 的取舍

历史选型说明：本节的动态 PIE 选择已由后文的 [static-pie 复核](#static-pie-final)取代；以下测量和首次失败记录保留。

**采用动态 PIE，A07 修复。** 使用 `-Ctarget-feature=-crt-static -Clink-self-contained=no -Clink-arg=-pie`。体积代价可接受；性能存在下面记录的小幅延迟代价，首次筛查信号经定向确认后未持续达到预设回退门槛，因此接受这项取舍。完整决定及构建文件身份见 [PIE 取舍记录](audits/20261011/fixes/pie_decision.json)。

同源静态与 PIE 按冻结计划执行 UDP 命中、TCP 未命中、DHCP 和并发重载，三轮交替顺序，共24窗；每窗预热10秒、测量30秒，未做饱和测试。所有窗口的行为和测量方法有效，没有生成器限制。预设回退规则是：中位数增加超过10%、超过两组最大 W，且各配对轮全部同向；W=(最大值−最小值)/中位数。

原24窗结果如下（CPU为 µs/正确单位，p95为 µs；DHCP单位是完整cycle，其余是DNS query）：

| 场景 | CPU：静态 → PIE（变化） | p95：静态 → PIE（变化） | 回退标记 |
| --- | --- | --- | --- |
| udp-hit | 12.327 → 12.985（+5.33%） | 22.280 → 22.561（+1.26%） | 无 |
| tcp-miss | 94.769 → 96.904（+2.25%） | 620.005 → 678.565（+9.45%） | 无 |
| dhcp-lease | 540.987 → 553.568（+2.33%） | 3154.506 → 3240.346（+2.72%） | 无 |
| reload-concurrent | 27.378 → 27.152（-0.82%） | 70.681 → 83.521（+18.17%） | p95 |

原筛查 **accepted=false**：重载p95增加18.17%，最大W为17.58%，3/3配对同向，触发唯一标记；其余七个指标未触发。没有用无生成器限制或正确回答来否定这个延迟信号。[原始24窗结果](audits/20261011/fixes/pie_cost_initial.json)、[原冻结计划](audits/20261011/fixes/pie_cost_plan.json)。

遵照原计划“标记后拒绝或定向复核”的规则，在确认开始前冻结了仅重载的第4–6轮，共6窗。除轮次、种子及输出目录，负载／时长／CPU／工具／ELF不变，继续交替执行顺序。确认组和保留全部数据的六轮合并组，任一组的CPU或p95仍触发相同规则即拒绝；没有追加其他场景或反复重跑至通过。

| 重载数据组 | CPU：静态 → PIE（µs/query） | p95：静态 → PIE（µs） | p95变化／最大W | 回退标记 |
| --- | --- | --- | --- | --- |
| 新增第4–6轮 | 27.807 → 26.924 | 72.321 → 72.681 | +0.50%／16.40% | 无 |
| 保留全部第1–6轮 | 27.694 → 27.080 | 71.460 → 78.101 | +9.29%／18.80% | 无 |

新增6窗同样无行为错误、方法错误或生成器限制。[确认计划](audits/20261011/fixes/pie_reload_plan.json)、[确认与合并结果](audits/20261011/fixes/pie_reload_confirmation.json)保留每轮原始数值、方向及hash。**六组p95均是PIE较高，不能说没有延迟代价**；确认组的增量为0.360 µs，合并中位数增量为6.641 µs。结合未触发持续回退门槛、体积下降和恢复ASLR，认为本轮代价可接受。

“不触发”不等于性能等效；W对极端样本敏感，且只重复重载，前置负载历史不同于初始四场景顺序。原24窗的 `accepted=false` 保持不变，本节不将其称为通过。

动态 PIE 的解释器是镜像 `/lib/ld-musl-aarch64.so.1`，NEEDED 只有镜像已有的 `libc.so`、`libgcc_s.so.1`。三次独立实际启动观察到不同装载基址，RELRO覆盖页实际只读，栈无执行权限，无WX LOAD或TEXTREL。体积从同源静态1,998,888 B降到1,925,712 B，减少73,176 B（约3.66%）。这不是整个APK/flash或相对C的A08成本结论。

默认 release 构建和包配方同步使用这三个链接参数，显式声明 `+libgcc`（APK 名称 `libgcc1`）。包校验从 static-only 改为验证 AArch64 PIE、精确解释器／共享库、NX／RELRO／立即绑定及无 WX／TEXTREL，保留冻结源码、SDK 与最终 ELF 的身份检查。配方移除本轮冻结产物未使用的 `pack-relative-relocs`，使链接策略对齐；这不是宣称目标 musl 不支持 RELR。测试／诊断构建仍沿用原静态链接。

直接受影响的 `python3 tools/dnsmasq/test_build_package.py` 18项通过；真实冻结PIE通过新的ELF门，同源static被按预期拒绝。见 [包工具验证](audits/20261011/fixes/package_elf_gate.json)。这次没有重新生成APK；新构建可能因路径映射等因素产生新SHA，仍须通过冻结ELF身份门，不能把本轮验证自动转给另一份ELF。

链接参数依据 [rustc codegen说明](https://doc.rust-lang.org/rustc/codegen-options/index.html#relocation-model)及本机固定编译器／SDK，最终以ELF和实际映射为判据，不只检查命令行flags。仅在Oracle检查，未测Cortex-A53真机性能；本轮不增加APK安装／升级／回滚或部署资格。

### 失败记录与工具修正

所有首次失败／中断目录保留，没有挑选单条成功记录拼成最终通过：

- 首轮并行 lease-name 两次0.4秒 ACK等待超时未在原样定向、完整重跑中再现；最终受影响族改为串行，不增加请求时限。
- hostsdir共用流式解析器后，1MiB旧输入太快，采样看不到有效的FD开放期；改为16MiB，保留原先重叠期与健康断言。定向验证19次Rust查询全健康，11次有开放期双端见证。
- PIE的allocator符号来自镜像共享libc，原静态link-map定位无效；工具改为实际动态符号／映射定位，校验inode和ELF SHA，仍真实注入NULL，未跳过失败边界。
- dns-files的fresh TCP查询已由前一UDP填充缓存，原配置漏标cache。明确标记后只使用已有的1秒缓存时钟规则，fresh miss、RCODE、回答和上游因果校验不变。
- 原UBus工具直接执行PIE却缺host musl interpreter；改用精确镜像loader，保留真实ELF身份。一次family启动前占位符`image_root`错误更正为既有`image`，当时没有任何族开始执行。
- logging 的完整329场景首轮仅 DHCP INFORM option 51／对应日志出现600与599秒差异。匹配C源码使用 expires−now；工具现在保留每侧租约文件与发送／接收时钟，先验证该侧的剩余时间，再对这一字段及对应XID日志做等价比较。五个控制例确认错误wire、错误日志仍失败，其他option和新ACK差异仍保留。原失败不回填为通过。
- UBus完整族首轮在empty-activation遇到工具自身未定义变量；前面的584检查／69对照不当作完整通过。修正遗漏的image-loader前缀后从头执行整个族，不跳过empty-activation。一次临时工具副本漏保留 `tools/dnsmasq` 层级，令客户端C源码编译在产品启动前失败；保留该记录，恢复原目录布局后再次从头执行整个族。
- Linux专用TCP单测fixture补齐新增auth字段。构建前误启动的unit命令未实际执行测试；最终只计成功构建后的757＋74结果。
- 旧source01的长回归在产物被补修替代后受控终止，后代进程清理；它们不具最终资格。最终产物、原复现和完整功能族分别绑定真实ELF与工具hash。

### 本轮结论与边界

**A01–A06、A09、A10 的指定行为缺陷已修复，定向 C/R 差分和受影响完整回归通过；A07 采用动态 PIE，取舍及证据见上节。** 就本轮范围而言，这些问题不再构成替代 C 版的阻断项，修复分支可以进入 main 的独立合并复审。所有修复和证据提交都留在 `fix/audit-20261011`，没有自行合并。

这项结论限定于本轮修复与验证范围，不将整个 dnsmasq 的生产替代验收宣布完成。原报告关于 A08 资源预算及部署边界的限制继续有效。

上文没有覆盖的物理路由器、真实客户端、目标内核压力、整个APK/procd/ujail部署生命周期、长期soak等范围仍未据此自动验收。原审计的A08资源差距本轮没有优化或豁免。

<a id="static-pie-final"></a>

## 2026-10-11 A07 复核：保持静态链接，采用 static-pie

**本节取代前一节采用动态 PIE 的决定。最终选择 static-pie，撤销新增的直接 `libgcc1` 依赖。** 按用户本轮要求，dnsmasq 沿用 [0017 号决定](../decisions/0017-release-profile-opt3-static.md)的静态发布策略；该决定当时覆盖六个组件。其设备测量是含启动的 UCI 调用，不能直接当作 dnsmasq UDP 稳态 CPU 结果；同样，前一轮 Oracle 上的动态 PIE 对照也不足以绕过这项既有决定。

### 可行性与最小构建改动

固定 Rust 1.98.1、`aarch64-unknown-linux-musl`、匹配 SDK/BFD 上，static-pie **可行，但仅有两个 Rust 参数不够**：

| 实际尝试 | 结果 |
| --- | --- |
| `-Crelocation-model=pie -Ctarget-feature=+crt-static` | 编译成功，但 rustc 选择普通静态启动文件并传入 `-static -no-pie`，最终仍为 `ET_EXEC`。 |
| 仅追加 `-static-pie` 给链接器 | 可生成 `ET_DYN`，但没有纠正启动对象，三次启动均 SIGSEGV；不能把 ELF 类型当作成功。 |
| 正确选择 static-pie 启动对象和链接参数 | 完整 dnsmasq 为 `ET_DYN`、无 `PT_INTERP`、无 `DT_NEEDED`，实际启动与 ASLR 验证通过。 |

发布构建保留上述两个 Rust 参数，并共用一个39行的[链接适配器](../../packaging/openwrt/owrt-dnsmasq/static-pie-linker.py)：将独立的 `-static` 换成 `-static-pie`，移除独立的 `-no-pie`，把 Rust 自带的 `crt1.o/crtbegin.o/crtend.o` 换为同目录 `rcrt1.o/crtbeginS.o/crtendS.o`。其余链接参数与顺序保持不变；输入、对象来源或替代文件不符合固定契约就失败，不静默退回普通静态 ELF。无需改编译器、自定义 target、nightly、重编 std 或修改组件运行时源码。[rustc 的链接选项说明](https://doc.rust-lang.org/rustc/codegen-options/index.html#relocation-model)也区分代码生成模型和最终链接行为；本结论以实际链接输入和产物为准。

两个版本的 `libc.a`、`libunwind.a`、`crti.o`、`crtn.o` 均逐字节相同；此工具链的 `crtbeginS/crtendS` 与原对象也逐字节相同，在所比较的启动／静态库输入中，新增的是负责自身重定位的 `rcrt1.o`；这里不把全部 ELF 增长归因于该对象。保留 opt3、原静态库及现有单测构建方式。Makefile 和 Oracle release 构建均使用这个适配器；原有 `libubus` 包合同依赖不变，没有新增共享库需求。

### 产物与实际保护

| 项目 | 原静态基线 | 最终 static-pie |
| --- | --- | --- |
| ELF SHA256 | `2c475f83983596d2a4e7dd7927f2116bf1fa41e0d8ac6fe6ab66f98950f72549` | `e1eb80e30b2a28da516bcd1a26baeb548e4baa8926d904b32689b7bbe2b41fcd` |
| ELF 大小 | 1,998,888 B | 2,052,576 B（+53,688 B，约+2.69%） |
| 类型／解释器／共享库 | ET_EXEC／无／无 | ET_DYN／无／无 |
| 三次真实启动 | 固定 `0x400000` | 三个不同映射基址 |
| 栈执行权限／WX LOAD | 无／无 | 无／无 |
| GNU_RELRO 区间实际只读 | 否 | 否 |

**ASLR 已恢复；full RELRO 没有实现。** `/proc/PID/maps` 证明，两种静态 musl 产物的 GNU_RELRO 覆盖页仍可写。这里保持了原静态策略的行为，没有继承动态 PIE 的实际只读 RELRO；也不与 C 的完整运行时保护等同。检查实际 `/proc/PID/exe` SHA 和映射文件，确认运行的正是上述 ELF，且没有映射共享库。

构建快照为 `16144937c85f6682329bcb77bdaa815f6d72e620`，目录为 Oracle 的 `/home/ubuntu/dnsmasq-audit-fix-20261011/source-03`。167个组件文件与已修复的 `4a72e245` 快照相同。原始失败尝试、构建参数、静态库身份、实际映射和包门检查见 [构建与保护证据](audits/20261011/fixes/static_pie/build_protection.json)。

### 最终验证与范围

- 新 ELF 的11组原复现／补充回归全部通过：信号12例，DHCP9例，配置12例，hosts三对条件，异常DNS16个组合；DHCP/DNS34、反向名称28、TCP15项检查／116个答包、重载23项检查、hosts generation两轮、DHCP range76服务场景。结果绑定新 ELF，见 [static-pie 复现证据](audits/20261011/fixes/static_pie/reproductions.json)。
- 按与上一轮相同的注册清单及既有例外判据，**22/22 个受影响完整族、43/43 个命令通过，零失败**；本轮未做失败项替换或缩减清单。覆盖日志329场景、完整缓存／接口／文件／UBus／DHCP／TFTP等族，见 [static-pie 完整回归](audits/20261011/fixes/static_pie/families.json)。此处不表示全部44族或整个部署生命周期通过。
- 直接受影响的包工具测试 **20/20通过**，包括链接适配器输入检查、真实Make配方解析SDK裸编译器路径、静态PIE布局和直接依赖检查。普通单测的组件源码及构建参数均未变，保留上一轮lib757＋bin74通过／23个ignored的证据，没有将它冒称为新static-pie单测结果。
- 验证结束后再次核对167个组件文件、产物SHA、同次构建link.map及所有命令结果身份；没有遗留相关测试负载。

包校验要求 AArch64 ET_DYN、无解释器及共享库依赖、NX、GNU_RELRO 结构、无 WX/TEXTREL，并继续核对冻结源码／SDK／ELF 身份；不把 GNU_RELRO 结构或 BIND_NOW 标志伪称为静态运行时只读保护。普通静态 ELF 和前一轮动态 PIE 都被新门拒绝。包元数据另明确拒绝直接 `libgcc`／`libgcc1` 依赖，包括版本限定形式，不限制原有依赖的传递依赖。

由于 static-pie 已可行并被采用，未触发“不可行后做真机动态／静态 UDP CPU 对照”的条件。本轮没有访问或修改物理路由器，也没有将动态 PIE 或 UCI 的历史性能数字当作 static-pie 的 CPU 证明。没有新增真机性能、APK 安装／升级／回滚或部署资格；[0018 号决定](../decisions/0018-canonical-build-host-ci.md)的 canonical 发布边界不变。A08 仍未优化，修复仍留在 `fix/audit-20261011`，不自行合入 main 或推送 GitHub。
