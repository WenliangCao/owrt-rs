# dnsmasq-rs 重写与优化记录

当前状态：进行中；DNS UDP 主循环已经接入本地回答、配置路由和真实 UDP 上游事务，TFTP 已有文件/传输运行时，DHCP 已有 wire/runtime 边界，但仍未达到完整功能等价、性能验收或生产验收。阶段成果不等于完成替换。

## 固定身份

目标为 AX3000T、OpenWrt 25.12.5、九组件 Rust 原生镜像，dnsmasq 仍为 C 2.93-r1
普通 nodhcpv6 变体。启动核验使用现有同日源与部署证据，没有访问或修改物理设备。
`private/native-deploy-20260929/native-identity.json` 记录九个 ROM 原生路径已验证、无
可执行文件 bind mount；`live-image-verified.json` 记录 164 个包版本及 910 个 ROM
普通文件与 canonical 一致。镜像 SHA256 为
`144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720`。

精确配方为 OpenWrt `f0a60eee2fe051741c643ea6118718aae1ef17fb`，归档 SHA256
`0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19`。
`tools/dnsmasq/prepare_reference.py` 由版本清单逐一核验配方 13 文件，重新解包并应用
两份 OpenWrt 补丁，保存完整 patched source 哈希。复跑检查漂移，不覆盖输入。

编译选项：IPv6、UBus、DHCPv4、TFTP、loop-detect、inotify、dumpfile；无 DHCPv6、
DNSSEC 验证、DBus、Lua、conntrack、ipset、nftset、权威 DNS、IDN、i18n。
BOOTP/PXE、DHCP relay/leasequery、AD 透传、可启用的 DNS 订阅也必须完成；不能用
当前配置未启用来裁剪。odhcpd/odhcp6c、内核和驱动的职责不变。

## 阶段与验收

| 阶段 | 当前状态 | 通过条件 |
|---|---|---|
| 身份与 C 参考 | 进行中 | 精确源码、选项、依赖、可重建参考和测试器校准 |
| DNS | 进行中 | wire/forward/cache、本地 hosts/RR、CNAME 链、UDP/TCP framing、EDNS dispatcher、非阻塞 UDP upstream、域名路由、rebind/bogus/ignore 地址策略和 UDP daemon 已有对照；负缓存 SOA/`neg-ttl` 选择原语已补齐，但完整包缓存/回复合成、TCP upstream、ubus doctor、reload 仍待做 |
| DHCPv4 | 进行中 | 状态/租约原语、BOOTP 64-byte vend、datagram dispatch、DHCP reply wire、Linux pktinfo 目的/本地地址区分和广播接口发送边界已有对照；真实 listener、ARP、relay/PXE/DNS 同步仍待做 |
| TFTP 等可用能力 | 进行中 | path/permission/admission、真实 Unix 文件读取、OACK/DATA/ACK、TID、重传、超时和清理已有对照；空文件、整块文件和窗口传输均等待最终 DATA ACK；监听器端口/pktinfo、脚本、PXE/TFTP 接线仍待做 |
| OpenWrt 集成 | 进行中 | 全配置、UCI/procd/ujail、ubus/ACL、reload、调用方 |
| 优化 | 未证明收益 | 正确性通过，冻结工作负载，逐轮成本与资源证据 |
| 目标构建/打包 | 部分完成 | 早期匹配 SDK 已构建 inert `owrt-dnsmasq-0.1.0-r1.apk`（aarch64 Cortex-A53 musl，SHA256 在 `private/dnsmasq-rewrite/package-20260930/`）；它只安装 `/usr/libexec/dnsmasq-rs`，未替换 stock dnsmasq。UDP daemon 接线后的源码尚未用匹配 SDK 重新出包，完整 ABI/镜像装配仍待完成 |
| 真机验收 | 未执行 | 单独授权、恢复门、目标环境测量 |

具体源码映射分文件记录。所有原始报文、配置、地址、租约、ELF 和测量记录放
`private/dnsmasq-rewrite/`。用户现有的 prompt 修改保持原样。产品代码不调用 C
参考、不使用 DNS/DHCP C FFI；C 仅用于隔离测试 oracle。

## 证据目录

- `private/network-research-20260929/dns/`：此前已核对的精确输入。
- `private/dnsmasq-rewrite/reference/identity.json`：本次重建的精确源码身份。
- `private/dnsmasq-rewrite/local-c-audit-20260930/answer-rust-final.json`：108 个本地回答 C/Rust 语义 case，0 mismatch；`class-rust-final.json`：9 个非 IN class case，0 mismatch。
- `private/dnsmasq-rewrite/local-c-audit-20260930/routing-review/rust-results/`：10 组路由配置、240 个 case，0 mismatch。
- `private/dnsmasq-rewrite/tftp-service-diff/result.json`：C path/admission oracle 255,528 + 20,000 cases，0 unexpected mismatch；2,408 个显式 `..` hardening differences。
- `private/dnsmasq-rewrite/dhcp-reply-diff/result.json`：hash-pinned `rfc2131.c` reply wire oracle 1,008 cases，0 mismatch，覆盖 primary/file/sname overload、PRL、OFFER/ACK/INFORM/NAK、option 57 capacity 与 broken-string workaround。
- 后续构建、差分、fuzz、基准逐轮追加；未运行项目不计作通过。DNS reply envelope 的 1,537 个结构有效包/19,981 条命令、address policy 的 68 个 ASan/UBSan C/Rust case、negative cache 的 4 个边界测试和 upstream transport 的 loopback 测试详见各阶段文件。

当前 crate 门：`cargo test --all-targets` 为库 197 passed、4 ignored，主程序目标 5 passed；`cargo clippy --all-targets -- -D warnings`、`cargo fmt -- --check` 和 `aarch64-unknown-linux-musl cargo check --all-targets` 通过。4 个 ignored 测试要求显式精确 C reference，未把 ignored 计入通过。主程序 loopback smoke 已验证本地 UDP 回答和 UDP 上游回送均保留客户端 ID；SIGTERM 优雅清理仍未实现。

## 已冻结的局部性能证据

TFTP netascii correctness gate `tftp-oracle-07` 使用当前 C/Rust 源码、97,384 个
case、ASan/UBSan C driver，0 mismatch。随后按 `PERFORMANCE_PROTOCOL.md` 固定的
512/1468/4092 字节、普通/每 80 字节 LF/全 LF 三种输入，C/Rust 交错五轮、每组
1,000,000 次运行；原始窗口在 ignored `private/dnsmasq-rewrite/tftp-bench-03/`。
CPU 比值 Rust/C 的五轮中位数为：普通输入 0.995–1.014、每 80 字节 LF
1.003–1.019、全 LF 0.102–0.387（块越大收益越明显）。这只证明 netascii 热点的
局部主机筛选结果；没有 DNS/DHCP 吞吐、尾延迟、RSS/PSS、目标路由器或端到端收益
结论。

## 下一步

完成 native C 参考构建与隔离实验，继续接线完整 DNS/DHCPv4/TFTP/OpenWrt 服务、构建真正替换包，再冻结主要场景做性能与资源测量。
保持功能等价和优化目标两条验收线；当前二进制仍是受限的 loopback 本地-DNS 开发探针，SDK 包是 inert staging artifact，尚无可替换生产 dnsmasq 的兼容 package。
