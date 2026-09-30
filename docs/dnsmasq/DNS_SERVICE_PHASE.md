# DNS 本地服务接线阶段

本阶段把已经对照过的 wire、hosts 和配置记录原语接成一个可嵌入的本地 DNS 服务边界；它没有把上游转发或完整 dnsmasq 守护进程能力伪装成已完成。

| 位置 | 行为/不变量 | Rust 实现 | 验证 |
|---|---|---|---|
| `rfc1035.c:1730-1768,1753-1807,2450-2462` | 只接受 QUERY、单 question、无 QR/authority；完成本地回答时保留 RD/CD、设置 RA；CNAME A/AAAA 追目标；local-only 未命中为 NXDOMAIN，已知子树为 NOERROR/AA=0 | `dns/local.rs::LocalAnswerer` | 本地回答测试覆盖 A/AAAA/TXT、CNAME+A、未拥有名称、QCLASS 非 IN 的 local-only 边界、族过滤、zero-address、NXDOMAIN/NOERROR、截断、标志 |
| `cache.c:1322-1545` | hosts 地址族筛选、同名轮转、TTL 和配置 host-record 记录 | `LocalAnswerer` + `Hosts` | `hosts` 原有对照；本地 A/AAAA/TXT 测试 |
| `option.c:2335-2373,4971-5251` | CNAME、PTR、TXT、MX、SRV、NAPTR、raw RR 的 typed 数据进入 bounded writer；CNAME 链先于别名自身记录 | `dns/local.rs` | 配置解析与 wire writer 单测；多跳链、任意 qtype、别名遮蔽、独立 TTL、hosts nonterminal/raw 边界已覆盖；MX 默认主机名仍待完整服务复现 |
| `forward.c:1635-1796`、`forward.c:2425-2470` | TCP DNS 两字节长度前缀、分片读取、多帧连接、零长度拒绝；超过 `packet_buff_sz` 的长度前缀在 C 中先拒绝，不读取帧体 | `dns/service.rs::TcpFramer`；`with_max_frame` 在长度前缀阶段返回 `TooLarge` | 分片/多帧/空帧边界测试；`bounded_tcp_framer_rejects_length_before_reading_body` |
| `forward.c:32-119,1635-1796` | UDP/TCP socket 与两字节 TCP framing 属于传输边界；未拥有的名字显式返回 `None`，交给独立的上游 dispatcher | `LocalDnsService` + `TcpFramer`；`dns/forward_service.rs::ForwardDispatcher`；`dns/upstream.rs::UpstreamResolver` | 分片、多帧、最大帧后续帧、长度前置超限、零长度/截断与本地服务接线测试；主程序对未实现 TCP forwarding 的未拥有查询及时关闭；上游 EDNS/合并/回复匹配及非阻塞 UDP socket 见 `DNS_FORWARD_SERVICE_PHASE.md`/`DNS_UPSTREAM_PHASE.md`；完整 process-reply、TCP upstream fallback 和 daemon 接线仍未完成 |
| `rfc2131.c:565-697` | BOOTP vend 固定 64 字节、cookie、TLV/END、空间不足跳过并继续 | `dhcp::packet::encode_bootp_vendor` | exact boundary/full/truncation/malformed 单测；无真实 DHCP listener |

## 当前边界

`LocalDnsService` 只回答本地拥有的名字；`None` 不是 NXDOMAIN，而是上游 dispatcher 的明确交接点。`dns::daemon::DnsDaemon` 现把这条边界接到 `RoutingTable`、`ForwardDispatcher` 和有界非阻塞 `UpstreamResolver`：调用方提交一个客户端 UDP 数据报，再从 `poll` 取得已恢复客户端 ID/大小的回复。`ignore-address` 在上游匹配后、forward 状态完成前执行；回复仍只经过现有地址策略和 EDNS envelope。daemon 现接入窄范围缓存：仅 IN、单问、无 EDNS/DNSSEC、NOERROR 的直接 A/AAAA RR，以及无 SOA 的 NXDOMAIN fallback 会按 TTL 写入；命中用 bounded writer 恢复新客户端 ID。缓存目前由每个 UDP listener worker 各自持有，多监听地址之间不共享。CNAME、ANY、NODATA/SOA、缓存响应 EDNS 与完整 cacheability 仍未接线。ubus/TCP fallback 仍明确未完成。二进制 listener/reload 生命周期尚未改为使用该边界。

本地回答边界由精确 C driver 在 2026-09-30 重新核验：A-only `host-record` 对 AAAA 返回上游边界，对 ANY/IN 只返回 A；CNAME 的 A/AAAA/ANY 查询先返回 CNAME 再返回本地目标地址；未知 `local=/domain/` 是 NXDOMAIN 且 AA 清除，已知子记录存在时父域是 NOERROR/AA 清除；`address=/domain/#/` 对 A/AAAA 分别返回全零；QCLASS 非 IN 在 local-only 域仍由本地边界返回 NXDOMAIN/NOERROR；本地记录数据只接受 IN。证据在 ignored `private/dnsmasq-rewrite/local-c-audit-20260930/`，不包含物理路由器访问。

当前二进制只允许显式 `no-resolv`、loopback `listen-address`、非特权端口和本地记录；它会拒绝 upstream/resolv/interface 等未接线配置，缓存只在正式 daemon 路径启用窄范围正向与 NXDOMAIN fallback。尚未完成的交付门包括：完整上游 server 选择/EDNS mutation/查询合并、完整 cacheability/CNAME/NODATA/SOA/缓存 EDNS metadata、生产级连接/FD 生命周期，DHCP/relay/PXE/TFTP socket 与脚本，UCI/procd/ujail/ubus/reload，匹配镜像的替换包和冻结性能窗口。因此本阶段不能称为功能等价、包替换或生产验收。

## 验证命令

```sh
PATH="$HOME/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin:$PATH" \
  cargo test --manifest-path components/dnsmasq/Cargo.toml
PATH="$HOME/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin:$PATH" \
  cargo clippy --manifest-path components/dnsmasq/Cargo.toml --all-targets -- -D warnings
PATH="$HOME/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin:$PATH" \
  cargo check --manifest-path components/dnsmasq/Cargo.toml \
    --target aarch64-unknown-linux-musl --all-targets
```

本轮结果：库测试 **214 个通过、4 个需要精确 C 路径的测试保持 ignored**，主程序目标 6 个通过；Clippy `-D warnings` 通过。daemon 新增 loopback 正向缓存与无 SOA NXDOMAIN 命中回归（第二次查询不再发送上游，恢复新 ID）；`tools/dnsmasq/dns_local_service_probe.py` 提供隔离 loopback UDP/TCP、本地 CNAME/AAAA/NXDOMAIN 和未拥有查询丢弃的可重复 smoke；`tools/dnsmasq/dns_forward_service_diff.py` 对精确 `add_pseudoheader(optno=0)` 完成 1,007 cases、0 mismatch。上述证据仍不等同于完整 daemon 服务验收。
目标 musl `cargo check` 通过；在 macOS 主机直接链接 release ELF 仍被宿主 clang 拒绝 OpenWrt 的 `--fix-cortex-a53-843419` linker flag，不能把主机 check 标为目标产物构建通过。
主机 loopback smoke（显式 UDP socket、TCP length framing、本地 host-record）已得到 UDP/TCP 各 1 个正确 ID/answer；`tools/dnsmasq/dns_signal_smoke.py` 的 SIGINT/SIGTERM smoke 已确认进程退出码为 0 并回收 listener/client workers。SIGHUP reload、resolver 轮询和配置重载仍尚未实现。
