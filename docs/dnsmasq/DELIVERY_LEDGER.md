# dnsmasq-rs 持续交付账本

更新时间：2026-09-30。这个账本只覆盖 dnsmasq-rs，不替代各阶段源码报告。它把“入口已索引”“解析器已实现”“运行时已接线”“Linux 行为已验证”“C 差分已完成”“目标包可替换”和“真机已验收”分开记录；任何一层通过都不能推导出下一层通过。

## 固定身份与当前快照

| 项目 | 固定事实与证据 | 结论 |
|---|---|---|
| 镜像/包 | AX3000T、OpenWrt 25.12.5、dnsmasq 2.93-r1、`nodhcpv6`；OpenWrt revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`；归档 SHA256 `0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19` | 这是部署规格和 C 参考身份 |
| 编译边界 | `HAVE_UBUS HAVE_POLL_H NO_DHCP6 NO_AUTH NO_IPSET NO_ID`；目标包含 DHCPv4、TFTP、BOOTP/PXE、relay/leasequery、inotify、dumpfile；不包含 DHCPv6、DNSSEC 验证、DBus、Lua、conntrack、ipset/nftset、权威 DNS、IDN、i18n | 不能以当前配置未启用删减上述可用能力 |
| 入口清单 | `docs/dnsmasq/options.json`：195 个长选项，169 个 `variant=available`，26 个未编译能力；`python3 tools/dnsmasq/contract_inventory.py --check` 输出 `195 options indexed; 169 target capability entries` | 169 是本账本的总入口，不是已实现数 |
| 参考源码 | `private/dnsmasq-rewrite/reference/identity.json`、`docs/dnsmasq/DNS_SOURCE_MAP.md`、`docs/dnsmasq/OPENWRT_CONTRACT.md` | C 参考只用于差分，不进入产品依赖 |
| 版本状态 | HEAD `327d63b`（TFTP 配置/监听接线、DNS SOA cache、DHCP listener/runtime 已提交）；工作树只剩用户已有 prompt 修改 | 未提交内容不是交付物，提交前必须重新格式化、测试和身份核验 |
| 现时本地门 | 当前运行：`cargo test --all-targets` 为 226 passed、4 ignored；主程序 6 passed；aarch64 musl `cargo check --all-targets` 与 clippy `-D warnings` 通过；fmt/diff-check 通过 | 这是源码门，不是 Linux 服务或包验收 |
| 目标包 | `private/dnsmasq-rewrite/package-20260930/manifest.json` 的 `owrt-dnsmasq-0.1.0-r1.apk` SHA256 `334a6e98fd55b125ba691fef2381f74e2e55cc8211010eb97c261c25e6984962`，只安装 `/usr/libexec/dnsmasq-rs`，`activation=inert` | 不是 stock dnsmasq 替换包；不能部署或宣称可回滚替换 |
| 设备 | 没有物理路由器部署、刷写或真机性能窗口 | 真机验收未执行 |

## 169 个可用入口总表

下表逐项列出 169 个入口。各组的状态描述适用于组内每个名字；“索引”只表示选项、参数和变体边界已记录，不表示对应引擎可运行。

| 能力组 | 数量 | 169 入口 | 当前层级、证据和关闭项 | 下一 owner |
|---|---:|---|---|---|
| 启动、配置文件与日志 | 23 | `version`, `no-hosts`, `no-poll`, `help`, `no-daemon`, `log-queries`, `user`, `group`, `pid-file`, `conf-file`, `conf-script`, `conf-dir`, `keep-in-foreground`, `test`, `log-facility`, `log-debug`, `log-malloc`, `quiet-dhcp`, `quiet-tftp`, `dumpfile`, `dumpmask`, `log-dhcp`, `log-async` | `options.json` 和 loader 已建立元数据/词法边界；部分 scalar/loader 单测和 C 接受/拒绝差分通过。日志、权限、dump、脚本和 `--test` 后启动副作用未完成全链路；主程序只显式接收少量运行开关。 | 配置/启动 owner：补跨选项 finalization、权限、日志、dump、FD/错误清理和 OpenWrt 启动回归 |
| DNS 上游、传输与缓存 | 29 | `resolv-file`, `servers-file`, `cache-size`, `port`, `domain`, `domain-suffix`, `strict-order`, `server`, `rev-server`, `no-resolv`, `query-port`, `dns-forward-max`, `all-servers`, `edns-packet-max`, `fast-dns-retry`, `max-tcp-connections`, `port-limit`, `use-stale-cache`, `max-ttl`, `min-cache-ttl`, `max-cache-ttl`, `neg-ttl`, `min-port`, `max-port`, `no-negcache`, `no-round-robin`, `no-0x20-encode`, `do-0x20-encode`, `cache-rr` | UDP upstream dispatcher、域路由、reply envelope、基础 cache、CNAME/负缓存窄路径已有单测和局部 loopback；`DNS_FORWARD_SERVICE_PHASE.md`、`DNS_UPSTREAM_PHASE.md`、`DNS_CACHE_REPLY_PHASE.md` 为证据。servers-file/动态 resolv、完整 cacheability、ANY/generic、CNAME 查询、查询合并/TCP upstream fallback、缓存 EDNS/DNSSEC metadata、stale 全合同、端口/接口选择仍关闭。 | DNS runtime owner：按 `forward.c/process_reply/extract_addresses/answer_request` 接完配置、TCP、EDNS、缓存和失败边界 |
| DNS 本地记录、hosts 与 RR | 22 | `mx-host`, `mx-target`, `local-service`, `local`, `localmx`, `address`, `expand-hosts`, `local-ttl`, `addn-hosts`, `hostsdir`, `read-ethers`, `alias`, `srv-host`, `txt-record`, `caa-record`, `dns-rr`, `ptr-record`, `naptr-record`, `cname`, `host-record`, `synth-domain`, `interface-name` | `dns/local.rs`, `hosts.rs`, `config/records.rs` 已覆盖本地 A/AAAA/TXT/部分 RR/CNAME 线；`local-c-audit-20260930` 有 108 个本地回答、9 个非 IN class、10 组路由案例的 C/Rust 记录。完整 MX 默认主机名、hostsdir/inotify、动态名字、synth/interface 派生和所有 raw RR 的 daemon 消费未完成。 | DNS local owner：完成文件监测、所有 RR 类型、名字同步、接口域和 caller 选择 |
| DNS 策略、安全与身份 | 14 | `bogus-priv`, `bogus-nxdomain`, `ignore-address`, `selfmx`, `filterwin2k`, `filter-A`, `filter-AAAA`, `filter-rr`, `domain-needed`, `stop-dns-rebind`, `rebind-domain-ok`, `rebind-localhost-ok`, `proxy-dnssec`, `no-ident` | `process.rs` 已有 ignore/bogus/rebind address policy，C/Rust address 差分 68 cases；基础 flags/EDNS envelope 有差分。rrfilter、doctor/UBus rewrite、proxy DNSSEC 全路径、CHAOS/NO_ID 语义、配置与 upstream 组合仍未交付。 | DNS policy owner：接 process_reply 完整调用链，补 filter/doctor/identity 和配置联动 |
| DHCPv4 租约、选项与状态 | 43 | `dhcp-leasefile`, `dhcp-lease`, `dhcp-host`, `dhcp-range`, `dhcp-option`, `dhcp-boot`, `dhcp-lease-max`, `dhcp-vendorclass`, `dhcp-userclass`, `dhcp-ignore`, `dhcp-authoritative`, `bootp-dynamic`, `dhcp-mac`, `no-ping`, `dhcp-script`, `leasefile-ro`, `script-on-renewal`, `dhcp-ignore-names`, `dhcp-option-force`, `dhcp-circuitid`, `dhcp-remoteid`, `dhcp-subscrid`, `dhcp-no-override`, `dhcp-match`, `dhcp-name-match`, `dhcp-broadcast`, `dhcp-alternate-port`, `dhcp-scriptuser`, `dhcp-fqdn`, `dhcp-sequential-ip`, `dhcp-client-update`, `dhcp-generate-names`, `dhcp-ttl`, `dhcp-reply-delay`, `dhcp-rapid-commit`, `dhcp-ignore-clid`, `dynamic-host`, `dhcp-hostsfile`, `dhcp-optsfile`, `dhcp-hostsdir`, `dhcp-optsdir`, `tag-if`, `leasequery` | `dhcp/packet`, `allocation`, `request`, `state`, `lease`, `lease_file`, `reply` 已有原语；C differential 覆盖 18,015 项、state 51 项、reply wire 1,008 项，BOOTP vend 429 定义 cases。`dhcp/runtime` 已有 StateProvider、prune/commit-before-send 适配器。完整 `dhcp_reply` caller 的 context/tag/config/FQDN/options、leasefile真实恢复/fsync、脚本/hotplug、DNS 同步、leasequery wire/ACL、PXE/relay 不在通过范围。当前 `main.rs` 没有把 DHCP listener 接入 daemon 生命周期。 | DHCP owner：接 config→context→state→reply→send→lease/script/DNS，先完成真实 listener 生命周期 |
| DHCP 网络、PXE 与 relay | 16 | `interface`, `listen-address`, `except-interface`, `no-dhcp-interface`, `no-dhcpv4-interface`, `bind-interfaces`, `bind-dynamic`, `bridge-interface`, `shared-network`, `dhcp-option-pxe`, `dhcp-pxe-vendor`, `pxe-prompt`, `pxe-service`, `dhcp-proxy`, `dhcp-relay`, `dhcp-split-relay` | `dhcp/service` 有 AF_INET/pktinfo admission、Dispatch 分类、局部 Linux loopback listener 证据；`DHCP_SERVICE_PHASE.md` 明确 relay/PXE/ARP/动态接口/生产端口未接线。近期 listener/runtime 提交是隔离 adapter 草稿，不是 C/Rust 真实服务差分。 | DHCP/Linux owner：接口发现、67/4011 socket、pktinfo/bridge、ARP、relay/PXE 和关闭/重载 |
| TFTP | 11 | `enable-tftp`, `tftp-secure`, `tftp-no-fail`, `tftp-unique-root`, `tftp-root`, `tftp-max`, `tftp-mtu`, `tftp-lowercase`, `tftp-single-port`, `tftp-no-blocksize`, `tftp-port-range` | `tftp_service`, `tftp_runtime`, `tftp_listener`、TFTP 配置和主程序 Linux listener 已接线；path/admission oracle 255,528+20,000、netascii oracle 97,384、局部 benchmark 有证据。listener/config 仍缺完整 C/Rust UDP/PXE/helper 对照；script queue、open/share race、retry/timeout/cleanup、port/interface/pktinfo、single-port 全服务和 package startup 未验收。 | TFTP owner：完成全 socket/文件/helper/PXE 对照及真实 Linux isolated service gate |
| OpenWrt 集成与高级能力 | 11 | `enable-ubus`, `localise-queries`, `add-mac`, `strip-mac`, `add-subnet`, `strip-subnet`, `add-cpe-id`, `clear-on-reload`, `dns-loop-detect`, `script-arp`, `umbrella` | OpenWrt init/procd/ujail/ubus/odhcpd/dhcp-script 调用方已读并记录于 `OPENWRT_CONTRACT.md`；代码尚无完整 ubus metrics/doctor/events、reload、helper/hotplug、subnet/cpe/ARP/dump 生命周期。 | Integration owner：按调用方合同完成 procd/ujail/ubus/reload/odhcpd/helper/metrics |

169 项逐项已落入上述八组，组计数为 23+29+22+14+43+16+11+11=169。未编译的 26 项仍需保持 C 的拒绝/启动行为，但不计入本表能力分母。

## 按交付层级的状态

| 层级 | 已有事实 | 未关闭缺口 | owner/出口条件 |
|---|---|---|---|
| Metadata | 195 入口、169 可用/26 excluded 已由精确 `option.c` 清单生成；变体 COPTS、参数、重复策略和源码位置均在 `options.json` | 元数据不是 runtime；每项的完整副作用/调用方合同尚未闭环 | 配置 owner：逐项把 `options.json` 连接到实际 consumer 并保留 unavailable 行为 |
| Parser/config | `EncodedArg`、scalar/dns/records/tftp loader，CLI/include/重复/inode/引号边界有单测和 59/59 接受拒绝、19/19 state probes、157/157 累计记录 | 大量 169 选项仍 metadata-only；跨选项 finalization、platform resolver/interface/gethostname、DHCP/TFTP 文件和 config-dir 动态输入未闭环 | 配置 owner：完整 parser→typed state→finalize 差分，不把 `apply` 成功当引擎完成 |
| DNS parser/primitive | wire/name/RR canonicalization、hosts、local records、routing、reply envelope、address policy、cache primitive 有单元/C oracle | parser primitive 未覆盖完整 daemon 语义；unknown RR、EDNS/DNSSEC/cache metadata、TCP fallback、UBus doctor、reload 未闭环 | DNS owner：完整 `receive_query→answer_request→process_reply→cache` 状态机 |
| DNS daemon/runtime | 主程序可在受限 loopback/非特权配置启动 UDP DNS、local TCP framing、非阻塞 upstream UDP；缓存窄路径已含正/负/CNAME/SOA 子集 | 主程序拒绝大多数真实 OpenWrt 配置；TCP forwarding fallback、resolv polling、SIGHUP、multi-interface/source-port、ubus/metrics、完整 cacheability 未接线；当前 daemon 有未提交改动 | DNS runtime owner：提交前清理草稿并做真实 Linux isolated lifecycle |
| DHCP state/wire | packet/state/lease/reply/runtime adapter 有 C 原语差分，运行时保留 commit-before-send/prune/lost names | `main.rs` 未启动 DHCP listener；完整 options/context/tag/FQDN/PXE/relay/leasequery/script/DNS/leasefile 生命周期未接线；近期 Linux listener 仅隔离 loopback Rust 测试 | DHCP owner：完整服务接线后再做 C/Rust service diff |
| TFTP parser/runtime | path/admission/real file opener/transfer/netascii/listener API 存在；局部 oracle/benchmark 通过 | 最近 listener/config 变更未有完整 Linux C 对照；helper script/PXE/port/interface/cleanup/package gate 未完成 | TFTP owner：isolated UDP/PXE/helper service differential |
| Linux execution | 存在 DHCP loopback listener test、signal smoke、TFTP listener 代码；测试均为本地隔离或库边界 | 无 67/69/4011 生产权限/接口/桥接/ARP/relay/文件 race/长运行证据；无 C/Rust 同负载服务级差分；未验证 OpenWrt jail/procd | Linux execution owner：隔离 namespace + exact C + Rust + lifecycle/recovery |
| C differential | DNS wire/reply/process/cache/local、DHCP packet/state/reply、TFTP path/netascii、配置输入均有不同粒度 oracle | 缺完整 daemon service oracle、DHCP/TFTP listener/PXE/helper、完整 169 semantics；ignored tests 仍未算通过 | Differential owner：先校准成功/失败计数，再覆盖 caller side effects |
| Performance/resources | 仅 TFTP netascii 局部 host benchmark 有相对结果；协议和主目标场景已冻结 | 无 DNS/DHCP end-to-end throughput/CPU/p95/RSS/PSS/FD/long-run；不能把局部 netascii 结果推广为组件收益 | Performance owner：功能 gate 后按 `PERFORMANCE_PROTOCOL.md` 交错 C/Rust |
| Package/release | 早期 SDK 构建出 inert APK，目标工具链/manifest/hash 可追溯 | 尚未用当前完整源码构建可替换 dnsmasq 包；未做 package install/upgrade/rollback/ABI/ownership/size gate | Release owner：匹配 SDK clean build、manifest/APK、ownership、rollback |
| Physical router | 未访问或修改设备 | 无部署、Wi-Fi 管理回归、自动 rollback/client health/recovery gate | 仅获单独授权并满足 AGENTS 恢复门后执行 |

## 证据索引与“不能据此宣称”的规则

| 证据 | 覆盖 | 不覆盖 |
|---|---|---|
| `docs/dnsmasq/OPENWRT_CONTRACT.md`, `options.json`, `contract_inventory.py` | 精确 169 入口、参数和调用方线索 | 运行时等价 |
| `DNS_SOURCE_MAP.md`, `DNS_CACHE_REPLY_PHASE.md`, `DNS_SERVICE_PHASE.md` | DNS 原语、窄 daemon 边界和明确缺口 | 完整 DNS、完整配置、生产服务 |
| `DHCP_SOURCE_MAP.md`, `DHCP_REPLY_PHASE.md`, `DHCP_RUNTIME_PHASE.md`, `DHCP_SERVICE_PHASE.md` | DHCP 状态/wire/runtime/service adapter 边界 | 完整 listener、relay/PXE/leasefile/script/DNS |
| `TFTP_SOURCE_MAP.md`, `TFTP_RUNTIME_PHASE.md`, `TFTP_SERVICE_PHASE.md` | TFTP path/admission/transfer/netascii | 完整 UDP/PXE/helper/长运行服务 |
| `private/dnsmasq-rewrite/local-c-audit-20260930/` | 局部 C/Rust local DNS | 上游/cache/真实 daemon |
| `private/dnsmasq-rs/cache/differential-soa-redesign/summary.json`、`private/dnsmasq-rewrite/dns-reply/run-1200b`、`dns-process`、`dns_cache_diff.py` 输出 | Cache primitives 21 scenarios/22,571 commands 0 mismatch；DNS wire/process/cache 原语或窄状态 | 完整 `extract_addresses→answer_request` service differential 与 OpenWrt callers |
| `private/dnsmasq-rewrite/dhcp-differential/run-04`, `dhcp-state/state-run-04`, `dhcp-reply-diff` | DHCP 原语/state/reply | Rust DHCP listener 与 full config |
| `private/dnsmasq-rewrite/dhcp-listener-linux-20260930/final.log`、`final-local-identity.txt`、`final-remote-identity.txt` | 一个隔离 Linux loopback listener/runtime smoke | 真实 67/4011、C/Rust service differential、生产权限/接口 |
| `private/dnsmasq-rewrite/tftp-oracle-07`, `tftp-service-diff`, `tftp-bench-03` | TFTP helper primitive/path/netascii/local benchmark | 完整 listener/PXE/helper/target performance |
| `private/dnsmasq-rewrite/package-20260930/manifest.json` | SDK artifact identity and inert install path | Replaceable package/upgrade/rollback |
| `private/dnsmasq-rewrite/signal-*`、`dns-signal-smoke-review` | Signal exit smoke | Reload, procd, all worker/resource paths |

The following claims are intentionally disallowed until their corresponding
rows close: “169 options implemented”, “dnsmasq-compatible”, “C/Rust service
equivalent”, “DHCP/TFTP production-ready”, “performance improved”, “package can
replace stock dnsmasq”, and “router accepted”.

## Ordered next work

1. **Freeze the source snapshot.** Finish or revert uncommitted daemon/service drafts, run `cargo fmt --check`, full crate tests, clippy, musl check, and record the exact HEAD and artifacts.
2. **Close daemon contracts.** Complete DNS full cacheability/EDNS/TCP/reload/UBus, then add complete daemon C/Rust service differential; do not widen the claimed subset while SOA/negative/CNAME corner cases remain.
3. **Wire DHCP end to end.** Add config/context/tag/FQDN and actual listener ownership in `main.rs`; integrate reply options, leasefile, script/hotplug, DNS updates, relay/PXE/leasequery; run isolated C/Rust listener cases.
4. **Finish TFTP service.** Integrate port/interface/pktinfo, transfer sockets, helper queue/scripts, PXE callers, retries/timeouts and long-run cleanup; compare exact C and Rust service behavior.
5. **Complete OpenWrt lifecycle.** Replay UCI/init/procd/ujail/ubus/odhcpd/hotplug contracts, then build an actually replaceable package with ownership and rollback checks.
6. **Measure only after correctness.** Freeze current source/ELF identities, run the DNS/DHCP/TFTP fixed workloads, report p50/p95/resource peaks and failures separately; no physical-device claim before explicit deployment authorization and recovery gates.

This file is a planning and evidence ledger, not a completion declaration.
