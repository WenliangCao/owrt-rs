# M2 场景回归报告

M2 的最终 DHCP 对照使用同一 exact OpenWrt rootfs，C ELF SHA-256 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`，Rust release ELF SHA-256 为 `8cd25e3236b740ccb91a8d97d7c6980fd33758201e6eb9cdc5e2030a52fc85f1`。Rust 的 `--version` 已逐字输出镜像 C 的 feature 行：

`Compile time options: IPv6 GNU-getopt no-DBus UBus no-i18n no-IDN DHCP no-DHCPv6 no-Lua TFTP no-conntrack no-ipset no-nftset no-auth no-DNSSEC no-ID loop-detect inotify dumpfile`

OpenWrt init 能力检测随后生成了与 C 相同的 `dhcp-range=set:lan,192.168.1.100,192.168.1.119,255.255.255.0,2m`。最终 DHCP 对照的四组为 actual20、static-ethers、expiry120 和 ping-conflict；每组 C/Rust 结果零差异，比较结果保存在 ignored `private/dnsmasq-rewrite/evidence/M2/dhcp/m2-final-current-1790953392/`。失败路径曾留下 C/Rust 资源和 PID 清理差异，修复后的 runner 增加 SIGTERM 超时、SIGKILL 和 stale PID 文件清理，回归单测通过。

生命周期与 odhcpd 收尾证据在 `private/dnsmasq-rewrite/evidence/M2/integration/c-lifecycle-m2-version-1790948584/` 和 `rust-lifecycle-m2-version-1790948548/`。两边均完成 init start、SIGHUP hosts、init reload、rpcd UCI staged/apply、stop、真实 DHCPv6 Solicit→Advertise→Request→Reply、`odhcpd.hosts.lan` 写入和 AAAA 查询；固定客户端地址为 `fd00:2::7ed`，原始四个 DHCPv6 报文和租约文件均保留。

DNS exact-image 既有 UDP/cache、expiry、TCP/cache、故障恢复、strict-order 和代表性混合流证据位于 `private/dnsmasq-rewrite/evidence/M2/dns/`。2026-10-03 的 M4 复核发现，旧 all-servers 夹具实际同时启用了 strict-order，因此撤销旧 all-servers 覆盖声明；工具修正后在 M4 最终 ELF 上完成真正 all-servers 的镜像 C 对照，见 [M4_REPORT.md](M4_REPORT.md)。旧结果和 runner 红色记录全部保留，不把配置错误的场景算作已覆盖。

DNS、DHCP 和配置解析器的定向语料保持零差异。新增 cargo-fuzz 目标为 DNS wire、DHCP packet 和 config line；每个目标已在 nightly libFuzzer 上运行至少 30 分钟，未产生崩溃或 panic，运行日志和 corpus 在 `private/dnsmasq-rewrite/evidence/M2/fuzz-final-1790955830/`。

M2 未覆盖完整 DHCP relay/PXE/自定义 option 合同、M3 长时资源趋势、M4 可替换 APK、性能协议和物理路由器。M3 正式窗口必须使用上面已验证的 Rust SHA，且不得把历史 debug、旧 release 或压力 setup 失败当作新通过。
