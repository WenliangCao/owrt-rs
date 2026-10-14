# DNS 行为独立审计

本分项不能给出无条件上线通过：常规 DNS 矩阵与精确镜像 C 一致，但实际启用的 `local=/lan/` 和 RFC 6761 本地区域存在可复现的 TCP 缓存 CNAME 差异。后续上游失联时，C 可立即给出本地答案，Rust 会让客户端超时。另一个同状态下的直接目标名 A 查询在 C 成功、Rust NXDOMAIN。没有观察到 daemon 崩溃。

审计对象是 main `58365e8c8ebe1805573baa02543baf1c9d45be68`，不是根据旧报告的合并资格推定上线资格。以下结论来自本轮重新运行；后补的 local CNAME 定向检查参考了一个旧问题线索，但使用了原实际配置、当前构建和精确镜像 C 重新复现。

## 身份和方法

| 输入 | SHA-256 |
| --- | --- |
| 精确镜像 `/usr/sbin/dnsmasq` | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 当前 Rust release | `5931b2d114ae5c3e911775e8fd529dcf83ef8718e2c11b50916ce1164dab0966` |
| 原实际生成配置，737 B | `273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe` |

C 直接使用镜像自己的 musl 加载器与库运行，**不是宿主重编的 C**。运行在 oracle AArch64 宿主的独立 network/mount/PID namespace；原配置、include、resolver 列表、端口和 LAN 接口名不变。`actual_config_rootfs.py` 只复制捕获文件；捕获缺少的 `passwd/group/hosts/ethers` 从精确镜像补入该实验的私有挂载。受控上游占据实际四个 resolver 端点，两个 IPv4、两个 IPv6；没有访问 ISP DNS 或物理路由器。

客户端使用真实 UDP/TCP socket；IPv6 LAN 传输使用实验新增的 ULA 地址。客户端并发是独立 socket/连接，仍共享一个合成客户端网络 namespace，不冒称数十台真实终端。比较只忽略耗时，不忽略 ID、flags、问题、记录顺序、TTL 或错误；域名压缩先独立解码为语义。

## DNS-01：已缓存 CNAME 的 TCP 本地终点路由错误，P2，条件性上线阻断

**确定复现，不是疑似。** 外部别名 `local-chain.audit.example` 的上游答案为 `CNAME audit-terminal.lan` 加公网 A。先在一个 TCP 连接查询 A，再在同一连接查询 AAAA/TXT/ANY：

| 查询 | 精确 C | Rust |
| --- | --- | --- |
| 预热 A | 相同的 CNAME + A，TTL 120 | 同 C |
| 后续 AAAA/TXT/ANY | NOERROR，空 Answer；不再请求上游 | 再次访问上游，返回 CNAME + 对应终点记录 |
| 新鲜独立别名的 A 预热后，四个上游全部不回应，再问 AAAA | 立即本地 NOERROR，空 Answer | 发出上游 TCP AAAA；客户端 2 秒超时 |

`.invalid` 终点同样复现，来自实际 include 中的本地区域，不是额外添加了一个冷门选项。断网例使用独立 `audit-outage-terminal.lan`，避免前面 AAAA 结果已经预热终点而产生假阴性。

触发不限于同一长连接：**UDP 只预热 A 后，立即建立新 TCP 连接查询 AAAA**，仍然 C 本地空答案、Rust 上游 CNAME+AAAA。对照中，同样状态下的 UDP AAAA 两者都会转发；没有任何预热的全新别名 TCP AAAA 两者也都转发。不能把这个差异外推为一般 AAAA 或一般 `.lan` 查询都失败。

客户端影响是本应由实际本地区域截住的请求额外发送上游，并可收到不同地址/文本；上游故障时还会失去 C 原有的即时本地响应。本轮实际观测到超时，未把额外转发推测直接当成超时。A/AAAA/TXT 是普通 DNS 类型，但“外部 CNAME 指向本地区域且缓存已预热”是有条件的流量形态；没有真实家庭流量记录，**发生率未知**。

源码依据与包证据相符：匹配 C `forward.c:2582–2603` 在 `answer_request` 后用可能已变为 CNAME 终点的 `daemon->namebuff` 做 `lookup_domain/is_local_answer`；Rust `tcp_service.rs::prepare` 从原问题重新取名字选路。`cache_engine.rs::append_local_terminal` 又明确丢弃 `answer.forward_rule`，不能把两种传输的 C 终点状态混同。

## DNS-02：同轮 TCP 缓存之后直接终点 A 丢失，P2，条件性上线阻断

**行为确定，根因尚未独立隔离。** 在 DNS-01 的健康上游预热/查询序列结束、连接关闭之后：

| 直接查询 `audit-terminal.lan` | 精确 C | Rust |
| --- | --- | --- |
| AAAA，UDP/TCP | NOERROR/NODATA | NXDOMAIN |
| A，UDP/TCP | `8.8.4.4`，TTL 119 | NXDOMAIN |

预热前的直接 AAAA 基线，两者均 NXDOMAIN。预热后的 A 控制排除了“仅仅 AAAA 的 NODATA/NXDOMAIN 表示不同”：C 仍可解析的地址在 Rust 客户端侧确实失败。TTL 还很长，不能归因于记录自然过期。

当前证据不能区分 TCP 子视图向主缓存的回传/导入、缓存替换与本地查询选择，也不能证明它与 DNS-01 有完全独立的根因。它是同一合法流量序列之后的第二个客户端可见失败，不应写成普通 DHCP 主机名普遍失效。

**普通公网终点控制通过**：单独重启，TCP 预热 `cname.public.audit.example CNAME target.audit.example + A`，然后四个上游全部丢包，直接查询 `target.audit.example A`（UDP/TCP）两者仍从缓存得到同一个 A，且没有新增上游请求。这排除了“所有 TCP CNAME 终点均未向父进程缓存发布”的泛化；不能由 DNS-02 推定普通公网 CNAME 日常解析普遍失败。[控制比较](public-cache-control/comparison.json)、[控制观测](public-cache-control/observations.json)。复跑将下方命令中的 `--focused` 换成 `--public-cache-only`，本轮私有目录为 `c-public-01` / `rust-public-01`。

完整定向观测在 [focused/observations.json](focused/observations.json)；严格比较和源结果哈希在 [focused/comparison.json](focused/comparison.json)。最终定向运行是 oracle 私有 `c-focused-05` / `rust-focused-05`，19 个场景、每实现 26 次客户端交换，8 个场景有语义差异；全部差异在上面两个发现的范围内，daemon 和受控上游均正常退出 0。

## 其余已验证行为

最终常规矩阵 `c-06` / `rust-06` 有 **71 个场景、每实现 452 次客户端交换，客户端语义零差异**。结果见 [comparison.json](comparison.json)。两者各记录 420 次上游请求。端点选优和每隔一段请求的多端点探测会受并发顺序影响，单个名字对应的上游索引/探测归属不要求逐条相同；派生结果保留了这些计数差异，没有隐藏。

- IPv4/IPv6 客户端 × UDP/TCP × A/AAAA 的冷、热查询；单独只有 IPv4 或 IPv6 上游能响应。
- CNAME、CNAME→AAAA、TXT、HTTPS、NXDOMAIN、NODATA、NXDOMAIN 跨类型查询、TTL 到期后重新查询。
- 配置 `stop-dns-rebind` 拒绝 IPv4 私网和 IPv6 ULA 答案；`rebind-localhost-ok` 保留 IPv4/IPv6 loopback 答案。
- 1232-byte EDNS、DO/CD/AD 标志处理、大于 512-byte TXT 的有/无 EDNS 情形。无 EDNS 大答案确实触发截断；上游 TC 原样给客户端，随后 TCP 可取得完整答案。
- 已选上游丢包后由客户端重试切换；REFUSED 切换；全体 REFUSED/SERVFAIL/丢包及恢复。SERVFAIL 竞速中 C 自身可能先交付错误而不等待健康服务器，Rust 在受控时序下相同，不能将“所有上游故障仍必须成功”当作 C 基线。
- 64 个独立 A/AAAA 并发、48 个相同问题合并、24 个 TCP 连接；单 TCP 的 12 帧流水及长度/DNS 头分片；12 个不完整慢 TCP 连接同时存在时的 16 个 UDP 健康查询。
- 176 个新名字在全上游丢包时逼近默认 150 个 forwarding 槽位：两者本轮均 149 个客户端超时、27 个 REFUSED（此前仍有一个未答条目）；缓存查询仍成功，新查询暂时 REFUSED；11 秒后新请求和 48 个并发请求恢复。没有把上游已断开造成的共同失败算成产品回归。
- 定向控制另覆盖 TCP 上游连接关闭后的换端点，以及 TCP REFUSED/SERVFAIL。后两者 C 本身直接返回错误，Rust 一致。

首轮没有固定多个上游的回复先后，曾观察 C SERVFAIL、Rust 成功；包记录显示先到的服务器不同。补充可控端点延迟后两者相同，依据 C/R 同一 SERVFAIL 状态机判断，这是响应竞速，不是本轮确定缺陷。首次缺失账户文件导致 C 启动失败属于 fixture 准备错误；修正后重跑，未计作产品失败或通过。旧运行保留，没有覆盖删除。

## 最小复现和运行入口

工具：[predeploy_audit_dns.py](../../../../../../tools/dnsmasq/predeploy_audit_dns.py)。下面在 `ssh oracle` 会话内运行；变量仅引用既有离线输入。输出必须选择新的 `private` 目录。`--focused` 重现上述两项并执行控制；改为 `--saturation` 重跑 71 场景常规矩阵。

```sh
audit_base=/home/ubuntu/dnsmasq-predeploy-behavior-20261014
audit_tools="$audit_base/source/tools/dnsmasq"
audit_capture=/home/ubuntu/dnsmasq-dhcp-network-actual-20261001/private/runtime-source/rootfs
audit_image=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
audit_reference=/home/ubuntu/dnsmasq-rewrite-20260929/c-native-01
audit_topology=/home/ubuntu/dnsmasq-northstar-dns-20261002/private/c-network-07/topology.json
audit_cidr="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["router"])' "$audit_topology")"
audit_run="repro-$(date +%s)"

audit_one() {
  audit_side="$1"
  audit_binary="$2"
  shift 2
  sudo -n sh "$audit_tools/run_isolated.sh" \
    python3 "$audit_tools/actual_config_network.py" \
      --source-root "$audit_capture" --router-cidr "$audit_cidr" \
      --output "$audit_base/private/dns/$audit_run-$audit_side-network" -- \
    python3 "$audit_tools/actual_config_rootfs.py" --source-root "$audit_capture" -- \
    python3 "$audit_tools/predeploy_audit_dns.py" --focused \
      --binary "$audit_binary" --image-root "$audit_image" \
      --reference-build "$audit_reference" \
      --out "$audit_base/private/dns/$audit_run-$audit_side" "$@"
}
audit_one c "$audit_image/usr/sbin/dnsmasq" --image-elf
audit_one rust "$audit_base/private/release/dnsmasq-rs"
```

最小行为步骤为：保持原配置启动；上游为外部别名提供 CNAME→`.lan` 加公网 A；同 TCP A 预热后问 AAAA。要看失败而非额外转发，在 A 回复后让上游不回应 AAAA。完整工具还自动保留单包、原始结果、上游请求、daemon 日志及执行时工具副本和哈希；首次结果不能覆盖再用。

比较器命令：`python3 predeploy_audit_dns.py --mode compare --reference C/result.json --candidate RUST/result.json --out DERIVED`。它保留 DNS TTL，定向发现预期退出 1；主进程正常退出和协议一致是两个不同检查。

## 未覆盖

没有验证物理 AX3000T、OpenWrt 内核/驱动、无线丢包、ISP 真实上游响应、odhcpd RA/DHCPv6、SDK 安装包本身、持续数天的负载、所有畸形/恶意报文、DNSSEC 验证、OOM/系统 FD 耗尽或时间大幅跳变。TCP 上游黑洞的完整内部超时/全部四端点耗尽时长也未资格化。该分项不替代 DHCP 租约和配置重载分项的证据。
