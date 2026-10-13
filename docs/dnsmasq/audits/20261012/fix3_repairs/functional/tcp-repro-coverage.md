# 三份复审的 TCP 复现入口映射

`#N` 是 [最终 49 条收据](validation-types.json) 中 `commands` 的一基序号。
以下逐一核对三份复审及其链接的 DNS/hosts/config 记录；补充执行后，所列
TCP 查询功能复现入口均已覆盖。原 49 条收据不改写，实际范围为 **49 + 1**。

| 复审与项目 | 原脚本入口 | 本轮对应执行 |
| --- | --- | --- |
| FIX：F02 缓存 CNAME / alias TXT 优先级 | `independent/dns_hosts_cname.py` | #2 `F02-cached-cname`，原严格回答与上游断言 |
| FIX：旧 NXDOMAIN 后发布 DHCP A；stale/EDE 控制 | `independent/dns_hosts_stale.py` | #3 fresh 严格匹配；#4 完整 stale 观察，保留 EDE 差异 |
| FIX：A10 / 368 个 DNS 输入；FIX2 对 A10 的复核边界 | `tools/dnsmasq/audit_20261011_dns.py` | #10，366 个 C 等值结果及两个精确历史 forward-pointer 基线 |
| FIX：F07 / 普通 hosts、hostsdir、配置 CNAME、缓存开启的 malformed Additional | `independent/dns_hosts_probe.py` | #48，62 个 UDP/TCP 查询组合及原诊断检查 |
| FIX 修复记录：F07 的 ordinary/debug、启动/HUP、DHCP 权威名控制 | `tools/dnsmasq/audit_fix_20261011_hosts.py` | #49，原 8 组配对场景 |
| FIX 的 54 组 auth/ACL；FIX2 配置复核；FIX3 O3 TCP 拒绝表示 | `independent/config_signals_probe.py` 的 TCP/ACL 部分；`fix2/config/config_normal.py` | #12 `O3-auth-ACL`：65 syntax + 54 service；仅原 8 组 EOF/RST 表示差异，集合与内容未扩大 |
| FIX2：R1 动态 CNAME 的本地终点；原 F02 控制 | `fix2/dns/cname_compat.py` | #5，20 场景，含 TXT/MX/SRV、alias/terminal、ordinary/debug、UDP/TCP |
| FIX2：RD/DO 控制 | `fix2/dns/cname_flags.py` | #6，原 16 场景 |
| FIX2：F07 的 A/AAAA/PTR、文件/目录/hostsdir 与启动/HUP | `fix2/dns/hosts_compat.py` | 原 49 唯一遗漏的独立 TCP 功能入口；现单次补充，见下文 |
| FIX3：N1 与无 filter 的旧 known-name 控制 | `fix3/dns/filter_cname_tcp.py` | #7，72 场景，含 ordinary/debug、cold、UDP warm、同连接 TCP warm |
| FIX3：O2 / CNAME、本地终点、RD/DO、长度与异常输入广矩阵 | `fix3/dns/matrix.py` | #8，原 1,852 查询；另 #9 扩展 56 profile / 1,736 同连接 UDP/TCP 配对 |
| FIX3：N2 权限边界 | `fix3/dhcp/hosts_permissions.py` | #11，保持与 C 一致；该探针查询本身是 UDP，并非遗漏的 TCP 入口 |
| FIX3：N4 100/1,000 条 dns-rr 的 TCP 命中 | `fix3/performance/raw_records_window.py`，由相应冻结计划调用 | [首版 32 窗](../performance/shared-answer-first-summary.json)及[最终类型摘要 32 窗](../performance/types-summary.json)，旧不利结果保留 |

auth/ACL 两个脚本从 `base`、`query` 到全部 syntax/service 循环的正文逐字一致；
比较块 SHA-256 为 `898cb62faa9a5be35d9ccc358f3bdcc48c1ea2ef517a85790e8f645c5ff0aff8`。
第一份脚本随后附加的信号压力部分仅调用 UDP，并未被冒称为本轮重新执行的 TCP 实验。

[补充收据](hosts-compat-supplement.json)记录实际原 argv、输入/结果 SHA、时间和退出状态。
原 `hosts_compat.py` 与同目录 `cname_compat.py` 依赖均未修改。
额外独立断言确认：6/6 配置/模式 `matched`，全部 phase 存活、daemon 正常退出；
启动/HUP 共 **228 个 C/R 答复对（114 UDP、114 TCP）**，按相同问题的传输分组为
**114 组**。各组 C 与 Rust 的 UDP/TCP 解码语义也相等；仅沿用原 fixture 路径归一化，
没有增加 TTL、flags 或 RDATA 归一化。它在全部性能窗口结束后独立执行，未重跑 49 条
或任何性能窗口。[28 份原始/控制文件索引](hosts-compat-supplement-raw-index.json)。

边界仍按原结论保留：9 个 C 自身非截断传输差异采用共同 UDP 语义；长 TXT/MX 的
UDP 截断及 `label-truncated`、`over-udp-limit` 的传输差异按 C 控制检查；F08 stale EDE、
两条 forward-pointer 和八组 ACL 表示差异没有被包装成逐字相等。F04 的启动查询只是
RELRO 健康控制，本轮没有重新执行 maps 实验；DHCP/helper/资源发现不是 TCP 查询
反例。S1 原普通 TCP 短窗属于用户允许不专门处理的性能疑点，未宣称逐项重放或消除。
