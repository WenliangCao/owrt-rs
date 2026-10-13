# DNS 独立审计证据（2026-10-13，交付编号 20261012）

审计对象：`main be531cee49e366bb5044443d473944dbea45b87e`，修复分支 `e3a37f55b2939ee2a0c229b0ac96a2a9c407b8aa`。实际运行本轮重新编译的 release ELF；C 为 exact image 的 `/usr/sbin/dnsmasq`。所有服务均在 oracle 独立 network/mount/PID namespace + exact-image chroot 内启动。未修改产品代码，未接触路由器。

## D1 — P2，本分支新增：filterwin2k 的 TCP 查询出现新的 NXDOMAIN

**确认，不是疑似；按用户的“不新增功能回归”标准阻止合并。**

配置 `filterwin2k`，先查询 `alias.example A`，由可控上游返回 `alias.example CNAME target.example`、NXDOMAIN 和 `example SOA`（合法的 CNAME 负目标响应，TTL=300）。在缓存仍有效时，经 TCP 查询 `alias.example SOA` 或 `SRV`，设置 RD=1、EDNS DO=1：

| 行为 | exact C 2.93 | main | fix |
|---|---:|---:|---:|
| RCODE | NOERROR (0) | NOERROR (0) | **NXDOMAIN (3)** |
| AA | 1 | 1 | 0 |
| Answer / Authority / Additional | 1 / 1 / 0 | 0 / 0 / 1（OPT） | 1 / 1 / 0 |
| 本次请求上游次数 | 1 | 0 | 1 |

**main 原先的完整行为也不等于 C**：main 提前用 filterwin2k 返回空 NOERROR；C 会转发，再通过缓存中已存在的 alias 将 NXDOMAIN 改成 NOERROR。fix 修正了前半段执行顺序，却没有覆盖后半段 TCP 缓存存在性检查，导致客户端新收到 NXDOMAIN。这里的新增退化是实际 RCODE 从 NOERROR 到 NXDOMAIN，不是单纯压缩方式或附加记录差异。影响限于上述配置和缓存状态，不能外推为普通 CNAME 解析普遍失败。

机制与定位：

- 本分支 `components/dnsmasq/src/dns/local.rs:277-287` 新增 `has_cname` 提前返回；执行不到 `:308-325` 的 filterwin2k 本地抑制。
- DO 或 RD=0 使动态 CNAME 不能直接由缓存回答，进入 TCP 转发。
- `components/dnsmasq/src/dns/tcp_service.rs:621-635` 对上游 NXDOMAIN 的 known-local 修正只看配置/hosts/leases/routing，未查看动态缓存。这一底层缺陷在 main 已存在；本分支使原先返回 NOERROR 的 filterwin2k 路径新进入该缺陷。
- 相比之下 UDP `components/dnsmasq/src/dns/daemon.rs:1388-1402` 包含 `cache.contains_forward_name`。相同 UDP 对照 fix 与 C 相符。
- matching C `src/rfc1035.c:1754-1806` 在 filterwin2k 前遍历 CNAME，`src/forward.c:795-804` 在 TCP/UDP 共用回复处理将已知名字的 NXDOMAIN 改为 NOERROR。

定向证据：[filter-cname-summary.json](filter-cname-summary.json)。共 **72 个配置/连接/模式/重复组合，216 次产品进程**：普通 `-k` 与 debug `-d`、UDP 预热后新 TCP 连接与同 TCP 持久连接内预热、SOA/SRV、每组 3 次。所有 **24 个相关 warm + filter 组合**均 C/main=0、fix=3，进程存活。无缓存的 filter 对照全部 C/main/fix=0，且不转发。移除 filter 的 warm 对照全部 C=0、main/fix=3（24 个），明确分离旧根因与本分支新增可见回归。广矩阵还复现 RD=0 变体；定向三次重复集中使用 DO=1。

原始结果保留于 oracle `/home/ubuntu/dnsmasq-audit-fix3-20261013/private/dns-filter-cname/result.json`，SHA-256 `2b5a7a7052d92708b8ffe21e4b6b07b596c061b43d65739df9c0eb98869f1fb6`。派生 JSON 保留全部 72 行结果和 12 组完整三方 query/reply/upstream 原始报文代表证据，包括预热请求和响应。

复现（输出目录必须不存在）：

```sh
sudo -n sh /home/ubuntu/dnsmasq-audit-fix3-20261013/source-fix/tools/dnsmasq/run_isolated.sh \
  python3 /home/ubuntu/dnsmasq-audit-fix3-20261013/filter_cname_tcp.py \
  --tools /home/ubuntu/dnsmasq-audit-fix3-20261013/source-fix/tools/dnsmasq \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --main /home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs \
  --fix /home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-fix/dnsmasq-rs \
  --out /home/ubuntu/dnsmasq-audit-fix3-20261013/private/dns-filter-cname-recheck
```

驱动源为 [filter_cname_tcp.py](filter_cname_tcp.py)，无需产品源码改动。

## D2 — P2，main 已有：TCP 回复修正缺少动态缓存名字存在性

去掉 D1 的 `filterwin2k`，其余 warm CNAME 负终点 + TCP SOA/SRV DO 请求不变，C 返回 NOERROR、main/fix 均返回 NXDOMAIN。根因即 `tcp_service.rs:621-635`。这是已有兼容性问题，**不单独阻止合并**；与 D1 共用根因，避免重复计算影响。证据、复现及 24 个三次重复对照见 D1。

## D3 — P2，main 已有：TCP CNAME 缓存未命中后不沿终点选择本地域规则

使用 `local=/target.example/`，上游对预热 `alias.example A` 返回 CNAME→target.example + A。再次以 TCP 查询 `alias.example TXT`（RD=1，无 DO）：C 返回空 NOERROR，**不访问上游**；main/fix 均访问上游一次。SOA/PTR/MX/AAAA/SRV/ANY/CAA 同样出现。`address=/target.example/192.0.2.4` 下 ANY 的 C 返回该配置地址，main/fix 则继续转发。问题涉及本地域保护和配置响应的一致性，当前合并不新增。

matching C 的 `answer_request` 会更新 `daemon->namebuff` 为 CNAME 终点，TCP 之后的规则查找使用该终点。Rust `components/dnsmasq/src/dns/tcp_service.rs:436-439` 从原始 query 重解析 alias 并选择路由，未接受 cache lookup 的终点；`cache_engine.rs:1731-1732` 丢弃局部 resolver 的 `forward_rule` 回答。后者在 main 原有 Local terminal 路径也存在，前者相关源文件本分支未改。

证据：[summary.json](summary.json) 的 `target-local-positive / 16-rd-tcp` 与 UDP 对照，以及 `target-literal-positive / 255-rd-tcp`。完整广矩阵和另一次独立 focused 重跑均观察到；focused 原始输出在 oracle `private/dns-focused-1/result.json`。广矩阵 stub 对后续 TXT 等也返回固定 CNAME+A，因此不要把这些上游回复内容当作 C 的预期；本发现依据是 C 不转发、main/fix 却转发这一网络行为。

## 验证修复与覆盖

独立阅读 DNS/cache/CNAME/hosts 改动和 matching C source 后，建立 [matrix.py](matrix.py)：14 类配置 × 正/负终点 × 每类 62 个 UDP/TCP/RD/DO 查询，另 116 个本地/异常 DNS 包，共 **1852 个三方案例**。每个 CNAME 案例单独 SIGHUP 清缓存，等待 12 ms，再用 UDP A 预热后执行，避免顺序用例污染；保留完整请求/回复，按解码后的 flags、counts、owner、RDATA 比较，忽略 TTL 倒计时和合法压缩差异。

- 目标配置包括 TXT/MX/SRV/raw CAA、hosts、interface-name、local/address 规则、filterwin2k，以及多个长 TXT/MX 触发 UDP 截断。
- **129 个案例的 main/fix 输出改变，其中 121 个变为完全匹配 C**。余下 8 个属于 D1 的两个 filter 配置 × SOA/SRV × DO/RD0 TCP 交互；不能因 main 原先也有其他字段差异而漏报其 RCODE 回归。
- cached CNAME 后端 TXT/MX/SRV/CAA、alias 上本地 TXT 遮挡、NX SOA 保留和 filterwin2k 顺序的相关修复在正常 RD 路径得到三方验证。
- 七个 TCP 非法问题包由 main EOF 改为与 C 一致的拒绝响应：多 question、压缩多 question、zero question、自指针、越界指针、bitstring label、过长名字。进程保持存活。
- 长目标 TXT/MX 超出 UDP 尺寸时 fix 和 C 均 TC 并清空所有 RR section；TCP 完整响应正常。
- `forward-pointer` 畸形输入两例 C 自身生成指针循环回复，main/fix 均重编码为可解析响应，是已有有意/无害差异，不列为 Rust 缺陷。
- 逐行检查 hosts streaming parser 的 token/comment/NUL/EOF/断块语义，对照 C `gettok`，未找到新增解析问题；启动加载时序和资源由其他审计分工测试。
- 新增动态 CNAME 终点 `append_local_terminal` 会构造临时查询并再次运行本地 resolver；普通 A hit 测试不能覆盖此成本。已交性能审计作专门 CNAME→A hit 对照，本文件不把代码成本推断写成实测退步。

未覆盖：全部 DNS 协议组合、真实外网权威服务器、DNSSEC 验证（目标 C 编译特性关闭）、长时高并发与复杂超时重试/随机故障、任意深 CNAME 链、所有 stale 时间边界、IPv6 链路本地 scope、运行中接口/hostsdir/DHCP 更新交叉竞态、SIGUSR1 counters 每个失败分支。这里不声明完整替换 C 的协议等价性。
