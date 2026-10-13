# DHCP / inactive config / TFTP / diagnostic sub-audit

本分工范围未发现本分支新增的合并阻塞。结论来自新建边界用例和重新运行实际 C / main / final SDK ELF，不只是复读旧报告。全部请求均为隔离 net/mount/pid namespace 中的合成 loopback 流量，没有操作物理路由器、修改产品代码或推送。

## 身份与结果

- exact image C：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
- main release：`ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`。
- final SDK payload：`55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca`。`build` 分工另行核对当前 HEAD、冻结 source-final 的 178 项构建输入与该 SDK 产物一致。
- `boundaries.json`：39 个独立配置语法边界，final=C **39/39**，main=C **10/39**；27 个 DHCP 场景，final=C **27/27**，main=C **14/27**。其中 9 个保留原始最小重现作为控制，18 个新增边界。
- `repairs.json`：重新运行 helper 10 场景、TFTP 96 组合、配置 dump 5 场景、C/main/fix 的 SIGUSR1/SIGALRM 6 场景、C/fix 完整指标摘要 2 场景与强制 lease 持久化恢复 2 场景。
- `check_evidence.py` 独立重算退出状态、观察字典、TFTP 结果和 dump 字段多重集；`check.json` 为其输出。没有任何性能主张。

## 最新 retained-SOA 修复的 fresh SDK 验证

性能独占窗口结束后，又在最终 SDK 上重新运行 `dhcp_negative_cache_diff.py`、`dhcp_negative_soa_boundaries.py`、`dhcp_negative_cursor_diff.py`。`negative_final.py` 仅复用它们的流量生成，另写独立 DNS wire decoder 验证 header 全字段与计数、完整帧边界、名称指针、owner/type/class/TTL、SOA 两个名称及五个整数、其他 RDATA/OPT、请求对应关系、上游行为和 DHCP header/options/timers。它不会仅信任旧 probe 的 `passed`。

| 套件 | 场景数 | 响应对 | 完整解码精确相同 | 受界限 SOA 时钟差 |
| --- | ---: | ---: | ---: | ---: |
| NXDOMAIN 缓存后真实 DHCP 发布 | 24 | 504 | 504 | 0 |
| direct / cached-CNAME、RD/DO、UDP/TCP、大 SOA 截断、normal/debug | 64 | 256 | 255 | 1 |
| raw CNAME/ANY、原名/目标 NX、配置别名提前终止、reverse synth/显式 PTR | 12 | 80 | 80 | 0 |
| 合计 | 100 | 840 | 839 | 1 |

唯一时钟差在 `large0-debug1-alias-tcp-rd0-do1` 的 `ack-visible-a`，authority SOA TTL 为 C=3599、Rust=3600；各自从该实例第一次查询起的 elapsed 是 0.003471 / 0.003687 秒，按墙钟相邻秒边界，下限均为 3599。这不是放宽 DHCP TTL、flags、数据或记录次序的白名单。其余所有字段及上游事务均严格相同。详见 1201 行派生收据 `negative-final.json`，200 个完整侧结果的 SHA256 逐项保留，原始 wire 保留于 Oracle `private/dhcp-config/negative-final-01`。

`negative_checker_calibration.py` 对比较器注入 flags 错误、过大 SOA age、帧尾多余字节，均能拒绝；相同报文和有边界的一秒 SOA 差可以通过。校准收据见 `negative-checker-calibration.json`。

这证明最新 footer/cursor 修复在这 100 个场景有效，没有以 main 的旧错误作为正确答案。这里没有运行 stale NXDOMAIN→DHCP 的时间推进扩展，不据此宣称 stale EDE / 后台刷新已与 C 完全一致。

## 修复确实生效的证据

| 修复 | 新观察与代码依据 | 归属 / 实际影响 |
| --- | --- | --- |
| rapid commit 在最终地址/上下文确定后处理姓名 | `runtime.rs:435-465` 先选择 DISCOVER 地址，再调用 `daemon.rs:2183-2209` 的 ACK 名称规则。新增 requested IP 在池外/异网段、`tag-if`、ignore/generate、hosts 域不符、空名称/首点/多点的组合全部 final=C；main 在 13/27 场景不同。对应 C `rfc2131.c:1363-1372,1599,1676-1720`。 | main 已有错误，本分支修复。影响 ACK option 12、租约名及由租约发布的 A/PTR；不是仅日志差异。 |
| multi-MAC 静态地址切换复用租约 | `state.rs:375-406` 依据最终 `existing_id` 判断是否分配。三方 `multi-mac-static-handoff` 中 C/final 正常 ACK，main 原本的复用错误仍可复现。 | main 已有，修复。影响已配置的两 MAC 共用固定地址切换。 |
| helper 的一次性 metadata 生命周期 | `daemon.rs:2542-2549` 仅真实分配或带 option 50 的 REQUEST 刷新，不把 rapid commit 的 option 50 当 REQUEST。重新运行 10 场景，C/final 的 callback 数、add/old、完整 argv/环境（排除绝对过期时间，验证 renewal T1/T2 范围后归一化）一致，包括 handoff rapid/renew/selecting、同 MAC rapid/renew 与 `script-on-renewal`。C 依据 `rfc2131.c:1401,1556`。 | 本分支此前修复引出的 F03 已修复；当前无未修复新增项。 |
| NO_AUTH / NO_DHCP6 下仍有效的选项 | 39 个新配置边界覆盖 `auth-server` 空字段、多个接口、/4 /6 非法后缀、引号；auth TTL 溢出/空值；auth-peer 地址、空 token；no-dhcpv6-interface 空值/通配符。全部 final=C。`config/auth.rs` 与 C `option.c:2451-2487,2996,3522` 一致；TFTP 96 组合覆盖 bind modes、auth family、v4/v6/dual 禁用及 dedicated enable-tftp override，C/final 一致。 | main 缺失接受/运行语义，本分支修复；未发现额外语义退化。 |
| SIGUSR1 / SIGALRM | main 分别以 -10/-14 退出且 DNS 失联；C/final 保持运行并继续回答。final 输出与 C 相同的指标摘要；lease 文件写失败后创建父目录并 SIGALRM，C/final 均立即重试持久化、保留 DHCP lease dump、继续 DNS 服务。路径 `main.rs:4259-4288` → `daemon.rs:1556-1577`。 | main 已有服务退出问题，本分支修复。 |
| 配置记录 dump 来源/标志 | 5 场景包括孤立/已解析/链式 CNAME、双栈 host-record 与 IPv4-compatible IPv6，声明记录的显示字段与数量多重集相同。 | 修复已通过限定内容检查。表迭代次序与 C 的内部空槽行不同，仍明确保留在证据中；它们不代表不同的可回答记录/来源。不能把这一检查写成“完整 dump 字节一致”。 |

## 复现

主驱动与新增边界脚本就在本目录。Oracle 上：

```sh
SOURCE=/home/ubuntu/dnsmasq-fix4-repair-20261013/source-final
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
MAIN=/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs
FIX=/home/ubuntu/dnsmasq-fix4-repair-20261013/private/sdk-acquire-final/payload/usr/sbin/dnsmasq
WORK=/home/ubuntu/dnsmasq-audit-fix4-20261014/private/dhcp-config
sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" python3 "$WORK/boundaries.py" \
  --source "$SOURCE" --image "$IMAGE" --main "$MAIN" --fix "$FIX" --out "$WORK/boundaries-NEW"
sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" python3 "$WORK/repair_checks.py" \
  --source "$SOURCE" --image "$IMAGE" --main "$MAIN" --fix "$FIX" --out "$WORK/repairs-NEW"
sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" python3 "$WORK/negative_final.py" \
  --source "$SOURCE" --image "$IMAGE" --fix "$FIX" --out "$WORK/negative-final-NEW"
```

原始合成 config / wire / daemon logs 留在 Oracle `private/dhcp-config/boundaries-01` 与 `repairs-01`。Git 中仅脚本与派生结果。`boundaries.py` 比较 DHCP 解析后 option、lease 字段、DNS owner/type/address；没有把 transaction id、绝对租期时钟或者 C/Rust 内部内存布局当作语义差异。

## 未覆盖

本分工没有新跑 relay-agent option 82/外部 relay、多网卡真实广播、DHCPv6（精确镜像无该特性）、完整 BOOTP/PXE/TFTP 传输故障矩阵、数小时租期耗尽/恢复、helper 被杀/慢脚本背压、时钟跳变，以及信号洪泛。TFTP 此处是接口准入组合，不能替代完整传输协议验证。dump 内容检查不要求 C 的哈希表占位和迭代次序相同；绝对时间仍可能导致跨进程字节差异。性能与打包/保护由其他审计分工提供，不从本结果外推。
