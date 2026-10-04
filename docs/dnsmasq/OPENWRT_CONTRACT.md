# dnsmasq-rs：精确 OpenWrt 入口合同

本页记录研究与实现阶段证据，**不是功能等价或生产验收**。任务已选择完整重写 dnsmasq；旧 DNS 研究中的“不立项”建议不再适用。基线是 AX3000T、OpenWrt 25.12.5、Rust9 原生固件，待替换的 dnsmasq 仍为 C 2.93-r1；没有在物理设备上执行新实验。

## 身份与边界

包为 `dnsmasq` 的 `nodhcpv6` 变体。精确配方来自 OpenWrt `f0a60eee2fe051741c643ea6118718aae1ef17fb`；归档 SHA256 为 `0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19`。本轮重新验证配方和 12 个辅助文件，13/13 SHA256 与 `manifests/ax3000t-stock-openwrt-25.12.5/sources.json` 相符。补丁为 `100-remove-old-runtime-kernel-support.patch` 与 `200-ubus_dns.patch`。

编译定义为 `HAVE_UBUS HAVE_POLL_H NO_DHCP6 NO_AUTH NO_IPSET NO_ID`，目标支持 IPv6 DNS。`config.h` 默认开启 DHCPv4、TFTP、脚本、loop-detect、dumpfile；Linux 自动选择 inotify。没有 DHCPv6/RA、DNSSEC 验证、DBus、Lua、conntrack、ipset、nftset、authoritative DNS、IDN、i18n。`proxy-dnssec` 是 AD 代理语义，不能与 DNSSEC 验证一起排除。BOOTP/PXE、DHCPv4 relay/split-relay、leasequery 与 TFTP 都在合同内。

补充精读纠正一个容易误用的注释：`config.h` 对 NO_ID 的“forward such requests upstream”描述不足以代表实际行为。`rfc1035.c:1838-1853` 在 CHAOS 类 `*.bind` / `*.server` 没有配置 TXT 回答时返回 NOTIMP，该分支不受 NO_ID 编译条件包围；NO_ID 只是取消默认 CHAOS TXT 的创建。后续回答引擎以此真实调用链和 C 差分为准。

依据依次是现有已核对研究 `docs/reviews/NETWORK_DNS_20260929.md`、精确清单、实际配方和已应用补丁的 C 源码。实现依据路径前缀为 ignored `private/network-research-20260929/dns/dnsmasq-2.93-openwrt/`；配方前缀为 `private/network-research-20260929/dns/recipe/dnsmasq/`。设备原始配置和产物不进入本页。

## 全配置入口清单与真实覆盖

[options.json](options.json) 由 [contract_inventory.py](../../tools/dnsmasq/contract_inventory.py) 从精确 `src/option.c` 的 `opts`、`usage` 和 `case` 生成。**195 个长选项完整索引；169 项归于变体可用能力，26 项归于未编译能力。** 每项带参数要求、短选项、别名共享 ID、重复策略、源码行、变体 gate、研究/实现/差分状态。计数是入口清单覆盖率，绝不是 169 个选项已实现。

未编译功能也不能简单删掉对应 CLI：C 某些选项解析时拒绝，某些在 `--test` 之后的启动阶段拒绝，另一些接受但无对应引擎。清单分别记录这些行为。IPv6 DHCP range/host/relay 的分支另由 `HAVE_DHCP6` 控制；不能把一个同名选项的 IPv4 解析成功推广为 IPv6 支持。

| 层 | 当前实现 | 当前证据 | 待完成 |
|---|---|---|---|
| 全入口元数据 | 195 项，精确参数要求、重复/别名规则、变体边界 | 生成器 `--check`；元数据单测 | 每项语义与所属引擎逐项验收 |
| 配置词法 | 字节、引号/转义、隐藏逗号、注释、空参数、非 UTF-8、NUL 截断 | 单测；C 接受/拒绝差分 | 定向 fuzz 与完整语义消费者联动 |
| CLI 与 include | 长短选项、长选项缩写、第一 `-C` 延后、额外 `-C` 立即读取、默认文件、stdin、递归/include inode 去重、conf-dir、conf-script | 本机/构建机单测；C 接受/拒绝差分 | 目标 musl getopt 边缘语义；FD/内存压力；深 include 栈 |
| DNS 标量 | cache/port/forward/EDNS/TTL/retry/stale/TCP 限额；解析与运行时最终校验分离 | 单测；已列 corpus 的 C 接受/拒绝差分 | 所有最终状态值差分、服务接线、每项运行时效果 |
| DNS typed 配置 | server/local/address/rev-server、interface/listen、resolv/hosts、host-record、domain 选择器和 DNS flags | 6 个新增单测；57 输入 C 接受/拒绝一致 | 上游名字/scope 解析、接口域、IPv6 显式 domain range 原版疑点、运行时接线 |
| 其他配置语义 | callback 要求所属模块 apply 或报错 | API 不会把 unhandled 当成功 | 完整接口策略、DHCP、TFTP、日志、权限、ubus 全语义 |
| OpenWrt 集成 | 已读调用方并建立下面的合同 | 源码引用 | daemon 生命周期及所有集成场景执行验收 |

普通 DNS/DHCP/TFTP 引擎的实现进度以各模块报告为准；本页不替它们标记通过。

## C 调用链、状态与所有权

`dnsmasq.c:45-118 main()` 安装信号处理、设置 umask 022、初始化随机源，再 `read_opts()`。`read_opts():5952-6090` 分配单一 daemon/config 状态，设置默认值，按 argv 顺序处理选项；第一份非空 `-C` 文件延后到 CLI 全部处理后，之后的 `-C` 则立即读取。文件标量可以覆盖 CLI 一次；同一 canonical ID 的文件标量再次出现报 `illegal repeated keyword`。别名 `dhcp-leasefile`/`dhcp-lease` 共享重复状态。

`one_opt():2016-2053` 对 `ARG_ONE` 跟踪 CLI/file 状态；额外 `-C` 立即读入文件后才出现的 CLI 同一标量，C 会跳过赋值甚至跳过语义校验。Rust `OccurrenceTracker::record` 显式返回是否需要 apply，保留该顺序。所有文件/include 共享一个重复状态，不能按文件清零。

`read_file():5471-5615` 每物理行解析。行内 `#` 仅在行首或空白之后开始注释；`server=127.0.0.1#5300` 的端口不是注释。双引号内的数字、空格、逗号、冒号、句点等先隐藏，逗号拆分后才还原；这会影响 DHCP option 的字符串/数字判别和 TXT 内容。Rust 使用 `EncodedArg`，不提前按 Unicode、空白或逗号拆词。参数缺失与 `option=` 的空参数不同。CLI 参数不执行配置文件的引号处理。

`one_file():5631-5718` 按 device/inode 记录已读文件，避免 symlink/hardlink/recursive include 重读；stdin 只读一次。只有默认配置的 ENOENT 被容忍，显式文件缺失报退出码 3。相对路径依据进程 cwd，不依据当前 include 所在目录。`conf-dir` 过滤点文件、`*~`、`#*#`，应用要求/排除后缀（文件名必须比后缀长），仅取常规文件，按完整路径 `strcmp` 顺序读入。`conf-script` 通过 shell 运行命令，读取 stdout 并等待退出，非零状态是启动失败。Rust loader 持有文件去重与重复选项状态，局部 RAII 持有 reader/child；成功或错误返回后释放文件句柄。

`read_opts():6115-6350` 在输入完成后做跨选项 finalization：源端口、TTL 继承、CNAME loop、resolv/domain 组合、local-service 与显式访问控制互斥等。此时 `--test` 返回成功；`main()` 随后才将 EDNS 最小值夹到 512，并检查未编译功能、端口范围、权限、接口、文件和网络。Rust 的标量 `finalize_runtime()` 与加载 `Action::Test` 分开；其余跨选项检查仍待实现。

## 最小源码 → 不变量 → Rust → 对照

| C 源码 | 行为/不变量 | Rust | 验证 |
|---|---|---|---|
| `option.c:619-660,5471-5597` | 引号内 metachar 隐藏；空白后的 `#` 才开始注释；空值不等于缺参数 | `config::lex_line`, `EncodedArg` | quote/comment/split 单测；scalar C corpus |
| `option.c:210-409,418-616` | opts 参数数与 usage 重复策略分离；别名共享 ID | `config/options.rs`, `lookup`, `validate_directive` | 全195项生成一致性、alias/arity 单测 |
| `option.c:2023-2050` | CLI/file 重复状态与覆盖顺序 | `OccurrenceTracker` | alias 单测；CLI/include C corpus |
| `option.c:2057-2218,5631-5718` | inode 去重、目录过滤排序、stdin 一次、shell 输出失败 | `config::loader` | recursive/hardlink/dir/script 单测；CLI/include C corpus |
| `option.c:5952-6090` | 默认值、短/长参数差异、首 `-C` 延后、帮助/版本立即退出 | `loader::load`, `Action` | CLI 顺序与失败顺序单测；C corpus |
| `option.c:3413-3575` | cache 上限 5M；TTL floor 3600；EDNS 显式 u16 narrowing；retry timeout 毫秒转整秒 | `ScalarConfig::apply` | 边界单测；已列 scalar C corpus |
| `option.c:5335-5350,5453-5462` | stale 0 表示无限；TCP 最少 1 | `StaleCache`, `ScalarConfig` | 单测；scalar C corpus |
| `dnsmasq.c:117-118,251-265` | EDNS 512 floor，min/max port 补值与 port-limit 上限在 --test 之后 | `ScalarConfig::finalize_runtime` | 单测；运行时值 C 对照待完成 |

初始差分为 **59/59 输入接受/拒绝一致**：scalar 36 项（21 接受、15 拒绝），CLI/include 23 项（14 接受、9 拒绝）。两组都断言成功和失败计数非零且达到阈值。期望来自精确补丁 C 的 `--test` 退出状态，不由 Rust 自生成。运行于隔离构建机进程，没有创建 DNS/DHCP listener。第一阶段本机及构建机配置单测 12 通过；两个需要 C 的测试默认 ignore，必须显式设置 `DNSMASQ_C_REFERENCE` 后 `--ignored` 执行，未执行不算通过。这只验证列出的解析输入，尚未比较全部运行时标量值与副作用。

原始记录在 ignored `private/dnsmasq-rewrite/config/`：`differential.log`、`unit.log`、`identity.sha256`、`recipe-integrity.json`、`empty-conf-file.strace` 与对应 stdout/stderr。`strace` 已确认 `--test -C ''` 实际尝试打开默认 `/etc/dnsmasq.conf`；不要把它假设为 `/dev/null`。

复现：

```sh
python3 tools/dnsmasq/contract_inventory.py --check
cargo test --manifest-path components/dnsmasq/Cargo.toml config::
DNSMASQ_C_REFERENCE=/path/to/exact-patched-dnsmasq \
  cargo test --manifest-path components/dnsmasq/Cargo.toml config:: -- --ignored --nocapture
```

## 第二阶段：typed DNS 配置（运行时尚未验收）

`config/dns.rs` 在进一步阅读 `option.c:900-1305,2407-2436,2634-2798,2882-3157,5253-5333`、`domain-match.c:25-383,651-766` 与 `domain.c:218-302` 后实现。`DnsConfig::apply` 返回是否由本模块消费；未实现的选项返回 false，调用方须交给所属模块或拒绝。普通内存中的配置对象不自动代表对应网络行为已经实现。

- `ServerRule` 保留域 suffix、wildcard、dotless，与 Upstream / DefaultResolvers / LocalOnly / Literal / ZeroAddresses 目标；`address=/#/#` 和 `server=/#/#` 是不同目标。不要按 Vec 第一个匹配就决定结果：C 按最长域、wildcard 优先级、请求 RR family、local/default/upstream 优先级过滤。
- `ServerEndpoint` 保存上游 IP 或未解析 hostname、port、IPv6 scope、可选 source IP/interface/port；有 `@source` 时默认源端口 0，无 source 时继承最终 query-port。跨地址族的显式 IP/source 被拒绝。hostname 按 C AI_ADDRCONFIG/SOCK_DGRAM 解析以及 IPv6 scope 的 if_nametoindex 必须在语法成功前完成；当前 `validate_ready` 明确阻止未实现的这些步骤。
- `reverse_patterns` 按 C 的非整 octet/nibble CIDR 展开最小 suffix 组；`domain=...,prefix,local` 同时添加反向和正向 LocalOnly 规则。IPv4 范围及 IPv6 prefix 的 `domain_for_address` 供 hosts 扩展使用；条件域保持 C 的后声明优先。
- `host-record` 保留别名顺序（第一个名字拥有 PTR）、每地址族最终地址、可选 TTL；引号内 IP/数字在 C 中可能被当作 hostname，不能先统一 decode 再做类型推断。可选 TTL 在使用时继承最终 local-ttl。
- `finalize` 保留多 resolv/no-poll 约束，以及 local-service 在显式 interface/except/listen 时关闭的规则；host-only 无显式接口时生成 loopback-only 接口条目并 bind-interfaces。

本阶段新增 6 个配置单测。构建机正式性能窗口期间暂停远程测试；窗口结束后，57 项 DNS 配置接受/拒绝差分全部一致（41 接受、16 拒绝）。

一个原版行为疑点必须单独核验：`option.c` 的 IPv6 显式 start/end domain 分支保留 `prefixlen=0`，`domain.c:255-280` 对小于 64 的前缀仅检查该 prefix，似乎把显式地址范围扩大为 /0。当前模型保留 `DomainSelector::Range6` 输入但运行就绪检查拒绝它，没有静默改为猜测语义；等待原版最小运行复现后记录兼容或缺陷修复决策。接口派生域同样需要平台地址列表，尚未声称支持。

## 第三阶段：本地 RR 配置与真实解析状态

`config/records.rs` 跟踪 `option.c:2335-2373,4971-5251,6139-6248`，覆盖 CNAME、TXT、PTR、MX、SRV、NAPTR、CAA 和通用 `dns-rr` 的 typed 配置，仍须由回答引擎实现运行行为。TXT 保留引号内逗号与每 255 字节拆段；CNAME 保留别名/target/TTL，按大小写不敏感拒绝重复并检测环；C 的 `ptr-record=name` 省略 target 经 `rfc1035.c:1931,1600` 编成 root PTR，不是负响应。MX 平台 gethostname 输入通过显式 `needs_hostname/finalize_mx` 接口完成，不能把未填缺省 target 当成完整配置就绪。

新增 4 个单测与 **41/41** C 接受/拒绝输入一致（25 接受、16 拒绝）。当前配置单测共 **22 通过**，四个需 C 的入口默认 ignore；四组已执行接受/拒绝差分合计 **157/157**。计数不包括没有执行的 fuzz 或服务回答测试。

为避免仅比较 `--test` 成败，`contract_inventory.py --state-differential` 还将薄 C driver 链接到精确 reference 的现有对象（仅重命名 main），直接调用真实 `read_opts`，打印其 daemon 中解析后的标量和 RR 数据。对应 Rust driver 为 `config/state_probe.rs`，仅是测试工具，未链接进 daemon。**19/19** corpus 一致：16 个成功输入逐项比较实际字段、3 个错误输入比较失败；覆盖 EDNS narrowing、TTL floor、retry 整秒、stale infinite、显式 query-port、host-record 的 quoted 类型判别/名字顺序、CNAME TTL 继承、TXT 分段、RR hex 原版通配符字节行为、CAA narrowing、PTR omitted/empty、显式 MX/SRV/NAPTR。允许的 RR 行顺序排序归一化，但 host-record 与其 PTR 名字顺序使用显式 index，未被排序忽略。上游规则/平台 resolver/gethostname 默认值、配置副作用和网络报文仍不在这 19 项状态比较内。

额外接受/拒绝轮的已完成工具控制台 stdout 保存在 `phase2-console.txt`、`phase3-console.txt`（从实际工具返回保存，没有重跑冒充新窗口）。原始 state corpus、逐例 stdout/stderr 和 `result.json` 位于 ignored `private/dnsmasq-rewrite/config/state-01/`、`state-02/`。第一轮 oracle 有 `use_dhcp_ttl` 的 printf 宽度警告；第二轮修为显式 int cast，并加 `-Werror=format`，19/19 再次一致。第一轮证据保留，不用它替代第二轮。此工具不会监听网络；例：

```sh
python3 tools/dnsmasq/contract_inventory.py --state-differential \
  --reference-build /isolated/exact-c-build \
  --work /ignored/private/config-state
```

M5已补齐RR/TXT保留长度的u16窄化、CAA tag的u8窄化、NAPTR字符字段先u16再截255和整数32位窄化；21配置／418服务观察／102语法镜像通过，见DELIVERY_LEDGER中的记录边界闭合。CAA总长度65536/65537的原版在窄化后分配、再按完整长度memcpy，隔离--test均SIGSEGV；Rust继续安全拒绝这一原版内存越界路径，缺陷与非法hex的原版ENOMEM差异均单独留证。CNAME target 索引从原版逐项查找转为 HashMap 加迭代图遍历，改善 finalization 的预期复杂度；配置重复别名检查、整体时间/内存成本和真实性能收益尚未测量。

## OpenWrt 调用方合同

| 调用方/源码 | 必须保持的行为 | 状态/所需验收 |
|---|---|---|
| `files/dnsmasq.init:987-1112` | UCI 生成 DNS、DHCP、TFTP/PXE、hosts、resolv、ubus、多实例配置；普通配置附加文件保持可用 | 已读；全部生成配置 replay 待做 |
| `files/dnsmasq.init:1250-1286` | procd 运行 `/usr/sbin/dnsmasq -C <instance-config> -k -x <pidfile>`，配置文件监测、respawn、netdev、ujail 文件/目录读写挂载 | 已读；jail 权限/启动失败/restart 测试待做 |
| `files/dnsmasq.init:1310-1380` | UCI dhcp/system 和 interface 触发 reload；重新提交 procd 配置，再发送信号 | 已读；需比较重新启动与 SIGHUP 的选择及事件顺序 |
| `components/procd/src/proc.rs` | command/env/user/group/capabilities/jail 独立边界；替换仍为独立服务 | 调用形状已核对；不并入 PID1 |
| `components/netifd/src/main.rs:3480-3540` | resolver 文件按 metric 排序，内容不变不替换；IPv6 link-local 带 zone；不能将上游文件与本地 `/etc/resolv.conf` 混为一体 | 已读；原子替换/空文件/接口改址/多文件 mtime 选择待验收 |
| `components/rpcd/src/luci.rs:640-647` | `dnsmasq --version` 输出包含准确 `Compile time options: ` token；LuCI 按 `no-` 与小写 key 判能力 | 已读；在对应引擎实现前不能宣称其能力已可运行 |
| `components/rpcd/src/lucirpc.rs:215-360` | UCI 每实例 leasefile，fallback；IPv4 expiry/MAC/IP/hostname/clientid 字段；`*` 未知，0 infinite | 已读；租约持久化与消费端对照待验收 |
| odhcpd `statefiles_write_state` → `odhcpd-update` | IPv6 hosts 地址/名字哈希变化写 hosts 再向 dnsmasq 发 SIGHUP；不接管 odhcpd DHCPv6/RA | 复用已核对 DNS 研究；后续联合离线验证 |
| `files/dhcp-script.sh`、`helper.c` | add/del/old 与 ARP、TFTP 子命令及 `DNSMASQ_*` 环境；USER_DHCPSCRIPT 先执行；hotplug object/method 不变 | shell 逐项已读；helper 环境全字段及事件顺序待实现/验证 |
| `files/dnsmasq_acl.json` | dnsmasq 系统身份发布服务、调用 hotplug.dhcp/neigh/tftp.call；不能用 LuCI session ACL 替代 | 文件已核对；allow/deny 权限回归待做 |

SIGHUP 由 `dnsmasq.c:1570-1603` 走 `clear_cache_and_reload`、no-poll resolver/servers-file 更新和脚本重新执行，**不会重读主配置**。SIGALRM 走 lease prune → file → DNS。SIGTERM `:1711-1759` 停 TCP 子进程、排空 pending lease/helper 事件、关闭租约、删除 pidfile、关闭 dump/log 后退出。Rust 需要保存等价操作顺序和释放证据，不能只重新 parse 一份主文件后声称 reload 兼容。

## UBus 与统计

`src/ubus.c:49-223` 注册 `<ubus_name>`（默认 `dnsmasq`）的 **`metrics` 方法**，以及 `<ubus_name>.dns` 无 RPC 方法的订阅对象。`dnsmasq.metrics` 是 object.method 简写，不能错建名为 `dnsmasq.metrics` 的独立对象。变体无 `set_connmark_allowlist`。metrics 对每个固定名称用 u32 写入；`metrics.c` 即使未编译相应能力也保留 DNSSEC/DHCPv6 计数字段，以及原拼写 `dhcp_lease_actve`，不能擅自纠正公共字段。

`ubus_event_bcast()` 仅在对应对象有订阅者时推送 DHCP 通知，按非 NULL 参数包含 `mac/ip/name/interface`。ACL、连接断开、重连后重新注册与订阅恢复、无订阅者时无回调开销，都需要实际验证。

OpenWrt patch 的 `forward.c process_reply` → `rfc1035.c do_doctor` → `ubus_dns_doctor` 为 A/AAAA 发送 `dns_result`，字段为 `name/ttl/type/address`。订阅者可返回同地址族 `address`；有效改写清 AA；无响应或不可解析地址保持原值。`ubus_complete_request(..., 100)` 是每次通知最多等待 100 ms，不是无条件每 DNS 查询固定 100 ms。TCP fork 分支先 `drop_ubus_listeners()`，不能在 Rust TCP 路径无依据地引入通知行为。后续必须逐项覆盖无订阅者、立即/迟延/无响应、断开、多订阅者、非法/异族地址、有效改写和缓存交互。

统计时间窗不是统一累计：`cache_reload` 重置缓存插入/活跃淘汰；`dns_queries_forwarded`、`dns_local_answered` 不随之清零。`dns_local_answered` 包含本地记录/缓存/本地错误；`dns_unanswered` 在尚未完成转发记录回收时增加。性能报告不得直接拿不同窗 counters 相除。

## 行为差异、算法候选与未验收项

目前明确的安全边界：数字解析拒绝超出 C `int` 定义域的输入，不复制 `atoi` 溢出/未定义行为；第二个空 `-C` 在 C 中把 NULL 交给文件逻辑，Rust 诊断为空附加文件（应保留 C 最小复现再定差异）；conf-script 输出解析失败时 Rust 会杀死并 wait 直接 shell 子进程，孙进程/复杂管道的最终回收仍未验收。正常配置行为不能借这些边界例外删除。

两个候选已有机制依据但**尚未测量收益**：词法扫描 O(n) 追加替代 C 每个 quote/escape 对余串 memmove（构造的多引号长行可达 O(n²)）；conf-dir 收集后 O(n log n) 排序替代 C 有序链表逐项插入 O(n²)。两者只影响启动/重载配置工作，不得宣传为 DNS QPS 或路由器 CPU 提升。当前实现仍分配行缓冲和部分 owned 参数；后续 profile 若表明成本值得降低，再在相同语义下减少复制。

下一门槛是全部配置语义、跨选项 finalization 与运行引擎接线、所有 OpenWrt 生命周期副作用、目标构建/打包、压力/fuzz/释放验证和冻结性能场景证据。任何元数据、12 单测或 59 输入解析差分都不足以称为功能等价。这里没有性能结论，也没有物理设备验收。
