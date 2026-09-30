# DNS wire 阶段：源码、实现与证据

2026-09-29。状态：**wire 核心已实现并完成限定范围对照；DNS 服务替代尚未完成，性能收益尚未证明。** 本任务已取代旧 DNS 研究报告的“不完整重写”建议。

接口与变体依据是 `docs/reviews/NETWORK_DNS_20260929.md` 的第 1、2、7 节。参考为镜像对应的 dnsmasq 2.93-r1 普通 nodhcpv6 包，源码归档 SHA256 `0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19`，应用该镜像两份 OpenWrt 补丁的树位于 ignored `private/network-research-20260929/dns/dnsmasq-2.93-openwrt/`。没有访问或更改物理路由器。

## 调用链与不变量

正常 UDP 路径是 `forward.c:receive_query()` → `rfc1035.c:extract_request()/answer_request()` → 转发/缓存选择；上游回复经 `forward.c:process_reply():695` → `edns0.c:find_pseudoheader()` → `rfc1035.c:extract_addresses()` → `cache.c:cache_insert()`。TCP 在 `forward.c` 的独立连接路径使用同一名称、RR 与缓存处理函数。这里只实现这些路径共享的纯报文原语，没有用 wire 单测代替传输、缓存或状态机验收。

| 精确 C 位置 | 行为及所有权 | Rust 实现 | 当前对照 |
|---|---|---|---|
| `dns-protocol.h:149–221` | 12 字节 header，网络字节序；名称内的 NUL、`.`、字节 1 在 C 内部字符串用字节 1 转义 | `dns/wire.rs:Header`、`Name::dnsmasq_bytes` | 固定 A 响应、binary labels；C oracle 名称输出逐字节比较 |
| `rfc1035.c:37–194` | 首次 compression pointer 决定返回 cursor；后续指针只影响解码；最多 255 跳；解压 wire 名称含终止符最多 255 字节，内部转义字符串最多 503 字节；保留原大小写 | `decode_name`，所有读边界检查，返回拥有的 `Name` 与 offset，无裸指针/unsafe | C `extract_name(EXTRACT)` 原函数 oracle；前向/越界/循环指针，255/256 跳，二进制标签、254/255/256 字节边界 |
| `rfc1035.c:305–393` | skip 不解压、不追踪指针目标、不施加 expanded-name 限制；可跳过旧 bitstring label `0x41`，extract 却拒绝；检查问题尾部 4 字节、RR 固定尾部 10 字节和 RDLEN | `skip_name`、`skip_questions`、`skip_records`、`RecordRef`、`Message` | 精确 C skip 三函数 oracle；每个固定报文截断点及计数字段变异 |
| `rfc1035.c:395–416` | 完整报文末端由声明节计数决定，允许末尾额外字节；畸形时 C resize 保留原长度 | `Message::end` 返回结构末端；调用方决定是否裁剪，parse 错误不会自行改包 | C section-end oracle；末尾 opaque 字节单测。恢复被删 OPT 的 resize 分支未实现 |
| `edns0.c:19–98` | 扫完附加节后返回最后一个 OPT；QUERY/IN/TKEY 或末尾 ANY/TSIG 标记 signed；仅发现 OPT 不验证其 option TLV | `find_pseudoheader`、`EdnsScan`、`EdnsRef` | C 函数 oracle 比 offset、record 长度、UDP 字段位置、signed（存在 OPT 时）、is_last；另 48 个完整 QUERY 报文逐项对照无 OPT 的 signed 状态 |
| `forward.c:1880–1906`；`edns0.c:add_pseudoheader` | 客户端 EDNS UDP 长度先受配置上限限制，再在另一分支夹至最少 512；DO 标记单独读取；无签名时上游包宣告配置上限，签名请求不改包 | `EdnsRef::udp_size`、`dns/forward_service.rs::prepare_query`、`QueryMetadata` | 固定 OPT 字段与边界测试；`forward_service` signed/无 OPT/已有 OPT 单测；不宣称完整 EDNS option/reply 处理等价 |
| `edns0.c:130–170,461+` | option 是 16 位 code、16 位长度和 payload；packet envelope 与 options 内容验证分层 | `EdnsOptions` 借用 payload，零长度 TLV 可读，截断明确报错 | 固定零长度/正常/截断 TLV 单测；尚无 option 修改算法的 C 差分 |
| `rrfilter.c:296–343,349–380`；`rfc1035.c:980–1065` | 通用缓存复制必须按精确 RR 描述表解压 RDATA 中名称并折叠 ASCII case；未知 RR 保持 opaque；名称编码本体不能越过 RDLEN，指针目标可以在 RR 外 | `RecordRef::rdata_name`、`canonical_rdata`；每个 RR 借用整个原报文，避免丢失 compression target 的生命周期 | 独立固定 MX/未知 HTTPS/越过 RDLEN 用例；精确 rrfilter_desc/to_wire 及原缓存复制循环对照；超过 u16 RDLEN 的安全差异见下文，完整缓存策略未实现 |
| `rfc1035.c:1514–1657` | RR 超出输出边界不推进提交 cursor；TC sticky；完整成功才提交 RDLEN/cursor/count | `PacketWriter` 先检查长度再提交，name pointer 必须能在当前 packet 中解码；禁止 section 倒序 | 独立固定响应逐字节预期；精确边界、失败不提交、sticky TC 测试；尚未对 C variadic writer 作全面差分 |

`Name` 保存未压缩 wire labels 而不是 UTF-8，避免丢失合法二进制名称；cache key 可调用 `canonical_wire`。`RecordRef` 与 `EdnsRef` 借用报文，RDATA 没有逐记录复制。`Message` 只保存 section ranges；其分配不受不可信 count 字段驱动。指针循环以固定跳数上限终止，所有加法边界使用 checked arithmetic。没有 unsafe。

### 已识别的兼容细节

- C 的 `find_pseudoheader(..., is_sign != NULL, ...)` 在 opcode 不是 QUERY 时不跳过 question section（`edns0.c:35–55`）。当前 Rust scan 明确保留此路径，不用 RFC 理想化行为替代；调用方必须区分需要 signed 检查与仅定位 OPT 的路径。是否修复该 C 行为需单独最小复现与服务级差异说明。
- `skip_name` 接受指针编码不代表该名称可以解压；不能把 `Message::parse` 成功当成每个 RR owner/name RDATA 语义已验证。
- `EdnsOptions` 对四字节、零 payload 的 TLV 能正确迭代。C `add_pseudoheader` 的修改循环条件是 `i + 4 < rdlen`，不是完整 TLV 验证器。尚未实现其修改语义，也未把 Rust TLV 校验错误映射成拒绝整包。
- 不复制 C 裸指针、不依赖 UB。已识别的 C quirks 和风险仍需在实际调用合同中判断；当前没有对守护进程发送路径作行为豁免。

## 可重复验证

本机 Rust 工具链位置为 `/Users/USER/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/`（不默认处于 PATH）。可用 `rustc --edition=2021 --test components/dnsmasq/src/dns/wire.rs -o private/dnsmasq-rs/wire/wire-unit-tests` 独立编译；模块接入由主代理在 `lib.rs` 加 `pub mod dns;`。无第三方 crate 依赖。

运行 `python3 tools/dnsmasq/dns_wire_diff.py --rustc <rustc-path>`。工具直接从已补丁 C 文件提取五个完整函数并 include 原 `dns-protocol.h`，未人工改写算法。C oracle 使用 ASan/UBSan；Rust driver 调用实际模块。oracle、driver、corpus、stdout/stderr、mismatch 和 summary 均位于 ignored `private/dnsmasq-rs/wire/differential/`。

2026-09-29 首轮结果：seed 293、10,000 个定向变异输入，共 **62,389** 次原语对照，**0 mismatch**；C sanitizers 无诊断。成功和失败通道逐操作校准，并要求两端输出数等于输入数，不能通过少输出掩盖失败。此轮结果不含随后增加的 `canonical_rdata`（该方法当前只有固定预期单测）。该轮的独立单测为 18 项；随后新增溢出边界回归后 wire 单测为 **19 passed / 0 failed**。原始 corpus SHA256 `0661d23293f769736b5fc5162a84ef5d1d3a5a0664b595bacfb33871ebcdf03c`。

五原语对照的错误归一化：C NULL 与 Rust error/absent OPT 均为失败通道；成功时保留名称全部字节、消费 offset、OPT 长度/位置、signed（存在 OPT 时）和 last-OPT。因此没有把不同 malformed-error 类别当成一致行为的证据；没有把“找不到 OPT”与“整包应该丢弃”混为一谈。

## 尚未覆盖的完整 DNS 合同

UDP/TCP IPv4/IPv6 实际收发与 socket/FD 生命周期；上游认证/随机化/重试/分组/合并/失效；缓存 LRU、TTL/负缓存/SOA/CNAME 状态；hosts、DHCP/odhcpd 名字同步；所有配置生成和 local/rebind/access 策略；EDNS 添加/删除/修改与 signed 透传；动态接口/reload/ubus 订阅；资源压力、长运行和关闭回收均未因本文测试而验收。未知 RR 的借用解析已存在，但完整缓存/转发能力还未完成。没有 DNS 性能基准、CPU/请求、内存改善或路由器结论。

当前实现的成本候选是 borrowed RDATA 与单次 section 扫描，避免每条 RR 分配；其是否相对 C 有收益需由冻结场景证明。不能从 Rust 内存安全或单测通过推导性能目标完成。


## RDATA 复制与安全差异增量

已复用 `private/dnsmasq-rs/wire/differential-rdata/summary.json`：seed 293、10,000 定向变异、**76,213 原语对照，0 mismatch**，含 **13,776 RDATA 复制**与 **48 无 OPT signed** 对照。C ASan/UBSan 无诊断。该 corpus SHA256 为 `7918ca636cd768866fec722a0c2248b81ce13096a9c19d0eb821b51089de8e73`；不能和首轮 62,389 相加当成独立新增覆盖，也没有为了文档更新重跑它。

`rfc1035.c:1018–1059` 原循环把展开长度累加到 `union all_addr.rrblock.datalen`，其定义是 unsigned short。MX 的 compression pointer 指向 255-byte 名称时，原始报文可在 65,535-byte 内，但展开 RDATA 超过 65,535。提取的原 C 循环将长度取模：65,536→0，65,765→229。Rust `canonical_rdata` 在追加尾部前返回 `RecordTooLong`，防止把无法编码的 RDATA 或截断前缀放入缓存。

这是**提取函数级的已复现安全差异**，尚无 daemon 级复现，不能据此声称远程利用或实际服务影响已证实。最初的原始输入/输出在 `private/dnsmasq-rs/wire/rdata-overflow/`；新的生成式最小边界回归在 `private/dnsmasq-rs/wire/overflow-regression/`。命令：`python3 tools/dnsmasq/dns_wire_diff.py --rustc <rustc> --output private/dnsmasq-rs/wire/overflow-regression --overflow-only`。四例：展开 65,534、65,535 与 C 一致；65,536、65,765 明确记录安全拒绝差异。期望由独立 fixture 构造及精确 C 输出确定，不由 Rust 生成。上述正常 corpus 不含溢出案例；安全差异单独统计，不冒充零差异。

## 动态 forward cache 阶段

`dns/cache.rs` 与 `dns/cache_reply.rs` 现在由 daemon 接入一个窄范围的缓存路径：仅 IN、单问、无 EDNS/DNSSEC、NOERROR 的直接 A/AAAA RRset、完整 CNAME→终端 A/AAAA RRset，以及 SOA-backed 或无 SOA 的 NODATA/NXDOMAIN fallback，按 TTL 写入并用 bounded writer 命中回答；本地 hosts/DHCP/config 记录、reverse cache、TCP 子进程缓存 IPC 仍属于后续集成。原语已增加 `insert_negative` 的 SOA TTL/MINIMUM 选择、`neg-ttl` 回退和零 TTL 边界、包含 name-wide NXDOMAIN 的 question lookup、负记录 authority 保留，以及调用方已选定正 RR 的 bounded wire append。`append_positive_record`/`append_cname_record` 不执行完整 cache lookup/synthesis，daemon 负责 CNAME 负链、NODATA/NXDOMAIN RCODE 与 SOA authority；EDNS 仍留给调用方。`Record.data` 仍是调用方校验后的 canonical RDATA；负缓存 SOA metadata 保存在 `NegativeAuthority`。未将剩余缺口标记为完成。

| 精确 C 位置 | 行为与不变量 | Rust 原语 | 当前对照 |
|---|---|---|---|
| `forward.c:782–845` → `rfc1035.c:768–815,1205–1209` | 截断/错误/非 IN/非递归/CD 等决定是否缓存；每次提取先 start，只有允许的回复才 end | cacheability 留给调用方；`start_insert/commit` 只表达事务 | 未接完整 process_reply/extract_addresses，不以原语对照替代 |
| `cache.c:176–193,359–407,737–828` | cache-size 计算记录数量；pending 脱离 LRU；命中提升到头；压力先扫过期，再按 LRU spill 整个冲突 RRset；长名称额外额度为容量/10、内部转义名长度 ≥75 | 固定 `Vec<Slot>`、索引链表、每名字索引、pending、长名字额度 | 容量 1/2/8/10/100 的固定/随机用例；完整所有权链不变量测试 |
| `cache.c:450–488,665–691`；`rfc1035.c:1649–1690` | max-cache-ttl 先于 min-cache-ttl；TTL=0 默认使整个事务失败；stale 有限/无限；expiry 用 now≥ttd，stale 标志用 now>ttd；reply TTL 夹至0和max-ttl | `Policy`、`Entry::reply_ttl/is_stale`；时刻加法溢出显式错误 | 默认/finite/forever、0/1/10/60 TTL、边界时刻、min>max 对照；Seconds(0)归为禁用单测 |
| `rfc1035.c:1205–1209,1649–1690`；`option.c:2280–2294` | 负回答有 SOA 时使用 SOA TTL/最小值；无 SOA 才使用 `--neg-ttl`，零回退不缓存；name-wide NXDOMAIN 可参与 question lookup | `Cache::insert_negative`、`Cache::lookup_question` | 4 个 SOA/回退/零值/NXDOMAIN 回归测试；尚未接入 daemon 回复合成 |
| `cache.c:518–602,643–718,844–919` | 冲突立即删除旧记录；插入失败后新记录不 commit；下次 start 清理 pending；不会恢复已删除旧记录；A/AAAA/不同 RRtype 可共存；CNAME 与其他类型冲突；NXDOMAIN 与 A/AAAA 不直接冲突 | `Kind::conflicts`、显式失败态、`start_insert/insert/commit` | abort、遗漏commit、同事务多个 RR、负记录、不同type及 6 个状态序列种子 |
| `cache.c:157–174,450–465,564–574,811–825,855–861` → `rfc1035.c:928–956,1114–1124,1185–1196` | CNAME 持 target crec+UID；目标复用给不同名字时失效；同名目标替换保留 UID；未找到 target 的 CNAME 在commit丢弃 | `EntryId` slot+generation、`set_cname_target`；只在同名目标替换保留代数 | 替换目标、过期目标、无目标、回收后不复活；C差分与独立状态测试 |
| `cache.c:1174–1260` → `rfc1035.c:2283–2347` | 第一次查找提升所有同名匹配记录；按 flag 组轮转；Generic F_RR 查出多种type后调用方过滤 | `lookup` 返回 handle，不复制 payload；Generic(_)按组查，再由调用方筛真实type | 保留同type准确顺序、round-robin/no-round-robin；仅跨 generic type 的组顺序归一化 |
| `rfc1035.c:1649–1690,2100–2170,2283–2347` | 完整 answer_request 选定正 RR 后按剩余 TTL 写入目标 section；CNAME/negative/NXDOMAIN/ANY 与 RCODE 仍由上层状态机决定 | `append_positive_record` 仅写 live A/AAAA/generic EntryId，拒绝 CNAME/negative/NXDOMAIN | 6 个正 RR wire/TTL/过期/限长/拒绝边界测试；未接入 daemon |

C cache 源文件 SHA256：`51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`；`dnsmasq.h` 为 `318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228`。工具先校验 hash，然后从精确文件提取 19 个完整函数（含真实 hash/scan/insert/find），不手写 C 替代算法。仅配置、内存分配及未启用 IPC 的依赖是最小桩；触发不应执行的 IPC/log 路径会 abort。C ASan/UBSan 启用；分配失败不是本轮范围。

运行 `python3 tools/dnsmasq/dns_cache_diff.py --rustc <rustc>`。`private/dnsmasq-rs/cache/differential/summary.json` 记录 **21 场景、22,571 命令、0 语义 mismatch**；首个固定 calibration 验证 I success/failure、C success/failure、L failure、Q hit/expiry/missing及输出数量，期望常量独立于Rust。另有 **7 个 cache 单测**，其中 2,000 轮反复 abort/expiry/reuse 检查每个 slot 唯一归属、LRU 无环、前后链接一致及索引完整。

首次对照的 138 条差异均为 Generic(16)/Generic(33)跨类型组顺序，保留在 `private/dnsmasq-rs/cache/differential-initial/`。精确 C hash 的桶内顺序受其他名字及运行时地址影响；实际 answer_request 按请求 RRtype 过滤。工具只按 RRtype 稳定分组再比较，**同一 RRtype 内的顺序、值、negative、expiry、reply TTL、stale 标志仍精确比较**；当前跨类型原始顺序差异另外记录于 `cross-type-order-variations.json`，未删掉原始输出。不同 hash 桶附带回收过期/失效 CNAME 的时机不同；本轮没有断言内存压力下 C 与 Rust 所有中间 slot/逐出顺序相同。

成本基线来自源码：C 命中/同名替换为桶长线性扫描，LRU unlink/link 为 O(1)，容量压力的过期回收为全表 O(N+桶数)，name 比较按字节；Rust 使用按名称的随机化 HashMap 将碰撞链与同名 RR 分组分开，槽位 LRU 仍 O(1)，压力回收仍 O(N)。这只是算法机制，不是测得收益。Rust 当前 key/索引/payload 有分配和复制，C 的小名/小 RR 内嵌布局可能更省空间，必须量测后再优化，**尚未证明 CPU、内存或吞吐改善**。后续候选是减少临时 key/lookup 分配、内嵌短 RDATA、可删除的过期队列，并在完整缓存合同对照后冻结性能场景。
