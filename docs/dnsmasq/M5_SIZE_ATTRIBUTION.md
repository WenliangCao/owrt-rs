# M5 体积归因（持续更新）

M4 获准 ELF 为 1,159,280 字节。当前归因基准 `ff2b2d22` 在固定源码路径重编译后为 1,695,784 字节，增量 536,504 字节；首尾控制均为 `6a9a0d84…787009b`，逐字节一致。该基准是归因构建，交付候选和后续功能族各有独立身份，M5 结束后统一测量并交用户决定。

以下是同一源码路径、工具链和 opt-level 3/static/strip/panic-abort/no-unwind 的连续构建差额。混合阶段包含多族和链接布局交互；表中明确标记，不把它们冒称纯单族成本。完整源码与构建日志、ELF、归档 SHA/metadata 见 [固定路径时间线](../../private/dnsmasq-rewrite/evidence/M5/size-family-resume3-fresh/qualified-size-timeline.json)。

| 功能族/阶段 | 源码 | ELF 字节 | 相对前阶段 |
| --- | --- | ---: | ---: |
| M4 基线 | `4b3fc62c` | 1,159,280 | — |
| DHCP tags/options、本地记录、TFTP 初始实现（混合） | `7f3d0d1c` | 1,224,816 | +65,536 |
| Boot/TFTP/RR-filter/leasequery/helper 接线（混合，helper 单独补测） | `7a1d4b76` | 1,343,600 | +118,784 |
| Leasequery 修复与只读 init（混合） | `5d9da237` | 1,368,176 | +24,576 |
| Helper/TFTP 收尾（混合） | `db51616d` | 1,376,368 | +8,192 |
| Relay、DHCP identity、DNS 策略（混合） | `9e81b3e2` | 1,396,848 | +20,480 |
| PXE 主接线 | `c4d63591` | 1,437,808 | +40,960 |
| PXE 收尾、DNS files 与 owner（混合） | `13950029` | 1,474,584 | +36,776 |
| DHCP TTL/记录宽度/诊断收尾（混合） | `275a1150` | 1,474,584 | +0 |
| Config 输入/planner/SIGPIPE | `dcabd66a` | 1,482,776 | +8,192 |
| DHCP files/range/interface-I/O（混合） | `1614c0fd` | 1,511,448 | +28,672 |
| Endpoint/listener/lease 首次接线（混合） | `712a281b` | 1,564,696 | +53,248 |
| Endpoint/listener 边界（混合） | `b235fc2c` | 1,581,080 | +16,384 |
| 日志 sink/CLI/lease warnings（混合） | `dd9f565d` | 1,626,152 | +45,072 |
| 默认后台/NO_ID/source 诊断（混合） | `0ac6d6da` | 1,638,440 | +12,288 |
| Prefork lease/source cache（混合） | `585221ef` | 1,646,632 | +8,192 |
| Source pool/预分配/TFTP owner（混合） | `f987f941` | 1,663,016 | +16,384 |
| TFTP 错误/启动日志等中断前修复（混合） | `814a7eed` | 1,671,208 | +8,192 |
| Endpoint 枚举接线（独立） | `d55d91f4` | 1,671,208 | +0 |
| EDNS policy/neighbor/cache/runtime 接线（独立） | `98656142` | 1,691,688 | +20,480 |
| EDNS 解析、TFTP 分配和日志（混合） | `fead4da2` | 1,703,976 | +12,288 |
| 邻居负缓存刷新等后继修复（混合） | `ff2b2d22` | 1,695,784 | -8,192 |

该表从 M4 到归因基准完全守恒。独立 helper 完整接线相对 `ab5f36a` 的固定路径补测为 **+20,480 字节**（1,323,120 → 1,343,600），与旧族证据一致。helper-wired 的 SSH 回传在构建完成后失败；已从完成的 build.json、Finished 日志、ELF SHA 和已核验归档恢复，原控制器失败码 255 保留。第一轮没有强制重编译的固定路径矩阵复用了旧 Cargo 产物，已整轮拒绝；`ff2b2d22` 在共享构建锁内清 dnsmasq package 产物、保留依赖缓存，确保每次源码重新编译。旧 planner/SIGPIPE 矩阵主动刷新 mtime，原证据仍有效。

`08f2e213` 的 GNU map 构建与候选 `468b5d72…be89` 完整 ELF 逐字节一致；2,322 个可验证 executable input sections 共覆盖 1,458,700 字节，8,376 字节执行区未归因。存储归属为 DNS 216,796、DHCP 189,112、配置 156,412、main/owner 122,560、helper 37,676、TFTP listener/runtime 37,316 字节；这些是当前存储量，不能直接当新增成本。unstripped profile 改变 ALLOC/LOAD 布局，已拒绝作为 companion，未用于归因。

已找到可保持选择行为的简化：source pool 原来收集候选并完整稳定排序，只读取首个最小 rank；`ad66dfba` 改为直接取同 rank 最小值，唯一 ServerId 使用不稳定排序。精确 Rust 1.98.1 的等值首项和 16,512 个选择控制通过；物理 pool slot 唯一性和排序键已独立审查。同一可编译 `46aaaef5` 基线仅替换 upstream.rs 为排序前版本的受控构建：1,703,976 → 1,687,592，**节省 16,384 字节**；优化前后源码 SHA 固定，优化后首尾控制 ELF 逐字节同为 e95f7f26…f11bd0。直接构建中间 library-only commit 的两轮失败 101 已留档，未用于归因。优化候选完成镜像 C source pool/preallocation 61 配置/350 观察/67 required 子集和 10 负控，不据此冒称全候选已统一回归。[优化构建证据](../../private/dnsmasq-rewrite/evidence/M5/size-family-resume3-fresh/pool-root46-before/source-identity.json)，[C 回归证据](../../private/dnsmasq-rewrite/evidence/M5/interface-records/endpoints-optimized-46aaa-close-summary.json)。

较大混合阶段继续补独立对照：helper、端点/source allocator、DNS files 和日志。保留成熟 std/process 与现有执行路径；没有为了体积变更功能合同或复用 M4 的体积特许。最终新增体积与满载 RSS 在 M5 统一版本验收后交用户决定。

后继产品候选差额如下；这些构建各自使用冻结源码和唯一共享构建目录，但源码路径不同，不把链接布局差额当纯函数成本。4207 的 Linux 650 lib/10 main 单元实际通过，族级资格仍由各自清单给出。完整 source-identity.json、build.json 和产物在 [后继构建证据](../../private/dnsmasq-rewrite/evidence/M5/resume3-20261005/)。

| 后继功能族/阶段 | 源码 | ELF 字节 | 相对前阶段 |
| --- | --- | ---: | ---: |
| 日志、端点首轮收尾及 source pool 优化（混合） | `46aaaef5` | 1,687,592 | — |
| ARP primitive/owner、日志与启动收尾（混合） | `10bf41fe` | 1,712,168 | +24,576 |
| 接口 immutable records/parser/枚举 caller 与 cache primitive（混合） | `b612de44` | 1,728,552 | +16,384 |
| TCP 缓存独立视图/时钟/parent import owner | `8389a0fa` | 1,732,648 | +4,096 |
| TCP 日志上下文/owner及接口空 root parser（混合） | `4207c732` | 1,736,744 | +4,096 |
| 接口 collector、dynamic CNAME terminal/cache metadata 修复（混合） | `90a84a55` | 1,757,224 | +20,480 |
| 接口完整defer/CNAME诊断、FIFO/ARP恢复（混合） | `f3ec456b` | 1,765,416 | +8,192 |
| 反向缓存/helper分配、FIFO fallback tag、synth ANY（混合） | `7a3af081` | 1,773,608 | +8,192 |
| 普通TCP日志pin/EOF、继承stderr/raw path、helper104B/POLLOUT/TERM（混合） | `7440f1fd` | 1,777,704 | +4,096 |
| 合成NX tier、DHCP proxy、helper凭据诊断（混合） | `486635d7` | 1,789,992 | +12,288 |
| 共享DHCP context、负缓存SOA修复（混合） | `c1053a31` | 1,785,896 | -4,096 |
| bridge本地/relay有效接口、dump协议handle（混合） | `8f95e5ab` | 1,798,184 | +12,288 |
| dump配置及主owner PCAP接线 | `2f298a3d` | 1,806,376 | +8,192 |
| DHCP reply-delay/Windows过滤接线（混合） | `955f681b` | 1,810,472 | +4,096 |
| Windows过滤普通AA/TCP层序补正 | `19d49a73` | 1,810,472 | +0 |
| loop probe/owner首次接线、dump上下文API（混合） | `1ed97bef` | 1,830,952 | +20,480 |
| loop初始fixed-port修复、本地query producer（混合） | `f2a991c7` | 1,839,144 | +8,192 |
| 反向SYN generic-negative tier | `9ef4567a` | 1,843,240 | +4,096 |
| query cache/upstream producer、PCAP EOF诊断（混合） | `47ebdc1a` | 1,847,336 | +4,096 |
| query主owner/UDP/TCP接线、SYN empty-cache补正（混合） | `f16c0971` | 1,871,912 | +24,576 |
| domain接线、RR空token解析、query policy及hosts readnotice（混合） | `3a9ab75e` | 1,884,200 | +12,288 |
| relay reply dump、loop固定31字节数组替代Vec/format（混合） | `c36eacbc` | 1,884,200 | +0 |

当前构建候选 `c36eacbc` 相对 M4 共增加 724,920 字节；dump/domain/query/loop仍有未资格项，不冒称统一验收。已资格SYN/forward-max的f16候选增量为712,632字节。loop固定31字节探测改用内联数组和直接hex编码，消除每包Vec扩容与format分配，包头布局未变；与relay修复混合构建净体积0，不能声称独立节省。较大的loop初次20,480和query接线24,576阶段继续留作独立拆分/等价简化评估，保持实际日志/调度行为。Arc<Record> 的 TCP 接受视图共享记录 payload，独立保留容器和状态；具体满载 RSS 成本仍待 M5 统一候选实测，不以代码结构推测内存结果。

