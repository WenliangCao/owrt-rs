# httpd 2026-09-28 工程研究

本轮按用户明确的工程结案边界执行：允许披露性能退步和未归因项，不要求每项胜过 C/R89；功能、正式构建、身份与生产隔离仍是必要门。此规则取代旧 R95/R94 文档中冲突的性能收尾要求。生产九组件保持精确 C，候选只进既有隔离 namespace。

当前状态：H1+H2 已在 Oracle 筛选，正式构建和最终功能/实机门待完成，**尚未验收**。

## 证据与机制

- 精确 C：OpenWrt 25.12.5 r33051-f5dae5ece4，uhttpd revision `7b1bec45826bd78c8afc993435bdc0f1df2fe399`，ubus revision `24864e7840b3a02a9ef76284a373f6b2f00b8a9b`。合同来源为 `docs/contracts/httpd.md` 与匹配源码，不能把其他 libc 的行为套到镜像上。
- 正式 R89 只用 `/root/r89-before-r90` manifest 与 ELF；SHA256 `1e54a6d8d80e0ebfb61cfdccfb0fc58c3710eadac99eda5c74f9640e63c6b31d`。C ELF `1f8dc03d563489626215a1e7b33ebac693737e39e3f8d862a5d836c178b491b3`。
- R94 四并发 JSON-RPC 470.2 vs C 462.8 µs，范围重叠，未证明胜 C，也不是本轮已证实的稳定退步。静态/停放路径保持原实现。
- H1：同步 ubus 回复直接消费匹配的 DATA/STATUS 接收缓冲，省掉中间 Message 的 Vec；乱序消息仍物化入队，DATA 仍有独立所有权，deadline、FD、鉴权和 lookup 次数不变。profile 完整 RPC allocations 49→41，requested bytes 7748→5508；目标 lookup 每请求一对4096字节 mmap/munmap 消失。Oracle 两侧各两窗，小回复主体 CPU 75–80→62–63 µs，四并发139→103–105 µs。
- H2：直接将 Blob 回复序列化到 JSON 字节，跳过键、字符串和数组的中间树。复用原字符串/数字编码，仍逐项 batch flush，写失败停止后续调用。相对 H1，约31KiB回复 Oracle 主体 CPU 354–358→304–315 µs，四并发454–470→368–374 µs。小回复四并发窗口波动保留，未宣称全胜。

原始 profile、ELF、逐窗结果保留于 ignored `private/httpd-20260928/`，Oracle `/home/ubuntu/httpd-20260928/`。profile 分配/trace 是诊断，不能混入正式性能。最初分段计时与构建并发，只用于归因；后续筛选是描述性证据。

## 确认前冻结

冻结时间：2026-09-28 08:01 UTC（正式构建前）。

- 依赖始终为镜像 C ubusd/rpcd；HTTP 明文 namespace loopback，Wi-Fi 仅管理。连接复用，不测 TLS 握手；HTTPS/CGI/慢读由相关功能门保护。
- 代表矩阵：`jsonrpc`、`jsonrpc_c4`、`jsonrpc_large`、`jsonrpc_large_c4`、`static_16k_dat_c1`、`static_16k_dat_c4`、`cgi`。大回复为 UCI list 256×120字节字符串，独立生成预期 JSON；配置和 ACL 准备在计时外。
- 先做最终 ELF 单侧 pilot，N=1000；记录准备、采样、传输、校验、清理的完整耗时。确认默认 N=10000、三个独立 C/R89/候选 block，random-blocks seed=20260928。若 pilot 预测超预算则缩小并记录，不补轮直到变绿。
- 每客户端预热20；CGI为N/20、预热5。c4外窗 CPU 分母含4×20预热，延迟/调用方CPU仅正式请求；吞吐分子正式请求，外墙窗含启动/预热。不累加重叠的daemon计时。
- 分别列主体、依赖、调用方 CPU，mean/p50/p95/p99、吞吐、错误、资源。CPU首选进程CPU时钟，子进程CPU另列；报告逐轮与中位数，不做统计等价声明。
- 实际影响参考：CPU变化同时达5%且10µs/请求；mean同时达5%且20µs；p95/p99增加同时达10%且100µs需显式解释。阈值只辅助工程判断，不隐去更小退步、不抵消尾延迟。
- 总墙钟上限两小时（07:44:41 UTC起），最后20分钟留结案；AX3000T实验累计45分钟。性能异常停止队列，最多一次有界诊断；功能或隔离失败不可用性能取舍接受。

## 门状态（待最终更新）

新接收路径覆盖 DATA大小16/8192、乱序消息、重复STATUS；直接编码差分覆盖嵌套、重复键、控制字符、非UTF-8、截断字段与未知类型。Oracle httpd release unit 51/51通过。首次并行运行两项CGI报 Text file busy；保留失败，按既有 RUST_TEST_THREADS=1 串行重跑通过。正式构建、完整HTTP gates、实机确认尚未完成。
