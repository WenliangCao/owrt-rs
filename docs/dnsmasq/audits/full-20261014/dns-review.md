# DNS 协议、缓存与 TCP 调用补充审计

2026-10-14。对象仍是冻结 main `e9d89b17` 的 fresh release ELF
`e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`，
对照为精确 OpenWrt 25.12.5 dnsmasq 2.93-r1 nodhcpv6 ELF
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
本页不把独立修复分支或组合候选的身份混入基线。

**列明的 DNS 正常协议和缓存边界没有确认新的 Rust 产品阻断。**
两条前向压缩指针输入的字节差异，是 C 返回名称压缩循环、Rust 返回可解码答案；
不能照抄旧报告，将当前 Rust 仍描述成 UDP 丢包或 TCP REFUSED。
F1/F2 的资源故障结论不因这里的正常运行通过而改变。

## 恢复的真实运行与重新核对

原会话在 Oracle 已完成两次 `audit_20261011_dns.py`，但未交付专项报告：
`/tmp/full-audit-dns-boundary/private/run` 于 12:19 UTC 完成，
`/tmp/full-audit-dns2-20261014/private/protocol-matrix` 于 12:33 UTC 完成。
此次接棒恢复两份原始结果，核对两侧 ELF、工具 SHA、完整请求/响应、上游记录与
daemon 退出；**没有把这两次旧于接棒的执行冒称成接棒后新跑**。

| 每轮配置 | C/Rust 对数 | 客户端完整字节一致 | 每侧上游请求 |
| --- | ---: | ---: | ---: |
| 本地记录、名称解析与异常问题 | 116 | 114 | 0 |
| 普通转发 | 84 | 84 | 86 |
| AAAA/TXT 过滤 | 84 | 84 | 86 |
| DNS rebind 过滤 | 84 | 84 | 86 |

每轮合计 368 对，366 对完整结果相同；两轮是同一 corpus 的重复，不增加独立
输入种类。每轮 8 个 daemon 均已 ready、结束时仍健康、SIGTERM 后退出 0。
逐请求的上游数量和 UDP/TCP 类型一致。上游随机 ID 与大小写报文保留在原始结果，
这里没有宣称它们逐字节相同。

范围包括 A/AAAA/ANY、CNAME 链、TXT/MX/SRV/PTR、非 IN class、RD/CD/AD、
EDNS/DO/版本/长度、重复 OPT、多问题、压缩循环、截断标签、超长名称，以及
上游 CNAME/负答复/SERVFAIL/TC/异常 RDLENGTH/owner/OPT 的 UDP 与 TCP 路径。
该矩阵明确 `cache-size=0`，不能据此声称缓存老化已经通过。

新增 [独立检查器](../../../../tools/dnsmasq/check_full_audit_dns.py) 从保存的
wire 重算长度、header、比较结果与名称指针，不信任 `same_client_result`。
两次均通过；删除场景、改响应字节、伪造存活、改字节后伪造通过标记四类负控制
均被拒绝。负控制是检查器校准，不是额外 daemon 场景。

### 前向指针差异的实际内容

构造的问题名从 offset 12 指向 offset 18，原请求后部存有 `host.audit.test`。
C 的 34 字节回复却让 offset 18 成为指回 12 的答案 owner，形成 **12→18→12**
压缩循环；这不是可解码的同一答案。Rust 的 49 字节回复展开问题名，返回
`host.audit.test A 192.0.2.42`、TTL 60。两轮 UDP/TCP 均如此，均没有访问上游。
独立 decoder 对 C 检出循环，对 Rust 核对问题、owner、type/class/TTL/address
与整个报文尾部。保留两个原始不相等结果，不要求 Rust 复制 C 的畸形输出。

## 接棒后新执行的有状态补测

在新的 `/home/ubuntu/full-audit-dns-resume-20261014/private/` 中，使用冻结工具
`m5_dns_cache.py` 事先选择四个完整边界：`EXTRACT-BASE` 30 项、`NEGATIVE` 38 项、
`ROUND-ROBIN` 18 项、`TCP-CALLERS` 24 项，共 **110 对**。C 和 Rust 各自进入
新的 network/mount/PID namespace，使用精确镜像私有 overlay，未重编产品。
Oracle 内核为 `6.17.0-1020-oracle`。

两侧各 110 个实际 daemon 场景均正常完成，分别产生 **337 个客户端观察、150 个
上游报文**。所有实际进程 ELF hash 正确；保存的每个请求/回复及上游 wire 均重新
解码并与 trace 核对，没有只信任汇总计数。

首次比较为 108/110，差异是 `round-reverse-default` 与 `round-reverse-disabled`
的 PTR 记录顺序。首个额外 C 控制只证明 default 自身会变，比较仍为 109/110。
随后事先固定四次仅 C 双场景控制并全部执行、全部保留，两个场景均证明同一 C
ELF 不同启动的顺序变化。沿用原比较器已有规则：只有真实 C 变化得到证明，且
每个进程内部重复顺序保持稳定时，才比较 PTR 记录集合；不对其它 RR 排序。
最终 **110/110，通过 452 个检查器负控制**。原两次失败比较没有覆盖或删除。

此补测覆盖正/负缓存提取、SOA 选择/替换/到期、无负缓存配置、A/AAAA/泛 RR
轮转、HUP 清缓存与旧/新 TCP 视图、接受时钟、绝对过期、慢上游期间父进程进度，
以及租约 add/rename/release 的 TCP 可见性。四项 DHCP/TCP 调用另用专用 qualifier
核对真实 ACK/release 见证和 3.2 秒时钟，全部通过，9 个负控制均被拒绝。

TTL 比较使用原先冻结的具名时钟窗口；只允许观测时刻证明的整数秒边界，
没有全局忽略 TTL。上游数量、协议元数据与客户端记录均参加比较。
完整 cache family 的资格字段仍为 **false**：这里没有执行其余所有场景。

## 证据、收尾与限制

[派生证据](dns-evidence.json) 保存每轮身份、通过/失败计数、负控制、原始文件
SHA 与运行边界。原始报文、配置、trace、驱动副本、全部比较和执行 argv 已归档到
电脑 `private/full-audit-20261014/dns/oracle-evidence.tar.gz`，SHA-256
`30e488e17130a4c3d5b9797703b1cb3583022c3febcac7af1dfd7f7e8d077bc2`；
本机重新计算一致。Oracle 同份归档保留在上述任务目录的 `evidence.tar.gz`。
可重建的 overlay 副本不进归档；精确镜像保留在原证据位置。

完整 runner、选定场景正则和每次命令均在归档中。协议结果可直接以新增检查器
重新校验；缓存补测的 runner 为 `run_cache.py`，C 顺序控制为 `run_order_panel.py`。
初次 SSH 客户端在远端 runner 已退出后仍未关闭，经核对无远端 runner 才终止本机
连接；持久执行收据保留 C/Rust exit 0、初次比较 exit 1，没有因此重跑实验或改判。

收尾没有本任务 daemon 或宿主残留挂载。未修改产品代码、未操作物理路由器、
未 push。没有执行最终组合 ELF/APK、全部 DNS 族、长期 fuzz、任意 TCP 分帧/
连接洪泛、无线客户端或硬件性能验收；本页不为这些未做项目签发资格。
