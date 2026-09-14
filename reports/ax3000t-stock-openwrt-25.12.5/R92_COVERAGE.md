# R92：第 2–5 批逐项处置与验证边界

基线为 [R88 审计 §6.2/§6.4](R88_FULL_AUDIT.md#62-确认但未修复记录为已知差异或待下一轮)
和正式 R89，运行时固定为 `ca1a9121df0380448a19d474e29796066b6734e8`。
本表的“修复”指已有可区分原版/旧版/候选的证据；“保留”必须同时说明行为、理由和回归门。
完整实机验收状态以 [部署证明](R92_parts/deployment.json) 为准。

原始故障数据、回复、无线标识、配置和备份不入 Git。下表引用的正式门、断言名、运行身份及日志
SHA256 见 [validation.json](R92_parts/validation.json) 和
[recovery_compatibility.json](R92_parts/recovery_compatibility.json)。
原版控制项的 `passed` 仅表示符合该行写明的原版预期；不能把原版崩溃、无界增长等反例说成恢复成功。

## 第 1 批与 R91 的交接

| 原问题 | 最终处置 | 证据 |
|---|---|---|
| netifd F2–F5/F10–F12；procd F3 | 沿用 R90 生命周期修复及已声明的差异；不重复把它们记为 R92 新修复 | [R90](R90_BATCH1_LIFECYCLE.md)，正式 `procd-r90`、`netifd-suite` |
| netifd F6 接口级 restart | 撤销误报；精确镜像原本没有这个方法，不能引用较新源码扩充接口 | [R91](R91_NETIFD_LOGGING.md)，精确 C 方法表 |
| netifd F8 日志 | 纳入 R92 正式构建与部署；恢复默认 syslog、级别过滤、脚本日志和重连 | `netifd-suite` 内 R91 九场景双侧；日志文本、分帧及 udebug 边界仍按合同 |

## 第 2 批：异常恢复与资源边界

| 项目 | 处置与可达性 | 回归证据 |
|---|---|---|
| ubusd U-2 半关闭慢读 | 修复。EOF 后取消读就绪，已有输出排空后关闭；R89 在 0.8 秒观察中消耗约 0.79 CPU 秒，候选为 0 | `ubusd_halfclose`；正式候选完整回复、关闭并继续服务。原版不空转，但不保证完整回复 |
| ubusd U-8 遍历中删除 | 修复。保存下一路径的 owned 下界，从删除位置继续，避免重复回复；精确 C 对照可崩溃，不复刻悬空指针 | `ubusd_lookup_delete`：无重复、遍历到末尾、继续服务 |
| netifd F7 netlink 溢出 | 修复。真实 ENOBUFS/截断触发有界扩容、完整设备与载波重同步；失败 dump 保留重试 | `netifd_overflow`：两侧 drop 计数实际增长，均看到被删除设备及后续事件；候选 buffer 131070→262140 字节 |
| procd F5 总线断连堵日志 | 修复。断连期间继续排空 stdout/stderr，维护回收、定时器并重连 | `procd_disconnect_logs`：超过管道容量的 writer 在断连中继续前进，重连后完成 |
| procd F6 非 PID 1 喂狗 | 有意改进共有缺陷。精确 C 在该模式只写一次；候选继续维护节拍 | `procd_watchdog`：模拟 WDTFD 计数 C 1→1、候选 1→4；未触碰主机或物理看门狗 |
| httpd H-07 batch 放大 | 修复候选整批 materialize。逐项序列化、写出并 flush，写失败停止后续 RPC；原版慢读同样可能积压 | `httpd_batch`：52691 字节请求，投影回复 21352000 字节；C 峰值 RSS 25660 KiB、候选 1720 KiB；完整顺序和继续服务通过 |
| rpcd F2 提前关输出 | 保留候选有界生命周期。关管道后继续等待真实退出，到 deadline 回 TIMEOUT 并回收；原版有输出时可提前回成功且留下子进程 | `rpcd_closed_output`、`rpcd_closed_empty`；区分有输出及完全空输出两条路径 |
| rpcd F3 输出超限 | 保留候选有界回收。超过 256 KiB 关闭两管道、等待短宽限后杀死并回收直接子进程；原版可留下存活子进程 | `rpcd_output_limit`：返回 NOT_SUPPORTED，候选子进程已回收，后续 RPC 可用 |
| logd F4 慢读积压 | 作为共有资源治理处理。1 MiB/流、4 MiB 总排队、64 流；达到边界断开滞后者，资源释放后可再接入 | `logd_slow`：C RSS 820→17396 KiB，候选 364→456 KiB；`logd_limits` 覆盖初始 backlog、65th stream、总预算及恢复 |

边界：batch 仍保留至多 65536 字节输入 JSON 树和单个 RPC 的回复；这不是任意 RPC 都有固定回复
字节上限的保证。logd 的策略会让落后客户端失去实时流，需重新连接；不能宣称无损无限缓冲。
RPC/脚本回收验证的是直接子进程，不外推为任意自行脱离的孙进程也会被收回。

## 第 3 批：协议与数据兼容

| 审计项 | 处置 | 对照/回归门 |
|---|---|---|
| HTTP H-02 | 修复顺序：RFC1918 检查→TLS redirect→100 Continue | `httpd_policy` |
| HTTP H-04 | 修复 `-E` 对文件/目录 403 的处理，递归有界 | `httpd_files_cgi` |
| HTTP H-05 | 保留完整 chunk terminator；原版 header error 可缺结束符。选择可完整解析的 framing | `httpd_date_framing` 原始字节断言 |
| HTTP H-08 | 保留 chunk extensions 与有界 trailers；超大 chunk 改为立即拒绝，长度不得超过 INT_MAX | `httpd_date_framing`、133 例 `httpd-fuzz` |
| HTTP H-09 | 保留 framing 错误 HTTP 400 + close；不复刻原版 `/ubus` 的 HTTP 200 + JSON parse error | 22 项逐项合同及 fuzz |
| HTTP H-12 | 修复重定向 TLS 端口选择：同族、实际成功 listener、优先 443 | `httpd_policy` |
| HTTP H-13 | 修复裸端口同时尝试 IPv4/IPv6；按解析结果处理主机名 | `httpd_policy`、listener 回归 |
| HTTP H-14 | 修复 CGI 三字符 Status 的 atoi 前缀语义，含 `abc`→`000`、符号及数字尾字符 | `httpd_files_cgi` |
| HTTP H-15 | 保留线程唤醒次序；不保证原版 LIFO。客户端合同不依赖 LIFO，不增加全局排队结构 | `httpd_script_queue`：槽位上限、每请求仅执行一次、全部完成 |
| HTTP H-16 | 错误码按原版；保留断连后的重连和 deadline，原版可能长期失效或 lookup 无超时 | `httpd_bus_errors`、`httpd_bus_timeout` |
| HTTP 既有 22 项畸形请求 | 每项固定原版、R89、R92 响应及处置；不是“畸形请求均可忽略” | [r92-deviations.json](../../tests/reference/httpd/r92-deviations.json)；133 例只允许 header-ctrl、chunked-huge-size 相对 R89 改变 |
| ubusd U-3 | 短 raw attribute 按 4 字节补齐继续走；SIGNATURE 短成员按原版类型创建失败处理 | `ubusd_wire` |
| ubusd U-4 | 复用 OBJTYPE 且同时有 SIGNATURE 时补回 OBJTYPE | `ubusd_wire/reused_type_reply` |
| ubusd U-5 | 同名 event 字段取首个类型正确字段；object 仅 INT32，保留事件名字节 | `ubusd_wire` |
| ubusd U-6 | 长 TARGET 读前 4 字节；不足 4 字节有意 INVALID_ARGUMENT，不复制跨 attribute 读取 | `target_first_four`、`target_short` |
| ubusd U-7 | ACL 的 methods/tags 仅 ARRAY、私有 acl 仅 TABLE，错误类型不能授予权限 | `ubusd_acl_types`，非 root 可见性 |
| ubusd U-9 | 修复批量前缀回复的 padding 估算，debug assertion 不再由非 table 签名触发 | `ubusd_wire/padded_prefix`、debug 单测 |
| rpcd F4 fnmatch | 对齐精确 musl，包括非法 bracket、POSIX class、Unicode 字符及 login 转义 flags | `rpcd_compat` 的 18 个 glob 控制 |
| rpcd F5 非 UTF-8 授权标识 | 保留拒绝策略；非法函数不提升授权，非法 ACL 文件整体拒绝，sid 返回 INVALID_ARGUMENT | `rpcd_compat`：grant/revoke/no-promotion、ACL 文件、sid |
| rpcd F6 UCI values | 修复 get/state 的 U+FFFD 转换；线上 blob 保留原始值字节 | `uci_get_bytes`、`uci_state_bytes` |
| UCI U1 非 UTF-8 rename | 原子拒绝，不写替换字符或半完成状态。纠正旧审计：“C 同 batch 直接显示原始名字”不成立；C 的非法 delta 在重新加载时被忽略 | `uci_rename` 双侧；修正后的 `uci-r83`；不声称 C 必然删除 delta 文件 |
| logd F2 截断 | 按原始字节 LINE_SIZE−1=1023 截断，不退到字符边界 | `logd_bytes` |
| logd F3 非 UTF-8 数据报 | 改为保留原始字节，包含 `log write`；撤销旧的有损转换策略 | `logd_bytes`，既有 r15/r28/stream/ring 门 |
| fw4 F3 start/reload | 按精确 shell pipeline 继续阶段，缺状态最终 exit 1；print 中止 exit 254 | `abort_print/start/reload` |
| fw4 F5 usage | 空行、文本对齐镜像 wrapper | `usage` |
| fw4 F6 无 ubus warning | 补原版 warning；同次加载复用连接，失败只报一次 | `no_bus` |
| fw4 F7 errno | 保留准确的本次 errno；不复制 ucode stale errno 和解释器 backtrace | missing/directory/notdir/loop/write-state 对照；[fw4 合同](../../docs/contracts/fw4.md#5-r92-cli-与特殊输入) |
| fw4 F8 fractional log | 修复 `0.5` 的 action 链选择，先按 ucode 数值真值再取位图 | `fractional_log` |
| fw4 F9 any device | 撤销未复现假设；精确 ucode 实际生成规则与候选一致 | `any_device` |
| fw4 F10 include signal/timeout | 使用实际负信号号；超时杀死并等待直接子进程 | `include_signal`、`include_timeout`，用 `exec sleep` 固定回收边界 |
| fw4 F11 monthdays | 撤销未复现假设；NaN/小数实际行为与候选一致 | `month_nan`、`month_fraction` |
| reload-config F2 | 保留 4096 个去重 basename 上限，失败前不执行 uci/md5sum/ubus；写入合同，非静默丢项 | 4096/4097、重复/隐藏文件、基线不变单测；[合同 §11](../../docs/contracts/config-change-dispatch.md#11-资源边界与转义r92) |
| reload-config F3 | 统一 byte-oriented JSON 转义，trace 与 ubus payload 共用 | 全部 32 控制字节单测、正式 r1 |
| procd F7 bundle-only | 修复不带 command 的 OCI bundle；同时给两者时仅把 bundle 交给 ujail | `procd_bundle`：argv、spawn、running |
| procd F8 watchdog reset 日志 | 补支持位、CARDRESET、GETBOOTSTATUS 分支及原版诊断 | `procd-watchdog-status` mock ioctl 五结果；不制造硬件复位 |
| netifd F9 global restart | 改为延迟同 PID re-exec，重建对象并保留 argv | `netifd_restart`；区别于已撤销的接口级 F6 |

HTTP H-01/H-03/H-06/H-11、ubusd U-1、rpcd F1 等 R89 已修项仍由本次完整门保护。
procd 丢尾修复、200 ms 维护节拍和 ubusd 既有队列合同等非本批新增差异继续按各组件合同执行，
不能把这份清单解读为九组件对所有异常输入完全等价。

## 第 4 批：性能与内存的处置标准

该批不以“每项必须更快”为完成标准；先复测同一正式 R89、量化离散度和资源，再决定是否改实现。
具体数值、逐轮范围及保留决定统一见 [R92 性能报告](R92_PERFORMANCE.md)。

| 原缺口 | 新证据 | 结论边界 |
|---|---|---|
| c4 尾延迟波动 | 同一启动三侧四轮，ubusd/procd 另做 CPU 0 affinity 与独立 syscall trace | affinity 同时限制服务端和客户端；没有 perf/IRQ 跟踪，不能声称证明唯一调度根因 |
| HTTP JSON-RPC c4 CPU | C/R89/R92 完整 HTTPD 矩阵；额外 configs/get 两方法、两依赖栈及同机 live 控制 | 隔离矩阵的 configs 与整机 get network 不是同一种输入，分别给结论 |
| HTTP H-10：50 ms 停放/重建 | 构建机 66 组、实机 42 组 gap/内存/trace；另 60 组新连接 HTTP/TLS 真 netem | gap 不是 RTT；新连接明文 HTTP 与 TLS 不能共用 clone 结论；未改路由器管理链路 |
| 连接关闭后内存 | 实机 40 次及构建机 500 次×64 连接，两轮三侧，逐轮 fd/线程和 RSS | 平台期支持有限保留；不能证明所有工作负载永远无泄漏 |
| MemAvailable 少约 6–7 MB | 四窗口 mincore、dev/inode 去重；独立两次仅对非运行副本的 advice/重读控制 | 文件页、RSS、MemAvailable 不可相加；不使用全局 drop_caches，不声称全部差额来自同一因素 |

## 第 5 批：覆盖与发布

| 缺口 | 处置及证据 |
|---|---|
| hotplug 启动后存活 | 正式 `procd-r71-hotplug` 命令确实包含 `R90_HOTPLUG_PROBE=1`；延迟 coldplug 子进程后再触发 uevent，断言队列继续执行。设备四冷启动是另一个健康层面的证据 |
| netifd_vrf 偶发差分 | 固定两侧相同的 apk 版本夹具，移除 EOF/SIGCHLD 的夹具竞争；保留真实 apk 与信号注入的 feature 门，不把环境探测值静默 mask |
| getFeatures Unicode | 新发现并修复非 ASCII 版本切片 panic；正式 R89 反例退出，C 存活，正式 R92 通过 |
| luci-rpc 畸形 DHCP 标识 | 新发现并修复 DUID/IAID 字节边界 panic；正式 R89 反例退出，C 存活；R92 线上调用与后续服务通过 |
| iwinfo/rrdns 缺参/坏输入 | iwinfo 全部带 device 方法缺参和不存在设备、100 次失败打开 fd 稳定；PTR 截断、坏 additional、指针环、无关 ID、短包后恢复；正式双侧门 |
| 无线覆盖 | 四窗口共 212 调用、4 次扫描、28 组；两个 radio 精确动态库清零/置位/再清零 flags 控制；固定邻居 add/remove/NOARP/stale；262144 个固定 HT IE；同启动完整 HostHints JSON 对照 |
| freqlist flags | 确认为原版调用者缓冲未初始化。R92 与清零 C 逐项一致；保留确定的内核 flags，不复制随机限制位，也不当信号波动遮罩 |
| 跨窗口地址/扫描变化 | 非 IPv6 字段及其它 scan 静态字段仍严格比较；单列地址成员变化和两条 HT width 差异。历史邻居表/原始 IE 未采，固定输入控制不是历史帧重放，不能证明 AP 当时实际改变带宽 |
| UCI 内部复核 | 复核缓存、delta、文件事务、快/一般解析器及失败保持；正式单测、r16、r24 1000 例、修正 r83 通过；精确参考源码 SHA 单列 |
| HTTP 缓存注释 | 对齐精确 musl 镜像：IMS/IUS 因日期解析失败被忽略，ETag 生效；同响应 Last-Modified 往返对照，合同同步 |
| 4096 上限、README、保留包 | 合同显式化；最终 README 指向 R92；保留精确 C、正式 R89、已接受 R90 和当前 R92，其余三包先离线全读/hash 后删除；R90 回退须先重装对应 APK |

正式验证汇总为 69 道门，其中 68 道必需门通过；C procd busy 的既有丢尾控制项失败保留。
Rust 是 449 个不同 crate 内测试名、450 次执行：rpcd wake-pipe 测试同时编入 library/binary，
不能把重复执行算成两个独立测试。netifd 31/31，无跳过；HTTP fuzz 133 例；fw4 上游 31/31、
r29 200/200，原版 23 次 ucode 崩溃单独保留。

正式采集期间的三个夹具失败没有修改运行时来迁就：sudo 丢失 HELPERS 使用旧 probe、
fd 基线采得早于 EOF 清理、UCI r83 未应用原子拒绝合同。旧结果保留，修正工具后由正式产物
复跑闭合。性能采集的 SSH 超时、deleted-mapping 失败，以及 HostHints 小数 sleep、HTTP 探针
把成功的空 ubus 回复当 JSON 的夹具失败，另列在部署证明；旧失败保留，不能改写为从未失败。

这批完成的是上述已列问题的修复或明确处置及对应回归，并非全源码形式证明。
尚不能外推的范围包括任意 udebug/debug 行为、所有无线脚本路径、所有硬件/国家码、任意孙进程
逃逸、任意长期负载和不同内核上的调度表现。真实硬件看门狗复位没有为了测试而触发。
