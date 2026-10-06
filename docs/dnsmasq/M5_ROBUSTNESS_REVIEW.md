# M5 健壮性审查

收尾审查仍在汇合，最终源码身份和同 ELF 实际回归尚未冻结。这里记录已完成的审查边界，不把静态检查或仅构建当运行通过。

主代理已审查 `main.rs`、`dump.rs`、`net.rs`、`listeners.rs`、`interfaces_broadcast.rs`、`startup.rs`、`startup/{daemonize,lease_init}.rs` 和 `dhcp/*.rs` 的生产网络、文件与定时器路径。代理继续审查 DNS/cache/source sockets、接口/config、logging、TFTP/helper；完成后补全本表与最终身份。

| 范围 | 已处理的边界 | 保留的不变量 |
| --- | --- | --- |
| 单 poll owner 与 dump | `37c187e1` 将 ParentDns、ParentEvents、接口快照、DHCP provider 和 PCAP writer 的 Mutex 改为 Rc/RefCell，去掉 callback 的 Send 约束。 | Rc 使这些状态不能跨线程。短借用在 socket 等待前结束；DHCP probe 活跃期间移出当前 DHCP owner，metrics 用显式快照，helper/清理用 try_borrow_mut，不能借用则留待下一回合。信号处理只访问原有原子标志。只读 TCP 视图继续保留其接受时快照。 |
| main 的网络与定时器 | 删除全部生产 unwrap/expect；缺失 deadline 采用立即 poll，其他缺失状态显式退出当前路径；取消 reload 中未使用的事件锁。 | 恢复、探测与旧 TCP 视图的发布边界保持原先顺序。RefCell 的内部排他借用由同一 owner 的结构约束；重入入口用可失败借用。 |
| DHCP daemon、状态机与租约 | `e79fdf13`、`0e6fb560`、`6e3a8bc8` 给失踪租约、缺失PXE套接字和定时器长度返回已有错误类型；恢复、命名、helper 队列的 Option/Result 传播替代 panic。 | 已提交租约、名称丢失、持久化及日志依然先于 send。错误不发伪造回复，provider 仍回到 owner。BOOTP header 字段使用 parse 后的固定字节数组。 |
| net/listeners/startup | syscall 的指针长度、FD 唯一归属、sockaddr/ifreq/timeval/capability 布局与 fork 边界均有 SAFETY；固定数组转换去掉不必要 unwrap。 | FFI syscall 返回值与系统错误保持原处理；fork 时无服务线程或未结束借用。libc passwd/group 记录在下一次同类查询前复制。 |
| DHCP 剩余固定转换 | packet/relay/PXE/filewatch 只在已有最小长度和帧范围验证后转换；lease_file 在全部 token 存在检查后取值，十六进制 digit 在 is_ascii_hexdigit 过滤后转换。 | 没有以默认值掩盖外部格式错误；slice reader 不能产生 I/O 错误且无实际可达的 usize::MAX 记录上限。 |
| DHCP 文件状态机 | files_runtime 的 job 与 generation 在创建处成对建立，私有状态只由单 owner 转移，解析/读取失败仍返回原诊断；job 完成后才取出。 | 此类内部状态 unwrap 已逐处审查，外部文件内容不能令 generation 或 job 消失。测试 unwrap 保留为断言，未机械替换。 |

`37c187e1` 在 Linux 实际通过 692 库测试和 10 main 测试，19 ignored 不计。M2 TCP 的 10 配对/3负控和真实 DHCP ping-conflict 配对通过；源版本及 ELF 为 `bcebb72d…64074f`，1,912,872B。完整 SHA+metadata 已核验并清远端，见 [预检证据](../../private/dnsmasq-rewrite/evidence/M5/unified-preflight/refcell-preflight/)。

`e79fdf13` 也已实际通过 692+10 Linux 测试，19 ignored 不计。后继 DHCP 状态错误传播与 dumpmask VT 修复须在新候选继续实际复测；最终各族、M2、资源/压力和APK结果在完成后统一记入报告。

收尾分工已交审查：[DNS17模块](audits/20261006/DNS_RUNTIME_SAFETY.md)、[config29/接口/hosts审查](audits/20261006/config-interface-safety-review.json)、[TFTP/helper13模块](M5_TFTP_HELPER_SAFETY.md)、[logging审查](M5_LOGGING_SAFETY_AUDIT.md)。后继device binding、typed PID和截断notice属于已审模块的显式增量，最终源码身份/回归结果仍需汇合。新device service不保留新增PXE unwrap；last errno按C两次实际syscall站位，包括后继ignored EPERM。
