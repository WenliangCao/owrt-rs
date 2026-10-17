# K 相对 v0.2.0 的 unsafe 与编译警告检查

范围：v0.2.0标签`ded73bae75f44269c93366593481d866a2e68e35`与K源
`4ce24c627615ae5ff42d3dcdbccb66d57b218b5a`；正式集成的181输入digest与K一致。
只记录，不清理旧警告，不改产品。首次失败CI与最终成功CI分别列示。

## unsafe结论

**发货代码没有新增unsafe块；删除了1处fcntl调用，1处既有from_raw_parts只是移入分支。
真正新增的7个unsafe调用块全部位于cfg(test)，另有1个测试内extern声明。**
逐处检查未发现这些新增测试调用缺少必要性或违反已列的内存/所有权/ABI前提；这属于
针对差分的静态审阅与既有运行证据，不宣称对全项目unsafe作形式化证明。

| K位置 | 必要性与安全前提 |
| --- | --- |
| source_sockets.rs:445、446，fcntl(F_GETFL/F_GETFD)，测试2处 | 标准UdpSocket API不暴露这两个状态；需直接验证NONBLOCK/CLOEXEC实际安装。Linux cfg下命令3/1无需第三参数；FD由活跃UdpSocket唯一持有，仅读状态，无指针或所有权转移。 |
| listeners.rs:591、625，getsockopt，测试2处 | 验证静态IPv4确实关闭pktinfo，动态/广播/IPv6保留原策略。限Linux64；活跃FD、独立且对齐的i32输出与u32 socklen，入口长度4，写入不超过对象，引用覆盖同步调用且内核不保留指针。 |
| net.rs:896，socket(AF_INET,SOCK_RAW\|SOCK_CLOEXEC,IPPROTO_UDP)，测试1处 | 生成普通UdpSocket不能表达的零UDP源端口负例；参数仅标量，返回FD先检查非负，运行受原Linux隔离测试入口约束。 |
| net.rs:899，OwnedFd::from_raw_fd，测试1处 | 对刚创建且检查成功的FD仅转换一次，后续只有RAII拥有者关闭；assert或其他错误退出也由Drop释放，不重复构造所有者。 |
| net.rs:904，sendto，测试1处 | 9字节初始化报文和32字节对齐Address储存均存活，传入IPv4实际16字节地址；无重叠可变别名、无异步指针留存，返回值检查完整发送。 |

既有发货unsafe的相关变化亦核对：

- source_sockets.rs的socket调用改用Linux原子SOCK_NONBLOCK/CLOEXEC；仅改变标量kind，
  fd错误检查→单一OwnedFd→UdpSocket所有权链不变，原单独F_SETFD unsafe已删除。
  非Linux继续原set_nonblocking，不使用Linux常量。没有新增缓冲区或裸指针。
- net.rs:616的from_raw_parts与旧版本表达式相同，只在需要pktinfo时执行。底层是已初始化
  `[u64;5]`，转u8后只读长度`min(msg.controllen,40)`，不越40字节分配，读取发生在recvmsg
  返回后，切片不逃逸栈作用域。静态DNS分支跳过这次读取，不扩大原unsafe范围。
- D1、D2及K双族hint没有新增unsafe；新增地址转整数仅用于身份比较，不从整数重建引用或
  解引用。报文操作仍用受检查的Rust切片与现有所有权/RefCell边界。

新增测试分别为`udp_factory_returns_nonblocking_close_on_exec_descriptors`、
`dns_socket_bound_ipv4_metadata_policy`、`static_dns_ipv4_preserves_zero_port_and_receive_errors`。
它们属于K既有Linux/SDK资格证据，本检查未重复构建、扩大测试或更改源码。

## 清理取舍

用户随后允许酌情清理。工程判断是本次仍交付精确已验收K：源码或FFI声明清理会改变
181项冻结输入，可能影响PGO/ELF身份；不能把它当作无需复核的编辑，也不以allow或
诊断过滤隐藏warning。必要的FFI unsafe保留，数量归零不是安全保证。

后续可单独处理的清单：2项unused imports、2项unused mut、2项unused variables、
1项drop Copy；1个未使用方法须先确认外部语料/测试接口。14项extern声明冲突应逐个
核对实际目标ABI后统一声明，不能盲用cargo fix或笼统抑制。SDK/Kconfig的39项提示属于
固定SDK环境，不能为日志整洁改动原厂包/驱动依赖。本次没有因此新增产品改动。

## 实际编译警告

比较口径固定为实际v0.2.0正式CI38636115402与本次成功CI的同类编译日志，去除ANSI、
宿主路径和行号差异，分别统计真实warning诊断与Cargo的“generated N warnings”汇总，
汇总行不再次计为诊断；还检查新增类别/消息，不能只比总数。

首次CI39006620445因为2858条PGO missing停在身份门，不能把这批失败当最终发布的
警告基线。另有22条普通Rust诊断、3条Cargo汇总及SDK/Kconfig提示，分别保留，
0 CFG/hash mismatch；此前按所有含warning文本行计出的31不能称为31条普通Rust诊断。
最终成功CI为[39007479025](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39007479025)，
提交867c9c53。与实际v0.2.0原日志逐类别/消息多重集合比较，**warning未增加，既有warning
原样保留**，没有使用allow、过滤编译输出或修改产品来降低计数。

| 实际构建日志 | v0.2.0 | K正式CI | 新增/消失 |
| --- | ---: | ---: | --- |
| dnsmasq Rust诊断 | 22 | 22 | 0/0 |
| dnsmasq库/程序Cargo汇总 | 21/1 | 21/1 | 汇总行不重复计数 |
| dnsmasq SDK/Kconfig提示 | 39 | 39 | 0/0 |
| PGO missing诊断 | 0 | 0 | 0/0 |
| netifd Rust诊断 | 41 | 41 | 0/0 |
| rpcd Rust诊断 | 1 | 1 | 0/0 |
| 其余七个发货组件Rust诊断 | 0 | 0 | 0/0 |

dnsmasq的22条细分为extern声明冲突14、unused imports2、unused mut2、unused variables2、
dead_code1、drop Copy1。全部11份同类日志（另含不发货的switch辅助包）类别/消息均一致；
并非只比较总数。原v0.2.0 ZIP与35项清单、本次ZIP与36项清单均校验通过，最终CI的
PGO profile/ELF身份门通过，未用失败CI的计数作为“清零”基准。

脱敏比较结果源自`private/release-v0.2.1/warning-review/warning-comparison.json`，SHA256
`abaee13f26280b3168912f6b9d71cd04f90ea5d8ca8d27d43196ceae0da09561`。原日志在本次上线
验收完成前保留，之后按用户清理要求删除；本记录及Git历史保留。用户确认的0.2.2清理
方向属于后续独立工作，0.2.1继续使用原K产物。
