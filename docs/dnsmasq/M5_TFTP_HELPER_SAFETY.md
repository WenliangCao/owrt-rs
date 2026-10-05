# M5 TFTP/helper/dump 静态审查

本次覆盖下面 13 个生产文件的完整非测试代码。没有把 `cfg(test)` 中的
故障注入 unwrap 或 ptrace 工具当作产品路径，也没有把静态审查记为最终
运行资格。dump 按主代理的 `37c187e1` 单 owner/Rc 版本只读核对；其产品
修改由主代理承担。最终 freeze 后还要绑定实际文件 SHA 和统一重跑证据。

| 文件 | 覆盖与保留依据 |
| --- | --- |
| `tftp.rs` | RRQ/ACK/ERR 先检查长度再访问 opcode、block、字符串；无 unsafe 或无条件 unwrap。 |
| `tftp_service.rs` | `if_indextoname` 使用清零的 16-byte Linux 名称缓冲；成功保证 NUL 后转 CStr，失败不解引用。其余消息/路径长度按调用边界检查。 |
| `tftp_runtime.rs` | `TransferTable` keys/values 使用相同 ID 顺序。admission index 来自立即 preceding active snapshot，没有中间回调/修改。网络未知 ID/TID 在 receive 入口返回明确错误。内部 map unwrap 只跟随同一可变 owner 的已证明 live ID。active 创建前完成 file slot；prune 仅移除没有 active 引用的 slot，所以 file index/Some 可保留。 |
| `tftp_listener.rs` | pending 的固定 waiting 数只 pop 初始成员，callback 不获得 self；Occupied/插入成功的 transfer socket lookup 保持 live。setsockopt 接收 live native int，ioctl 使用 40-byte aligned zero ifreq，名称少于16、MTU字段固定4 bytes。getrlimit 接收两 native unsigned long。FD/route/读取失败走 io::Result。 |
| `tftp_policy.rs` | 接口策略及 root/per-peer 后缀走 bounded 数据与明确拒绝；无 unsafe 或无条件 unwrap。 |
| `config/tftp.rs` | 参数/范围在配置边界规范化；不引入新的共享锁。 |
| `helper.rs` | 事件是 owned snapshot，old/del 名称与当时 transient fields 由调用者提供；无 unsafe 或无条件 unwrap。 |
| `helper/process.rs` | pipe 成功后每 FD 仅转 OwnedFd 一次；fcntl 调用期间保留 pipe owner。getpwnam 仅 sole startup thread，NULL gate 后复制 UID/GID。fork 在单线程 startup，child 用 _exit 不回到 parent ownership graph。poll/waitpid 保留 live native structs 且 WNOHANG。close_inherited 先销毁 /proc iterator，再 child-only close，保留 commands/events。零组 NULL、UID/GID 与 SIG_DFL/IGN 使用精确 Linux ABI。pre_exec 只改 SIGPIPE、不分配或访问共享 Rust state。 |
| `helper/wire.rs` | MAX_FRAME、Reader::take(count) 与类型/字段长度在解码边界检查；固定 4/8/16-byte try_into unwrap 的长度由 take 保证。未知类型/短帧返回 invalid，不走网络 panic。 |
| `helper/packet.rs` | enterprise value 长度 >5 才取前4与 length byte，block 用 get 范围检查；长度转换 unwrap 已被这些 guard 证明。 |
| `config/script_arp.rs` | 参数与开关纯配置消费者；runtime helper 行为通过已有子进程通道，不引入 Mutex。 |
| `dump.rs` | metadata Some 分支、24/16-byte read_exact 缓冲、queue front 非空循环证明各固定转换/pop。Rc<RefCell> 仅单 poll owner 同步 producer 使用；writer 构包/write/notices 不回调 producer，signal handler 只更新原子请求，因此没有嵌套 borrow。FILE I/O 错误走 notices/typed errors；主代理已移除 Mutex poisoning unwrap。 |
| `config/dump.rs` | 普通 base0/sign/trailing grammar 和 signed-long saturation 已实现；VT 差异已交主代理，在 `0e6fb560` 改为 C 的六种空白。需要 fresh PCAP 复验，静态修复不冒称通过。 |

本次未发现可由当前网络/IPC输入触达的无条件 unwrap/expect panic。
保留点是上述固定长度或单 owner 状态不变量；没有把真实 I/O、credential、
未知 peer/ID 或 malformed frame 的失败边界改成 panic。helper 的 stdout
take 在 successful spawn + Stdio::piped 后始终 Some。helper/TFTP 没有可去掉
的生产 Mutex；dump 的旧 Mutex 已由主代理处理。

helper 的 pipe/fd/passwd/fork/wait/signal/credential/pre_exec 不变量补成邻近
SAFETY 注释，TFTP 的 active/file-slot 和 admission-index 不变量也补在其
定义/调用点；这些修改只补证据说明，不改变执行行为。
