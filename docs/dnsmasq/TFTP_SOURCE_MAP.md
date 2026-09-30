# TFTP 源码映射与阶段证据

源为 `prepare_reference.py` 核验并应用 OpenWrt 两份补丁的 dnsmasq 2.93。
`src/tftp.c` SHA256 `a6971bf4ce77c0ca4c7ebf0194a2ee9c2ad702b1b8a882d46de87c6c6f5e63f3`。

| C 位置 | 行为与不变量 | Rust `src/tftp.rs` | 对照/状态 |
|---|---|---|---|
| tftp.c:369–444, next():856 | RRQ/WRQ、非空NUL字符串，残缺option停止；mode大小写不敏感；option后者覆盖前者 | parse_request | 固定独立单测；完整C协商差分待补 |
| tftp.c:398–437 | blksize按共享buffer和MTU限额；IPv4/6开销32/52；netascii不协商tsize/window；timeout允许0 | Options | 固定单测；整数溢出差异见下 |
| get_block():916–956 | OACK固定blksize/tsize/timeout/windowsize顺序；file size只发低32位 | Options::write_ack | 固定报文，不是Rust自生期望 |
| get_block():967–1028 | 二进制offset；offset==size发空块；只将LF变CRLF，跨块carry防止重复CR | file_offset/encode_netascii | 原C函数抽取：97,384例0差异，含ASan/UBSan |
| handle_tftp():769–850 | ACK16位绕回；先更新high/previous再判断重复/未来ACK；确认才推进offset | Transfer::receive | 固定边界用例；状态机C差分待补 |
| check_tftp_listeners():671–735 | >120秒超时；重传指数backoff；OACK窗口1，数据窗口≤32 | expired/begin_window | 固定超时边界；C事件循环差分待补 |
| check_tftp_fileperm():543–624 | open后fstat避竞态；root须world-readable；secure owner；同inode+dev+path共享FD | `tftp_service::permitted`、`RealFileOpener`、`TransferRuntime::SharedFile` | C path oracle；真实文件和权限单测；C/Rust服务错误码与共享FD差分 |
| tftp_request():51–366, dnsmasq.c:1862 | 接口检查、IPv6 pktinfo、独立/单端口、transfer上限 | listener按TransferId管理独占dedicated socket；single-port按peer替换；保留C的dedicated `active<=max`门与排队 | `TFTP_LISTENER_PHASE.md`、`TFTP_SINGLE_PORT_PHASE.md`；仅isolated loopback，接口选择未完成 |
| tftp.c:303–357 | 按端口范围低端起试；仅EADDRINUSE重试；start=0用ephemeral；single-port忽略range | `TftpListener::bind_with_port_range` | `TFTP_PORT_RANGE_PHASE.md`；IPv4/IPv6 38项0差异，包括耗尽/释放/错误回收 |
| tftp.c:724–761, free_transfer():852, do_tftp_script_run():1037 | 成功入helper队列后释放；错误直接释放；single-port不能关闭listen FD | completion/error/timeout释放对应TransferId/socket/file；server socket存活；helper queue未接 | isolated FD/端口回收、真实120秒timeout及关闭；不计helper/整机完成 |

C netascii 对每个LF移动剩余后缀，换行密集块为 O(B²)。Rust一次顺序扫描 O(B)，
每字节输出至多两次。独立代理已核查两实现的 expansion/carry 分支和ACK恢复点。
这只是局部算法候选，CPU、内存和端到端收益尚未测量。

差分工具 `tools/dnsmasq/tftp_oracle.py` 直接抽取已核验原C `get_block()`，只替换
文件读入为相同输入内存；比较 DATA 字节、expansion、carry_lf，期望非Rust生成。
私有证据：`private/dnsmasq-rewrite/tftp-oracle-02/result.json`，固定枚举、seed
`0x293001` 变异和最大块回归。该工具不证明socket、权限、OACK或完整传输行为。

独立review发现首版工具的8192字节buffer未给4字节DATA头留空间；原语料最大4092
未触发。已修为8196，增加六个8192极限用例并开启ASan/UBSan，保留首版记录。
最小复现在 `private/dnsmasq-rs/wire/review-tftp/`，这是测试器缺陷，不是C原程序缺陷。

明确差异：C `atoi` 的有符号int越界输入没有可移植定义，Rust返回NumericOverflow；
配置MTU令块长度为0时Rust拒绝，尚须保留端到端原C最小复现，不能据此声称C漏洞。
普通负值转换为unsigned再clamp（如timeout=-1→255）保持C行为。

近期服务证据：dedicated与single-port的IPv4/IPv6、同peer并发/替换、窗口partial/duplicate ACK、
错误、FD耗尽/恢复及端口范围已进入真实C/Rust差分；具体覆盖和失败记录见各listener阶段报告。
single-port参考C的旧DATA与FD泄漏差异明确保留，不能计作0差异。剩余包括完整协商边界、
netascii连续多块、任意丢包/乱序、接口变化、helper/PXE、广义内存/发送故障和OpenWrt生命周期；
现有loopback证据不替代整机交付门。
