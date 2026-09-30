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
| check_tftp_fileperm():543–624 | open后fstat避竞态；root须world-readable；secure owner；同inode+dev+path共享FD | `tftp_service::permitted`；文件打开、fstat、引用共享仍由调用方持有 | C path oracle 255,528例；权限 predicate 单测；不计整机完成 |
| tftp_request():51–366, dnsmasq.c:1862 | 接口检查、IPv6 pktinfo、独立/单端口、transfer上限 | `tftp_service::admission` 仅覆盖已授权 peer 的 single-port/limit 决策；socket/pktinfo 未接线 | C/Rust path+admission boundary；不计 daemon 完成 |
| tftp.c:724–761, free_transfer():852, do_tftp_script_run():1037 | 成功入helper队列后释放；错误直接释放；single-port不能关闭listen FD | `admission` 返回 Replace/Existing；旧 transfer、FD、helper queue 仍由调用方处理 | 不计整机完成 |

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

剩余：协商与ACK/重传/错误的整机差分、打开后 fstat 与 inode 引用共享、netascii 连续多块、窗口丢包/
乱序、single-port/TID、接口变化、脚本、FD上限及退出清理；全部保留在交付门内。
