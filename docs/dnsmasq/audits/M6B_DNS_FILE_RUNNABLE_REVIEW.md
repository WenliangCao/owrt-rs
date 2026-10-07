# DNS 文件续步与同次唤醒的重载边界

本审查针对无A产品4816b19f的实际DNS-files失败，不修改物理设备。最小逻辑续步修复提交为32af4734；实际镜像C回归与Linux运行资格由主线程记录，本文的读码和本地typecheck不能代替运行。

## 当前请求丢失续步

原main在一轮服务结束后消费HUP，`reload_data`后向`DnsFiles::request(Signal)`添加逻辑trigger。`DnsFiles::append_poll_fds`只登记watch、FIFO job和endpoint worker pipe；新的trigger尚无fd。普通wait仅使用上一轮`FileStep.runnable`，于是无resolver watch的servers-file或已排空watch的no-poll请求可以睡到下一次DNS网络活动，先使用旧bank响应，再开文件/发布新bank。21个实际失败由主线程保留完整证据，不因本审查而改记通过。

32af增加只读`DnsFiles::runnable`：无等待job时requests/triggers/notify可立即运行；regular reader立即续步；FIFO及未完成endpoint worker等fd，后续trigger不能跳过它们。main用与`step_dns_files`一致的hosts/interface/DHCP文件前置门判断DNS逻辑work，连旧的cached runnable也被该门约束。既不增加普通空闲timer，也不读取无就绪的inotify。新增三个Linux门覆盖无watch的两代servers-file发布、held hosts FIFO保留请求、held servers FIFO及后续Signal不忙等；本地aarch64-linux-musl类型检查通过。

精确C在`dnsmasq.c:1570–1596 EVENT_RELOAD/INIT`先`clear_cache_and_reload`，再同步读取no-poll resolv和servers-file，再`check_servers`；`network.c:1699–1724 reload_servers`、`option.c:5848–5870 read_servers_file`是读取/发布边界。Rust有界输入保留既定FIFO行为差异，普通有效输入的发布顺序仍须相同。

## 独立风险：HUP与DNS同时就绪

C在`dnsmasq.c:1263–1264`处理signal pipe的`async_event`，之后才在`:1308–1309`调用`check_dns_listeners`。普通UDP在`:1986–1990`消费，TCP在`:1993–2006`接受；`:2010–2151`是接受及fork继承状态。Rust目前在`step`中处理UDP与TCP接受，之后才在主循环末消费HUP。因此逻辑runnable修复并不改变这个同次唤醒的顺序；TCP可能在重载前捕获旧的hosts/server snapshot。它是待真实caller验证的差异，不能默默遗留或凭读码称已通过。

`m6b_reload_same_wake.py`准备两个最小实际caller，不修改107族原测试器。复用它的精确镜像rootfs、启动身份和生命周期：

1. `no-resolv/no-hosts/bind-interfaces/cache-size=0`，普通`addn-hosts`给`samewake.files.test`旧A记录192.0.2.42，UDP阳性确认。
2. SIGSTOP并实际观察owner为T；写新A记录192.0.2.43；发送HUP；排队UDP或TCP连接+首query，确认请求位于owner拥有的socket inode的rx queue，确认HUP pending位仍为1。TCP此时尚未accept，区别于合法的重载前既有snapshot。
3. SIGCONT；严格检查第一回答的新43和之后UDP的新43，保存原始wire、完整parsed响应、状态/queue证明、正确PID/ELF、正常退出和零残留caller。C结果必须先过42→43→43阳性，再判断Rust；所有失败与fixture异常留存，不以sleep替代barrier。

冻结预期：C第一回答43；按现Rust顺序预计42。实测反证须修改解释。工具本地七个ownership/queue/signal/response守卫通过，尚未访问Oracle运行；没有性能资格。主线程先复跑107全族，再运行这两个caller，证实后才独立调整HUP处理位置并回归，避免与32af混合归因。

## 独立风险：暂时不能运行的DNS listener仍登记poll

普通`wait_for_files`和probe内wait都登记DNS UDP/TCP listener，但`step_udp`及`step_tcp_accept`会在`files_initializing()`或`interface_work_pending()`时直接返回。初始resolver FIFO等待writer且有DNS包排队时，网络fd一直POLLIN，owner却不能消费它，每次poll都会立即返回。该风险有明确读码因果；本审查没有捏造循环率或CPU实测。

独立最小修复应只在上述两个消费者允许接收新DNS请求时登记它们的监听interests。上游、既有TCP client、signal、TFTP、DHCP、文件、helper与timer保持各自interests。待输入的UDP仍留在kernel queue；输入/接口完成后重新登记即唤醒处理。不得以提前返回空server应答消除忙等。实际Linux负向门需以pending startup FIFO＋已排队UDP验证wait集合排除该监听fd、原UDP仍留队，以及probe等待不会被不可处理DNS提前结束；普通DNS-file与TFTP/DHCP/退出健康需在同新ELF复跑。
