# M6b 信号 wake pipe：原子非阻塞准备

2026-10-08续接独立代码审查发现普通资源/错误边界，不属于A存储增量或极端豁免。
69bc与e8b都先`sys::pipe().ok()`，随后分别忽略writer和reader的`set_nonblocking`失败；
原pipe2仅CLOEXEC。handler写1字节、owner以64B循环drain都依赖NONBLOCK：flags失败会
留下blocking FD，满pipe写或恰64B后再次读可能阻塞单owner。

精确C调用链是dnsmasq.c583–589→util.c352–358 safe_pipe(pipefd,1)→network.c884–894
fix_fd，两端NONBLOCK全部成功后才发布和prime EVENT_INIT；pipe/flags失败fatal5。
dnsmasq.c1341–1414保存errno/send_event，1437–1458一次event_desc<PIPE_BUF writev。

共同修复增加小型`sys::nonblocking_pipe()`：pipe2一次传CLOEXEC|NONBLOCK，成功才返回
两端OwnedFd；仅信号wake调用新接口，删两次忽略错误的fcntl。原`sys::pipe()`仍blocking，
startup errorpipe/helper合同不改。创建失败沿用已有原子计数与100ms无pipe兜底，不改为C的fatal；
这是已声明self-pipe分配差异的M6b当前实现，不能继续写“Rust不分配信号pipe”。

新增两条sys测试实际检查blocking默认合同、两端NONBLOCK、空读/满写WouldBlock及完整排空；
新增owner测试恰64B读满后drain返回且再读WouldBlock。已有无pipe STOP/USR2/HUP测试保留。
此提交仅代码与测试，git diff-check过；Linux构建/执行、新两组ELF、完整服务及所有后续门
仍待实际。不得把69bc现轮通过或准备好的资源/CPU资产充后继资格，不增加无A27窗。

当前Oracle继续不可变69bc服务证据，物理路由器未操作。修复同时进入NoA与独立A后，
统一新pair构建、同源诊断prepare/source-join以及服务/资源/45CPU，旧原始结果保全。
