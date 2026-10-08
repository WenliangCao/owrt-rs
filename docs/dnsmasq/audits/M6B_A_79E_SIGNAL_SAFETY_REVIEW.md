# A79e 信号安全增量复审

2026-10-08。独立本地复审 `69bccf2738f2c07cbc6d8b8a950015d4cea10af3` →
`79e29d7de66c57fcdbfa2c98b9bec05675c30462`，核代码、现有构建收据、实际 ELF 和已归档测试日志。
本 reviewer 未访问 Oracle、未 build/test、未改产品/账本。[A69bc 原审查](M6B_A_69BC_SAFETY_REVIEW.md)
及其 SIG-01/SIG-02 open 历史保持原样；**两项只在 A79e 上关闭代码与精准实际 Linux 资格**。
最终 source-bound `complete` 仍未授予，此增量 `complete=false`，不替代全服务/资源/压力/CPU/最终统一门。

## 精确源码和产品

从既有 `E/M6B/pair-signal-01/a-source.tar` 读取 PAX commit，并逐个同 A79e Git blob 核 byte/SHA。
163 个 dnsmasq/ubus 组件文件全部匹配；161 个与 A69bc完整字节相同，只有下表两文件变化。
archive SHA256 `337f2f346a27518c9659fcdd90af4b89fcf1101c0f04d9752f47ff78a7466494`。
其余缓存/COW/generation/LRU/private-index/owner/files证明按相同源码继承，不能以旧 runtime receipt 授新 ELF 资格。

| 改变文件 | A69bc SHA256 | A79e SHA256 |
| --- | --- | --- |
| `components/dnsmasq/src/main.rs` | `f8ef495f70b2e262c509b25a4cebae0e7ccb733d8cfc90cc69f3e02592b9e322` | `6d504810e6bfe188fc670eb5c95b00e90b7d0590d683afcd445bcd6568e35bae` |
| `components/ubus/src/sys.rs` | `23203d875c3adf20e70eed077f3911da65aa7baf6084fa2557698fbf59bd1a15` | `cf163c665374d34e1b950eaaff410f01aef4a0da131f5a74a77ccb9fd14fbd9d` |

NoA原archive PAX commit为 `cd9edcf7727faa199f225587ea76eb283c52b15f`；其sys.rs逐字等于A79e，
main.rs实际有相同NONBLOCK/errno修复，分别同对应Git blob核字节，未执行额外tests。

两文件 diff 已逐 hunk 读完：生产只有 NONBLOCK准备/errno保护两个普通修复，另有四个精准 test。
没有改缓存/租约、poll兴趣/预算、parent/TCP借用、generation/LRU、packetcodec或diagnostics开关；
第4包不在本增量内。

本地实际读取 `pair-signal-01/products/a-dnsmasq-rs`：**1,962,024 B**，SHA256
`9480899e197df47fdd56d3b336f0872716d925fc259260ce90c32bc41669d078`。
它与 `a-build.json` artifact及 `source-join.json` identity相同；build JSON实际SHA
`67f79f039c5e4c99fbc086287a4c62701becdaad7a0968a99fc3b214c5943bed`。
收据为同 source release、opt3、features空、唯一共享target `/home/ubuntu/dnsmasq-cargo-target`。
link.map SHA字段在build/join均为
`6b94a64a18711009f83338a03f5135ef80bcb7e971b4cc35ec4a6bf8086ccae4`；
当前products镜像不含map原字节，本 reviewer不宣称独立rehash过本地map。
`source-join.qualification=false`及prepared字样保留：join只是身份连接，实际 test结果另看原日志/构建records。

## 两个关闭的不变量和错误边界

| Finding | A79e 位置与复审 | 采用的实际证明/限制 |
| --- | --- | --- |
| SIG-01 NONBLOCK | `main.rs:846–849`在发布global writer前调用新`nonblocking_pipe()`；1399–1402直接转移两owned端，两个ignored fcntl调用已删。`sys.rs:415–433`默认`pipe()`仅CLOEXEC，新接口才经`pipe_with_flags(CLOEXEC\|NONBLOCK)`；成功后恰两fresh OwnedFd，失败返回Err，不能产生半准备的blocking信号端。 | sys实际核两端F_GETFL含NONBLOCK，empty read真实EAGAIN、写至真实EAGAIN、完全drain且bytecount相等；main实际写恰64B后drain不需第二次writer，<50ms且再次read真实EAGAIN。原来reader读满64B后再次blocking read的条件已被原子flags排除。未运行fcntl故障注入，新代码已无该两步setup入口。 |
| SIG-02 errno | `main.rs:78–97`Linux声明`__errno_location()->*mut i32`；fd>=0路径取得当前线程live TLS pointer，save→async-safe栈1byte write→restore。pointer/scalar不逃逸，成功、EAGAIN及其他write错误都restore；fd<0不做IO/TLS写。与精确C `dnsmasq.c:1341–1414`master sig_handler errsave/send_event/restore合同一致。 | main实际three branches `(no pipe, writable pipe, saturated pipe)`先创建/填满后将TLS设EIO5，再直接调用`request_stop(15)`，核STOP delivered且errno仍5；fixture先有真实EAGAIN，不能拿fill产生的errno冒充wake观察。测试直接调handler函数，不称实际OS信号恰夹在failed syscall和last_os_error之间复现；该竞态根因及消除条件由代码/ABI证明。 |

Linux c_int/TLS地址在当前thread生命期有效，handler仅暂存pointer、读写scalar；没有malloc、
锁、Rc/RefCell或跨fork/poll保存。嵌套不同信号的save/restore按栈组合，每个handler恢复自己中断时的errno。
write错误仍忽略其通知byte结果；STOP/HUP/reopen原子状态继续是authority，不因满pipe丢语义工作。

## 无pipe fallback和普通blocking IPC

- `main.rs:4014–4016`仍在无readpipe时使用原100ms最大deadline；原子STOP/HUP/reopen已有工作直接timeout0。
  `delivered_signal_counters_wake_even_without_a_pipe_byte`在A/NoA两真实入口日志均ok：三种counter、确实None、<50ms。
  这没有模拟实际pipe2分配失败，源码None分支与已有counter actor组合证明该caller边界。
- `main.rs:1850`在正常teardown仍先global writer=-1，两pipe OwnedFd保留到owner结束。
  新`nonblocking_pipe`生产caller扫描仅signal setup；其余新调用都在cfg(test)。
- `sys::pipe()`默认flags仍CLOEXEC，没有给其他消费者增加NONBLOCK。实际`ordinary_pipe_keeps_blocking_ends`
  核reader/writer两端F_GETFL均没有NONBLOCK。
- `helper/process.rs:53–70`和`startup/daemonize.rs:27–38`完整字节与69bc相同，各自原CLOEXEC-only pipe2保持；
  helper只将parent writer/event reader设NONBLOCK并传播setup错误，child blocking/error-frame完整读取合同不变。
  没有把startup/errorpipe改成partial EAGAIN协议，也没有给helper新增timer或线程。

## 已记录的实际测试资格

读取 `E/M6B/pair-signal-01/products/build-controller.log`中的五份真实build记录和同目录完整test日志，
核source/feature/opt3/shared-target与实际artifact身份；本 reviewer只读，没有重跑这些tests。
A库的20 ignored不计passed，不把库/入口tests当镜像六族或最终44族功能资格。

| 原日志 | 实际结果 | SHA256 |
| --- | --- | --- |
| `a-lib-tests.log` | 753 passed / 0 failed / 20 ignored | `7ffd1194e59295d815516cc822794ffe39d29243c8d30e14ed45b294c6301cda` |
| `a-bin-tests.log` | 68 passed / 0 failed / 0 ignored | `adf61deb81d34a61a2df50219eb748c80698f151ec0f231263b504af91cd527b` |
| `noa-lib-tests.log` | 744 passed / 0 failed / 20 ignored | `26f819a1ed01fadda33d9492358520394a705dcd6857f781c101e2d8e2019c09` |
| `noa-bin-tests.log` | 67 passed / 0 failed / 0 ignored | `8afbe8be0c48e2d7b3a4c75f71d13e62fe178b083de57b2165e82c17b84d2d8a` |
| `ubus-tests.log` | 70 passed / 0 failed / 0 ignored | `a840db7bad7bf676574cf5e9cf26368f297516e5b02fbce61e90683a3d0b5dc3` |

四个新增精准 test 名称均在对应完整实际日志中 `ok`：

- A/NoA入口 `signal_wake_drains_a_full_buffer_without_another_write`；
- A/NoA入口 `signal_wake_preserves_interrupted_errno_with_or_without_backpressure`；
- UBus `nonblocking_pipe_handles_empty_reads_and_full_writes`；
- UBus `ordinary_pipe_keeps_blocking_ends`。

## 最终复绑定

本增量只关闭SIG-01/SIG-02的代码和精准实际资格，当前increment无新增普通未解，final complete仍false。
最终合main后须核完整组件map等于A79e；docs/tools变化不允许暗改产品。
若main/sys或其他产品字节再次变化，增量重审并fresh执行受影响资格，不能改本审查commit字段复用。
最终同source/feature-off opt3的完整服务/原语/资源/压力/45CPU、44族/M2/perfguard/唯一135/APK
仍由账本各实际收据判定，本报告不导入旧A69结果、不豁免最终统一链。

[增量JSON/source map与身份连接](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a79e/incremental-review.json)
SHA256 `c98fc8809565db0bbdcedf215e2e008bcf6ef9b2e70bdfc8b5f385410e11db49`；
[增量manifest](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a79e/manifest.json)
SHA256 `209c180a0384167af2c1337cd5b37d3cc326d02c07f41014d97830bace779791`，complete=false/final_qualification=false。
