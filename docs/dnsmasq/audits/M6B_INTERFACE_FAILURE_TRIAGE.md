# M6b interface service 失败归因与 hostsdir Init 收尾

2026-10-08。读取本地回拷 raw，未访问 Oracle、未构建或运行测试。
实际失败对象为 A `ae1cdba6/e2900727…27695`；修复分支基无A `0ba85656`，
仅修改DNS文件owner的Init工作资格，main新增测试模块登记。A由root移植后重新绑定产品和受影响门。

输入：`E/M6B/interface-ae1-failed-01/result.json`及hostsdir-basic、
interface-enum-fault-before-clear、两个same-cycle的原始observed/config/stdout/stderr/traceback。
原始C/R失败保留，下面不把工具错误、派生缺见证或源码推断当作实际通过。

## 127条记录不是127个产品缺陷

完整service有276case，44case含失败，127是它们的失败明细总数：

| 类别 | case数 | 明细数 | 实际证据与处置 |
| --- | ---: | ---: | --- |
| hostsdir及domain-hostsdir startup未ready | 35 | 105个startup/identity/kernel缺失＋3个stream见证缺失 | hostsdir-basic语法0；C ready并6row，Rust七次ready_attempt response=null、lookup pending=false；deadline时exit=null，最终TERM exit0且清理空。不是未执行SHIM，确实启动并探测过；没有ready所以未运行后续action，identity/kernel是派生失败。stdout/stderr为空本身不能推断崩溃，默认syslog和-k使用标准流重定向。 |
| 提前接口/domain发布 | 7 | 17个runtime语义差异 | domain-interface-publication、domain-suffix-interface-publication、interface-udp-ptr-refresh、interface-caller-ordinary、interface-caller-local-service-host、interface-caller-acl-disables、interface-enum-fault-before-clear。最后一项C/R都真实注socket198/EIO，但C保留旧.9，Rust已发布.10+.9和新PTR。原fault期望不放宽，按精确C NEWADDR资格另修。 |
| same-cycle tracer收尾 | 2 | 2个infrastructure TimeoutExpired | C trace completed；Rust已产生.go/.stop、两个DNS答案通过guard后在tracer.wait(5)超时，trace最终JSON未写。当前tracer只到下一syscall stop才检查.stop，真正事件等待可睡在ppoll；仅工具主动interrupt和detach另修，不加健康query/HUP污染枚举计数。 |

现工具没有`--rust-link-map`参数。`--allocator-map`只定位allocation-fault的realloc；
before-clear/count按真实syscall选择，不读map。这两个代表错误不靠新增map参数解决。
外层metadata中的map仍必须同产品build，但不能误称CLI已经使用它定位这些syscall。

## hostsdir Init 的丢失工作

生产链为`main`外层`step_dns_files → step_hosts_files → wait_for_files`：

1. `DnsFiles::step_with_watch_readiness`弹出Init trigger，返回
   `initial_cache_reload=true/runnable=true`，等待owner先发布hosts目录；此时`initializing`仍true。
2. `apply_dns_file_step → scan_hosts_dirs`排regular source。后续`step_dns_files`
   因`hosts_work_pending`将旧`files_runnable`清false并返回；真实HostsRead开文件、读chunk、EOF后发布。
3. hosts全部结束时，DNS文件owner已无job/request/trigger，旧`runnable()`遗漏仍待收尾的Init。
   原`has_work()`也会过早返回false。startup admission依据`initializing`仍关闭，poll无该逻辑工作且
   不登记DNS listener；发UDP健康也不能唤醒，直到信号/外部事件碰巧到来。

修复：空闲job分支把`initializing`视为可运行工作，`has_work`同样纳入Init。
只需要下一owner turn完成既有Init逻辑、解除admission；没有新timer、忙扫描或主动发query。
有FIFO job时仍以`!job.wait_readiness`判runnable；endpoint lookup仍用原fd/reap资格；
main已有hosts/interface/provider门继续阻止DNS工作越过尚未完成的发布。
MAC-tail的`0ba85656`与这条独立链互不替代。

## 准备的回归，尚未执行

| 测试 | 实际入口/断言 |
| --- | --- |
| `dns::files::runtime::tests::empty_init_finish_remains_work_after_hosts_barrier_yields` | 真实目录/文件＋Init barrier；无job/request/trigger时init仍has_work/runnable；一次收尾后全false。实际lib-test名称以root复制ELF `--list`核对模块命名。 |
| `hostsdir_init_tests::hostsdir_init_finishes_without_another_event_and_releases_queued_dns` | 正常owner扫描/打开/读取/EOF真实hostsdir；旧cached files_runnable已false时新Init资格使实际poll零等待；DNS FD仍不admit直到收尾，随后完成原已排UDP ID7并返回.42。 |
| `hostsdir_init_tests::held_hosts_fifo_keeps_init_finish_blocked_without_spinning_or_losing_dns` | 真实FIFO writer保持打开、消费有效prefix但不EOF；pending Init不能越过hosts gate，实际poll等待100ms无signal-pipe fallback且不登记DNS FD；writer关闭产生真正HUP/EOF，再完成Init及原已排UDP。 |
| 既有`large_regular_input_yields_and_fifo_does_not_busy_poll_the_owner` | 增强真实FIFO断言：init有工作仍非runnable，排Signal也不能覆盖job背压；未改原数据/期望。 |

没有在本机执行cargo/测试，只有静态diff检查。root按统一builder复制Linux测试ELF、fresh TMPDIR后
运行对应actual测试及受影响库/入口；随后新同源feature-off NoA/A产品在精确镜像C上fresh重跑
hostsdir-basic/相关startup与full interface族。修复前七个timeout和127明细保留；
unit通过不能替代镜像caller。NEWADDR与tracer分别由独立提交处理，不能把本Init修复宣称关闭全部44case。
物理路由器未操作。
