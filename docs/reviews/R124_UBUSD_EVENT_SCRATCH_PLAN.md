# R124 事件编码复用现有 scratch

这是 R121 分配热点下的另一项独立假设，不依赖尚未完成的 R123 实机成绩。
当前事件 closure 每次创建 BlobBuf、扩容，再用 `as_bytes().to_vec()` 复制完整帧；
只取走 Vec 能省最后一次复制，仍留下 builder 的反复分配。

候选基于 R123 `948e133`。只将 `dispatch_event` builder 改为 `FnOnce(&mut BlobBuf)`，
在首个合格接收者出现时 reset/build 已有 `self.scratch`；每次发送短暂借用最终化后的完整可变 blob，
保留 OBJID patch、mirror、send_borrowed、去重轮次、序号与 touched 逻辑。
适配 event_send、send_obj_event、load_acl 三个生产调用者；输入、path clone、FD、接收策略不变。
`BlobBuf::as_mut_bytes` 复用现有 head 长度最终化，返回完整 blob，不用 `into_payload`。
不引入新 buffer 字段、buffer 池、mem::take/swap、unsafe 或接收控制流变体。

容量政策显式沿用 Server scratch 现状：没有新的独立保留上限，不在事件后新增 shrink/reset_bounded。
这会将大事件的 builder 容量留到后续请求，原局部 Vec 则会释放；可能提高事件后的常驻内存，必须记录，不能宣称零开销。
容量足够、无 monitor、直写成功时可消除每事件 builder 分配/扩容/释放和整帧复制；
METHOD/DATA 写入、monitor 构造和慢读者排队所需的复制仍存在。无合格接收者仍不构造。

回归：BlobBuf 头部最终化/可变字节/nested padding；扩展服务器排队事件/monitor 测试，
两个目标对象、较大嵌套事件、随后另一请求覆盖 scratch，再发小事件，最终核对完整字节、OBJID、序号和无旧尾部。
保留不匹配不构造、只构造一次、事件轮次回绕及全部 FD/协议/恢复门。
新共享库测试必须单独运行，不能只跑 ubusd binary tests。

先在独立 worktree 实现、提交；R123 实机系列运行期间仅做本地准备，不新增网络传输干扰。
之后同规范参数重建控制，运行单测与门，再冻结与 R123 的同 ELF A/A及反序指令筛查。
沿用两规模 instructions/op 中位至少下降 3% 的研究筛选，再决定是否进入固定实机 C 对照。
该筛选不是性能收益的必要条件或语言极限判据。
若进入最终候选，还必须实测固定大事件后空闲/断连的内存，记录新增保留成本；其计划在测量前独立冻结。
