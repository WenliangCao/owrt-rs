# R130：仅合并成功 ADD_OBJECT 的 DATA 与 STATUS

恢复后的单一候选从精确 R124 `a5b0ff1ec71a38d8c840b6995f859b503a08387d` 建独立分支；
不在主工作树旧运行时上叠补丁，不合入 R126。R124 控制 ELF 必须复现
`42435a31e2917186fb353e2c70143f4b3f6d82ec3dd53265bf6d826897b69926`。

两个独立源码审查均发现：成功 ADD 在对象事件、owner 和 objects 更新之后发送 DATA，随后仅返回 OK，
由 receive 紧接发送 STATUS。无 monitor 时可复用已存在的 DATA+STATUS scatter/gather 发送函数，
返回 NoStatus；monitor 非空时完整保留旧发送/镜像边界。不改 REMOVE：其 DATA 与 STATUS 之间还有
free_object、订阅通知和删除事件。输入 FD 仍由原 handle 入口关闭，输出两帧不携带 FD。

假说是每个无背压 ADD/REMOVE 周期的回复 sendmsg 从四次降为三次，不承诺固定耗时幅度。
在 AF_UNIX stream 上只合并无 FD 的相邻完整帧；保留逐帧队列上限、短写偏移、丢弃与所有权。
参考 [sendmsg](https://man7.org/linux/man-pages/man2/sendmsg.2.html) 与
[unix stream](https://man7.org/linux/man-pages/man7/unix.7.html) 的接口语义，最终以字节差分验证。

验证顺序：

1. Linux 单测、既有六组 Oracle 功能/恢复门；新增 ADD 的 12/20 字节 DATA、失败回复、
   自身对象事件的 EVENT→DATA→STATUS、monitor、输入 FD 关闭、排队与逐帧 cap 差分。
   沿用同一发送函数的大帧强制短写测试，不添加 syscall mock。
2. Oracle 使用精确 R124/R130 ELF、相同 caller 的小规模 syscall 跟踪，确认每成功 ADD 少一次 sendmsg，
   REMOVE、接收、报文和返回结果不变。跟踪只证明调用数量，不作为路由器性能结论。
3. 物理路由器隔离功能/FD 门通过后，另冻包含产物/工具哈希、统一 argv0/affinity **运行时断言**、
   全部执行顺序的性能 JSON，再启动固定系列。旧 R128 的启动归一化正在复核，不能拿其比值与新系列相除。
4. 预定三方为精确 C、精确 R124、R130；六个三方块使用全部六种排列，每方六窗，共十八窗，
   5000 次、20 次预热，注册 1/16 方法，每方均为新 daemon。主要指标是周期 mean latency；
   每次 latency、p50/p95/p99、daemon/caller CPU 和内存均保留。独立查询/调用检查作为共享发送函数护栏。

验证范围说明：固定 `register-cycle` caller 每周期检查 ADD/REMOVE 成功 STATUS，并从 ADD DATA 解析 OBJID；
完整方法签名/路径/ID 只在计时前一次 lookup 中核对，预检及计时循环之后检查 registry 为空。
它不逐周期核对 REMOVE DATA/OBJTYPE 或 ADD 的全部属性/额外帧。第 1 步的单测和独立协议门负责
精确 DATA/STATUS/monitor 字节及 FD 行为，报告必须把这些证据与计时 caller 的检查分开说明。
查询/调用护栏的 `lookup-fixture`/`rpc-fixture` 则逐次核对完整预期结果。本说明不改变计时客户端、采样或判定门槛。

工程判定：主要注册 lane 对 R124 六块同为降低方向且配对中位至少降低 3%，才能写稳定实用收益；
相对 C 独立报告，不从旧系列拼接。±1% 记工程平手，不是统计等价。注册 p95/p99、daemon CPU 若
配对中位上升超过 5%，或功能门失败，不接受候选；共享查询/调用若出现明确退步也不接受。
这些门是本轮工程筛选规则，不是总体显著性证明。不删除异常窗、不追加窗口追结果。

原 R126 A/A 失败继续保留。其同 ELF 新进程差异不是候选代码退步证据；没有 hash seed/桶布局记录，
不能定因或通过改门补发接受结论。本轮不继续该候选。

每一步单独 commit；生产始终为精确 C，候选只在临时 namespace 中运行，每窗结束核对清理及生产身份。
