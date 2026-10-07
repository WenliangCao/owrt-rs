# M6b netlink 错误来源实际资格工具

2026-10-07。新增工具仅在本地准备，禁止把本篇写成 Oracle 实际通过。它独立于第1包 baseline/A，不改变产品、不扩运行矩阵。root 已报告 `0f79463f` 的隔离 Linux main46 通过，含 ENOBUFS→EAGAIN state actor；这证明代码 actor，**不是这里尚未运行的 syscall 注入对照**。

## 最小实际 membership pair

`m6b_netlink_membership_fault.py` 复用已有 `m5_logging.traced_startup`、`m5_edns_netlink` 的 AArch64 ptrace ABI。只选择实际镜像 ELF 的 `bind(200)` 且 live sockaddr_nl family16、groups=`0x550`；不靠“第几个bind”猜目标，避免误注 libc/getifaddrs 的 unicast group0 socket。首目标通过 `NT_ARM_SYSTEM_CALL=-1` 跳过，实际 ENOSYS return 留证，再注 errno；其后 group0 bind 和 getsockname 均真实执行。

- **EPERM**：精确 `netlink.c:68–86`。要求一条550目标注入、一条同FD真实groups0 bind成功、随后同FD真实getsockname成功，kernel返回groups0且auto port非0；守护进程继续启动，完整本地A健康请求/答复留证，TERM正常回收。
- **EINVAL**：仅首550 bind失败，不得fallback/getsockname；实际启动退出5。原始 stdout/stderr、syscall args/内存、实际/注入return、时间和cleanup均保留。

执行接口（交由root在最终freeze前调度，不得和正式性能窗口并行）：

```text
python3 tools/dnsmasq/m6b_netlink_membership_fault.py
  --side both --image-root EXACT_IMAGE --rust-binary FROZEN_NO_A_ELF
  --out FRESH_PRIVATE_OUTPUT
```

外层分别通过 `run_isolated.sh` 创建C/R两个namespace，精确镜像C SHA仍为097a9e21…；`--side c|rust`仅单侧，不称pair完成。只使用loopback、synthetic ready.test配置，物理路由器不碰。输出已有则拒绝，失败/半注入/超时不删，不把“请求了fault”当“fault发生”。

本地3个测试已实际通过：AF_INET错误目标/短地址/非550 unicast负控；缺fallback、wrong fd/mask/errno、非真实kernel return、wrong order、getsockname groups/port错误；EINVAL不得误走EPERM路径。没有运行ptrace、守护进程或namespace。

## Runtime 接收错误：实际门与来源边界

精确 C `netlink.c:354–370`：ENOBUFS再次非阻塞drain，不产生NEWADDR、NEWROUTE或snapshot resync；最终EAGAIN结束drain回fdwait。root已执行代码actor `multicast_enobufs_continues_without_fabricating_any_event`。其它 read-error 的Rust一秒冷却需要实际fd/POLLERR fault窗口；C源码只结束当次drain，不能把Rust冷却或附加诊断写成C原有行为。

若后续需要真实errno入口，最小步骤如下，未在本任务执行：

1. 用 `/proc/<pid>/net/netlink` group550的inode匹配 `/proc/<pid>/fd`，选真正multicast watch，不能选邻居/接口dump的group0 fd。
2. 附加现有ptrace receive机制，识别C recvmsg212 / Rust recvfrom207的consume（非MSG_PEEK）；保留fd、flags、sender、容量、实际bytes/return。
3. 在隔离namespace用安全userspace NLMSG_NOOP唤醒该watch；只在真实consume退出注105，再记录后续实际EAGAIN及ppoll watch-fd/timeout，确认bounded继续与撤retry。user sender不可伪装成kernel sender，不能注NEWADDR/NEWROUTE来“证明”没有误发布。
4. 若内核拒绝NETLINK_ROUTE的安全peer unicast，保留其EPERM/失败；该项只能标为源码＋现有代码actor，不可声称实际syscall通过。不得为绕过拒绝制造生产地址/路由事件。
5. 普通EIO/POLLERR窗口应记录一秒冷却前后read次数/实际间隔、健康与回收；并逐字保留C/R日志，C没有“failed to read netlink socket”的原诊断时须显式列差异或另修。未执行不能算资格。

这个runtime流程当前是步骤说明，没有新增假pass字段。新startup工具的结果明确写 `runtime_errno_syscall_qualification: not executed by this startup-only tool`。socket/getsockname及二次group0失败仍是精确C源码边界，未在两case工具里假装已注入；保留给必要的独立故障门，不阻塞新baseline/A。
