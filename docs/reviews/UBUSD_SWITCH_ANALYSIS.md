# ubusd 切换路径分析（P1.3 的前置，**不是执行请求**）

日期：2026-09-06。基线 `f43b1ea`。状态：**分析，未执行，未接触设备**。
本文的作用是把两条路径的证据、代价和恢复边界摆清楚，供你判断；
任何一条真要执行，都要另外单独授权。

## 0. 三条硬事实

1. **总线由 procd 在 `STATE_UBUS` 直接启动**：
   `service_start_early("ubus", "/sbin/ubusd", "ubus", "ubus")`
   （`SERVICE_GRAPH.md:193`，procd `state.c:155`）。它**没有 init 脚本**，
   所以现有六个组件那套 `Sxx` + switch 脚本的模式**根本够不到它**。
2. **它以 uid/gid 81（`ubus`）运行**，不是 root（`PRIVILEGE_SURFACE.md:78,125`）。
3. **失联的客户端不会自己回来**：r37 在两个 daemon 上都复现了
   `network.wireless`、`dnsmasq`、`dnsmasq.dns`、`dhcp` 不恢复（= 决策 0015）。
   这属于客户端缺陷，与换不换总线无关。

## 1. 路径 A：在线受控切换

做法：让候选二进制出现在 `/sbin/ubusd`（overlay 覆盖或 bind mount），
杀掉当前 ubusd，由 procd 的 early service 用新二进制 respawn，然后按名单重启
恢复不了的客户端。

**代价**（r37 实测，不是推测）：切换瞬间总线消失，随后必须重启

| 客户端 | 原因 | 顺序 |
|---|---|---|
| netifd | 重连后不恢复 `network.wireless` | 1 |
| dnsmasq | 空闲时不迭代主循环，不重试 `ubus_init` | 2 |
| odhcpd | 无 `connection_lost` 处理，永久脱离总线 | 3 |

重启 netifd 意味着重新配置网络与无线——SSH 会断，Wi-Fi 会掉。

**致命问题：控制脚本自己踩在被换掉的东西上。** 切换脚本要通过 SSH 跑，
而 SSH 会话依赖网络，网络又要靠重启后的 netifd 重新建立。一旦中间任何一步失败，
就没有第二条通道把它退回去——除非事先准备一个**不依赖 ubus、不依赖网络、不依赖 SSH 会话**
的独立回退任务，并且**先证明退出会话后它仍然会执行**。

结论：路径 A 在这台唯一设备上**目前不具备可验证的恢复保证**，不推荐。

## 2. 路径 B：开机时选择

做法：让下一次开机的 `/sbin/ubusd` 解析到候选二进制。procd 在 `STATE_UBUS`
按**绝对路径**启动它，而 overlay 在 preinit 的 `80_mount_root` 阶段就已经挂好
（`BOOT_CHAIN.md`），所以 overlay 里的 `/sbin/ubusd` 会遮住 squashfs 里的那个。

**为什么这条路径有救援出口**：`docs/RUNBOOK_AX3000T_RECOVERY.md:46` 明确记录
**failsafe 不挂载 overlay**。所以 failsafe 下 `/sbin/ubusd` 解析到 rom 里的原版，
救援 shell 不受候选影响；进去后 `mount_root` 再撤销选择即可。这是**已记录的事实**，
不是推断——但它是**针对现有六个组件的 boot-enable 标记验证过的**，用在替换
`/sbin/ubusd` 上属于同一机制的新用法，仍需在真机之外先把这一点单独走通。

**代价**：必须重启才能验证，也必须重启才能撤销。重启本身受决策 0016 约束。

**已知未验证点**（真要做之前必须先关掉）：

- overlay 覆盖 `/sbin/ubusd` 是否真的被 procd 的 early service 取到（需要在一个
  能跑 PID 1 的环境里演练，容器不算）。
- 候选以 **uid 81** 启动是否一切正常。见 §3，这一条我正在补测。
- procd 自己是 ubus 客户端（50 ms→1 s 退避重连，只有源码依据）。开机路径下它是
  先起总线再连，与重启总线不同，但没有实测。
- `/etc/init.d/rcS` 不在镜像里、由 procd 内建处理；启动脚本串行执行、普通非零退出
  不阻断后续（`BOOT_CHAIN.md`）。选择机制不能破坏这一点。

## 3. 一个我自己漏掉的前提 —— 已补测通过

到 `f43b1ea` 为止，**所有沙箱运行都是以 root 跑 daemon 的**，而设备上它是 uid 81。
这不是小差别：`/var/run/ubus` 的创建、socket 属主、`/proc/<pid>/status` 的读取都在
非 root 下才会暴露问题。

已补跑（`DAEMON_USER=ubus`，两端同样降权）：**79 行 transcript 逐字节相同**，
socket 属主 `ubus:ubus` 模式 0666，传 fd、非 root ACL、描述符零泄漏全部成立。
这一项不再是阻塞点，但 §2 的其余未验证点仍然有效。

## 4. 现在能做、且不碰设备的

- ~~以 uid 81 重跑 r36 差分~~（已通过，见 §3）。
- ~~性能对照~~（已完成：常驻内存约为 C 的一半，全量 lookup 慢 14%，其余持平；
  见 `reports/.../R36_UBUSD.md` §4）。
- 定位并修掉全量 lookup 的 14%（怀疑是每次调用的分配，未验证）。
- monitor 流量逐条比对、构造真正撑爆 1 MiB 发送队列的负载。
- 在能跑 PID 1 的环境（虚拟机）里演练 overlay 选择与 failsafe 分支。
  这需要在构建主机上装虚拟化组件，属于系统级安装，**未经你同意不会做**。

## 5. 结论

两条路径里，**只有 B 有一条已记录的救援出口**，但它要求重启，而且还有 §2 那几条
未验证点。A 的问题不是"会中断"——中断可以接受——而是**中断后没有可证明的回来的路**。

在 §3 的非 root 差分通过、§2 的未验证点关掉之前，我不会提出任何设备操作。
