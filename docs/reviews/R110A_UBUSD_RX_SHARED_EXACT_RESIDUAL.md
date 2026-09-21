# R110-A：一次初始化的栈接收暂存与精确残帧

当前接受版仍是 R109（`8e716db`，ELF `1dfb317c…15259`）。
本轮早期草稿 `ddd80f7` 误用了堆 Vec 逐帧转移，与用户授权的栈方案不符；其 ELF
`7f7544cc…54929` 仅构建，未在路由器运行，也不进入性能样本。保留历史并在测试前修订方案。
早期测试失败是夹具没有走到本轮 `Ok(None)`，不是基线 rx_drained 缺陷；提前清除此标志会
额外探测 EAGAIN，不能接受该“修复”。

## 只读盘点修正

2026-09-21T21:26:50Z 原始记录有 17 条 ubus.sock，其中 1 条是监听 socket，
16 条为已连接服务端端点；这是一个瞬时快照，不证明连接寿命。原版 C 的
RssAnon=160 KiB、VmData=144 KiB。原文留在 Git 忽略的
`private/r110-rx-stack/inventory/router-long-connections.txt`，SHA-256
`dca1382c682c2c23aa0f0b8ad16524bb8a6dffddd08e805fcebda921a3e943c7`。

## 冻结设计

- 事件循环 while 外创建一次 `[u8;4096]`，同一服务轮次借用它解析连续完整帧。
- Client 仅在跨 readiness 时保存残帧 Vec；开始本轮时恢复到栈，结束时只保存未处理尾部。
  残帧路径允许复制，完整帧不交换 Vec、不重新清零暂存、不增加系统调用。
- 完整帧仍构造拥有型 InMsg，Server::receive 不变；LargeFrame 的拥有、读取和 FD 语义不变。
- FD 标记与残帧同时平移，EOF/畸形数据时由客户端销毁关闭 FD。保留 rx_drained 原有状态机。
- 借用派发为单独 R110-B，不混入 A。RX_SIZE=4076 不混入。

已核对匹配 ubus 24864e78 的 ubusd_main.c：C 先收前缀和 FD，再按验证后的长度
分配完整消息，通过 read 收正文；派发后继续读取。Rust 的批量预读属于实现选择，必须保留
既有协议行为。参考 [recvmsg(2)](https://www.man7.org/linux/man-pages/man2/recvmsg.2.html)、
[unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)。

## 门槛与实测

初稿把内存门错误写成“R89 增长另加 0.6 KiB”，现纠正为用户所述的
**每连接增长不超过约 0.6 KiB**：64 连接 RssAnon 增长必须 <=38.4 KiB，两个独立重复均满足。
报告完整的绝对值、VmRSS/VmData 和页粒度限制；PSS 若不可用记 NA。新测 C/R89/R103/R109
控制，不把旧数据当本轮配对样本。

CPU 对照 R103，同时补 R109 以分离方法名改动。低连接和 64 个持有连接分别测十个独立窗口，
使用现有 ABBA/BAAB，daemon CPU1、原版 libubus 调用者 CPU0，三个 user event lane。
**任一 lane 十个比值全部上升即触发退步诊断**，不是“三条中位数同时上升才拒绝”。
混合符号不代表等价，保留区间、总 CPU 和反向结果；稳定退步不能靠偶然一个负号通过。
约 1–2% 上升先检查 perf/指令与分支统计；无法计数则如实记录，不能猜内联或分支变体。

实现先通过 Linux 主机功能门、残帧/合并帧/大帧/FD/EOF/畸形长度/跨客户端隔离测试，
再运行路由器 SDK 单测和 C/R109/候选协议差分。统计采样、二进制和脚本 SHA 在性能前锁定。
生产始终为 C，既有 guard + namespace 保证候选限时和隔离，每个窗口验证 boot/config/mount、
生产身份、健康和清理。不安装、不部署候选。
