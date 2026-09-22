# R114：仅借用入站派发，实验计划

在 R113 `befbb16` 独立 worktree 上试验，主源码和正在采样的 R113 ELF 保持不变。
R113 CPU 探索尚在收集；本计划不根据它的中途比值选取有利 lane。

## 假设与边界

R113 完整小帧仍执行 `rx[8..total].to_vec()`，处理完即释放。普通 INVOKE 往返的
INVOKE/DATA/STATUS 三帧可以借用共享栈存储；小 PING 可以直接回送借用数据。
丢弃的事件 STATUS 也无需拥有 blob。减少的是每帧一次分配和复制，CPU 收益尚未测量。

`InMsg<'a>` 仅把 `Vec<u8>` 换成标准库 `Cow<'a, [u8]>`；`read_message` 返回值的借用
仅绑定事件循环 rx，不绑定 Client。小帧返回 Borrowed，大帧返回既有 Vec 的 Owned。
只在停车 LOOKUP 时将消息转成 `InMsg<'static>`；已有 Owned 大帧转移所有权而不复制。
PING/response 转发对 Borrowed 调用既有 `send_borrowed`，Owned 继续交给 `send`，
保留监视器顺序、FD 所有权、背压时复制、部分写入偏移及队列上限。

依据：[Rust 1.98.1 Cow 文档](https://doc.rust-lang.org/std/borrow/enum.Cow.html)明确区分
Borrowed 与 Owned，`into_owned` 对已有 Owned 转移值。这里不用共享引用计数或 unsafe 生命周期。
精确 C `ubusd_main.c` 的 prefix/body 消费边界保持不动；不得重新加入跨帧预读或负向 peek 推断。

## 此实验不混入的变化

不改 `touched` 记录、事件生成/凭据复制、系统对象调用参数复制、注册表、RX_SIZE、
分配器、编译/LTO/内联选项、argv0 或大帧接收算法。
这保证与 R113 的差异仅是入站 blob 所有权和两条直接转发路径。

## 必须验证

- 保留全部现有单测刺激。跨 readiness/其他客户端覆盖栈后，残帧仍完整；大帧仍拥有数据。
- 修改已有停车 LOOKUP/PING 背压回归，使其确实传入借用数据，派发后覆盖原字节再排空队列；
  FIFO、seq、peer、完整载荷不变。保留监视器完整入站/出站镜像验证。
- SDK 全部单测及原有七组实机协议门、六种 FD wireprobe 差分；六组主机功能/恢复门。
  额外 Oracle 九种 FD 边界/释放探针也重跑，固定有界泄漏检查，保留失败。
- 用相同 SDK、规范路径、标志先重建 R113 并逐字节核对，再构建候选和记录 SHA。
- 正确性完成后另行冻结物理内存与 CPU 采样工件和顺序，保留全部正负指标。
  内存目标继续是 64 连接增长两轮均 ≤38.4 KiB，报告绝对占用与断连后残留。
  CPU 先与正确的 R113 作独立消融；最终仍需 C/R89、调用与注册/查询等覆盖，
  不以两个探索窗口宣布胜出或等效。

R113 接收修复不能因变慢而退回已知有 FD 缺陷的预读实现。
R114 若失败，保留补丁及数据，回到正确的 R113 基线继续定位，不靠改控制流猜编译器。
