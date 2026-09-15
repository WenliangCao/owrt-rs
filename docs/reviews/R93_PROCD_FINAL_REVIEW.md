# R93 procd source05 收尾复核

2026-09-15。只读检查冻结源码及已有红绿证据；本轮未改运行时、未重新运行压力门、未操作路由器。
结论：**在本次待回复 set/add 的生命周期和完成顺序范围，未发现新的可确认阻塞缺陷。**
完整历史兼容门与 SDK 产物验收由主审继续，不能由本结论替代。

## 身份

- 完整冻结目录：构建机 `/home/ubuntu/r93-procd-watch/source05`。
- `main.rs` SHA256：`dcf5ba9966f09fc21fe463d717c95325349e3602ed46cbd2b6ff26d7c54647cf`。
- `dispatch.rs` SHA256：`9d2f739ac8c61dbafdf7e4b393ab2819b40407cb39ca08a7c77a538f026dd270`。
- 完整 437 文件 manifest：同级 `source05-manifest.json`，SHA256
  `2d911b73a4ab4362ac81be6e88a1960b4057139a79d17d992efd6be842666836`；排除生成缓存和 target。
- 与 source03 逐文件比对，`components/` 下唯一不同文件为 procd `main.rs`。
- 已做 focused 检查的 musl 二进制 SHA256：
  `3f375ee6cea5a024085c31ff39fda7ff2137536cb611df4354f9b110e9472c03`。
  这不是随后按 SDK recipe 重建产物的身份声明。

## 复核结果

| 边界 | 源码结论与证据 |
|---|---|
| 断连、半帧、回复失败 | `pump_pending_set` 先取走拥有 Request 的状态；尝试失败时只补本地 running hook，然后 Request/FD 自动释放；成功尝试后的回复失败不再次补 hook。重连清除旧请求和旧订阅，旧 peer/seq/id 不用于新连接。现有单测实际执行断连后的本地 init 脚本并确认 FD 关闭。 |
| 多次 set/add/delete 顺序 | 主循环有待回复请求时只做维护和一条 watch 尝试，不另行分派业务请求；完成后再读取 FIFO。新请求不会覆盖这一份 PendingSet。重复网络请求仍各自执行，和旧行为一样没有恰好一次去重承诺。 |
| 正常失败与缺失对象 | 每条仅完成本次一次尝试；NOT_FOUND/明确拒绝结束该项，暂态失败另入背景重试，不能用重试队列是否清空决定何时回复。六个不存在对象的 set 已在 1.09 ms 返回。 |
| 对象消失/重建 | 每次解析当前 id，同 id 不重复订阅；新 id 重订阅。处理下一项前按当前 watch 所有者过滤，回收已移除的实例不会强行恢复无人需要的路径。对象在前一项成功后又消失属于总线变化，不能承诺整个多对象批次存在原子快照；该竞争旧同步实现也存在。 |
| 完成顺序 | 有 instances 时：更新配置→本服务每条 watch 尝试→rc running 入队→新服务 service.start→成功 STATUS。无 watch 立即完成；无 instances 的旧 early path 保留。数据 trigger 在 pending 时只回收/整理，不启动新命令；已运行命令继续。 |
| 监管与等待范围 | 每次 watch 最多 lookup 1 s + subscribe 1 s，项间继续日志、回收、实例期限、watchdog、既有任务。pending 不主动读入额外业务；同步请求仍可能缓存穿插报文，这个共享连接缓存没有新的硬上限，不能宣称抗任意洪流的内存上界。 |
| no_reply | 仍经过同一次尝试/完成顺序，最终由共用 `reply_status` 的 no_reply 分支抑制 STATUS；拥有的 Request 仍释放。已有共享连接测试验证该分支，procd clean-timeout 测试覆盖 no_reply 待请求结束。 |

主要代码入口：[dispatch](../../components/procd/src/main.rs:1149)、
[待回复处理](../../components/procd/src/main.rs:1706)、
[trigger 启动屏障](../../components/procd/src/main.rs:2102)、
[主循环](../../components/procd/src/main.rs:2718)。

## 已有验证及限制

- 早期队列的 set-return 通知从 R89 **12/12** 退化为 **0/12**；仅推迟 STATUS 的中间版
  service.start 通知从 R89 **12/12** 退化为 **2/12**。两类失败均原样保留。
- 最终 source05 两类通知均 **12/12**，业务门 **11/11**；Linux native 单测 **83/83**。
- 最终 bin/tests Clippy 使用 `-D warnings -D clippy::undocumented_unsafe_blocks` 通过。
  先前仅 `-D warnings` 没有启用后一条 lint；不能把它误报为完整 all-targets 门通过。
- 本次多次 set/delete 顺序为控制流复核；既有业务探针为串行轮次，并不是并发突发队列的完整压力证明。
- 无物理 watchdog 复位验证；最大单项 I/O 预算也不代表所有文件系统、子进程和 handler 的硬实时上限。

公开数据：[summary.json](r93-procd-evidence/summary.json)。完整私有证据、源码 manifest、
中间反例脚本及最终输出保存在 `private/r93/procd-completion-evidence/`，首次返回时点反例另在
`private/r93/procd-immediate-evidence/`。
