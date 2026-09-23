# R142：只准备 monitor 构造与发送候选

R136 generic 为独立基线，控制 ELF 必须仍重现 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`。本步只生成 ignored `private/r142/source-01/{control,monitor}/components`，不改主运行时、不构建、不测试、不访问路由器。R141 PGO use 构建优先；本候选不叠加 PGO 或 A53 flags。

## 已有证据和 C 的确切行为

`server.rs::mirror` 当前每条镜像新建 BlobBuf，复制完整 payload，分配 monitor ID 快照，再为每个 ID 线性查找序号并 clone payload。R124 明确保留了这个成本；R131 为保持 `M1,E1,M2,E2` 顺序，对 monitor 回退逐帧，未优化镜像构造。R131 的独立 monitor 实机结果对 C mean +6.49%、p95 +7.46%、p99 +9.19%、daemon CPU +16.43%，六对 mean 均更慢，见 [原报告](R131_EVENT_STRESS_RESULT.md)。这些是 R131 的历史结果，不是本候选结果。

匹配镜像的原始 C 源码保留在 ignored `private/stage2/src`：

- `ubus/ubusd_monitor.c::ubusd_monitor_message` 用静态 `blob_buf mb`，依次写 CLIENT、PEER、SEQ、TYPE、SEND、DATA；最后一个 `blob_put` 复制原消息内容进完整 mb。`libubox/blob.c::blob_put` 明确调用 memcpy。C 并未把原 body 作为额外 scatter/gather 段借用。
- `ubus/ubusd.c::ubus_msg_new(..., true)` 的 external/shared 指完整 mb，仍分配一个消息 wrapper。直写提交 header + mb；排队时 `ubus_msg_ref` 才复制完整 body。候选复用已有 `Client::send_borrowed`，无需更改发送 API、短写或队列算法。
- `ubusd_monitor_connect` 先断开旧项，再 `list_add_tail`；Rust 的唯一生产插入点同样先 retain 排除当前 ID，再 push `(client, 0)`。退出/移除只 retain，Server 字段私有，单线程处理期间 `Client::send_borrowed` 不会修改 monitor 列表。因此可直接按现有 Vec 注册顺序一次遍历，不需要快照和二次 find。重复 add 仍把唯一项移到末尾并重置序号。

## 一个最小变更

仅改 `ubusd/src/server.rs`：增加独立 `Option<BlobBuf>`，初始 None，非空 monitor 列表首次镜像才创建。每条镜像 reset 后复用；不能共用已有 Server scratch，因为输入 blob 可能正借用它。保留全部七处 mirror 调用的时机，每个 monitor 的 wrapping u16 序号在目的 client 查询之前递增，按注册顺序调用 `send_borrowed(..., None)`，并在 client 存在时照旧 push touched。镜像仍不转发 FD、不递归镜像，属性字节、长度与 padding 编码沿用原调用。

空列表仍立即返回，没有新增堆分配。直写完成时不再创建 payload Vec/monitor 快照/逐目标 clone；消息内容仍需复制一次进入镜像 buffer。短写、已有队列、队列满时仍由同一个 `send_borrowed`/enqueue 路径拥有字节，保留 FIFO、偏移、限额和静默丢弃语义。镜像之间不合并系统调用。

空间代价：新增 buffer 保留曾见最大镜像的容量，monitor 停止后也保留至 Server 销毁，与 C 静态 mb 的生命周期相似；Rust Vec 增长策略可能导致不同容量，不能声称与 C 内存相同。之后必须记录未启用、正常 monitor、最大合法消息后空闲、monitor 停止/断连后的 heap 与 RSS。本步不另加 shrink 策略或第二变体。

## 复现和后续门槛

运行 `python3 tools/r142/make_monitor_source.py`。生成器核对冻结 R140 proof SHA 及所有 30 个源文件，输出两个完整快照、唯一文件 diff 和逐文件哈希清单；源不一致或输出已存在即失败。主树源码不写入。后续获执行指令时才按原 R135/R137 canonical 路径与 recipe 重建控制和候选，先完成同 ELF 正确性，再独立冻结性能系列。

必须复用全部 55 项 SDK 单测、wire/FD/recovery，以及已有 registration queued+monitored、system invoke scratch reuse、monitored fanout、monitor lookup/remove 字节与顺序覆盖。快照另插入一项尚未运行的回归：通过真实 INVOKE 注册两名 monitor，重复 add 验证唯一性和重排，然后预填一个 socket、另一名保持直写；连续大小不同的 PING 覆盖 scratch，分别检查完整回复和镜像、独立序号（含 65535→0）、注册顺序与 touched，最后排空慢 monitor 逐字节比较。测试源码和生成器均记 SHA。

执行阶段还需核实未启用 monitor 的分配边界、移除/断连、镜像不转发 FD、队列上限和恢复以及 ready 更新；不能把这一回归或已有单 monitor 测试当全部正确性证明。本阶段所有测试均未执行。

性能收益范围只限 monitor 开启的负载。使用相同 caller、C/R136/候选和固定窗口进行独立配对，同时保留无 monitor 注册、event、lookup/invoke 哨兵与上述内存成本。具体次数和门槛在测量前另冻；当前无性能结果，更不能宣称修复无 monitor 注册尾延迟或冲淡旧失败。生产保持 C，不授权部署。
