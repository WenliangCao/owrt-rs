# R138 REMOVE DATA/STATUS 合并的语义边界

独立只读审计支持一个小范围候选：只有删除过程不会发出任何中间消息，且没有 monitor 时，才合并 REMOVE 的 DATA 与成功 STATUS。保留现有 `free_object` 和 `Client::send_data_status_reply`，不新增发送队列或事件匹配逻辑。本审计没有运行性能任务或访问路由器。

## 精确 C 依据

参考源是 [source-baseline.json](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json) 指定的 ubus `24864e7840b3a02a9ef76284a373f6b2f00b8a9b`，包版本 `2026.06.28~24864e78-r2`，无包补丁。已在 Oracle 的 `sources/components/ubus` 核对 HEAD 一致、worktree 干净。以下行号均属于该 revision：

| 源文件与行号 | 必须保留的行为 |
| --- | --- |
| `ubusd_proto.c:116–140` | 检查 OBJID、对象存在、调用者 ownership；先回 DATA，再 free，最后返回成功。OBJTYPE 仅在 type refcount 为 1 时回传。 |
| `ubusd_proto.c:519–552` | REMOVE 不传递输入 fd；handler 完成后再发送 STATUS，seq/peer 使用请求值。 |
| `ubusd_obj.c:190–224` | 先解除被删除对象指向的 targets，再通知其 subscribers，再清自己的事件 patterns，再发送具名对象 remove event，最后删除索引与 type 引用。最后一个 subscriber 离开会通知 target owner。 |
| `ubusd_proto.c:628–661` | NOTIFY 使用 target 的 invoke sequence；UNSUBSCRIBE 使用 subscriber 的 invoke sequence，随后 unsubscribe 可能触发 NOTIFY。 |
| `ubusd_event.c:36–43,146–191,268–273` | 对象自己的 patterns 在 remove event 前移除；具名对象 remove 会推进 obj_event_seq，即使 patterns 空；只有命中接收方时才构建并发送 event。 |
| `ubusd.c:166–189` | 每条非 MONITOR 消息先生成镜像，再直接发送或按原帧排队。 |

当前 Rust 的对应边界在 [server.rs](../../components/ubusd/src/server.rs) 的 `remove_object`、`free_object`、`dispatch_event` 与 `mirror`，以及 [client.rs](../../components/ubusd/src/client.rs) 的 `send_data_status_reply`。handler 单线程运行到完成，期间不处理下一条请求。

## 充分条件

在完成现有输入与 ownership 检查、读取最后引用的 reply type 后，可用以下保守条件：

```rust
self.monitors.is_empty()
    && o.targets.is_empty()
    && o.subscribers.is_empty()
    && (o.path.is_none() || self.patterns.is_empty())
```

两个订阅集合为空，排除了 teardown 的 UNSUBSCRIBE 与 NOTIFY。无 path 就不发送 object event；有 path 且全局 patterns 为空，也没有 event 接收方。没有 monitor，排除了 DATA 与 STATUS 的逐条镜像边界。该条件只需空集合/Option 判断，不扫描 patterns，也不把匹配与去重规则复制到 REMOVE。

建议命中条件后保存 id/type，完整执行 `free_object(id)`，再发送合并的 DATA/STATUS 并返回 `NoStatus`。这样成功 STATUS 仍在清理完成后发出。DATA 的发送时机被移到内部清理之后，但这个分支无中间外发消息、无 monitor，且 daemon 不在 handler 内接收下一请求，所以客户端帧序与下一请求所见状态相同。其余情况继续使用 DATA → free（含通知）→ STATUS。

不要只检查 path：无名对象也能订阅或被订阅。不要只检查 caller 是否是事件接收方：其它客户端通知与 monitor 也有原有发送次序。`patterns.is_empty()` 是充分而非必要条件；即使只剩无关 patterns 或属于被删对象的 patterns，首轮候选仍可保守退回旧路径。

`free_object` 不能绕过：无 listeners 的具名对象仍推进 obj_event_seq；无名对象也必须移除自己的 patterns、owner.objects、registry/type 索引。读取 reply type 必须在销毁前完成。

## 发送与失败边界

`Client::send_data_status_reply` 已保持两条独立 wire frame，不附带 fd。已有队列时逐帧调用原发送函数，保留每帧 cap；空队列直接合并写，短写拆回原 DATA/STATUS，分别记录偏移并拥有排队内容。REMOVE 的 DATA 仅 12 或 20 字节 blob，可直接复用，不需要增加 `tx_empty` 作为语义条件。

合并改变 syscall 数量与调度机会，这是候选要测量的机制；它不证明性能收益。不得把静态充分条件当作真实流量始终命中，也不能由该审计推断实机无回归。

## 针对性验证

- 具名对象 + 空 patterns、无名对象 + 非空 patterns：仅 DATA/STATUS，正确 seq/peer、type 最后引用字段、owner/registry/type 清理；具名路径仍推进 obj_event_seq。
- 两个 client 的对象之间有订阅（同一 client 的 SUBSCRIBE 会被拒绝）：删除 target 时验证 owner 的 DATA → NOTIFY → STATUS 与另一个 client 的 UNSUBSCRIBE；删除 subscriber 时验证另一个 client 的 target 收到最后退订 NOTIFY。两个方向的全局发送次序可由 monitor 核对。
- 同一 client 的另一个对象监听 `ubus.object.remove`：验证 DATA → INVOKE → STATUS，event payload 与 sequence 不变；被删对象自己的 patterns 先清理。
- 有 monitor 时：验证请求镜像、DATA、teardown 通知、STATUS 的完整镜像顺序与独立序号。
- 无 OBJID、不存在对象、非 owner：保持单条错误 STATUS；共享 type 删除不能提前回传或删除 type。
- 保留现有 `registration_replies_remain_owned_while_queued_and_monitored`、`combined_reply_keeps_each_frame_cap_when_already_queued`、`combined_lookup_preserves_bytes_through_partial_and_queued_writes`，覆盖缓冲复用、排队 ownership、cap 和短写。

本页是候选实施前的源语义审计，不是新增测试已通过或候选已获准部署的记录。
