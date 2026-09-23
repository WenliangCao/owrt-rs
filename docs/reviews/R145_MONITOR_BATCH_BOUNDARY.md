# R145：为何不直接合并一轮事件的所有 monitor 发送

本项是对精确 C、当前 R136 和已有批发送实现的只读审查，没有候选或性能试跑。
减少系统调用值得检查，但不能把所有镜像集中到 fanout 前后发送。

原发送顺序是 `M(E1) → E1 → M(E2) → E2`。monitor 可以兼任 event owner，
此时镜像和原事件在同一 socket 上；只合并镜像就会改变字节顺序，这是直接反例。
两个 monitor 的顺序是 `A1 → B1 → E1 → A2 → B2 → E2`，也不能随意改为按 monitor 集中服务。
分离 socket 不构成自动豁免：在 M1 已完整直写且没有其他读者的条件下，接收 E1 后立即
检查 M1，可以区分将 M1 推迟到 E1 之后的实现；这不是对任意接收时序的普遍保证。

精确 libubox 的 `uloop_fd_add` 在此只注册 epoll，ubusd 未设置其可选 hook；Rust 的
兴趣更新也只操作 epoll。handler 不会同步重入 readiness，但其他进程仍可读取、关闭
socket。同一 readiness callback 还可能继续处理 monitor add/remove/re-add，因此
推迟到整个 callback 结束又会越过订阅和序号重置边界。

现有 `send_borrowed_batch` 的逐帧队列恢复也不足以证明任意镜像合批等价。
合法最大输入加镜像封装后可超过 1 MiB：第一帧零写、超限丢弃后，原逐帧路径会重新
直接尝试后续小帧，而 batch 会将其入队。队列上限、短写偏移、丢弃前序号递增、
镜像不携带 FD 和原帧 FD 的发送边界，都不能被合批顺带改变。

七处 mirror 调用点及无匹配/重复匹配/发送者自身对象过滤均已核查。暂不实现整轮
monitor 合批。一个更窄、尚未证明的方向是仅聚合**已经入队的连续无 FD 帧**进行 flush；
它不减少当前可写 monitor 的直接 sendmsg，不可作为本轮小包缺口的现成解决方案。

若热点证据将来支持排队发送研究，差分探针至少覆盖 monitor 兼任 owner、独立
owner/monitor、两 monitor 一快一阻塞、remove/re-add、自观察、队列临界和跨帧短写、
超大镜像后接小帧，以及穿插 FD、无匹配事件和 lookup 恢复。

参考：匹配镜像的 [C 发送路径](https://raw.githubusercontent.com/openwrt/ubus/24864e7840b3a02a9ef76284a373f6b2f00b8a9b/ubusd.c)、
[libubox uloop](https://raw.githubusercontent.com/openwrt/libubox/7dd127841e82eb1cfb61185da37dde7b9bd9ba6d/uloop.c)、
当前 [Rust mirror](../../components/ubusd/src/server.rs) 与
[Client 队列](../../components/ubusd/src/client.rs)。该审查不宣称语言极限。
