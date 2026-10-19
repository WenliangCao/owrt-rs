# 合同 C2：系统日志守护进程（R15 logd）

> 冻结日期：2026-09-02
> 依据：镜像内 `/sbin/logd`（ubox 6f78fa49）、`/usr/libexec/logread-ubox`、`/etc/init.d/log`、
> ubus 对象 `log` 的实测签名、`/usr/share/acl.d/logd.json`；上游源码 `ubox/log/{logd,syslog,logread}.c`。

## 1. 对外接口

| 面 | 内容 |
|---|---|
| ubus 对象 | `log`，方法 `read {lines:Integer, stream:Boolean, oneshot:Boolean}`、`write {event:String}` |
| 通知 | 有订阅者时对每条新日志 `notify "message" {msg,id,priority,source,time}` |
| 输入 | `/dev/log`（unix datagram，0666）；`/proc/kmsg`（只读非阻塞，逐行） |
| 进程 | `/sbin/logd -S <KiB>`，procd instance `logd`，respawn 5 1 -1；启动后降权到用户 `logd` |
| ACL | 用户 `logd` 可发布 `log`；root 绕过 ACL |
| 客户端 | 原 `logread` 不替换。它 `read {stream:1, oneshot:!follow, lines:N}`，从 STATUS 报文携带的 fd 读取 blob 帧 |

## 2. 记录语义（与原实现逐项一致）

1. 每条记录：`msg`（字符串）、`id`（自 0 递增的 u32）、`priority`（`<N>` 前缀解析出的 N，缺省 0）、
   `source`（0 kernel，1 syslog，2 internal）、`time`（CLOCK_REALTIME 毫秒，u64）。
2. 入库前处理顺序：所有 `\n` 换成空格；去掉末尾空白；解析并去掉 `^<([0-9]*)>`；来自 `/dev/log`
   且长度 > 16 且第 16 个字符为空格时，去掉前 16 个字符（syslog 时间戳）；facility 为 LOCAL7 的
   记录不入环形缓冲区。
3. 单条上限 1024 字节（含 NUL），`write` 按前 1023 **输入字节**截断，允许截在 UTF-8 字符中间。
   `/dev/log`、`write`、环形记录、blobmsg 回复保留非 UTF-8 字节，不再转换成 U+FFFD。
4. 环形缓冲区容量为 `-S` 指定的 KiB 数 × 1024 字节，缺省 16 KiB；每条占 32 字节头 + 4 字节对齐的
   正文。写入位置到达末端时回绕到起点，被覆盖区间内的旧记录淘汰。保留集合与原实现一致。
5. `read`：`lines=N` 表示只返回 `id >= current_id - N` 的记录；`lines` 缺省表示全部，显式 0 不返回历史。
   `stream=false` 时一次性返回 `{"log":[...]}`；`stream=true`（缺省）时原版新建 pipe，候选使用
   pipe，并尽力把容量设为 256 KiB（失败则保持内核默认值），把读端随 STATUS 传给调用方，写端按同样的
   blob 帧写出积压记录；`oneshot=true` 写完即关，否则保持并推送新记录。两侧 pipe 的内核
   缓冲容量不同，容量和背压性能须分别实测，不能假定均为 64 KiB。
6. `write {event}` 以 source=1 入库，经过与 `/dev/log` 相同的处理。

## 3. 不在合同内

udebug 环形缓冲区（设备上没有 `udebug` 对象）；远程 syslog 与文件输出由原 `logread` 实例承担，
不变。

## 4. 参考用例

见 [tests/reference/logd/](../../tests/reference/logd/)。每个用例给出一组输入（`logger` 写入、
`ubus call log write`、kmsg 行）与期望的 `logread`/`ubus call log read` 输出形态；在精确 rootfs
中对原 logd 与候选分别执行并比较。

## 5. 慢读流的资源治理（R92）

精确原版的 libubox ustream 队列也无上限，属于共同的资源问题。候选有意限制为：每条流
最多 1 MiB 待写 payload，全部流合计最多 4 MiB，最多 64 条流。慢读者触及积压上限后断开；
新流的初始历史记录超过单流预算或已无槽位时返回 NOT_SUPPORTED。释放读端后容量可复用。
oneshot 也受同一预算约束，普通非流式 read 的既有 ubus 消息上限不变。

预算计算的是排队 payload 字节，不等于 allocator capacity、RSS 或内核管道缓冲区大小。
断开意味着该慢读客户端丢失后续日志；它可重连按环形缓冲保留范围重新读取，不能承诺无限补发。
边界和正常读者用例见 `r92_compat_probe.py` 的 `logd_limits`，持续压力见 `r92_recovery_probe.py`。

## 6. 流隔离和总线恢复

某个流关闭或被预算淘汰，不能把它的就绪事件应用到另一个流。每轮先处理已轮询的流，
再接收可能增加/删除流的 ubus、syslog 和 kmsg 输入；新流从下一轮开始参与轮询。
总积压预算不足时先尝试发送可写数据，只对仍需排队的字节计费，再淘汰积压最多的流；
不因队列位置先淘汰无积压的健康流。

ubusd 断连期间，已有流仍可发送积压、完成 oneshot 和回收已关闭的读端，环形缓冲仍接收
本地日志。这与精确原版由 uloop 独立处理 ustream 的行为一致。重连尝试按一秒截止时间
进行，流就绪或持续日志不能提高尝试频率；单轮最多接收 256 个 syslog 数据报，余下数据
由下一轮读取，不主动丢弃。旧总线的 subscriber 标志立即清除，成功重连后重新注册对象。

`tools/test_logd_stream_recovery.py --ubusd PATH --logd PATH` 在 Linux 的临时 Unix socket
和独立子进程上覆盖双读者隔离、断连期间无新日志的积压排空/回收、持续日志下的重连节拍
及 64 流上限恢复。它不使用宿主 `/dev/log`、网络设备或路由器；可对修复前后同跑验证。
