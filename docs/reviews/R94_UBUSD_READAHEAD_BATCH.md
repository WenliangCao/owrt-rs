# R94 ubusd：每客户端读前缓冲 + 全总线 lookup 单次写出

2026-09-16。目标：让总线守护进程的每条消息与 lookup 路径既优于 C 原版、也优于正式 R89，收回 R93 记录的 `lookup_all_64/128` 延迟劣于 C（786/1549 对 775/1510 µs）与多条 lookup 对 R89 0.9–2.5% 的偏高。筛选在 Oracle Linux AArch64 私有 namespace loopback 上完成，终验在 AX3000T 实机（全 C 生产栈，从未切换）。候选 `bb95efdc`（SDK musl 交叉编译、静态、sstrip）。

## 改动

1. **每客户端读前缓冲**（`components/ubusd/src/client.rs`）。原先每条消息先 `recvmsg` 12 字节前缀、再 `read` 消息体，且每次就绪事件后再多一次探测 `recvmsg` 撞 EAGAIN；一次经总线中转的 invoke（客户端→ubusd→服务端→ubusd→客户端，3 帧入 3 帧出）要 13 次系统调用。现在一次 `recvmsg` 把 socket 中现有字节整块读入 4 KiB 缓冲，从中切出完整帧；只有超过缓冲的大帧才在自己的存储中续读；上一次读取未填满缓冲即视为已排空，下一次读取等待就绪事件而不再探测。描述符按「消费其末字节的帧」归属（同 ubus 库 conn.rs 的规则）。`strace`：单对象 lookup `recvmsg`+`read`→`recvmsg`；invoke 13→7 次/请求。

2. **全总线 lookup 走已有的有界批量写**（`server.rs`）。无 path 的 LOOKUP（`ubus list`、benchmark `lookup '*'`）原先每个对象一次 `sendmsg`（64 对象即 65 次，与 C 相同）；前缀 lookup 早已有 16 KiB 的批量路径（R92/R93 验证，含短写回退为逐帧队列项的语义）。现在无 path 且非续跑的 lookup 也走同一批量：帧字节完全相同，一次写出；超出 16 KiB 或有 monitor 时仍逐对象；背压续跑保持逐对象与 R93 `3262a56` 的边界。`strace`：64 对象 65→1 次 `sendmsg`。

3. **wire 模糊工具判定细化**（`examples/fuzz.rs`）。原判定把 `read` 返回 0 记为 `hung_up`、任何错误（含超时与 ECONNRESET）记为 `silent`。读前缓冲改变了守护进程在判定「长度字段超 1 MiB」前已消费的字节数：C 读 12 字节前缀后即断开、剩余 12 字节未读，内核因此向对端发 ECONNRESET（被记作 `silent`）；候选已整块读入，断开时接收队列为空，对端看到干净 EOF（`hung_up`）。该差别对同一输入取决于守护进程读了多少字节——C 自身对只发 12 字节前缀的客户端也会给出 EOF——不是协议契约。现在 EOF 与 ECONNRESET 同记为 `disconnected`，超时仍为 `silent`（664 行转录中 117 行）。R89 与候选对 C 均 `identical`。这是本轮唯一的门工具改动，已在此明示。

## 正确性门（Oracle，aarch64）

12/12 exit 0：R92 伞形 ubusd 集合——`ubusd-unit`（27）、`ubusd-clippy`、`ubusd-r36`/`-r36-user`（对 C 差分，含非 root 运行）、`ubusd-r83`（ACL wireprobe）、`ubusd-r42`（wire 模糊 664 行 identical，见上）、`ubusd-r41`（限额）；R92 恢复探针 `ubusd_halfclose`、`ubusd_lookup_delete` 与兼容探针 `ubusd_acl_types`、`ubusd_wire`；R93 `r93_ubusd_accept_probe` 8/8（该探针用 LD_PRELOAD 注入 accept 故障，须对本机动态链接构建运行，静态 musl 候选无法被注入——首轮 0 秒红即此原因）；R93 `r93_ubusd_prefix_probe` full/pipeline/acl 三例通过（64 大签名对象背压下 DATA 不丢、顺序保持）；`r37` 断连重连。

## 性能：实机三侧四轮矩阵（stock C / 正式 R89 / 候选，10 负载，120 观测）

前后健康、boot_id 一致。单位 µs/请求，逐轮中位数。

**对 C：10/10 负载的平均延迟和 CPU 四轮中位数较低**，全量/前缀 lookup CPU -67%…-72%，invoke -23%/-25%，单对象 lookup -28%/-31%。
2026-09-20 补充：`lookup_all_128` 的 **p50 高 2.56%**，四轮范围不重叠，
因此不是所有延迟指标全胜；RssAnon 中位数比 R89 多 8 KiB（诊断计数）。
完整尾项及测量限制见 [R94 审计](R94_COMPLETION_AUDIT.md)。

**对 R89：9/10 双优，CPU 范围全部不重叠。**

| 负载 | 候选延迟比 R89 | 候选 CPU（范围）| R89 CPU（范围）| CPU 比 R89 |
|---|---:|---:|---:|---:|
| lookup_all_64 | -6.4% | 102-113 | 309-311 | **-66.7%** |
| lookup_all_64_c4 | **-36.6%** | 111-115 | 338-343 | **-67.1%** |
| lookup_all_128 | -3.0% | 237-247 | 649-652 | **-62.9%** |
| lookup_all_128_c4 | **-38.6%** | 230-232 | 700-706 | **-67.0%** |
| invoke | -1.0% | 41-42 | 53-54 | -22.6% |
| invoke_c4 | -14.2% | 32.7-34.7 | 44.6-45.6 | -24.4% |
| lookup | -3.2% | 16-17 | 19-20 | -15.0% |
| lookup_c4 | -9.7% | 14.9-17.9 | 19.8-21.8 | -19.5% |
| lookup_prefix_64_c4 | -1.7% | 117-120 | 121-128 | -2.8% |
| lookup_prefix_64 | +0.5% | 106-110 | 111-121 | -4.4% |

R93 记录的 `lookup_all_64/128` 劣于 C（786/1549 对 775/1510）反转为 710/1463 对 753/1497；c4 全量 lookup 延迟比 R89 低三分之一以上。唯一非严格双优是 `lookup_prefix_64` 延迟 +0.5%（候选 675-719 对 R89 681-716，范围完全重叠；CPU 低 4.4%），该 lane 早已批量写出，本轮未改其路径。

## 机制

`strace`（Oracle，单客户端）：全量 lookup 64 对象 R89 每请求 65.65 `sendmsg` + 2 `recvmsg` + 1 `epoll`，候选 1 + 1 + 1；invoke R89 5 `recvmsg` + 3 `read` + 3 `sendmsg` + 2 `epoll`，候选 2 + 0 + 3 + 2。守护进程 CPU 约九成在内核，系统调用数即杠杆。C 原版对全量 lookup 也是逐对象写出（`ubusd_send_obj`），R89 与 C 在该 lane 打平正因如此。

## 边界

三侧仅替换 ubusd，provider 为冻结的 owrt-benchmark，生产栈保持全 C。候选为同 SDK recipe 的诊断构建。批量写出仍以 16 KiB 为界：更大的实机列表（如带完整签名的 `ubus list -v`）仍逐对象；放宽需另行评估 `lookup_batch` 常驻容量。invoke 每帧仍一次 `sendmsg`（与 C 相同）；把同一轮次内发往同一客户端的连续帧合并写出是下一处算法余量，本轮未做。逐轮范围、分位数、身份见 `private/r94/device-ubusd-01/report/results.json`。未部署。
