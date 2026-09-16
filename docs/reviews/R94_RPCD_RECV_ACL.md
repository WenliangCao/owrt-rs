# R94 rpcd：每请求单 recvmsg 读取 + 无分配 ACL 匹配

2026-09-16。目标：让 rpcd 会话权限与授权路径的每请求成本既优于 C 原版、也优于正式 R89，收回 R93 唯一可重复的 R89 退步（会话权限查询）。筛选在 Oracle Linux AArch64 私有 namespace loopback 上完成，终验在 AX3000T 实机（全 C 生产栈，从未切换）。候选 `a362c468`（SDK musl 交叉编译、静态、sstrip）。

## 改动

1. **ubus 服务端接收改为读前缓冲**（`components/ubus/src/conn.rs`、`sys.rs`）。R89 每请求发三次 `recvmsg`：`incoming_if_started` 的探测读、头读、体读。改为一次 `recvmsg` 把 socket 中现有字节整块读入固定 `INCOMING_BUFFER_SIZE` 缓冲，再从缓冲里切出完整帧。于是一个小 INVOKE 加其回复只需 `recvmsg`×1、`sendmsg`×1、`epoll_wait`×1；排在其后的已缓冲帧无需任何系统调用。随读到的 `SCM_RIGHTS` 描述符按「消费其末字节的那一帧」归属；半帧超时时释放其描述符。发送等待惰性固定预算——不阻塞的调用从不读时钟。INVOKE 直接从缓冲解码进复用的 `spare_request`，越界大帧仍用独立存储，界限与合同不变。

2. **会话 ACL 匹配去分配**（`session.rs`、`glob.rs`）。R89 用 musl `fnmatch` 回答 `net*` 形态，每条 ACL 为 pattern 与 name 各分配一个 `CString`（一次授权请求最多 4 次分配）。现在：单个 ASCII 尾星模式（`net*`、`r*`——ACL 的常见形态）按前缀直接匹配；匹配前先用每条 ACL 的无通配前缀 key 预筛（与 C 的 `strncmp` 一致），非以该前缀开头的对象直接跳过；其余 `fnmatch` 调用把短操作数复制到栈上 NUL 结尾缓冲，避免堆分配。key 计算把 NUL 也作为终止符，与 C 把对象存为 C 字符串一致。

3. **rpcd 主循环**（`main.rs`）。原「已到达帧免就绪系统调用」路径调用 `incoming_if_started`（自带一次探测 `recvmsg`）；改为在 `has_pending()`（缓冲中已有完整帧或排队消息）为真时直接 `read_incoming`，去掉那次探测读。

## 正确性门（Oracle，aarch64）

18/18 候选门 exit 0：`exact-image-libc`、`rpcd-unit`（55）、`ubus-unit`（45）、`rpcd-clippy`、`candidate-compat`、`candidate-features-stable`、`candidate-disconnect`、`candidate-half_header`、`candidate-recovery`、`r13/r17/r18/r19`、`rpcd-busy`、`rpcd-real-features`、`rpcd-bytes`、`rpcd-defer`、`rpcd-r26-stable-733`。

- 模糊测试 733/733 字节一致。首轮该门曾报一处 `file list /` 差异——某目录 inode 相差 1；该门是把候选二进制在两份一次性 rootfs 拷贝里各跑一遍互比，inode 由文件系统分配，并发门负载下两次拷贝拿到相邻 inode；三次静默复跑均 `differing=0`，R89 二进制同样 `differing=0`。属固件夹具非确定性，非 rpcd 行为。`_file_list` 与 `_file_stat` 不同，未对 inode 做掩码。
- 依赖 6 个链接 ubus 库的组件单测全绿：logd 18、httpd 51、procd 83、netifd 157、fw4 14、ubusd 27。
- R81 F23/F24、R88 F1、R92、R93（断连保留会话/回滚、离线到期恢复、失败通知去重轮转、总线 deadline 覆盖完整 header/body）合同均由对应门守住。

## 性能：实机三侧四轮矩阵（stock C / 正式 R89 / 候选，18 负载，216 观测）

前后健康、boot_id、运行身份一致（无重启）。单位 µs/请求，逐轮中位数。候选比 stock C 全部 18 负载在延迟与 CPU 上均更优；比 R89 在 16/18 负载两项均更优，多数 CPU 逐轮范围与 R89 不重叠。

**R93 会话权限退步已全部收回：**

| 负载 | 候选延迟比 R89 | 候选 CPU（范围）| R89 CPU（范围）| CPU 比 R89 |
|---|---:|---:|---:|---:|
| session_access | -3.37% | 19-20 | 22-27 | -14.9% |
| session_access_c4 | -0.34% | 13.9-15.9 | 15.9-17.9 | -14.7% |
| session_access_granted | -1.25% | 20-21 | 22-25 | -16.7% |
| session_access_granted_c4 | -8.39% | 14.9 | 16.9-22.8 | -21.1% |
| session_access_64 | -0.98% | 22 | 25-26 | -13.7% |
| session_access_64_c4 | -6.77% | 15.9-17.9 | 17.9-19.8 | -5.6% |
| uci_get_authorized | -0.23% | 180-184 | 185-232 | -2.4% |
| uci_get_authorized_c4 | -5.30% | 152.8-157.7 | 156.7-163.7 | -3.4% |

R93 中 `session_access_64_c4` 曾比 R89 延迟 +13.8%、CPU +27.8%；现为延迟 -6.8%、CPU -5.6%，范围不重叠。`session_access_granted` CPU 由 R93 的 23→27.5 退步变为 20 对 R89 22-25，范围不重叠。

**其余负载对 R89：** file_list CPU -50.6%/延迟 -40.2%（内部对象罕见分配路径）、file_list_c4 -52.8%、uci_configs -30.1%、uci_get_network -23.0%、file_stat -17.5% 等，均延迟与 CPU 双优。

**两处非严格双优（对 R89）：** `uci_get_64`（延迟 +1.61%、CPU +0.75%）与 `uci_get_64_c4`（延迟 -2.51%、CPU +2.10%）。这是 64 段 UCI **读取**重负载，非本轮优化的会话/授权路径；其 ~675 µs 的成本由 UCI 配置序列化主导，CPU 逐轮范围与 R89 大幅重叠（候选 670-680 对 R89 670-730；候选 657-694 对 R89 648-740），属轮间噪声而非本改动引入的退步。两者仍远优于 C（675 对 1510 / 1537）。

**对 C：** 全 18 负载在延迟与 CPU 上均优于 C，重负载优势超过一倍（uci_get_64 CPU 675 对 1510、file_list 226 对 458）。

## 机制

`strace -c`（单客户端 10000 请求，会话权限）：R89 每请求 5 次系统调用（3 recvmsg + 1 sendmsg + 1 epoll_wait），候选 3 次（1 recvmsg + 1 sendmsg + 1 epoll_wait）。daemon 约 80% 时间在内核，系统调用数就是杠杆；读前缓冲把 3 次接收降为 1 次。ACL 快路径去掉授权请求的 4 次 CString 分配。C 每请求 5 次（2 sendmsg + 2 recvmsg + 1 epoll_wait）。

## 边界

三侧仅替换 rpcd，依赖与正式运行栈保持 R92（生产为全 C，从未切换）。候选为同 SDK recipe 的诊断构建，构建 host 与 canonical R89 不同，不能把全部差异唯一归因于代码。c4 CPU 用单一外层区间、按成功与预热总数归一化，客户端在同一路由器消耗 CPU，不能当服务端极限。逐轮范围、分位数、内存、身份见 `private/r94/device-rpcd-01/report/results.json`。未部署到生产。
