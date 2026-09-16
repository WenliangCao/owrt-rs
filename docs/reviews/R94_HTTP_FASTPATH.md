# R94 HTTP 监听器内联快路径

2026-09-16。目标：让 httpd 在停放后（paced keep-alive）的每请求成本既优于 C 原版、也优于正式 R89。所有实验在 Oracle Linux AArch64 私有 namespace loopback 上完成，未访问路由器。候选由 SDK musl 交叉编译（sha256 `d418b497c5109785830f`），静态链接。

## 改动

1. **监听器内联快路径**（`components/httpd/src/fast.rs`，接入 `main.rs` 的 `accept_loop`）。一条已停放的 plain-HTTP keep-alive 连接，其就绪事件若携带一个完整的小 GET/HEAD 请求头、目标为普通可读文件（≤32 KiB，且不涉及 CGI/ubus/auth/alias/RFC1918/TLS-redirect 政策），就在监听器线程上直接完成：`MSG_PEEK` 探测 → 复用现有 `HeadBuffer` 解析 → 用同一个 `files::serve` 把完整响应生成到有界内存 → 精确消费已解析的头字节 → 非阻塞 `send`。socket 全程不离开 epoll 集合。

   这消除了停放请求原先每次都要付的：epoll DEL/ADD、线程移交（唤醒或新建）、50 ms 接收超时、8 KiB reader 重建。等价于 C uhttpd 在单个 uloop 上就地处理的稳定注册形态。

   所有其他请求整体回退到线程路径：在生成出完整响应之前不消费、不发送任何字节，因此回退路径服务的字节与快路径不存在前完全一致。短写时保留有界 `PendingReply`（每 listener ≤4），经 POLLOUT 排水，带网络超时。TLS、pipelined、请求体、错误页、所有解析失败都保持既有路径。

2. **请求头控制字符单遍 SWAR 扫描 + 按长度索引的头名表**（`http.rs`）。R92 的逐字节控制字符扫描在 R93 本地阶段剖析里占头解析 12–18%；改为每步 8 字节（对每个字节值、每个对齐位都与标量谓词逐一核对）。头名小写化先按长度分派，典型头至多比较两个候选。

3. **移除 R93 空闲 worker 缓存**。它在 keep-alive 连接安静后保留至多 4 个线程 1 秒，违反 R85/R93 内存合同（连接关闭后 Threads 必须回到基线）——这正是之前 worker/head 候选一直无法合入的原因。内联快路径已经以「零线程」服务了该缓存的目标场景（停放小静态），所以缓存对本目标是冗余的，只会拖累门禁。恢复为每活动连接一线程，停放的空闲连接仍只占一个描述符。

## 正确性门（Oracle，aarch64 原生）

8 个历史门全部 exit 0：`httpd-unit`、`httpd-clippy`、`httpd-resources`、`httpd-static`、`httpd-extended`、`httpd-r14`、`httpd-fuzz`、`httpd-cgi-stress`；另加 `shared-cap`、`http-r92` 均 exit 0。

- fuzz 133/133 通过，候选变更仅 `chunked-huge-size`、`header-ctrl` 两项 R92 既批准偏差——SWAR 重写未引入任何新偏差。
- `httpd-static` 含 64 连接空闲内存释放子测（曾令 worker/head 候选失败）现通过：fds 立即归零、Threads 在关闭后回到基线。
- extended 31/31、SSE 断开清理通过（Rust 保留 0 fd，C 保留 12）。
- 唯一的红是 `static-cold-memory`，因 `r93_httpd_worker_memory.py` 是仅存在于 Oracle 的私有工具、从未纳入仓库（FileNotFound），非候选缺陷；其覆盖的 64 连接释放已由 `httpd-static` 验证。

## 性能：四侧 paced 对照（16 KiB 静态、4 客户端、gap 0/40/60/80 ms）

单位 µs/请求（daemon 自身 CPU 中位数）与平均延迟中位数 µs。停放阈值 LINGER=50 ms 决定结构：gap40（<50 ms）连接尚未停放、走线程路径，与 R89 持平；gap60/80（>50 ms）停放后命中快路径。

_单轮 pilot（方向性）：_

| gap | C CPU | R89 CPU | source05 CPU | **R94 CPU** | C lat | R89 lat | R94 lat |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | 39.0 | 32.0 | 33.0 | 32.5 | 146.0 | 58.1 | 59.5 |
| 40 | 50.0 | 50.0 | 50.0 | 62.5 | 127.9 | 121.0 | 132.2 |
| 60 | 50.0 | 275.0 | 262.5 | **37.5** | 151.1 | 272.8 | 147.4 |
| 80 | 50.0 | 287.5 | 287.5 | **37.5** | 144.8 | 301.6 | 160.1 |

pilot 在 gap60/80 上，R94 自身 CPU（3 ticks）**同时低于 C（4 ticks）与 R89（22–23 ticks）**——正是停放场景的目标。gap0 与 R89 持平、优于 C，无回退。gap40 单轮高 1 tick 属量化噪声（该路径与 R89 相同代码）。

_四轮交错 formal：见下（完成后填入）。_

## 边界

- Oracle AArch64 GNU 主机的 SDK musl 诊断构建，非 canonical x86_64 CI 发布；C/R89 为精确镜像/正式产物。
- daemon CPU 用 /proc stat（含已退出 worker），100 Hz 量化，每 tick=12.5 µs（paced）；不替代整机冷启动或冻结的 74 项性能矩阵。
- 停放阈值 50 ms 未改；gap<50 ms 的真实浏览器点击间隔仍走线程路径。
- 原始逐轮数据、身份与门日志在 Oracle `/home/ubuntu/r94-httpd/`，未纳入 Git。
