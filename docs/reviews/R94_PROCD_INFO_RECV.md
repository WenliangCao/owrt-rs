# R94 procd：单 pread 的 system info + 单 recvmsg 总线读取

2026-09-16。目标：让 procd 的总线请求路径既优于 C 原版、也优于正式 R89，收回 R93 记录的对 R89 系统性 CPU 偏高（+0.7%…+6%）。筛选在 Oracle Linux AArch64 私有 namespace loopback 上完成，终验在 AX3000T 实机（全 C 生产栈，从未切换）。候选 `0df4baae`（SDK musl 交叉编译、静态、sstrip）。

## 改动

1. **总线读取继承 rpcd 轮的读前缓冲**（`components/ubus/src/conn.rs`，rpcd 轮合入）。procd 每请求原为 `ppoll` + 两次 `recvmsg`（头、体）+ `sendmsg`；现在一次 `recvmsg` 整块读入、从缓冲切帧，`strace` 4→3 系统调用/请求。C 原版为 5（2 recvmsg + 2 sendmsg + epoll）。

2. **`system info` 的 /proc/meminfo**（`components/procd/src/sysobj.rs`）。R89 每请求 `open` → `read` → 再 `read` 一次拿 EOF → `close`，读入 `String`（UTF-8 校验）后用 `str::lines` + `split_once(':')` 逐行找键，`perf` 显示仅 `CharSearcher` 就占 daemon 采样 8%。现在描述符在启动时打开一次（`Meminfo::open`），每请求从偏移 0 做一次 `pread`——procfs 对偏移 0 的读取会重新生成报告（`top`/`htop` 对 `/proc/stat` 的做法）；缓冲填满才继续读到 EOF，没有描述符（/proc 未挂载）则回退到逐次打开路径，因此启动后描述符数恒定（`r85` busy 门校验 fd 前后相等）。解析改为字节级、与 C 完全同构：`strtok(line, " :")` 取键、`strtok(NULL, " ")` 取值、`strcasecmp` 比较键，键或值缺失的行跳过；只有长度匹配的两个键才做比较。`strace`：`pread64`×1 取代 `openat`+`read`+`read`+`close`。

3. **blob 编码器收紧**（`components/ubus/src/blob.rs`）。表/字段头部一次 `reserve`，NUL 终止与 4 字节对齐由同一次 `resize` 完成；`open`/`close`/`set_raw_len` 加内联提示。`service list` 的 32 次 `Service::dump` 是其用户态热点，本项收益在 Oracle 上不可分辨，属零风险清理。

## 正确性门（Oracle，aarch64）

16/16 exit 0：R92 伞形验证器的 procd 集合 12 项——`procd-unit`（85）、`procd-clippy`（`-D clippy::undocumented_unsafe_blocks`）、`procd-watchdog-status`、`procd-tick`（R88 F1 维护节拍）、`procd-busy-original`/`-candidate`（R85 忙时 fd 恒定）、`procd-r65`（对 C 差分，需 `notifier` 例程）、`procd-r83`（R81 修复回归）、`procd-r71-hotplug`、`procd-r72`（tty）、`procd-r75`（sysupgrade）、`procd-r90`（生命周期）；R92 恢复探针 procd 用例（`procd_disconnect_logs`、`procd_watchdog`）与兼容探针 `procd_bundle`；R93 两个通知探针 `service.start` 与 data-trigger 各 **12/12**（R93 早期队列曾退化到 0/12、2/12 的两类）。ubus 45 单测通过；链接 ubus 库的其他组件单测已在 rpcd 轮全绿。

## 性能：实机三侧四轮矩阵（stock C / 正式 R89 / 候选，8 负载，96 观测）

前后健康、boot_id、运行身份一致。首次运行在第 9 个样本时被一次 ssh 传输中断（wifi 抖动），路由器残留清理后从头重跑；重跑期间 CLI 重启杀掉了分离的驱动进程，改为 `screen` 会话并用 `--resume` 续跑（保留 1 个已完成样本，重做被打断的样本）。单位 µs/请求，逐轮中位数。

**对 C：8/8 负载延迟与 CPU 双优**，CPU -19%…-46%。

**对 R89：**

| 负载 | 候选延迟比 R89 | 候选 CPU（范围）| R89 CPU（范围）| CPU 比 R89 |
|---|---:|---:|---:|---:|
| system_info | -24.4% | 91-94 | 137-177 | **-34.9%** |
| system_info_c4 | -17.8% | 75.4-80.4 | 116.1-139.9 | **-35.1%** |
| service_list_named_128 | -4.7% | 26-27 | 29-32 | -8.5% |
| service_list_named_128_c4 | -9.4% | 18.8-26.8 | 24.8-29.8 | -20.4% |
| service_list_32_c4 | -4.7% | 53.6-57.5 | 53.6-66.5 | -3.5% |
| service_list_32 | -1.1% | 63-66 | 63-81 | -2.2% |
| service_list_128 | -0.1% | 206-208 | 202-222 | -0.2% |
| service_list_128_c4 | +1.7% | 171.6-185.5 | 183.5-188.5 | -5.6% |

R93 记录的全部 8 项 R89 偏高（service_list_32 69→69.5、system_info 143→145.5、list_32_c4 +6.2%、named_128_c4 +5.9% 等）均已反转。`system_info` 两条为不重叠的大幅优势。唯一非严格双优是 `service_list_128_c4` 延迟 +1.7%：候选 2159.6-2216.0 对 R89 2145.6-2238.4，范围完全重叠，而其 CPU 低 5.6%；该 lane 由 128 个服务的 blob 编码与 4 客户端调度主导，不在本轮改动路径上。候选延迟离散度普遍小于 R89（如 list_32 候选 199.8-205.6 对 R89 201.0-295.7）。

## 机制与剩余空间

`perf`（Oracle，符号版构建）：`service list` 的用户态时间约 35%，其中 `Service::dump` + `msg_open_bytes` + `memcpy` + `msg_field` ≈ 15% 总采样——blob 编码是用户态主项，其余是内核的 recvmsg/sendmsg/ppoll。C 在同样的编码上与 R89 打平（69 µs），所以 list lane 对 R89 的余量只能来自系统调用削减（已做）与编码器；一个按服务缓存编码结果的方案可再削一半用户态，但其失效点遍及所有状态变更路径，未采用（正确性优先）。`system info` 的剩余成本是 `sysinfo`、两次 `statvfs` 与内核 `meminfo_proc_show` 的数字格式化，与 C 同构。

## 边界

三侧仅替换 procd（`-S` 监管模式，空 init/rc 目录），依赖为原版 ubusd，生产栈保持全 C。候选为同 SDK recipe 的诊断构建，构建 host 与 canonical R89 不同，不能把全部差异唯一归因于代码。c4 CPU 用单一外层区间、按成功与预热总数归一化，客户端在同一路由器消耗 CPU。逐轮范围、分位数、身份见 `private/r94/device-procd-02/report/results.json`。未部署。
