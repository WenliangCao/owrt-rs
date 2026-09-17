# R94 netifd：一次 RTM_GETLINK 取全部链路计数器 + 复用回复/netlink 缓冲

2026-09-17。目标：让 netifd 的总线只读路径既优于 C 原版、也优于正式 R89，收回 R93 记录的 `wireless_status`（+6% CPU）、`interface_dump_c4`、`device_status_c4`、`lan_status_c4`、`device_status_all_c4` 对 R89 的偏高。方法是先量再改：`strace -c` 逐 lane 数系统调用，`perf` 用带符号的构建定位用户态热点，再对照 C 源码确认字节忠实度。筛选在 Oracle Linux AArch64 私有 namespace 上完成，终验在 AX3000T 实机（全 C 生产栈，从未切换）。最终候选 `5f20a5a4`（SDK musl 交叉编译、静态、sstrip）。

## 发现

1. **`network.device status` 每请求约 85 次系统调用。** `strace` 逐调用跟踪：打开 `/sys/class/net/<dev>/statistics` 目录后对 23 个计数器各做 `openat`+`read`+`close`（70 次），加 6 次 ethtool `ioctl`、uevent 读取 4 次、总线 3 次。C 的 `system_if_dump_stats` 完全相同（固定 23 个文件名、列主序），所以 R89 与 C 在该 lane 只差用户态（616 对 667 µs）。
2. **32 接口 dump 用户态由 blob 编码与缓冲增长主导。** 带符号 `perf`：`msg_open_bytes`、`memcpy`、`memset`、`malloc/free`、`Display` 格式化；回复 `BlobBuf::with_capacity(1024)` 每请求从 1 KiB 经多次 realloc 增长到十几 KiB，在 musl 上表现为 mmap/munmap 与页清零。
3. 单接口 `status`/两接口 `dump`/`wireless status` 已由 rpcd 轮合入的 ubus 读前缓冲少一次 `recvmsg`（4→3 系统调用）。

## 改动

1. **链路计数器改自 netlink**（`components/netifd/src/{device,ethtool,main}.rs`）。sysfs 的 `statistics/*` 文件是内核 `rtnl_link_stats64` 同一结构的逐字段视图（`net-sysfs.c` 用 `dev_get_stats` 的相同结构按 `offsetof` 打印），而每个 RTM_GETLINK 回复都自带 `IFLA_STATS64`。现在每个设备 status 做一次 `RTM_GETLINK`（`sendto`+`recvfrom`），按 C 的列主序映射 23 个字段（`STATS64_INDEX`），值与 sysfs 完全相同；无回复或无该属性时回退到原 sysfs 路径。`strace`：85→19 次/请求。
2. **netlink 回复缓冲跨调用复用**（`netlink.rs`）。`dump_one` 原每次 `vec![0; 64 KiB]`，musl 下即一对 mmap/munmap 与缺页；改为 `Netlink.reply` 常驻。
3. **只读回复共用一个 BlobBuf**（`main.rs`）。dump/status/device/wireless 六处 `with_capacity(1024)` 改为 `take_reply()`/`send_reply()`，发送后 `reset_bounded(64 KiB)` 保留容量；地址、路由目标用栈上格式化（`IpText`，输出与 `to_string()` 逐字节相同）；静态地址不再为不存在的 lifetime 读时钟。

## 正确性门（Oracle，aarch64，候选 2）

9/9 exit 0：`netifd-unit`（157）、`netifd-clippy`、`netifd-suite`（r46 netlink 差分、r47 devstatus 差分、r48 ifstatus 差分、r49-r55、r83、r90、r91 等 **31/31**，对 C netifd 逐字节差分含 device status 的 statistics 表）、R92 恢复 `netifd_overflow`（溢出后缓冲增长、事件不丢、继续服务）、R92 兼容 `netifd_restart`、R93 重连探针 `network.device` 与 `network.interface.loopback` 两种故障、`r90` 生命周期、`r91` 日志。候选 1（仅改动 1+2，`0bfcfc7a`）同一套门亦 9/9。

## 性能：实机三侧四轮矩阵（stock C / 正式 R89 / 候选，14 负载，168 观测）

前后健康、boot_id 一致。单位 µs/请求，逐轮中位数。候选 1 与候选 2 各跑一轮完整矩阵；下表为候选 2。

**对 C：14/14 双优**，`device_status` 系 CPU -43%…-60%，`interface_dump_32` -56%，`wireless_status` -95%（C 起脚本）。

**对 R89：13/14 双优，CPU 逐轮范围除 `wireless_status` 外全部不重叠。**

| 负载 | 候选延迟比 R89 | 候选 CPU（范围）| R89 CPU（范围）| CPU 比 R89 |
|---|---:|---:|---:|---:|
| device_status | -29.4% | 372-382 | 612-618 | **-38.5%** |
| device_status_c4 | -29.5% | 349-355 | 599-607 | **-41.5%** |
| device_status_all | -40.5% | 457-468 | 942-956 | **-51.5%** |
| device_status_all_c4 | -46.4% | 431-434 | 944-959 | **-54.7%** |
| interface_dump_32 | -20.5% | 332-337 | 527-556 | **-37.3%** |
| interface_dump_32_c4 | -15.8% | 321-333 | 505-512 | **-35.2%** |
| interface_dump_c4 | -6.9% | 47.6-51.6 | 57.5-64.5 | -19.8% |
| interface_dump | -7.1% | 63-67 | 72-75 | -12.2% |
| lan_status_c4 | -0.5% | 36.7-39.7 | 44.6 | -16.7% |
| lan_status | -4.6% | 47-50 | 51-56 | -7.5% |
| interface_named_32_c4 | -5.1% | 34.7-39.7 | 40.7-42.7 | -16.7% |
| interface_named_32 | -3.9% | 46-49 | 48-51 | -7.0% |
| wireless_status_c4 | -0.9% | 14.9-21.8 | 19.8-24.8 | -23.3% |
| wireless_status | +0.3% | 23 | 23-24 | -4.2% |

候选 1（仅 netlink 计数器）实机：`device_status` 系已达 CPU -37%…-53%，但 `interface_dump_32` 仅 -5.7%；候选 2 的回复缓冲复用把它推到 -37%，并把 dump/named 各 lane 再压低 5-10 个百分点。R93 记录的五项 R89 偏高（`wireless_status` CPU 25→26.5、`interface_dump_c4` 63.5→65.5、`device_status_c4`、`lan_status_c4`、`device_status_all_c4` 延迟）全部反转。唯一非严格双优是 `wireless_status` 延迟 +0.3%（92-95 对 93 µs，1 µs 内；CPU 23 对 23-24），该 lane 在空无线配置下回复 `{}`，成本已是总线往返本身。

## 边界

三侧仅替换 netifd，ubusd 为原版，夹具为静态接口与空无线配置，生产栈保持全 C。候选为同 SDK recipe 的诊断构建。`IFLA_STATS64` 取值与 sysfs 读取相差纳秒级，计数器是活值，无契约差异；老内核无该属性时走原路径。回复缓冲上界 64 KiB，超过即丢弃重建。`wireless status` 仍经 JSON 文本再转 blob（与 R89 相同路径），真实无线配置下的成本未在此夹具中测量。逐轮范围、分位数、身份见 `private/r94/device-netifd-02/report/results.json`（候选 1 在 `device-netifd-01`）。未部署。
