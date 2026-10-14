# 最终冻结候选：Rust9 组合独立验收

2026-10-14，冻结源码 `19bd6162e1b33c92a1e5ea26e864497800c7cfed`。精确镜像 C 与最终 Rust dnsmasq 分别搭配同一组 Rust9，**两侧各 23 项集成检查和 5 项 DHCP helper 检查通过，共 56/56**。这是本页列明的正常集成路径通过，不是产品整体、低内存反例或物理部署通过。

[派生收据](integrated-stack-review.json) 保存全部检查、输入与运行中 ELF hash、比较结果、原始证据 hash 和收尾核验。本轮独立执行，没有复用旧运行结果充当新通过。

## 身份

| 输入 | 本轮核验 |
| --- | --- |
| 最终 Rust dnsmasq | SHA-256 `fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b`，2,089,440 B；每次启动前、安装后、运行中和收尾一致 |
| 精确镜像 C dnsmasq | SHA-256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`；两套 C 运行均核对实际进程 |
| Rust9 | ubusd、procd、netifd、rpcd、logd、uci、reload-config、fw4、httpd；复用[前轮](integration-review.md)从 `e9d89b17` 新构建的 9 个 ELF，本轮没有再构建 |
| Rust9 源码适用性 | `19bd6162` 中上述组件及共享 ubus 的 175 个跟踪文件逐项 SHA-256 对比原 Oracle 构建树，零缺失、零不一致；两个 Git 提交的这些组件无差异 |
| Rust9 ELF | 9 个输入和安装目标分别与原构建清单核对；stack 的 6 个常驻支撑进程另核对 `/proc/PID/exe`。uci、reload-config、fw4 为已核对磁盘 ELF 并实际执行的短命命令，未声称逐一采样其运行中 `/proc` |
| 底座 | 原镜像 init、ujail、odhcpd、libc/库和脚本；fixture 重新验证提取清单以及只读 lower，未改 init 或增加 jail procfs |
| 环境 | Oracle AArch64 `6.17.0-1020-oracle`，每轮独立 mount/network/PID namespace，真实 veth 合成客户端；未访问路由器 |

驱动复制到新私有目录，只参数化输入/输出、区分候选和支撑源码归属并增加身份断言。原 23/5 项行为检查保留；新 helper 驱动补记 ubusd、安装 ELF 与实际 dnsmasq 身份。原工具、源树、ELF 和旧证据未覆盖。

## 通过范围与保留边界

| 路径 | 最终候选与 C 对照 |
| --- | --- |
| init / procd | 启动、无配置变化 reload 保持真实 PID、变更配置生效、SIGKILL 后 respawn 与客户端恢复、stop 全通过 |
| 客户端 | 初始、fw4 加载、RPC apply、respawn 后均真实完成 DHCP OFFER/ACK，并从租约地址查询 UDP/TCP DNS |
| uci / reload-config / rpcd | commit → reload_config 派发，以及授权 session 的 staged set → apply 均使新 DNS 记录生效 |
| httpd / LuCI / ubus | `/ubus` HTTP 调用成功；dnsmasq capability 19 项相同，metrics 30 个字段名相同；未要求动态计数值相等 |
| netifd | 实际依次写入两个 resolver 上游，查询分别得到 `.82`、`.83` 对照地址 |
| fw4 / logd | print/check/start 成功且客户端继续工作；logd 实际接收服务日志 |
| odhcpd | 原镜像 DHCPv6 Reply、hosts 发布及 dnsmasq AAAA 查询链路通过 |
| DHCP helper | 原装 dhcp-script → shell → ubus → Rust procd hotplug 真链路通过；两侧 hotplug 行及 DHCP ACK 订阅事件相同 |

**共同 I2 管理边界仍存在：** 两侧重启 ubusd 后 `dnsmasq*` 对象均为空，DNS 继续回答；显式 init restart 后 DNS 与两个对象恢复。因此 `23/23` 包含对已知故障边界及恢复操作的验证，不能解释为 ubusd 重启能够透明恢复管理对象。原[集成审计](integration-review.md)中的 I2 没有关闭。

本轮没有执行 APK 升降级，不能关闭原 I1 激活问题；也未覆盖低内存 HUP/inotify、轮转语义、物理启动、无线客户端或硬件性能。特别是新的无 held TCP 的 inotify publication 分配失败调查，须以其独立反例验收为准。

## 证据与收尾

原始目录：Oracle `/dev/shm/full-audit-resume-20261014/stack-final/`；本地 `private/full-audit-20261014/resume/stack/`。四个新运行名为 `stack23-c`、`stack23-rust`、`helper5-c`、`helper5-rust`。私有归档 `final-evidence.tar.gz` 的 SHA-256 为 `26ec914e62a554bed67732878e90d85d27d406a8d67bf180c335e28a4d751381`。归档包含驱动、结果、日志和身份收据，不复制 rootfs/overlay；完整 overlay 留在 Oracle 新任务目录。

全部四轮退出 0，收尾按本任务目录核对，没有所属进程或宿主可见挂载残留；最终候选和 9 个支撑 ELF 前后 hash 不变。仅提交本文与派生 JSON，不提交原始配置、session、ELF 或设备材料。
