# 实际 UCI 配置启动与 DHCP/DNS 闭环

2026-10-02，北极星目标达成。产品源码 `3cfd22e` 使用 AX3000T 实际 UCI
生成的 dnsmasq 配置完整启动，在隔离环境完成一轮 DHCP 租约及 DNS 查询，
与匹配 OpenWrt 补丁源码构建的 C dnsmasq 对照一致。此次关闭账本中的全部
8 项阻塞；它是实际配置的功能闭环，不是完整 dnsmasq 替换或生产验收。

## 交付的行为

原配置及 include 保持不变，接口名、端口、路径和 resolver 语义保持原样。
产品接通了 range 标签、按名字设置标签、条件忽略客户端名字、条件广播和
DHCP 接口排除；`read-ethers` 在启动和重载时进入既有静态租约选择链。

DNS 现在加载 `addn-hosts` 目录，执行 `domain-needed`、`bogus-priv` 和
`localise-queries`。监听层处理 `bind-dynamic`、本地来源限制、IPv6 scope
和接口地址增删；接收接口上下文传给本地 DNS 回答。进程按原账户降权、保留
所需网络能力、管理 PID 文件并正常退出。

闭环发现并修复了一个实际 DHCP 差异：Linux `getifaddrs` 的联合字段可能把
本地地址放在缺失广播地址的位置。产品改为读取内核实际 `IFA_BROADCAST`，
缺失时交既有 context 逻辑推导，仍保留显式非标准广播地址。最终 OFFER 和
ACK 的 option 28 与 C 相同。

## 实际执行结果

实验只使用构建机上的网络、挂载和 PID 命名空间。服务端重建 `br-lan` 与
上游接口，独立客户端在获得 ACK 前不配置租约地址；独立受控上游使用原
resolv 文件中的四个端点。账户、include、hosts 和 ethers 来自已有离线
镜像/运行证据。原配置长 737 字节，SHA-256：
`273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`。

同一工具对 C 和最终 Rust 执行以下流程，结果零差异：

1. 原服务命令启动，实际 UBus `dnsmasq` 对象注册，UID/GID 均为 453。
2. DISCOVER 获得 OFFER，选择请求获得 ACK；固定字段及有序 DHCP options
   一致，包括租期、掩码、路由、DNS、广播、域名和主机名。
3. 真实租约文件出现唯一的测试客户端记录，地址、名字和 client-id 一致；
   12 小时到期时间按实际 ACK 时间窗口核对。
4. 租约 FQDN A、短名 A、PTR，以及受控上游 A 共四次 DNS 查询一致，包含
   ID、问题、标志、TTL、记录顺序与内容。原始请求/应答还逐对检查了关联。
5. 首次上游查询按 C 的初始探测行为访问原四个 resolver，每端点一次；
   保留原到达顺序，按端点核对次数。
6. 服务和上游正常退出，退出码均为 0，未强制终止，UBus fixture 清理通过。

辅助验证复用本轮各实现检查，没有在最终版本上重复所有旧门：

| 范围 | 实际结果 |
| --- | --- |
| DHCP 配置解析 | 114 项合同匹配，8 项已知未支持边界单列；无新增失败 |
| DHCP context | 145 场景、402 步一致 |
| DHCP 标签/接口/广播实包 | 13/13 一致 |
| ethers 解析与重载 | 29 cases、36 generations 一致 |
| 目录 hosts 与 DNS 策略 | UDP/TCP 共 38/38 一致 |
| 监听与来源/接口生命周期 | 26/26 一致 |
| 进程身份、能力与 PID | 6/6 一致 |
| 联合源码 `f099ffb` | native、SDK-musl 各库 405、main 8 通过；16 ignored 未计通过；Clippy、fmt 通过 |
| 最终 `3cfd22e` 的接口改动 | native、SDK-musl 各两个解析单测与一个显式隔离内核检查通过；Clippy、fmt、musl 链接通过 |

## 身份和失败记录

最终主机 Rust ELF（调试构建，仅功能验证）：
`1b0d474ef8c147c1d925a6c7461bed07da6d1375c2dde46e6034293017ea0e3c`。
C ELF：`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`，
由匹配 OpenWrt 25.12.5 / dnsmasq 2.93-r1 nodhcpv6 补丁源码构建。
这里执行的是构建机原生 C，不能称作镜像 ELF 或路由器运行。

最终原始结果为 ignored
`private/dnsmasq-rewrite/northstar-dns-20261002/c-e2e-06/result.json` 和
`rust-e2e-02/result.json`。同目录保留报文、租约、进程身份、端点请求、工具、
调用记录及 `stage-result-input.json`。其余检查分别保存在
`dhcp-tags-validation-20261002`、`dhcp-network-actual-evidence-20261002`、
`startup-listener-validation-20261002`、`startup-identity-20261002` 和
`actual-config-integration-20261002` 私有目录。

首次 PID 能力/清理差异、UDP 空闲时持锁造成的 TCP 超时、残留启动校验、
广播地址 option 28 差异均保留，修复后只重跑受影响检查。测试器的编译器路径、
无地址客户端 UDP 接收、启动身份观察时机和首次 resolver 数量假设错误也
保留。前者是产品问题，后者是实验准备/观察问题；未执行的操作不算通过。

复跑入口是 `run_isolated.sh` → `actual_config_network.py` →
`actual_config_rootfs.py` → `actual_config_e2e.py`。传入私有 rootfs、捕获的
路由 CIDR、独立输出目录和二进制；Rust 对照使用已保存的 C 结果。
实际参数和原配置不放进 Git。

## 边界与后续

这次只资格化该实际配置的一轮初始租约和四次 DNS 查询。relay/PXE、自定义
DHCP options、其他未启用能力、完整 TCP 缓存、动态 resolver 更新和长期资源
行为没有借此变成通过。反向缓存与 TCP 流式导入实验已经归档，未并入产品。

性能筛选未重启，本次调试构建不能用于性能结论。后续只按冻结协议进行一次
性能评估，先确认所测场景的功能前置条件，不恢复被拒绝的快照筛选。现有 SDK
阶段包仍旧，不是本次源码的替换包。没有访问、修改或部署物理路由器。
