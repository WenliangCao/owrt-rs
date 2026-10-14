# DHCP 行为独立审计（2026-10-14）

本子审计在实际配置下未发现阻止上线的 DHCPv4 行为差异，也没有仅凭源码提出的疑似 DHCP 问题。这个结论限于下述范围；整体验收还需要 DNS 转发、重载及其他子审计结论。

## 被测对象和证据边界

- Rust 源码：`58365e8c8ebe1805573baa02543baf1c9d45be68`；release ELF SHA-256：`5931b2d114ae5c3e911775e8fd529dcf83ef8718e2c11b50916ce1164dab0966`。
- C oracle 是**精确 OpenWrt 25.12.5 镜像中的 ELF**，SHA-256：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`，使用同一镜像 musl 加载；不是 native 重编译 C 替代品。上游匹配源码用于解释行为。
- 保持 737 字节生成配置及其 include、DHCP/DNS 端口、LAN 接口名、resolver 文件不变；配置 SHA-256：`273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`。
- 原 runtime capture 没有 passwd/group/hosts/ethers。私有 `dhcp/runtime-root` 用精确镜像补齐这四个文件后叠加已有捕获文件。四项均存在且逐字节一致，见 [runtime-inputs.json](runtime-inputs.json)。没有把真实配置、地址、租约或镜像文件加入 Git。
- Linux 网络、挂载、PID namespace 内重建 `br-lan` 和 client veth。12 个不同合成 MAC/client-id 在一个 client namespace 中发真实 DHCP Ethernet/IP/UDP 报文；包括普通 option 61 MAC ID、RFC 4361 形状的稳定 ID、无 client-id。没有连接或修改物理路由器。
- 初始获取从空的合成租约库开始；正常/异常重启恢复该次生成的租约。另有独立 C→Rust 接管门，使用精确 C 当次写出的租约文件，不依靠 Rust 自产文件推断兼容性。

## 执行结果

新增复跑工具：[predeploy_audit_dhcp.py](../../../../../../tools/dnsmasq/predeploy_audit_dhcp.py)。以下四组共 **134 对 DHCP 完整 payload、657 对 DNS 语义结果**，均零差异；计数包含各独立组重新建立的初始租约，不表示 134 个互不重叠场景。原始结果、报文和租约保存在 oracle 的私有目录，公开 JSON 记录原始结果文件 SHA-256。

| 组 | 已执行行为 | DHCP / DNS 对照 | 派生证据 |
| --- | --- | --- | --- |
| 生命周期及混合流量 | 12 个客户端同时发 DISCOVER，收齐 OFFER 后同时 REQUEST；单播续租、广播重绑、INIT-REBOOT、不带主机名续租、改名、同名争用、稳定 client-id 换 MAC、错误子网 NAK 后有效请求恢复、INFORM、RELEASE、HUP、正常重启、SIGKILL 后重启 | 67 / 303 | [concurrent.json](concurrent.json) |
| 无流量过期 | 客户端请求 1 秒租期，两端同样钳制为 120 秒；客户端离线不 RELEASE；真实等待到期加 2 秒，再获取地址 | 27 / 192 | [expiry.json](expiry.json) |
| 日常名字形式 | option 81 DNS 编码 FQDN、ASCII FQDN、外部域后缀；带下划线的 IoT 名字、混合大小写名字 | 29 / 111 | [names.json](names.json) |
| C 租约接管 | 将同一份精确 C 写出的 11 租约文件分别交 C 和 Rust 启动，先查询全部本地 DNS，再逐个续租 | 11 / 51 | [takeover.json](takeover.json) |

生命周期初轮另保留 [lifecycle.json](lifecycle.json)，67 / 303 零差异；混合流量组是在新增并发 DNS 检查后重跑，不重复累加该初轮。

独立检查得到的行为：

- 12 个已提交地址互不重复，掩码、路由、DNS、广播、12 小时租期、server-id、主机名等选项及顺序与 C 一致；完整 DHCP payload 对照还覆盖 xid、chaddr、BOOTP 固定字段和 padding。
- 每阶段查询短名 A、FQDN A/AAAA、每个地址 PTR；对照 ID、问题、flags/rcode、记录顺序、类型、TTL、内容。只有 IPv4 DHCP 租约的名字，其 AAAA 查询表现与 C 相同。
- 改名撤销旧名字；同名争用按 C 行为把名字移给后一个客户端，两个客户端地址仍保留；RELEASE 后文件与 DNS 同时撤销。`wpad`、`localhost` 客户端获取地址但租约名字被实际 bogus-hostname 规则忽略，与 C 相同。
- HUP、正常重启、主动 SIGKILL 重启、C 租约接管都在**发第一份续租请求前**检查 DNS，避免用续租意外修复启动发布缺失。主动 SIGKILL 的 `-9` 是测试注入，不是进程自身崩溃；其余退出码均 0。
- 到期组在发任何到期后 DNS/DHCP 报文之前读取 leasefile：两端都已自主移除过期客户端。之后 A/PTR 撤销及再次 DORA 恢复均与 C 相同。
- 在 12 客户端获取地址、ICMP 地址探测等待期间，池外观察客户端每 100ms 查询一个 `.lan` 本地不存在名字。C 与 Rust 各完成 232 次、没有 3 秒超时；最大观察延迟约 0.947ms / 0.510ms。这是 oracle 功能观察，不能用作 AX3000T 性能结论。

## 不一致和随机量处理

没有发现具有客户端影响的差异。续租/重绑的 option 58、59 原始字节不同，是 C 自身的随机化行为，不能直接按字节差异报 bug。

比较器对每一份含续租 timers 的 ACK 独立验证，再只屏蔽对应 8 字节，其余完整 DHCP payload 仍逐字节比较：

- 实际 43,200 秒租期：`T1 = 21,600 - f`，`T2 = 37,800 - f`，`0 <= f <= 2,700`，两个 timer 必须减同一个 `f`。
- 120 秒短租期：同样计算，`T1 = 60 - f`、`T2 = 105 - f`、`0 <= f <= 7`。
- OFFER、SELECTING、INIT-REBOOT 的非随机 timer 原样比较，不被放宽。INFORM 无 timer 时也不套用该归一化。
- 独立复核匹配 C `rfc2131.c:2751–2783`：16 位随机数反复减半至 `T1/8` 以下再共同相减。Rust `src/dhcp/reply.rs:392–430` 及 `src/dhcp/service.rs:684–685` 保持相同触发条件、16 位熵输入和计算。没有仅以“数值看起来合理”代替源码核对。
- 租约绝对过期时间随启动/ACK 时刻变化。比较器比较相对剩余时间，容许两轮执行时差不超过 5 秒；本轮四组实际最大差为 0 秒。租约地址、MAC、client-id、名字不归一化，逐项严格比较。

## 复现

在 oracle，公共源码位于 `/home/ubuntu/dnsmasq-predeploy-behavior-20261014/source`；以下路径均为离线输入或隔离输出，不能改成物理路由器。

1. 原捕获位于 `/home/ubuntu/dnsmasq-dhcp-network-actual-20261001/private/runtime-source/rootfs`；私有完整输入为 `/home/ubuntu/dnsmasq-predeploy-behavior-20261014/private/dhcp/runtime-root`。镜像 root 为 `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`。
2. 从 `/home/ubuntu/dnsmasq-northstar-dns-20261002/private/c-network-07/topology.json` 的 `router` 读取 CIDR，不公开展开。依次执行 `sudo -n sh run_isolated.sh` → `actual_config_network.py --source-root RUNTIME --router-cidr CIDR --output NEW_PRIVATE_NETWORK` → `actual_config_rootfs.py --source-root RUNTIME` → 下列审计命令。每层用 `--` 分隔其后命令，输出目录必须是新的 `private/` 子目录。

```text
python3 predeploy_audit_dhcp.py --mode run --out NEW_PRIVATE_RUN \
  --binary BINARY --image-root IMAGE_ROOT \
  --reference-build /home/ubuntu/dnsmasq-rewrite-20260929/c-native-01 \
  --source-sha SOURCE_ID --concurrent-dns
```

`BINARY` 分别使用精确镜像的 `usr/sbin/dnsmasq` 和冻结 `private/release/dnsmasq-rs`。`reference-build` 仅供测试 UBus fixture，**不是 DHCP oracle 二进制**。到期组把 `--concurrent-dns` 换成 `--expiry-only`；名字组换成 `--names-only`；接管组换成 `--takeover-from PRIVATE_C_CONCURRENT_RUN`，从该目录 `release.leases` 和合成 `clients.json` 恢复。

```text
python3 predeploy_audit_dhcp.py --mode compare \
  --c-result PRIVATE_C_RUN/result.json \
  --rust-result PRIVATE_RUST_RUN/result.json --out DERIVED_OUTPUT
```

本轮私有 run 名称分别为 `c-concurrent-01` / `rust-concurrent-01`、`c-expiry-01` / `rust-expiry-01`、`c-names-01` / `rust-names-01`、`c-takeover-01` / `rust-takeover-01`，共同位于 `/home/ubuntu/dnsmasq-predeploy-behavior-20261014/private/dhcp/`。

准备失败 `c-01` 保留在同一私有目录：缺少镜像账户文件导致 C 报 `unknown user or group: dnsmasq`，0 个 DHCP 应答。补齐离线输入后才执行有效对照；该次不计产品失败或通过。

## 未覆盖范围

- 没有真实 Wi-Fi 射频、独立 12 台设备/12 条链路、AP 隔离、漫游、丢包/乱序/节能唤醒，或真实 Android/Windows/macOS DHCP 客户端程序。测试的是这些客户端常用报文形式和服务器行为。
- 没有等待真实 12 小时自然到期，也没有长期运行/资源性能结论；以协议允许的短租期做真实计时，未修改系统时钟或服务端 range。
- 没有本轮独立穷尽满池、静态地址冲突的 ICMP 拒绝分支、广播风暴、全部畸形 option、外部 DHCP server 竞争、relay/PXE/BOOTP、leasequery、自定义 DHCP options、所有静态 reservation/tag 组合。后面几项未启用于实际配置，不能由本报告推定兼容。
- DHCPv6 不属于这个镜像中 `nodhcpv6` dnsmasq 的替代职责；没有据此宣称替代 odhcpd/RA/DHCPv6。AAAA 本地查询已对照，IPv6 DNS 传输/上游由 DNS 子审计负责。
- HUP 保留租约及名字、重启恢复已测；修改 UCI 后重新生成配置、ethers/hosts 动态修改的完整 procd/reload 调度由重载子审计负责。这里用真实 UBus fixture 供进程启动，没有用这份 DHCP 结果证明完整系统集成。
