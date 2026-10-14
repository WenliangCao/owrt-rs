# 实际配置报文边界检查

2026-10-14；源码 `58365e8c`。本子检查没有复现崩溃、服务退出、DHCP 分配失效或正常本地查询失效；发现一项不阻止上线的异常报文连接关闭差异。它是行为审计的补充，不单独给出整机可替换结论。

## 证据与结果

[summary.json](summary.json) 保存二进制、原配置、工具及私有原始结果 SHA-256，以及逐项匹配清单。C 是精确镜像 ELF `097a9e21…cab87`，由该镜像的 musl 及共享库装载；Rust 是本次 release ELF `5931b2d1…0966`。两边配置 SHA-256 均为 `273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`，没有删改原配置或 include。

完整 corpus 的 fixture 限制：`-02` 轮仅补入镜像 passwd/group，捕获 runtime 中缺少的 `/etc/hosts`、`/etc/ethers` 当时仍不存在。原 dnsmasq 配置及 include 字节保持不变，但这不是完整的原镜像文件环境；该轮只支持报文边界、进程健康与合成客户端 DORA 结论，不支持镜像静态 hosts/ethers 的兼容性结论。随后 `-03-control` 在私有 `/etc` 中补齐四份精确镜像文件，重跑了正常查询、两项差异及 DORA 控制，见下文。

完整 corpus 每个实现执行：

| 范围 | 数量 | 结果 |
| --- | ---: | --- |
| DNS UDP | 158 | 包含有效 A/AAAA、逐长度截断、计数字段、压缩指针、label 长度/type、EDNS 大小/TLV、超长尾部及固定种子的 64 个突变；与 C 结果相同 |
| DNS TCP | 158 | 同一 corpus；156 项相同，2 项仅 EOF/RST 不同 |
| DHCP | 31 | 短固定头、hlen/htype、坏 option 长度、空 PRL/client-id、FQDN 短值、overload 与未知类型；5 项回复逐字节相同，26 项两边均无回复 |
| 存活/健康 | 20 | corpus 中途及最终 DNS 检查均收到回复，末尾完整 DISCOVER/OFFER/REQUEST/ACK 成功 |
| 退出 | 1 | corpus 后进程仍活着，SIGTERM 退出码均为 0，无强杀 |

316 项 DNS 中，两边各有 180 个响应；其余是对无效查询的丢弃、连接关闭，或突变后外部域名没有受控上游回应。未把这些超时当成成功解析。逐项比较确认 314 项完全相同，另外两项如下。

补齐四份精确镜像文件的 `-03-control`：每边 8 项 DNS（A/AAAA、4096/65507 字节两种异常包，各执行 UDP/TCP）和 6 次健康观察全部完成，末尾 DORA 成功，进程正常退出 0。6 项 DNS 结果完全相同，两项异常 TCP 仍为 C EOF / Rust RST。因此 R-OBS-01 和该短控制的健康结论不依赖缺失 hosts/ethers。完整 316+31 corpus 没有在补齐四项后重复，不把短控制扩大成全 corpus 复验。`summary.json` 的 `complete_fixture_control` 保存四份文件 SHA-256、工具/结果身份及此次对照。

## R-OBS-01：超长异常 TCP 查询以不同方式关闭连接（已复现；低；不阻止上线）

用合成查询 `robustness-audit.lan A`，在 question 结束后添加零字节，将 DNS 消息填充到 4096 或 65507 字节，再加两字节 TCP 长度前缀发送。精确 C 的客户端读到 EOF，Rust 的客户端收到 `ConnectionResetError`。两边均不返回 DNS 回答，进程保持正常，紧随其后的 UDP/TCP 正常查询及 DORA 成功。

这是本次配置下超长、无 OPT 声明的尾随填充报文；已测普通查询、1233 字节以下填充及 EDNS 查询不出现该差异。客户端影响限于异常请求观察到的连接错误类型，不改变本次正常 DNS/DHCP 结果，故不阻止上线。没有据此声称所有可能的长 TCP 查询等价。

Rust 的长度界限来自 `main.rs:932` 的 `edns_packet_max + 255 + 10`，传入 `main.rs:5429` 的 `TcpFramer::with_max_frame`；`dns/service.rs:98` 在超过界限时拒绝帧。这解释了拒绝路径；未用抓包证明 C 与 Rust 内核关闭时序，因此 EOF/RST 的具体时序原因不作已证实根因。

## 源码检查

沿实际启用的 UDP/TCP 接收、DNS wire/EDNS、DHCP packet/options 边界检查了直接索引、unwrap/expect 和断言。DNS `wire.rs:31` 先检查加法及范围，`Header::parse`、`RecordRef::parse` 在读取固定字段前验证长度；`decode_name` 限制名称长度和指针跳数。DHCP `packet.rs:271` 在构造可访问的 Packet 前验证最短头、硬件地址长度，option 扫描通过 slice `get` 验证 TLV；overload 无递归扫描。所查看的这些边界没有给出实际配置可达的确定 panic 复现。此结论不等于对整个缓存/所有状态不变量的形式证明。

## 复现

工具为 `tools/dnsmasq/predeploy_audit_robustness.py`。在 oracle 上使用与主体审计相同的私有运行证据和网络：

```sh
sudo -n sh "$TOOLS/run_isolated.sh" \
  python3 "$TOOLS/actual_config_network.py" \
  --source-root "$RUNTIME" --router-cidr "$CAPTURED_ROUTER_CIDR" \
  --output "$PRIVATE/network-fresh" -- \
  python3 "$TOOLS/actual_config_rootfs.py" --source-root "$RUNTIME" -- \
  python3 "$TOOLS/predeploy_audit_robustness.py" \
  --binary "$BINARY" --image-root "$IMAGE_ROOT" \
  --reference-build "$REFERENCE_BUILD" --out "$PRIVATE/result-fresh"
```

分别令 `BINARY` 为精确镜像 `/usr/sbin/dnsmasq` 文件及冻结源码的 release ELF。`REFERENCE_BUILD` 仅用于 UBus fixture，不作为 C dnsmasq 行为 oracle。两边输出使用不同的新目录；`PRIVATE` 路径必须包含 `private`。工具仅向隔离网络发包，不访问物理路由器。

当前工具默认补齐四份精确镜像文件；添加 `--quick` 重现补齐后的短控制。

完整 corpus 原始结果位于 oracle 的 `/home/ubuntu/dnsmasq-predeploy-behavior-20261014/private/robustness/{c-02,rust-02}/`，保留每个输入、DHCP/DNS 输出、健康检查及进程日志。相邻 `*-02-invocation.json` 保留完整私有参数；`*-02-network/topology.json` 保留私有拓扑。首次 `{c,rust}` 两边启动失败，是 runtime capture 未包含 passwd/group 的测试准备问题；第二轮仅在私有 `/etc` 挂载中补入精确镜像的两份账户文件。首次记录保留，不计产品缺陷。补齐 hosts/ethers 后的短控制保存在同一私有目录的 `{c-03-control,rust-03-control}/`，相邻 invocation/network 文件保留调用和拓扑；未修改捕获源文件。

## 没有覆盖

这不是持续随机 fuzz、带 sanitizer 的运行、恶意洪泛、长时内存/FD 泄漏或资源耗尽测试；没有模拟碎片重组、物理 Wi-Fi、非 Linux 网络栈，也没有为此子检查引入上游异常应答 corpus。DHCP 主要使用不占用地址的 INFORM 边界包和末尾 DORA，其他租约生命周期由主体审计覆盖。未启用 DHCPv6/RA、PXE、TFTP 等不借此获得通过。
