# DHCPv4、租约、helper 与 TFTP 专项复审

审计日期：2026-10-14。冻结 main：`e9d89b17d72a58b723cce88038ceaa1be58d7f8c`。本专项没有修改产品代码、没有操作物理路由器、没有推送或提交 Git。完整审计结论由 `FULL_AUDIT.md` 汇总。

**在本轮审查和新运行的范围内，没有确认当前 DHCPv4、租约持久化、helper 或 TFTP 的产品正确性缺陷。** 一项 P3 审计工具归属问题和数处旧注释应清理。这里的通过结果不足以证明真实 Wi-Fi 客户端、所有 relay/PXE 拓扑或十组件长期共存已合格；这些范围没有被本专项的合成网络替代。

## 对象与方法

候选为其他审计分工从冻结 main 新构建的 AArch64 musl release：`e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`，2,073,056 B，SDK linker、opt3/LTO、static PIE，未经过完整 SDK strip/APK 包装。本专项所有新运行均使用这个 ELF。

参考是 OpenWrt 25.12.5 镜像实际 C ELF：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。没有拿宿主重编 C 替代镜像。DHCP 矩阵、lease recovery 和 helper 在独立 net/mount/PID namespace 的精确镜像私有 overlay 内运行；TFTP 旧驱动在独立 namespace 内以镜像 musl loader 和镜像库执行 C，数据文件位于私有宿主目录，并非 chroot 测试。

静态检查覆盖 DHCP 输入/overload、配置匹配后的状态事务、地址分配和 DECLINE/RELEASE、租约身份/名称/到期、持久化与 DNS publication 顺序、helper IPC/凭据/退出、TFTP 协商/窗口/路径/文件权限及 relay 转发边界。核对的匹配 C 源码 SHA：

| 文件 | SHA-256 |
| --- | --- |
| rfc2131.c | `14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c` |
| lease.c | `4260039af27b40084cbe6dbbae2bb9417fa3a91806ea53f3f6bdd20234cad763` |
| dhcp.c | `600dc068b0516d7edebcde9b02ae2091a278fc154551106823ddc388170d7001` |
| helper.c | `70feae3213bc32bd047c20b79b3f021a6135ea66fbff21e2ba272f8d965af719` |
| tftp.c | `a6971bf4ce77c0ca4c7ebf0194a2ee9c2ad702b1b8a882d46de87c6c6f5e63f3` |

可提交的派生收据：[dhcp-evidence.json](dhcp-evidence.json)。新驱动、检查器、原始包、lease 快照和日志保留在电脑 `private/full-audit-20261014/dhcp/`；Oracle 原始目录 `/tmp/full-audit-dhcp-20261014/private/`。完整原始归档为电脑 `private/full-audit-20261014/dhcp/oracle-evidence.tar.gz`，SHA-256 `8a95ba8280cdfdccc50f27fea013866b36dec8ca25120980febe179b48b9cc60`。归档不重复包含 rootfs 下层或候选二进制，候选归属使用主审的构建收据。

## 按严重程度排列的问题

### D1 — P3：TFTP 审计工具将新 ELF 的报告错误标成旧提交

位置：[audit_20261011_tftp.py:238](../../../../tools/dnsmasq/audit_20261011_tftp.py#L238)。报告的 `source_commit` 无条件写死为 `3e7df6c1cc45b74f0430e5460379713900172cb4`，不来自被测 ELF 或参数。

复现：本轮执行该工具，`--rust` 指向新构建 main ELF。结果同时包含上述旧提交和当前候选 SHA `e0ec7531…`；保留结果 `private/full-audit-20261014/dhcp/tftp-01.json`。主审已验证当前 SHA 对应 `e9d89b17`，故本轮没有误归属。

实际影响：后续把同一驱动用于新版本时，报告会产生自相矛盾的证据。只按 `source_commit` 汇总或挑选报告，就可能把旧版本的测试状态当成当前状态，或把新结果错误归入旧版本。这不直接改变路由器 DNS/DHCP 行为，但损害证据链，尤其不适合本项目的部署门禁。

建议：要求明确、可核验的源输入清单/commit 参数，并绑定实际 ELF SHA；无法证明归属时删掉该字段。不要依赖人工记住“这个字段一直是旧的”。

## 本轮新运行的结果

### 独立 DHCP 报文组合矩阵

新写驱动以固定 seed `2094001` 生成 750 个不同请求的有状态序列，C/Rust 分别从空租约库开始。配置包含静态 MAC 地址、`id:*`、domain-search、rapid commit、BOOTP dynamic、leasequery、真实脚本 hook。报文组合包括 option 12/81 名称与 NUL、不同 client-id、overload file/sname、空/完整/含 END 的 PRL、option 57 容量边界、租期边界、relay suboption，以及各 REQUEST 模式。

相同 750 请求执行两轮；这是同一 corpus 的重复运行，**不是 1,500 个不同测试用例**。第二轮额外记录每包发送/接收墙钟，单独写检查器校验原始结果。

| 请求类型 | 数量 |
| --- | ---: |
| DISCOVER | 211 |
| REQUEST | 205 |
| INFORM | 73 |
| LEASEQUERY | 60 |
| DECLINE | 66 |
| RELEASE | 74 |
| BOOTP | 61 |

每侧均为 577 个回复、173 个有意静默；双方整个序列存活且最终退出 0。第二轮结果：

- 全部 750 对请求的回复存在性、固定头、cookie、选项值/顺序、非 overload 的 file/sname 字段一致。针对异步执行的有限租约剩余秒数，8 个回复中共 9 个字段相差 1 秒；按该侧实际 lease expiry 和发送/接收时间校验后均正确，没有把所有 TTL/时间字段一概删除。
- 610 个单侧 OFFER/ACK T1/T2 校验通过：非 renewal 精确；renewal 的共同随机偏移有界且 T1/T2 关系保持。58 个单侧 INFORM/LEASEQUERY 剩余时间、14 个单侧 LEASEQUERY timer 校验通过。
- 每包落盘 lease 的顺序、硬件地址、IP、名称、client-id、agent-info/vendorclass 均与 C 一致。绝对 expiry 按各实例墙钟单独判断；402 个单侧 ACK/BOOTP 的落盘 expiry 与授予的租期一致。
- 两侧各 264 个 helper 事件，内容与次数一致。随机快速序列没有声称异步全局顺序完全相同；确定性生命周期顺序由下述 helper 门禁验证。
- 检查器真实注入五类负控制：修改回复头、lease 名称、T1，删一条请求结果、删一条 helper 事件；五项均拒绝。检查器修正过程中发现的 LEASEQUERY/INFORM 时间模型问题是测试工具问题，没有误列产品 bug。

第一轮快速筛查有 3 个仅剩余秒数差 1 的回复；第二轮计时更严格，结果见原始 `matrix-02/checked.json` 与 `calibration.json`。

### 租约恢复、持久化与 DNS 联动

以当前 ELF 新运行仓库 `m5_lease_recovery.py` 全族：**70 对场景、50 个冻结边界全部通过，0 failures，closed=true**。此处引用的是本轮实际新运行，未复用旧 ELF 的通过状态。

覆盖启动创建/权限/只读文件系统/软链接、持有原 inode、重复地址及 client-id 恢复、非法/截断/NUL/宽度/整数边界、容量耗尽、已到期与空闲到期、名称碰撞与 FQDN scope、静态名称恢复、扩展行、SIGHUP、restart、只读脚本初始化/凭据/慢初始化、部分读取 EIO，以及真实 ENOSPC。ENOSPC 场景确认提交租约后仍有 DHCP/DNS 可见状态，释放空间后按实际约 60 秒的重试更新文件。

这些结果支持“租约文件和 DNS 联动已实现并可工作”，不能继续仅依据早期 phase 文档称其缺失。未重新证明所有 DNS 缓存记录类型与租约碰撞的组合，主审 DNS 分工另有覆盖。

### helper 与 OpenWrt hook

以精确镜像 overlay 新运行 `m5_helper.py` 全部 16 类场景，C/Rust 共 32 次运行，全部通过；8 类门禁负控制也通过。包含 lifecycle、renewal、script-user 的 normal/debug 差异、慢脚本、退出/信号、leasefile-ro、精确镜像 dhcp-script.sh/hotplug、missing exec、未知用户、init 非零返回、helper 死亡、slow init、容量、shutdown。

这证明该组契约下的凭据、环境变量、事件顺序和清理可以与镜像 C 协作，不等于已测试全部另外九个 Rust 组件同时运行。

### TFTP

新运行 `audit_20261011_tftp.py` 的 24 对场景。22 对全结果一致；另外两对为 **C 自身未完成、Rust 正确完成**，不能列为 Rust 回归，也不能写成“24/24 与 C 相同”：

| 场景 | 精确 C | 当前 Rust |
| --- | --- | --- |
| netascii-one-byte-block | 返回首 DATA 后重复/超时 | 9 B 预期内容完整，正确完成 |
| bound-ipv4-single-port | 无响应，日志 Network unreachable | 1,025 B 内容完整，正确完成 |

其余包含 0/17/512/513/4097 B、netascii 多块、window 4/32、各 option、重传、IPv4/IPv6、single-port、路径拒绝和错误报文。Rust 全部 24 次场景验证通过，所有 C/Rust daemon 最终退出 0。C blksize=1 属非标准很小块的边界，不能据此要求 Rust 故意挂起。

## 需要清理的旧注释

以下不单独作为生产故障计数，但会使接手者误以为重写仍缺功能：

- `dhcp/state.rs:3–4` 仍称 pre-dispatch matching / reply-option generation 未实现。相应集成已存在于 `dhcp/daemon.rs:1716` 的 `resolve_events` 和 `dhcp/reply.rs`，本轮也实际运行了这些路径。
- `tftp_runtime.rs:3` 仍写 “eventual UDP listener”，现有 `tftp_listener.rs` 和真实 port 69 测试表明 listener 已落地。
- `dhcp/lease.rs:858–860` 称 agent-info/vendorclass 为 “explicitly pending integration contract”；紧接的 `write_leases`（882–900）已写这些扩展，本轮矩阵和 recovery 的 extensions 场景也验证了。

建议改成清楚的模块责任描述和实际调用者位置，避免保留历史“尚未实现”语气。

## 实际边界与收尾

本专项没有复测真实客户端断线重连、MAC 随机化切换、睡眠恢复、无线漫游、多个广播域/真实 relay/PXE 启动；没有进行长期全协议混合负载或低内存 allocator 故障注入。对家庭真实客户端首次 DORA、续租与 DNS 名称可见性，仍应在恢复门禁内让手机/电脑重连 Wi-Fi 并记录健康；需要用户配合时应列入主报告。

没有把镜像 `NO_DHCP6` 作为 Rust 缺陷：本任务匹配的是镜像 nodhcpv6 契约，IPv6 DHCP/RA 的其它组件配合须单独看。

Oracle 测试全部结束；按本专项路径与 `/m2/` 扫描未见残留测试进程，私有 namespace 已退出。只保留证据目录。本专项从未接触路由器，因此没有本专项造成的真机状态需恢复；主审应单独记录它的真机前后核对结果。
