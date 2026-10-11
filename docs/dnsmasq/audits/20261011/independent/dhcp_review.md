# DHCP 独立审阅记录（2026-10-11）

审阅对象：`fix/audit-20261011`，冻结提交 `6b8eee96eda8aaa4cc47580530e5f287baeaaaa4`；main 基线 `be531cee49e366bb5044443d473944dbea45b87e`。仅变更审计工具和派生证据，未改产品。服务实验全部使用 Oracle 隔离 network/mount/PID namespace，无物理路由器操作。

## 结论

地址分配和 DHCP 名称的主要修复有效；独立增加的 130 个 wire/lease/DNS 场景全部与精确镜像 C 相同。但多 MAC 租约交接的修复没有覆盖 `dhcp-script` 的元数据更新规则，存在已复现的 P2 兼容性遗漏。范围内未发现高于 P2 的 DHCP 问题。

## P2：交接复用的租约仍被当作新租约刷新 helper 元数据

位置：`components/dnsmasq/src/dhcp/daemon.rs:2391`、`:2537-2548`，与本次修改 `components/dnsmasq/src/dhcp/state.rs:376,397` 的集成遗漏。

`helper_new_lease = existing.is_none()` 在状态转换前按新客户端身份计算。新的 state 代码正确复用同一 `dhcp-host` 下另一 MAC 占用的租约，不再额外 allocate，但 helper 仍认为此租约是新分配的。`do_classes` 还把任何报文的 option 50 都视为 class 更新理由，未限定 DHCPREQUEST。

matching source `src/rfc2131.c:1401,1556,1596-1674` 只有 REQUEST 含 option 50 或实际新分配 lease 时才设置 `do_classes`。Rapid Commit 跳过 REQUEST；交接复用已有 lease，不满足实际新分配。`lease.c:948-970` 的 MAC 变化设置 `LEASE_CHANGED`，因此交接应有 `old` 事件；`lease.c:1293-1310` 在首次 `add`/`old` 后释放一次性 extradata，后续不应凭空重建。Rust 的 `lease.rs:650-666` 则因错误传入 `extra` 设置 `script.changed`，并刷新一次性元数据。

复现配置（其余 daemon/isolated 配置见脚本）：

```ini
dhcp-authoritative
dhcp-rapid-commit
no-ping
dhcp-range=set:pool,127.0.0.30,127.0.0.30,255.0.0.0,1h
dhcp-host=02:00:00:00:00:01,02:00:00:00:00:02,127.0.0.30,dual
dhcp-script=<capture-hook>
```

先让 MAC 01 REQUEST 租约，携 hostname `first`、vendor class `original`，等首个 helper `add` 完整落盘。再发送 MAC 02 的 Rapid Commit DISCOVER（分别含/不含 option 50）或 RENEW REQUEST（`ciaddr=127.0.0.30`、无 option 50）。

| 第二个动作 | 精确镜像 C | 修复分支 Rust |
| --- | --- | --- |
| MAC 02 Rapid Commit，无 option 50 | ACK；`old`；`DNSMASQ_DATA_MISSING=1`；无 vendor/supplied-name | ACK；`old`；vendor=`replacement`、supplied-name=`second`、携 requested-options/tags，无 DATA_MISSING |
| MAC 02 Rapid Commit，含 option 50 | 同上 | 同上 |
| MAC 02 RENEW，无 option 50 | 同上 | 同上 |
| MAC 02 SELECTING REQUEST，含 option 50 | ACK；`old` 携新 class/name | 完全相同（控制组） |
| MAC 01 自身 Rapid Commit，含 option 50 | ACK；没有第二次 helper 调用 | ACK；额外 `old`，携新 class/name |

影响：配置 `dhcp-script` 时，消费者收到不同的字段存在性和值；对已有客户端的 Rapid Commit 还能额外执行脚本，即使未启用 `script-on-renewal`。基于 `DNSMASQ_DATA_MISSING`、vendor class、supplied hostname、tags 的脚本会走不同分支；额外脚本执行会增加工作并可能重复外部副作用。本测试没有运行真实 OpenWrt 热插拔消费者，因此未声称已复现真实防火墙/业务配置破坏。

main 对照明确区分来源：4 种跨 MAC 交接在 main 的第二包均不回复，修复分支均 ACK，说明原分配错误已解决；错误 helper 元数据是在该修复打通的成功路径上显现。same-MAC Rapid Commit 的额外 `old` 在 main 已存在，属同一错误策略的既有缺陷，不应称作本分支新增回归。

附属日志观察：交接时 C 还记录 `abandoning lease to 02:00:00:00:00:01 of 127.0.0.30`，Rust 不记录（state.rs:370-376 无对应事件）；不影响分配，作为诊断兼容性遗漏，不单列合并阻断项。原始合成实验日志位于 Oracle `private/dhcp-extended-01/multi-mac-static-handoff-{c,rust}/service.log`。

## 证据与复现命令

- [最终修复分支结果](dhcp_helper_fix.json)：五个场景的每包输入、解析回复、lease 内容、DNS 回答、全部 helper argv/DNSMASQ_* 环境。
- [main 对照结果](dhcp_helper_main.json)：同一脚本、同一镜像 C，与新构建 main ELF 比较。
- [复现脚本](dhcp_handoff_helper.py)：只使用 frozen 工具的 transport/config scaffolding，独立构造动作和捕获 hook。

```sh
ROOT=/home/ubuntu/dnsmasq-fix-independent-20261011
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
sudo -n sh "$ROOT/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$ROOT/private/dhcp_handoff_helper.py" \
  --source "$ROOT/source" --rust "$ROOT/private/release/dnsmasq-rs" \
  --image-root "$IMAGE" --out "$ROOT/private/dhcp-handoff-helper-reproduce-new"
```

将 `--rust` 改为 `"$ROOT/private/main-release/dnsmasq-rs"` 并用另一全新 `--out` 可复现 main。目录不得复用。最终证据源是 `dhcp-handoff-helper-04` 和 `dhcp-handoff-helper-main-03`。

工具校准：最初 shell hook 的两次实验已看见差异；改为 Python 捕获完整环境后发现 `base.execute` 的快速退出会截断异步 helper 观测，因此 `helper-03/main-02` 不具最终资格。最终脚本在第二包前等待首个 hook 完整写入，第二包后保持 daemon 存活至少 1 秒并要求输出稳定至少 300ms，在终止前捕获完整事件。最终 `matched` 比较完整 hook，只对 `DNSMASQ_LEASE_EXPIRES` 与 `DNSMASQ_TIME_REMAINING` 作时间归一化；摘要事件与完整 argv/env 在导出后逐项校验。

精确镜像 C SHA-256：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。本次 Rust、main ELF 与脚本 hash 均见 JSON。matching source 本地 `private/dnsmasq-rewrite/reference/identity.json` 的 `rfc2131.c` SHA-256 为 `14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c`，`lease.c` 为 `4260039af27b40084cbe6dbbae2bb9417fa3a91806ea53f3f6bdd20234cad763`，本次读取已校验。

## 通过范围

[130 个场景的派生清单](dhcp_coverage.json) 与 [扩展矩阵脚本](dhcp_extended.py)、[多池矩阵脚本](dhcp_context.py)：

- 原 9 个复现及独立普通 ACK/Rapid Commit hostname、FQDN flags 0/1/4/5/8/9/12/13、域名/空短名/无效名/末尾 NUL；
- hosts 权威名称、ignore/generate、range tag + tag-if、configured name/name-matched host；
- 多 MAC 与 client-ID 交接、重复 ACK、`dhcp-lease-max=1` 复用；
- 多 pool 中请求地址不可用后的实际 pool 名称策略、hosts 地址对应、已有租约名保留；
- 比较完整 DHCP 选项及 yiaddr、每事件 lease 身份/名称、固定 DNS A/PTR 查询、进程健康/退出。未比较完整日志；130/130 不代表 helper 合约已通过。

源码同时审阅了 SIGALRM 路径：signal counter 经 `process_diagnostic_signals` 入队，`request_alarms/tick` 服从 file owner gate 并执行 prune/persistence/DNS/script maintenance，未在该路径确认新问题。运行期信号复核由另一审计分工提供。

## 本分工未覆盖

真实物理 DHCP 接口/广播转发、DHCP relay、PXE/BOOTP 全面回归、真实 OpenWrt hotplug/UBus 脚本业务结果、长期客户端流量、DHCP6（镜像禁用）。性能与构建资源由主审计另行测量，此处的功能测试不作性能结论。
