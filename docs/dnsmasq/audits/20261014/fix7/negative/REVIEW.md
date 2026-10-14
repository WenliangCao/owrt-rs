# FIX7 DHCP negative cache / retained SOA / owner fallback

冻结产品 `02659da6` 的 fresh release 对精确镜像 C：完整 NX24 + SOA64 + cursor12 重跑 **100/100 场景通过**；另加大 TXT/MX + retained NX SOA 的 14-bit 联合边界 **6/6 通过**。所有有效客户端报文按 C 全字段语义比较，本子范围没有发现由 `137c2882..02659da6` 新增的回归。未单独据此裁定主 F3。

当前 ELF SHA-256 为 `e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9`；精确镜像 C 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。Oracle 每套执行使用独立 network/mount/PID namespace、精确镜像私有 overlay；C 使用镜像自己的加载器和库。没有重编 C 或运行 diagnostic probe。源码/ELF全量身份由主审构建收据负责，本目录再次核验实际运行 ELF 及驱动、原始侧结果 SHA。

## 完整矩阵与异常保留

| Suite | 场景 | DNS 响应对 | 全字段严格相同 | 有界 authority SOA TTL | DHCP 回复对 |
| --- | ---: | ---: | ---: | ---: | ---: |
| NX24 | 24 | 504 | 485 | 19 | 48 |
| SOA64 | 64 | 256 | 256 | 0 | 128 |
| cursor12 | 12 | 80 | 80 | 0 | 4 |
| 合计 | **100** | **840** | **821** | **19** | **180** |

流量驱动未改，覆盖 direct/cached alias、normal/debug、UDP/TCP、RD/DO、EDNS512 大 SOA 截断，以及 raw/configured CNAME/reverse synthesis 的游标控制。独立 decoder 从原始 hex 检查完整 DNS header、question、section、RR 顺序、owner/type/class/TTL/RDATA；SOA 两个名称及五个整数也逐字段检查，仅规范化名称压缩。请求 ID/question、每次上游行为、DHCP header/options/timers 和 daemon 存活/退出/资源释放同时通过。见 [checked.json](checked.json)。

19 处时钟差全部来自同一实例 `rcode3-soa1-debug1-q16-tcp`，C=3599、Rust=3600。允许差最多 1，并逐侧要求 authority SOA TTL 落在 `[3600 - floor(elapsed) - 1, 3600]`；不是全局忽略 TTL。其他字段严格一致。

**首次执行未完全通过，原结果未覆盖。** 首轮 NX24 通过；SOA64 中 Rust 的 `large1-debug0-client1-tcp-rd1-do0` 在第一个 cold alias A 的 UDP 预热超时：`events=[]`、`upstream=[]`，daemon 退出 0、资源释放检查通过；同例 C 完成 4 次响应。其余 87 个首轮场景、756 对成功 DNS 已重新严格解析。失败发生在 DHCP ACK、最终 TCP 和大回答之前；该实例空缓存的首次 alias 请求没有可到达本次修改的 cached-CNAME terminal 分支。原驱动只在成功收发后保存客户端 event，因此该次超时没有保存客户端请求/响应原始包；仅能根据原 flow 确定尝试的是 cold alias A，并观察到没有上游 event。超时原因未确定，未将它宣称为 main 旧问题，也未删除它。见 [initial-attempt.json](initial-attempt.json)。

随后新目录完整复跑得到上表 100/100；再用未改变的原 SOA 流量定向重复该场景 **10/10**，40 对 DNS 中 38 对严格相同、2 对符合上述 SOA TTL 界限，20 对 DHCP 相同。两侧全部生命周期检查通过。没有复现首次超时。见 [repeat_soa.py](repeat_soa.py)、[repeat-soa-checked.json](repeat-soa-checked.json)。首轮、完整复跑及重复控制分别记录，没有把重读收据算成新运行。

## 大报文与 retained SOA 联合边界

新增 [soa_large_terminal.py](soa_large_terminal.py) 复用原 DHCP/SOA flow，先缓存 `alias.leases.test → client1.leases.test` 的 NXDOMAIN + SOA，证明 target NX 命中，再完成真实 DHCP DISCOVER/REQUEST 与 ACK，证明 A 已可见。最后通过 TCP 查询 alias ANY。配置只有普通 TXT/MX/host-record：60 条三位索引加 252 个 `x` 的 TXT、一条可调长度 TXT，以及 `mx-host=client1.leases.test,leases.test,10` 和 `host-record=leases.test,192.0.2.20`。

| 最后 TXT 长度 | 最终 MX target 位置 | C Additional owner | 当前 Additional owner | C / 当前报文长度 |
| ---: | ---: | --- | --- | --- |
| 184 | 16375 / `0x3ff7` | `fff7` | `fff7` | 16477 / 16477 |
| 192 | 16383 / `0x3fff` | `ffff` | `ffff` | 16485 / 16485 |
| 211 | 16402 / `0x4012` | `c012` → leases.test | 完整 leases.test | 16504 / 16515 |

每组 normal/debug 各一次，合计 6 场景、12 个 daemon；**24/24 DNS 对全部字段含 TTL 严格等于 C，12 对 DHCP 相同**。最终报文都是 flags `0x8580`、64 Answer + 1 Authority + 1 Additional，保留 SOA，未向上游转发最终查询。`0x4012` 例 C 回绕到 question offset 18，恰好解码为正确的 `leases.test`；当前写完整 owner，多 11 字节而完整语义相同。这直接覆盖新增 full-owner fallback 与中间 SOA 插入的交互。见 [large-soa-checked.json](large-soa-checked.json)。

确定该布局时另跑过尾长 185/193/212 × normal/debug 的探索：185 两例合法且相同；193/212 四例 C 的 Additional 指针落在 offset 0/19，独立 decoder 拒绝，当前可解码。该 4 个 C 自身无效控制不计作合法语义通过，也不据它们判当前回归。全部原始报文和最初驱动保留；[large-soa-exploration.json](large-soa-exploration.json) 明示解析失败。

## 校验、复现与收尾

对新观察到的 C 报文内存副本做 rcode、question、owner pointer、A TTL、SOA TTL 差 2、SOA RDATA、section count、上游行为八类破坏，独立 checker **8/8 拒绝**；原样自比较 21/21 严格通过。[校准工具](checker_calibration.py)、[calibration.json](calibration.json)。

原始结果位于 Oracle `/home/ubuntu/dnsmasq-audit-fix7-20261014/private/negative`：首次在 `negative/`、`soa/`；完整重跑在 `retry100/`；合法联合边界在 `large-soa-valid/`；探索在 `large-soa/`；定向复跑在 `repeat-soa/`。`negative_final.py` 的调用与 FIX6 相同，仅 source/fix/输出改为 FIX7，输出目录必须不存在。联合边界及定向复跑均接收 `--source --image --fix --fix-sha256 --config-evidence --out`；联合边界默认尾长 `184,192,211`。config evidence 使用首次 `negative/summary.json`。原始报文和 daemon logs 留在 private。

[collect_receipts.py](collect_receipts.py) 再次重算全部保留结果 SHA 和严格比较，确认 ELF 未变；仅按本子任务 `private/negative` 前缀检查 `/proc/*/{root,exe,cwd}` 及宿主 mount，无残留。[closeout.json](closeout.json)。本范围有效结果直接满足 C，不需用 main 豁免；未运行 main/before 的本矩阵副本。未测性能、完整 DHCP/helper 生命周期、长期并发或全部时钟交错。未改产品代码、未操作路由器、未部署、未推送。
