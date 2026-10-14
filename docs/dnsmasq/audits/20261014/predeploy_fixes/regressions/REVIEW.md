# 最终 SDK 产物：DNS、重载与历史边界回归

2026-10-14。本轮对真实 SDK 源码编译、打包后解出的 ELF 执行原审计流量；
本范围未发现新增客户端功能回退。B01/B02 的原实际配置序列已恢复到精确 C。
这不等于部署批准，包体积与部署恢复门槛由主报告分别记录。

| 输入 | 身份 |
| --- | --- |
| 产品源码 | `807db8a15e43452414acc048874bf04a4c639bd9` |
| SDK02 包内 Rust ELF | `0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728` |
| 精确镜像 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 原实际配置，737 B | `273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe` |

C 使用精确镜像自身 musl/共享库，未重编 C。运行在 Oracle 的独立
network/mount/PID namespace，使用原实际配置、include、接口与 resolver
拓扑。捕获遗漏的 passwd/group/hosts/ethers 全部从精确镜像补齐；受控上游
替代原四个端点，没有访问物理路由器。旧 native matching-source build 只
提供 UBus fixture。历史合成配置使用精确镜像私有 overlay。

## 实际配置重放

| 范围 | 最终 SDK02 与 C 的新运行结果 |
| --- | --- |
| B01/B02 原 focused | 19 场景，每侧 26 次交换；52 个响应独立解码。B01 上游丢包后 AAAA 本地空 NOERROR，双方该阶段仅一次预热 A 上游请求。B02 的终点 A 在 UDP/TCP 均可解析，AAAA 为 NODATA |
| 普通公网 CNAME 终点控制 | 3 场景、每侧 3 次交换；预热后断开上游，UDP/TCP 直接终点 A 均可从缓存解析；每侧总上游请求 1 次 |
| 日常 DNS 与压力矩阵 | 71 场景、每侧 452 次交换；604 个实际收到的响应独立解码。双栈 UDP/TCP、CNAME、TXT/HTTPS、正负缓存、EDNS、rebind、上游失败恢复、pipeline/分片和 forwarding 槽位压力均保持 C 行为 |
| hosts/resolver/HUP | 60/60 比较通过；24 次 HUP 期间每侧 160/160 双栈 UDP/TCP 查询成功；hosts 原子替换、删除重建、resolver 轮换/空/删除/恢复、缓存清理、旧 TCP 视图、主配置重启及动态监听均通过 |
| 完整健壮性 corpus | 每侧 316 DNS、31 DHCP、20 健康观察；314 DNS 与全部 31 DHCP 逐字相同，DORA 与后续 UDP/TCP 健康成功。仅保留原 B03 两个超长异常 TCP 的 C EOF / Rust RST；进程均存活并退出 0 |

本次完整健壮性 corpus 已补齐全部四份镜像文件，填补原报告只做补齐后短
控制的覆盖缺口。正常服务成功与双方对异常请求的共同丢弃/超时分开记录。

严格比较原始结果有 **6 个场景只有缓存 TTL 相邻秒差**：focused 1、public
1、regular 4；没有删除这些原始差异或将 TTL 全局忽略。
[focused](focused/comparison.json)、[public](public-cache/comparison.json)、
[regular](regular/comparison.json) 保留原严格比较。

逐侧使用上游收到 warm 查询的时间、warm reply 文件时间以及最终 request/
reply 文件时间，界定缓存插入和查询之间的真实时间区间 `[d_min,d_max]`。
初始 TTL 为 T 时，只允许 `[T-ceil(d_max), T-floor(d_min)]`，且 C/Rust
相差不超过 1；其余字段必须严格相同。五个 A 的允许区间为 119..120，
NX SOA 为 28..29，六个观察均满足各自区间。四份文件的 mtime_ns/SHA、
对应上游时间及逐侧计算全部保留在
[focused 时间证据](focused/timing-checked.json)、
[public 时间证据](public-cache/timing-checked.json)、
[regular 时间证据](regular/timing-checked.json)。pipeline 的 warm request
文件写在发送后，因此使用上游收包时间作为最早缓存插入边界；最终这些
单次查询的 request 文件写在 socket 发送前。每套的 TTL 加 2 和 flags
变异均被拒绝。没有用重跑中的偶然全等替代本轮保留的时间差异。

日常矩阵双方各 420 次上游请求，各阶段总数相同；逐问题/端点分配仍受
并发到达与选优影响，`endpoint_query_counts_equal=false` 原样保留。
focused/public 的逐问题端点计数也相同。没有把总数相同写成所有网络交错
完全相同。

## 既有终点、链式与边界

全部是最终 SDK02 的新运行，保留原 FIX7 流量生成器及历史 main/before
控制。当前是否通过只由精确 C 决定；不再给旧 O1 差异豁免。

| 范围 | 场景 | 结果 |
| --- | ---: | --- |
| F1/F2、anchor、extended、terminal、Dynamic/Local chain、N1/filterwin2k | 428 | 420 合法答案全字段含 TTL 等于 C；8 个 C 自身畸形控制仅断言 raw 相同。原 18 个 local/literal TCP O1 全部已等于 C |
| 大 TXT/dual/opaque + MX owner 边界 | 48 | alias 36、direct 12；包含 `0x3ff7`、`0x3fff`、`0x4012`，全部完整语义等于 C |
| NX24 + SOA64 + cursor12 | 100 | 840 对 DNS：819 严格相同、21 满足原逐侧 elapsed 约束的 SOA 相邻秒 TTL；180 对 DHCP 相同 |
| 大 TXT/MX + retained SOA 联合边界 | 6 | 24 对 DNS 全字段含 TTL 严格相同，12 对 DHCP 相同 |

前两组共 476 场景全部核验当前/C 的 warm、连接关闭后健康、daemon 存活和
exit=0；final 上游 query/reply 独立解码后相同，仅去除随机 transaction
ID。名称压缩被规范化，RR 顺序、owner、类型、class、TTL、RDATA 均保留。
8 个畸形 C 控制没有冒充合法协议答案。负缓存两组使用原独立完整包 decoder，
同时验证 DHCP header/options/timers、上游行为及资源释放。

中间 SDK01 曾执行 428+48 做修复过程控制，也全部通过；其数据保留在
`regressions/intermediate01/private/`，不计入上面的最终运行数。

## 复跑与证据

[run_actual.py](run_actual.py) 分别运行 `--side c` 和 `--side rust`，
Rust 必须提供 `--rust` 与 `--rust-sha256`；[run_history.py](run_history.py)
接受同一冻结产物；[collect.py](collect.py) 从原始包重新核验并生成派生
结果。[summary.json](summary.json) 绑定全部原始结果与二进制身份；
[collector 收据](collector-invocation.json) 记录完整收集器 exit=0。

Oracle 根目录为
`/home/ubuntu/dnsmasq-predeploy-fixes-20261014/regressions/`。`source/` 冻结原
审计工具，`private/actual` 保存实际配置、请求与响应，`private/regression`
与 `private/boundary` 保存历史矩阵，`private/negative` 与 `private/large-soa`
保存负缓存/联合边界；全部原始命令、配置、ELF、真实名字与拓扑留在 private。
Git 仅保存工具、派生结果和报告。[收尾核验](closeout.json) 确认本子任务没有
残留进程或宿主挂载，最终 ELF SHA 未变。

没有测试物理 Wi-Fi/路由器、长期负载、全部畸形配置、性能或任意 OOM/并发
交错。新增 literal 长名/大答案专项由 DNS 修复分项另外提供；本报告没有把
原 TXT/MX 大包边界冒充该新专项。未推送、合并、部署或触碰物理设备。
