# FIX7 fresh DNS 回归复核

2026-10-14，冻结产品 `02659da6`。本范围没有发现新增回归。全部为本次新启动的 **428 个场景、1,640 次 daemon 运行**；后续独立重算没有重复计入运行数。

运行使用精确镜像 C `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`，main `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`，FIX6 修复前 release `a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66`，fresh 当前 release `e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9`。N1 为 C/main/current 三方，其余为四方。每组在独立 network/mount/PID namespace、镜像私有 overlay 内运行，C 使用镜像加载器和库。

| 新运行范围 | 场景数 | 当前结果 |
| --- | ---: | --- |
| F2 原 `c062` + 三个 raw CNAME | 4 | normal/debug × UDP/TCP 全部与 C 逐字节相同，154 B，final 上游 0 次 |
| F2 anchor + mixed raw candidate anchor | 8 | 全字段及 TTL、上游行为与 C 相同 |
| F1 `c00c/c02b` × Dynamic/Local | 16 | 全字段及 TTL、上游行为与 C 相同 |
| extended controls | 80 | 全字段及 TTL、上游行为与 C 相同 |
| 原 terminal profiles | 88 | 62 个合法答案等于 C；8 个 C 自身畸形控制仅 raw 相同；18 个 main 原有 O1 |
| configured chain Dynamic/Local | 160 | 全字段及 TTL、上游行为与 C 相同 |
| N1/filterwin2k | 72 | 全字段及 TTL、上游行为与 C 相同；48 个 warm 答案相同 |

合计 **402 个合法当前答案与 C 全字段相同、8 个畸形 C 控制 raw 相同、18 个旧 O1、0 个新增差异**。18 个 O1 均是 target-local/literal TCP 场景，main/current 的完整 response 字典逐字相同；四方运行中的 **356/356 before/current response 字典也全部逐字相同**。没有把畸形 C 回答当成合法语义，也没有按旧 O1 否决增量。

原始 wire 由 FIX5 独立 decoder 重算，保留 header、question、各节及 RR 顺序、owner/type/class/TTL/RDATA，只规范化名称压缩。**没有 TTL 容差**。8 项负控制验证了 header、question、type、class、TTL、RDATA、名称循环、EOF 都能检出；TTL 改 1 秒也会失败。[完整逐例派生收据](final-checked.json)、[校准](calibration.json)

另用 FIX6 第二套独立 F2 decoder 重核四例布局：owner 为 `c00c,c02b,c02b,c02b,c02b`，RDATA 起点为 43/71/98/125/152，最后 `c062` 仍指向 offset 98 的 `other.example`；TTL 严格为 `[300,60,60,60,60]`。before/current/C 都为 154 B，main 为 223 B、最终语义相同但仍多一次转发。全部新运行的上游 query/reply 也独立解码比较，仅去除每次分配的 transaction ID；410 例当前 final 上游行为等于 C，18 个 O1 等于 main。[额外布局、上游及收尾检查](inspection.json)

所有 **404 个含预热场景**的四方/三方 warm 回答与 C 全字段相同；**1,640 次 daemon 全部存活、退出 0、关闭 TCP 后健康答案与 C 全字段相同**。terminal 配置由原 FIX4 profiles 逐字提取并核验，使用 FIX5 extended 驱动，以保证健康请求在 TCP 关闭后发送；查询和配置未改。没有沿用旧报告中健康时序造成的超时豁免。[实际 argv](invocations.json)、[运行协调器](run.py)、[最终重算工具](finalize.py)

中途交互中断后，协调器的部分收据停在第 10 组；12 组原始结果及各驱动完成标记全部保留。`finalize.py` 从原始数据重新核验全部 428 场景，没有重跑 daemon。前 10 组驱动 exit=0 有原收据；后两组没有保留下协调器读取到的驱动 exit 状态，因此没有补写 exit=0，仅声明已核验完成标记、完整场景数及所有 daemon 的实际 exit=0。原部分收据保留在 Oracle，SHA 在最终收据中。

收尾确认本范围私有目录无归属进程或宿主 mount，release SHA 未变化。日志、完整运行结果、ELF、overlay 留在 Oracle `/home/ubuntu/dnsmasq-audit-fix7-20261014/private/regression/`；本地仅工具、合成配置和派生报告。未修改产品、未碰物理路由器、未推送。本矩阵不替代 F3 大报文边界复现，也不声称覆盖全部 DNS/DHCP、性能、故障注入或长期并发行为。
