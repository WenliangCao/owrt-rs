# v0.2.2 隔离设备批次

**固定 148 窗与 40 次启动；最终资格未齐，不得开跑。** 当前限定 fork 候选冻结于
`a97edbc1`，须用该源码的新 PGO 完成完整正确性、无 `/proc` 与 FD 压力资格。
此前自执行候选及原始失败保留。对照与生产均为精确 K：
`f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08`。
不部署、不变更生产服务/配置/挂载；测试根仅为 `/tmp/dnsmasq-perf-v022-20261017`。

## 成本模型与顺序

普通查询的 syscall、复制、分配预计不变，差异预计小于 5 µs。真实 K 的公开规则单族
命中约 73 µs、同名双栈约 83.1 µs，仅作模型背景，不与新数据混池。
恢复限定 fork 后，仍测整棵自有进程树 CPU、就绪和资源；此前自执行的成本不继承为新候选结果。

| 阶段 | 固定负载 | 窗数 |
| --- | --- | ---: |
| 启动补充（最先） | helper/resolver × K/候选 × 10 次 | 40 次启动，单列 |
| K/K 校准 | ordinary、dual、mixed 各 2 对 | 12 |
| 原完整协议 | 简化 UDP-hit 9 对；其他 10 场景各 5 对 | 118 |
| 真实规则同名双栈确认 | K/候选 9 对，400 同名 A+AAAA | 18 |

所有最终资格齐备后，先取得新鲜健康 baseline，再跑 40 次启动，最后才跑 148 个窗口。
启动补充的 µs 级整树 CPU 单独判断；1 ms 墙钟观察地板不能抵消明确 CPU 代价。
whole 与 timed CPU 各保留十项和总和；同序差值至少 9/10 为正，且中位正差大于
K 内部五个相邻对差的最大绝对值与 6 µs 计数舍入界限时，停在 40 次之后交主代理审查，
不自动进入 148 窗。两个顺序 block 不称随机配对或统计显著性证明。

不重复加 5 对候选筛选；ordinary/mixed 直接使用完整协议，dual 直接使用确认。
ordinary 校准与完整协议同为简化配置、200 qps、5+45 秒；dual 为公开真实代表规则、
200 qps、5+95 秒；mixed 保留原 200 qps、5+20 秒及严格 1800 请求/应答 cohort。
CPU 分母包括 warmup，依次为 10000、20000、5000。dual 预热单列 A/AAAA 各 1000 次，
800 次上游填充；从第一预热到结束必须小于 TTL 120 秒，steady 上游为 0。
DHCP 6/150 客户端、20 次原 lifecycle 重复及 1 ms 比较地板均不变。

## 判断与停止

先测同场 K/K 最大绝对配对 CPU 差作为噪声。CPU-clock 仪器分辨率须不高于
5/3 µs；K/K 噪声达到 4 µs（接近 5 µs 关注量级）时先检查仪器，不从噪声中选取有利结果。
原 33 项 W、方向、tick 与生命周期地板门完整保留，任何原门可分辨退化阻止接受。
CPU-clock 补充门的 4/5 正差只记趋势；5/5 同向且中位正差超同场 AA 才进入退化判断。
双栈九对保留 d2/d8 和三个顺序 block 中位数；d2 超 AA 且三个 block 均正即阻断。

小于 5 µs 的一致退化不自动放行。ordinary 已排九对；mixed 首五对全部正差且中位数
超 AA、低于 5 µs 时，固定追加第 6–9 对，保留原五对，按九对规则判断。
这最多增加 8 窗，不重跑或替换负面结果。剩余强趋势由研究主代理判断，不自动接受。
无可分辨差异不称严格等价。

任何意外正确性、进程身份、guard、资源/FD 泄漏或生产健康失败立即停止自有隔离组。
每次尝试先完整归档；只对已分类的负载生成器 `scheduled_skipped`、且所有已发应答正确
且没有其他错误，允许阶段结束后补一次完整配对。禁止按效果、超时、候选或健康错误重试。
新鲜 baseline 为 125 秒，停止前前缀至少 120 秒；入场内存 90112 KiB，运行地板
65536 KiB；外部 IPv4/IPv6 HTTPS 每 30 秒。每场保留独立 guard 段。

## 工具与未完成项

`prepare_safe_v022_device.py` 从归档源码恢复模块与 case/group，并做可逆差分验证。
这不是已删除旧私有 raw/runtime 字节的重放。bundle manifest SHA256：
`9cfe77a4c3c6dc767da0014265c3dfe2a3a9f35d49c6d3e29c4c4ed8fe55cee5`。
`safe_v022_device_plan.py --bundle <private bundle> --out <private plan.json>` 逐文件核验，
生成 148 个唯一标签、原 group argv、时限、条件追加和全部门；工具没有远程执行入口。

支援工具重建保留原源码 basename：CPUclock 为 `device_cpu_clock_probe.c`，nice10 为
`perf_opt_nice10.c`；严格 mixed 为 `m6a_upstream.c`，原 recipe 使用 `-Os -static
-std=c11 -Wall -Wextra -Werror`，不能与普通上游统一按 `-O2` 重建。该差异来自保留的
原工具收据，源码 SHA256 为 `1f29f0e76d5e864443c3ca45f80b7e5e65899d809ada626a820bf719d25f37a8`。
首次统一构建的三个不同 hash 保留为准备记录；按原 recipe 补正后，9 个历史支援工具的
hash 全部复现。新启动工具独立构建，不沿用历史工具资格。

`safe_v022_device_run.py` 复用原模块，显式绑定当前生产/root/空闲 K/K slots；默认
dry-run。统一资格文件绑定新源码、新 PGO 的 ELF/APK/profile、完整正确性、无 proc
正负控及工具预演收据；主代理的机器排程 release 绑定该文件后才能执行，不涉及再次
向用户请求确认。旧模块中的生产哈希、恢复 E/F slots 和入口常量不能直接运行。
新 PGO 和实际目标资格未齐，执行状态保持 blocked。

40 次启动的 target 均有私有 mount/PID namespace、最小 chroot，由 root exec 后降到
UID/GID453、CapEff `0x3400`。helper 两侧无 `/proc`；resolver 两侧保留 `/proc`，因为
精确 K 的 runtime lookup 在 fork 前直接读取 `/proc/self/fd`，缺失便失败，没有 helper
的 RLIMIT fallback。K 的无 proc lookup 单列一次实际负控，不拿失败做时间排名。
新候选无 proc lookup 的功能和 pending child 权限/FD 由独立资格覆盖。

一次只读现场核验得到 daemon/ujail/procd/SSH 的 NOFILE 均为 soft1024/hard4096，
同 boot/PID/start、精确 K 与本地 DNS 健康成立；启动两侧明确使用这个限额。
raw SHA256 为 `f1c3a1fa90d3948b8aa79052b88bbb7d7d20d39ae5a3fdad26eef93808d74783`。
namespace/chroot 准备在 exec 握手前完成。子进程给出 pre-exec monotonic 和
RUSAGE_SELF，外部 subreaper 收齐自有后代后读 RUSAGE_CHILDREN；同时保留 whole CPU、
实测 setup CPU 与只减去该 setup 的 timed CPU，不猜减共同开销。返回计数单位 1 µs，
并保留十次总和；这不宣称实际准确度达到 1 µs。

真实 helper `old` callback 或 servers-file hostname 上游应答才算就绪；ready 截止后
在既定200ms内取得一个一致的资源/全部FD静态点，包含stdio。资源不称峰值或PSS。任何强制清理、漏reap、
500 ms 周期超时或失败停止；明确超过 1 ms 的启动退化
交主代理审查。两侧严格要求 owner 无 O_PATH pin，helper 非 stdio 恰为两根 pipe 的
两个 CLOEXEC 端点；不接受可选的0/1 pin或2/4端点。原 selfexec 四FD结果保留为历史。

a97 最终 PGO 的首次工具预演在 candidate helper 第4次留下资源采样失败：ready和最终
两条回调成功、正常退出，但FD捕获遇到脚本临时输出pipe。旧失败不改写。资源与FD捕获、
后验身份/数量/children一致性现合入原200ms静态点等待边界，每次尝试单独留raw；最终
helper仍严格总FD5/非stdio两IPC，持续多FD、身份变化或超时仍停止。ready时点、最终
整树CPU与500ms周期不改，资源仍不是峰值；仅重做受影响的完整40次工具预演。
修复后独立完整40次全部通过：K/helper有13次、candidate/helper有14次采样尝试，
7次未静定尝试原样保留；候选确实捕到临时6FD并拒绝，最终两侧均严格5FD。
两个resolver各10次均一次取得一致静态点。新observer为667320B，SHA256
`7de91a0c55b4e4137b4a243c4374f1fbedb1b3a8039bb23548368fd1dc8c8e0b`。
此项工具预演通过不代表完整产品资格通过；旧13个有效启动及第14个失败仍保留。

首次 Oracle jail 夹具将 helper 回调固定为一次，两侧均失败：exact K 与 8adc 的完整文件
均为相同 `old` 行两次，正常退出和身份成立。原 strict1 结果保留。启动计时现以首个
完整合法回调为 ready，最终校验所有回调内容并保留数量；K/候选十次逐序数量不一致则
停止比较，不删重复回调或将它当作零成本。

当前 owner 没有常驻映像 FD，helper 恢复两根 pipe 的单端点；pending resolver 为一根
结果 pipe并明确保留stdio3，全部FD仍按实际捕获报告。FD 压力只在 Oracle 对最终 PGO
验收，按实际 holes 设置2/3/4/8空闲槽，恢复限额后再次验证公开路径和DNS；此数据不称
A53性能。低限额还限制FD编号，已知shell的F_DUPFD最低编号10效应仍保留，不能只按洞数
排名。此前4槽resolver退化、helper失败和恢复结果均不改写。
