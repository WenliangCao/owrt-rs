# v0.2.2 隔离设备批次

**固定 148 窗与 40 次启动；当前只完成本地准备，不得开跑。** 候选必须先修复真实 jail
无 `/proc` 的自执行问题，重新冻结源码、训练 PGO 并完成资格。对照与生产均为精确 K：
`f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08`。
不部署、不变更生产服务/配置/挂载；测试根仅为 `/tmp/dnsmasq-perf-v022-20261017`。

## 成本模型与顺序

普通查询的 syscall、复制、分配预计不变，差异预计小于 5 µs。真实 K 的公开规则单族
命中约 73 µs、同名双栈约 83.1 µs，仅作模型背景，不与新数据混池。
自执行有额外 exec/编码和 pipe FD，另测整棵自有进程树 CPU、就绪和资源。

| 阶段 | 固定负载 | 窗数 |
| --- | --- | ---: |
| K/K 校准 | ordinary、dual、mixed 各 2 对 | 12 |
| 原完整协议 | 简化 UDP-hit 9 对；其他 10 场景各 5 对 | 118 |
| 真实规则同名双栈确认 | K/候选 9 对，400 同名 A+AAAA | 18 |
| 启动补充 | helper/resolver × K/候选 × 10 次 | 40 次启动，单列 |

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
首次统一构建的三个不同 hash 保留为准备记录，不宣称是历史产物。

尚缺：新 PGO 身份；无 proc/UID453/mount+PID namespace 正负控；完整正确性；9 个
原支援二进制与启动补充的 SDK 构建/Oracle 预演；pending resolver 资源与 2/4/8 FD
压力夹具；绑定当前生产/root/空闲 K/K slots 的执行控制器。旧模块中的生产哈希、恢复
E/F slots 和入口常量不能直接运行。最终绑定与控制器完成前，计划状态保持 blocked。

启动补充等真实 helper `old` callback 或 servers-file hostname 上游应答后才算就绪，
使用 subreaper 收齐子孙后读整树 CPU；资源只报告就绪后 RSS/Anon/FD 快照，不称峰值或
PSS。任何强制清理、漏 reap、500 ms 周期超时或失败停止；明确超过 1 ms 的启动退化
交主代理审查。原 helper 的 FD=2 首跑结论保留；新 selfexec 四 FD/两底层 pipe 结构资格
单列，不用改断言把资源代价变成相同。
