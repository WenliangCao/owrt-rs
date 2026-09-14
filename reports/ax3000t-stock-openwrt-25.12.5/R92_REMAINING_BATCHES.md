# R92：异常恢复、兼容、性能与发布验收

日期：2026-09-15（Europe/Berlin；原始记录使用 UTC）。本轮接续已经完成的 R90 第一批，
包含 R91 日志修复，完成原计划第 2–5 批。性能基线固定为正式 R89。

**四批已完成并通过对应回归；R92 已部署，四个冷启动、完整测量及最终客户端健康验收通过。**
已确认的问题分别修复、撤销误报或明确保留理由；性能增幅与有限验证的边界在本文及覆盖表列出。

运行时提交 **`ca1a9121df0380448a19d474e29796066b6734e8`**，
[正式构建 34874442503](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34874442503)。
后续工具、注释和报告提交不表示重新构建了运行时。九个二进制、七个 APK、core archive、
生成镜像及 manifest 链均已核验；本轮没有刷写固件，内核、驱动、执行面及无线 handler 保留。

## 1. 四批处置

| 批次 | 结果 | 证据 |
|---|---|---|
| 2：异常恢复与资源 | 修复 ubusd 半关闭空转及删除游标重复回复、netlink 溢出重同步、procd 断连日志/计时器与非 PID 1 喂狗、HTTP batch 放大；logd 为共有无界积压加预算；RPC 子进程有界回收作为有意差异保留 | [恢复/兼容断言](R92_parts/recovery_compatibility.json) |
| 3：协议与数据 | HTTP 错误/监听/重定向/CGI、ubus 属性/重复字段/类型、fnmatch、原始字节、fw4 CLI/特殊输入、JSON 转义完成逐项对照；22 项旧 HTTP 差异逐项固定；4096 配置项上限入合同 | [逐项处置](R92_COVERAGE.md)、各组件合同 |
| 4：性能与内存 | 四冷启动、九组件三侧四轮、affinity、真实延迟与停放追踪、500 次连接开关、文件页和非运行副本干预；有实测增幅，按证据保留边界 | [性能报告](R92_PERFORMANCE.md) |
| 5：覆盖和发布 | 补 hotplug 存活、稳定 feature 差分夹具、插件异常输入/无线对照、UCI 内部复核；修复两处 rpcd Unicode 切片崩溃；更新缓存合同、README、包保留与回退说明 | [覆盖表](R92_COVERAGE.md)、[保留与回退](../../docs/R92_RELEASE_AND_ROLLBACK.md) |

剩余项没有统称为“小瑕疵”。有些是已复现的 P2/P3 差异，有些是原版与候选共有的资源问题，
还有些是固定输入控制后撤销的假设。保留行为必须有明确理由和对应门，状态逐项列在覆盖表。

## 2. 正式验证

**69 道门中的 68 道必需门全部通过。** 另一个是原版 C procd busy 的既有日志丢尾控制，
其失败仍保留。Rust 为 **449 个不同 crate 内测试名、450 次执行**；rpcd wake-pipe 测试同时
编入 library/binary，不能把这次重复算成两个独立测试。十 crate Clippy 通过。

| 验证 | 结果 |
|---|---|
| netifd 完整套件 | 31/31，无跳过，包含 R90 生命周期、R91 日志 |
| hotplug 专项 | 正式 r71 确实启用 `R90_HOTPLUG_PROBE=1`，延迟 coldplug 后的 uevent 仍执行 |
| 新恢复门 | C/候选 20 行；候选所有不变量通过，原版 adverse 观察按原样保留 |
| 新兼容门 | C/候选 34 行，逐项所需断言全集通过 |
| HTTP fuzz | 133 例；对正式 R89 只允许 header-ctrl、chunked-huge-size 两项改变 |
| fw4 | 16 项专项、上游 31/31、r29 200/200；原版 23 次 ucode 崩溃另记 |
| UCI | 单元、r16、r24 1000 例、应用原子拒绝合同后的 r83 通过 |
| 离线冷切换/救援 | 5/5 |
| 同版本 APK 升级 | 4/4，安装期间旧进程与 CLI bind mounts 保留旧身份，新进程使用新产物 |
| 收尾工具 | shell/Python 语法、21 个 harness 测试、33 个 benchmark Python 测试通过 |

完整日志身份、尝试记录和更正理由见 [validation.json](R92_parts/validation.json)。
正式执行有三处夹具失败：sudo 丢失 HELPERS 误用旧 probe、fd 采样早于 EOF 清理、UCI r83
尚未应用非 UTF-8 rename 的原子拒绝合同。修正工具后用同一正式产物闭合所需门；旧失败没有删除。
最初的远端组合采集在 52 道门后断连，后续执行由完整门清单接续，不把任一不完整清单冒称全过。

## 3. 实机与恢复

用户已明确授权全部访问、Wi-Fi 调试及实际运行。部署前新采七份归档，完整读回，并对五份
bundle 的全部文件另验远端 hash；两份恢复固件的 SHA256 正确。配置/overlay 归档采用完整
归档读回检查，没有虚称每个配置文件都逐项远端校验。候选和原件身份、空间、离线升级与自动
回退门通过后，才用 `--no-scripts --no-network --force-reinstall` 安装同版本 APK 并冷切换。

| 窗口 | 首次 SSH s | 健康确认 s | 固定整批 CPU s |
|---|---:|---:|---:|
| R92-1 | 50.281 | 281.128 | 299.15 |
| C-1 | 40.289 | 272.031 | 391.02 |
| C-2 | 40.277 | 272.746 | 388.27 |
| R92-2 | 80.343 | 307.074 | 297.84 |

每窗口 ≥180 秒连续客户端健康，再观察 30 秒；双频 AP 桥、DHCP、IPv4/IPv6 DNS/HTTPS、
本地 HTTP/HTTPS、watchdog 及九组件身份通过。四次 boot 确实不同，配置、执行面及归一化
nft 规则一致。首次 SSH 是 10 秒轮询看到的时间，不当作精确内核启动耗时。

2026-09-14 **23:27:33 UTC** 的最终核验通过：九组件均为正式 R92，仍是第四窗口的同一 boot；
配置、内核 6.12.94、执行面及归一化 nft 规则不变，客户端双栈和双频健康通过。
R89/R90/R92 三个保留 bundle 各 29 个文件、7 个 APK 逐项核对；C 原件及已安装文件校验通过。
六个诊断文件核验后删除，临时目录、pending/reverting/canary 均已清除，overlay 可用
**28936 KiB**。自动回退目标仍为精确 C；回到 R90 要先重装对应旧 APK。

采集异常也保留：C 的 deleted udebug 映射无法按路径 mincore，失败文件页采集归档后修正工具，
有效冷窗口没有重跑；rpcd 第五轮 SSH 超时 exit 255，但远端已写 COMPLETE，下载逐文件 hash、
18 个 workload、计数与 CPU 区间均有效，核验健康后续跑其余轮次。不会把这次 SSH 退出码改成 0。
HostHints 首次在查询前因设备 `sleep` 不支持小数失败，改为有界整数等待后三组完整 JSON 通过；
HTTP 同机探针首次在准备阶段把成功的空 ubus 回复当 JSON 解析，修正 grant/destroy 的回复处理后
重跑。两次失败证据均保留，临时目录核验后精确清理；没有为探针修改运行时。

## 4. 性能结论与保留边界

相对本轮 C，固定整批 CPU 中位数低 **23.39%**，mixed 吞吐高 **12.05%**，
守护进程 idle-before RSS 中位数之和 **9606→5320 KiB**。但相对历史正式 R89：
HTTP lane CPU **+9.38%**、log **+29.49%**、mixed **+4.35%**，mixed 吞吐 **−3.73%**。
不能宣称性能全面无回退。固定输入的隔离对照、同机控制及其因果边界见性能报告。

50 ms 停放后的线程重建成本保留；长连接开关的后半程 RSS 平台只覆盖本次有限实验。
MemAvailable 差额不能直接等同于独占内存或泄漏；文件页与副本缓存控制单独给证据。
不为未知的唯一调度根因修改内核、管理链路或生产 affinity。

无线四窗口共 212 调用、4 次扫描、28 组。freqlist 的差异确认为原版未初始化 caller buffer，
候选与精确 C 清零缓冲逐项一致，保留确定的内核限制位。固定邻居及 262144 个 HT IE 控制通过；
历史邻居表和扫描原始 IE 没有采回，因此跨 boot 地址成员及两条 HT width 变化不冒称逐字节等价，
也不能据此证明 AP 当时实际改变了带宽。[无线派生结果](R92_parts/wireless.json)。

## 5. 复核入口

[部署证明](R92_parts/deployment.json) · [正式产物身份](R92_parts/canonical_build.json) ·
[验证](R92_parts/validation.json) · [逐项处置](R92_COVERAGE.md) · [性能](R92_PERFORMANCE.md) ·
[续接状态](../../docs/R92_RESUME.md)。

`tools/r92_publish_validation.py` 重验正式日志/产物链；`tools/benchmark/analyze_r92.py`
要求所有 COMPLETE、四 boot、正式 R89/C/R92 身份、下载哈希、无线控制和最终设备证明，
缺任一项即拒绝完整导出。`render_r92.py` 只读取公开派生 JSON 生成 Markdown、SVG/PDF，
不读取设备秘密。可复核的原始数据需要已授权的 private 证据目录；仅凭会话 ID 无法读取它。
