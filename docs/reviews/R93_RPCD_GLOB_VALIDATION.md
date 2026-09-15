# R93 RPCD ASCII 尾星号候选：分配与正确性验收

2026-09-15。**同 SDK 控制精确复现，候选 22/22 验收通过；尚未合入，也没有性能结论。**
完整身份和逐门日志哈希见 [验收 JSON](r93-rpcd-glob-validation.json)。

## 变更与实测边界

候选只改 `glob.rs`：保留原 NUL 截断，仅 `flags == 2`、pattern/name 均 ASCII、恰好一个尾部 `*` 且前缀无 `*?[` 时用 `starts_with`。反斜杠按 FNM_NOESCAPE 保持字面含义；复杂、非 ASCII 和 flags 0 保留原路径。没有恢复 R89 旧 glob，也未修改总线 1 秒期限或回收逻辑。

本机对 `net*`/`network` + `r*`/`read` 每侧各 100,000 次成功配对计数，两种 locale 结果相同：

| 每次权限查询的两个匹配 | R89 | source05 | 候选 |
|---|---:|---:|---:|
| Rust 申请 / 释放次数 | 0 / 0 | 4 / 4 | 0 / 0 |
| Rust 请求字节 | 0 | 21 | 0 |
| libc fnmatch 调用 | 0 | 2 | 0 |

这是匹配器分配机制证据，不是完整 daemon 分配轨迹，也不能解释多少设备 CPU 差值。
macOS shim 将 Linux FNM_NOESCAPE 2 映射为本机 1；C/en_US.UTF-8 每种 locale 的
6,500,243 次语义与回退路径比较均无差异。

## 同 SDK 与精确镜像

完整 source05 424 文件分成独立普通副本，唯一差异为 `components/rpcd/src/glob.rs`。
两侧固定路径、SDK GCC/bfd/ar/sstrip 和 Rust 1.98.1 相同；source/target 通过私有挂载隔离。

| 产物 | SHA-256 | 字节 |
|---|---|---:|
| 控制（精确 source05） | `d78a752cb383abfbc3c2d0050e445e3742595706e0baf05af17c60d3fcd5d1a8` | 1,256,211 |
| ASCII 尾星号候选 | `5d2dbbf67b6024306bc02232894a96b0fc7302818b499a2e0aef81c3acc4f1fa` | 1,256,211 |

两侧 ELF 均为 4 KiB LOAD 对齐、无解释器、有 GNU_RELRO、sstrip 后无节表。
这是 Oracle AArch64 构建主机的 SDK recipe 诊断产物，非 canonical x86 CI 发布。

动态 C oracle 在精确镜像副本中加载 image libc；C/C.UTF-8 每种 locale 2,864 次
source/candidate 对照、其中 2,815 次 image fnmatch 直接对照均为零差异。

## 验收

- Linux 56 单测、Clippy 通过。
- 控制/候选均通过 RPCD 字节/ACL/glob 兼容、plugin 边界和稳定 helper 功能输出。
- 两侧断连与半帧回收各 20 项检查通过；输出关闭、空输出、输出上限的期限及子进程回收通过。
- r13/r17/r18/r19 分别 63/283/77/11 项对照通过；busy、bytes、defer、real-features 通过。
- 已修正且有身份记录的 r26 稳定输入：733 步，零差异。

real-features 的 C 不良行为原样保留：信号干扰时 32 次中 dnsmasq 字段缺失 30 次、
odhcpd 缺失 32 次、netifd VRF 为 false 32 次；候选这些观察均为 0。未重跑掩盖 C 的结果。

首次精确 libc 探针因 `c_char` 写成 i8 在 AArch64 编译失败，原始 `validation/` 完整保留；
仅修正探针为 `std::ffi::c_char`，新目录 `validation-02/` 完成全部 22 门。没有候选运行失败。

证据保存在 ignored 目录 `private/r93/rpcd-glob-audit/local-20260915-resume-01/`；
下载归档的 6,473 个文件已逐个核验哈希。`ACCEPTANCE.json` 绑定完整源码、SDK pair 和最终门结果。
未修改主树运行时代码或物理路由器；下一步为协调后的 Oracle 四侧性能对照。
