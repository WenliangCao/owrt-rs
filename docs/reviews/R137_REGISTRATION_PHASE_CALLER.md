# R137 分相诊断 caller 已通过 Oracle smoke

独立 SDK/musl ELF `4930759767aeadb8f5c3267a1346a2d76e75862cd8575da59881a81081c68d0f`
通过 **12/12** 正确性 smoke：精确 C/R136 × 1/16 方法 × cycle-wall/phase-wall/phase-cpu，
各 100 周期、20 预热。全签名、末尾空对象、单线程、PID/starttime 与亲和性检查通过，
仅启动的隔离 daemon 已退出，临时 socket 目录已清理。没有 router 操作或 runtime 改动。

第一次 smoke 以普通 ubuntu 身份运行，精确 C 的注册 ACL 返回 Invalid argument；
该失败保留。runner 补上 root 前置断言后，第二次 sudo smoke 全过，未改 caller ELF。
编译成功但保留既有 `LookupEntry` unused warning 与 SDK runas.so preload warning；
本次没有顺手改动这些内容或重新布局 daemon。

构建使用 Rust 1.98.1 和 OpenWrt 25.12.5 SDK；[构建脚本](../../tools/benchmark/build-r137-registration-phase.sh)
要求新输出目录。三模式属于同一个 ELF，不受各模式重编译布局差异混杂。
本地 ELF 在 ignored `private/r137-phase/owrt-register-phase`，Oracle 原件在
`/home/ubuntu/r137-phase-build-01/owrt-register-phase`。

```sh
owrt-register-phase register-phase SOCKET METHODS 8 2000 200 DAEMON_PID MODE 256
```

`MODE` 为 `cycle-wall`、`phase-wall` 或 `phase-cpu`。每 case 输出全部原始 wall
样本、三处 CPU 快照及其双 wall 括号、256 组空时钟探针、进程前后状态。输出在循环
结束后序列化；循环内不读 `/proc`，不写日志。caller 不修改进程亲和性，保护 runner
负责冻结并检查预定 CPU mask。

Oracle 的 disabled self task-clock/context_switch `perf_event_open` 探针均成功，
errno=0；这是 Oracle 接口能力，不能推导 router 可用，也没有开启计数或 trace。
R137 只区分 phase 与 CPU 共现，无法在当前 router 能力下将阻塞与调度排队完全分开。
额外读钟开销不从样本中相减；CPU 模式的中间快照延迟 REMOVE，须按
[预冻结探索规则](R137_REGISTRATION_PHASE_PLAN.md)与两种 wall 模式校准。

源码审查确认匹配 ubus `24864e78` 的 ADD 与 REMOVE 都发送 DATA 后由统一路径发送
STATUS，REMOVE 的释放发生在 DATA 与最终 STATUS 之间；当前 register-cycle 合并
两相计时，所以先判断慢尾在哪一相有实际区分价值。R135 发送方式探索与正式否决仍
保持，不能由这个静态差异直接推断改回独立发送会修好尾部。

[派生 smoke 结果与证据哈希](r137-registration-phase-smoke.json)。全部原始输出及第一次
失败保留在 ignored `private/r137-phase/`。n=100 smoke 没有性能结论，不能与 formal
窗口拼接；实机诊断仍由主线程按既有恢复与健康门另行执行。
