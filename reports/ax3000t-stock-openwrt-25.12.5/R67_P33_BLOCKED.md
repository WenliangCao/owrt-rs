# R67：P3.3 本机 PID 1 接管——受阻

日期：2026-09-08。依据：[R66](../../docs/reviews/R66_ASTRA_P3_BOOT.md)（外部审查，
含三组用原始 init 二进制做的隔离交接实验）、`procd 58eb263d` 源码、
提取的发货 rootfs、以及匹配的 buildroot `f0a60eee` 配置。
**没有对设备做任何写入。**

计划 [RUST_CORE_CONTROL_PLAN.md](../../docs/RUST_CORE_CONTROL_PLAN.md) 第 212–213 行
明确允许这个结论：不刷机且找不到可验证的启动选择方案时，完成其余离线工作，
写明具体缺口。这就是那份说明。

## 交接点在哪里

镜像里的 `/sbin/init` 和 `/sbin/procd` 是两个独立的 ELF——`init` 由
`initd/init.c` + `initd/early.c` + `initd/preinit.c` + `watchdog.c` 单独构建。
正常路径最终在**原 PID 1 内部**执行：

```c
/* initd/preinit.c:114 */
execvp("/sbin/procd", argv);
```

四个直接决定选择器可行性的事实：

1. **目标路径写死。** 这份 init 不读 `INIT`、`PROCD` 之类的变量。
   在 preinit shell 里 export 只影响那个 shell 及其后代；在 preinit shell 里
   `exec` 候选，替换的是 preinit 子进程，不会让候选成为 PID 1。
2. **preinit 子进程的退出码不被检查。** 非零退出照样进入交接回调，
   而 `execvp` 失败后源码没有回退到原版的另一条路径。
   "preinit 失败 = 自动安全回退"是错的。
3. `check_sysupgrade()` 是专用升级路径，不是通用的下次启动选择接口。
4. **早期的 `procd -h`（hotplug daemon）和最后的正常 procd 共用
   `/sbin/procd` 这一个路径。** 任何替换该路径的方案都必须同时保留 `-h` 行为。

## failsafe 的确切范围

未改动的早期链上，`40_run_failsafe_hook` 让 preinit 子进程停在等待循环，
**原 init 继续作为 PID 1 并继续喂狗**，不进入正常 procd。实验里
failsafe 模式 8 秒内没有 HANDOFF，`/proc/1/exe` 仍是原 init。

但旧结论"failsafe 不加载 overlay 改动"**不能外推**成整个新机制的安全证明：
`spawn_procd` 自己不检查 FAILSAFE，它只等 preinit 子进程退出——子进程被杀
或异常退出照样触发交接。而且 shell 里的 `FAILSAFE` 不会传回父 init，
`/tmp/failsafe` 也不是所有入口都必然生成。

## watchdog：没有 30 秒窗口

原版请求 30 秒超时、每 5 秒喂一次，用 `WDTFD` 加继承的 FD 交接。
**但这台机器的失效来得更早**（源码与构建配置支持的路径，不是实测倒计时）：

- `mt7981b.dtsi:72` 声明 `mediatek,mt7986-wdt` 并给 IRQ；板级 dtsi 启用它。
- `mtk_wdt.c` 在 IRQ 可用时启用 pretimeout，且设置 timeout 时把 pretimeout
  更新为 **timeout/2**——dual mode 在一半时间触发 IRQ，完整 timeout 才复位。
- filogic 的 `config-6.12` 选了默认 **panic governor** 并内建；
  `pretimeout_panic.c` 直接 `panic()`。generic 配置 `CONFIG_PANIC_TIMEOUT=1`。

所以 SETTIMEOUT(30) 成立时，pretimeout 约 **15 秒**。不能给操作者留出
"还有几十秒可以 SSH 撤销"的窗口。

内核也不会替用户态兜底：内核续喂 worker 要求请求超时**大于**硬件最大
heartbeat，而 `mtk_wdt` 的上限是 31 秒，默认的 30 秒并不满足。

三组隔离实验（管道当 watchdog，原始二进制）的直接结论：

| 实验 | 记录 | 结论 |
|---|---|---|
| stock | HANDOFF 在 pid=1；父环境里 PROCD/INIT 仍未设置；同一 FD 从未设 CLOEXEC 变为已设；11.565s 仍有喂狗 | 交接确在 PID 1；子进程 export 不改父环境；非零退出不阻止交接 |
| failsafe | 无 HANDOFF，`/proc/1/exe` 仍是原 init，5.094s 有喂狗 | 该分支内父 init 继续喂狗 |
| hold | 交接后 PID 1 持有 FD 但不喂 | **最后一次喂狗停在 5.094s，之后再无** |

第三组是关键：**继承 FD 不会让旧 init 的喂狗定时器继续运行。**
候选必须在通用的"清理继承 FD"逻辑之前认出 `WDTFD`，尽早接管并立刻喂狗。

这些实验证明的是软件交接，**不能**证明硬件 SETTIMEOUT 成功、不能测出实际复位
时限、也不能宣布 P3.2 通过。

## 为什么没有可用的一次性选择机制

要求是两件事：下一次进 Rust，且**无论候选是否健康**，再下一次必回原版。
第二件要求授权在进入候选**之前**就被可靠消费。逐项看：

| 候选机制 | 结论 |
|---|---|
| overlay 里的 marker + `/sbin/procd` wrapper | 违反"不依赖 overlay" |
| `/tmp` 里的 once 标志 | 重启后 tmpfs 重建（`early.c:75`），下一次根本进不了 Rust |
| 当前启动的 bind mount / 临时改路径 | 不跨重启 |
| 原 procd 的 rcS 或回退服务 | 太晚；PID 1 崩溃时普通脚本没有执行保证 |
| 厂商 boot flags / 双槽计数 | `bootcount` 是 START=99（远晚于 PID 1 选择），且本机命中 `flag_try_sys2_failed == 8` 直接返回；counter 语义仍是未知项，见 H1_1B/R23 |
| kexec | **没有启用**：generic config 未开 KEXEC/KEXEC_FILE，filogic 也没开，发行 `config.buildinfo` 里 KEXEC 匹配项为 0 |
| bootloader 的临时 RAM 启动 | 原理上可行，但**这项能力当前没有被验证到** |

小米 TFTP 救援不是这个入口：`RUNBOOK_AX3000T_RECOVERY.md` 描述的是校验小米镜像
后刷入、回到厂商固件，不是已验证的任意 initramfs RAM 启动。

## 状态与下一步

> **P3.3 本机 PID 1 接管与恢复：受阻。**
> 已定位原 init 的固定 exec 交接点、overlay/failsafe 顺序和 watchdog FD 合同，
> 并用原版二进制完成隔离交接实验。
> 尚无经验证的、独立于 overlay 的一次性启动选择或临时 RAM 启动入口；
> 不能保证候选挂死、watchdog 复位或正常结束试用后，下一次必回原版。
> 继续 P3.1/P3.2 离线开发；不启用物理 PID 1 替换，
> 不以普通回退脚本或未经证明的 boot flags 代替恢复保证。

缺口不是"缺一条启动脚本"，而是：**没有一个已验证的早期入口，能在不依赖 overlay
的情况下只放行一次候选，并保证之后仍从原版路径启动。**

最小新增操作（仍需单独授权，现在不做）：只读核对现有厂商 bootloader 是否支持
可控的、只在 RAM 中加载并启动临时 kernel/initramfs——确切命令、镜像格式、
签名限制、控制台入口，以及它是否不执行 saveenv、不写 flash、reset 后恢复默认。
先用已有私有 bootloader 备份和匹配源码做只读核对。

离线仍可继续、且不需要设备的：真实 init → Rust 的 exec 交接、`WDTFD` 接管、
exec 失败、错误 FD、喂狗失败、事件循环阻塞、服务回收与停止路径。
