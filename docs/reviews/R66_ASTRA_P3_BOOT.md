# R66：Astra 对 P3 启动边界的回答（外部审查）

来源：`gpt-6-astra`，2026-09-08，问题见 `/tmp/ask3.txt`。
它在 oracle 的隔离 PID/mount/net namespace 里用**镜像里的原始 init 二进制**做了
三组交接实验，watchdog 端点是一根管道（没有暴露真实 `/dev/watchdog`），
没有对物理路由器做任何写入。

原样保存，未删改。文中的 `/tmp/ask3-evidence/...` 是它在本机留下的证据副本，
不在 Git 内；引用它们是为了可复核，不是要求这些路径长期存在。

---

三条结论先说清楚：

1. **这个镜像的 /sbin/init 是 procd 项目自己的早期 init。真正的交接在 initd/preinit.c 的 spawn_procd()：原 PID 1 在第 114 行 execvp("/sbin/procd", …)。** 正常启动走到这里时已经经过 failsafe 分支和 mount_root；普通 failsafe 则停留在原 init，不会继续到这个正常交接点。
2. **Rust 接管后不喂狗，确实可能在很短时间内重启，不能预留“还有几十秒可以 SSH 撤销”的窗口。** 原版请求 30 秒超时、每 5 秒喂一次，但匹配的 MediaTek 驱动与内核配置还指向约 15 秒的预超时 panic 路径。继承 FD 不会继承旧 init 的喂狗定时器，也没有自动恢复原 procd 的机制。
3. **在现有镜像、已经验证的引导能力，以及“不刷机、选择机制不依赖 overlay”的条件下，做不到你要求的“下一次 Rust、再下一次必回原版”的保证。P3.3 上机接管应标为受阻。** P3.1 和 P3.2 的离线开发可以继续。解除阻塞所需的是一个经验证的、独立于 overlay 的启动入口及一次性消费机制，或可验证的临时 RAM 启动入口；后文说明最小新增操作。

本轮只检查了 oracle 上的源码、提取的 rootfs 和已有报告，并在 oracle 的隔离命名空间中做实验，没有对物理路由器做任何写入。

以下采用的版本是：

| 对象 | 固定版本或路径 |
|---|---|
| 镜像 rootfs | oracle 上的 `/home/ubuntu/h1-4-extract.JK5fNS/rootfs` |
| OpenWrt buildroot | `f0a60eee2fe051741c643ea6118718aae1ef17fb` |
| procd | `58eb263d5abe03f8c1280bdfa65a3b052614215d` |
| fstools | `16718b6e3c0fc7db7be6ae5848db0eae88ac8a8b` |
| 内核源码参考 | Linux `v6.12.94`，结合匹配 buildroot 的目标配置、DTS 和补丁检查 |

rootfs 的发行版本字符串是 `25.12.5 r33051-f5dae5ece4`；这个字符串里的短 hash 与发行 tag 对应的 buildroot commit 分别登记，不能混用。已有 [SOURCE_BASELINE.md](/Users/USER/Developer/owrt-control-plane-rs/reports/ax3000t-stock-openwrt-25.12.5/SOURCE_BASELINE.md:23) 和 [SOURCE_MAP.md](/Users/USER/Developer/owrt-control-plane-rs/reports/ax3000t-stock-openwrt-25.12.5/SOURCE_MAP.md:61) 支持上述版本映射。此次也核对了三个 checkout 的 HEAD，以及 procd、fstools 配方中的 PKG_SOURCE_VERSION。

为了便于复核，所引用的源码和 rootfs 脚本已保存到本机 [ask3-evidence](/tmp/ask3-evidence/sources.json)。其中 `procd/`、`fstools/`、`rootfs/` 和 `linux-6.12.94/` 中的文件保留原行号；OpenWrt 配置另存为[带原行号的摘录](/tmp/ask3-evidence/openwrt-config-excerpts.md)。这些副本都在 /tmp，不在 Git 内。

对第一个问题，**要区分早期 init、preinit 子进程，以及最后成为 PID 1 的正常 procd。**

提取镜像中的 `/sbin/init` 和 `/sbin/procd` 是两个独立的 AArch64 ELF。构建规则也很明确：[procd/CMakeLists.txt](/tmp/ask3-evidence/procd/CMakeLists.txt:54) 第 54 行构建 procd，第 68–74 行单独用 `initd/init.c`、`initd/early.c`、`initd/preinit.c`、`watchdog.c` 等构建并安装 init。因此，这里的 PID 1 起点不是 BusyBox init。

启动顺序如下：

| 顺序 | 实际行为 | 与 overlay、failsafe 的关系 | 文件与行号 |
|---|---|---|---|
| 1 | 内核进入原 `/sbin/init`，PID 为 1；执行 early、cmdline、watchdog_init(1) | 早于用户态正常 overlay 挂载和 failsafe 判定 | [initd/init.c](/tmp/ask3-evidence/procd/initd/init.c:134)，134–136 |
| 2 | fork kmodloader，等待期间继续喂狗，然后启动 uloop 和 preinit | 仍是早期阶段，原 init 保持 PID 1 | 同文件，138–164 |
| 3 | fork 一个 `/sbin/procd -h /etc/hotplug-preinit.json` 子进程 | **这个 procd 调用早于 failsafe 判定和 overlay 挂载**；它是早期 hotplug daemon | [initd/preinit.c](/tmp/ask3-evidence/procd/initd/preinit.c:126)，126–143 |
| 4 | 设置 PREINIT、创建 /tmp/.preinit，再 fork `/bin/sh /etc/preinit` | shell 是子进程，原 init 仍是 PID 1 | 同文件，145–165 |
| 5 | preinit shell 先 source 全部 `/lib/preinit/*`，之后才运行 hooks | 这些文件在正常 overlay 挂载前就已经读入 shell | [rootfs/etc/preinit](/tmp/ask3-evidence/rootfs/etc/preinit:13)，13–29，尤其 19–21 |
| 6 | `failsafe_wait` 检查命令行、按键或按钮结果，设置 FAILSAFE | failsafe 判定在 mount_root 前 | [30_failsafe_wait](/tmp/ask3-evidence/rootfs/lib/preinit/30_failsafe_wait:91)，91–105 |
| 7a | 若 FAILSAFE=true，运行 failsafe hooks，并停在等待循环 | 普通救援路径不继续执行后面的正常 mount_root，也不结束 preinit 子进程 | [40_run_failsafe_hook](/tmp/ask3-evidence/rootfs/lib/preinit/40_run_failsafe_hook:4)，4–16 |
| 7b | 正常路径执行 `mount_root start`，随后运行 preinit_mount_root hook | 此处才接入正常的可写根文件系统 | [80_mount_root](/tmp/ask3-evidence/rootfs/lib/preinit/80_mount_root:36)，36–38、54 |
| 8 | 执行后续正常 preinit hooks，shell 最终退出 | `99_10_run_init` 只做 preinit_ip_deconfig，并没有 exec PID 1 | [99_10_run_init](/tmp/ask3-evidence/rootfs/lib/preinit/99_10_run_init:4)，4–8 |
| 9 | 原 init 收到 preinit 子进程退出通知，进入 spawn_procd，最终 exec /sbin/procd | 正常路径已经经过 overlay；**exec 发生在原 PID 1 内** | [initd/preinit.c](/tmp/ask3-evidence/procd/initd/preinit.c:91)，91–115 |
| 10 | 正常 procd 进入 EARLY、UBUS、INIT，处理 inittab 和 sysinit | rcS、init.d、rc.local 都位于正常 procd 已成为 PID 1 之后 | [procd.c](/tmp/ask3-evidence/procd/procd.c:131)，131–139；[state.c](/tmp/ask3-evidence/procd/state.c:133)，133–166 |

关于 overlay，fstools 的实际调用链也闭合了：[mount_root.c](/tmp/ask3-evidence/fstools/mount_root.c:66) 第 66–98 行处理 extroot、rootfs_data 和文件系统类型；通常的 UBIFS 分支在第 91–92 行调用 mount_overlay。随后 [libfstools/overlay.c](/tmp/ask3-evidence/fstools/libfstools/overlay.c:483) 第 483–487 行执行 mount_move 和 `fopivot("/overlay", "/rom")`。失败或没有可用持久 overlay 时还可能走 RAM overlay，所以不能把“执行过 mount_root”直接等同于“持久 overlay 一定健康可用”。

关键交接代码是：

~~~c
/* initd/preinit.c:91 起 */
spawn_procd(struct uloop_process *proc, int ret)
{
    char *wdt_fd = watchdog_fd();
    char *argv[] = { "/sbin/procd", NULL};

    /* ……清理早期 hotplug 子进程、PREINIT、sentinel…… */

    check_sysupgrade();

    if (wdt_fd)
        setenv("WDTFD", wdt_fd, 1);

    /* ……debug 环境…… */
    execvp(argv[0], argv);       /* 第 114 行 */
}
~~~

这里有四个会直接影响选择器设计的事实。

第一，**最终目标路径写死为 /sbin/procd。** 这份 init 没有读取 INIT、PROCD 等变量来选择另一个正常 PID 1 的接口。在 preinit shell 里 export 一个变量，只能影响该 shell 及其后代，不能改写父 init 的环境。在 preinit shell 里 `exec Rust`，替换的也只是 preinit 子进程，不会把 Rust 变成 PID 1。

第二，**ret 没有被检查。** preinit 子进程非零退出也会进入这个交接回调。最终 execvp 失败后，源码没有另一条 stock exec 回退路径，也没有在这里处理错误；原 init 可能仍留在事件循环里继续喂狗，但启动无法按预期完成。不能把“preinit 失败”理解成“自动进入安全回退”。

第三，`check_sysupgrade()` 是专用升级路径。[initd/preinit.c](/tmp/ask3-evidence/procd/initd/preinit.c:53) 第 53–88 行读取 /tmp/sysupgrade，再调用 sysupgrade_exec_upgraded。它不是通用的下一次启动选择接口，也不能拿它补出你要求的一次性试用保证。

第四，**早期 procd -h 与最后的正常 procd 共用 /sbin/procd 这个路径。** [procd.c](/tmp/ask3-evidence/procd/procd.c:104) 第 104–107 行对 -h 直接进入 hotplug_run。任何在不可变早期文件系统、initramfs 或更早的挂载层中替换这个路径的方案，都必须保留这项调用，不能只考虑“PID 1 最后 exec 的那一次”。

各个可讨论的选择位置，可以这样判定：

| 位置 | 能否真正影响 PID 1 | 当前限制 |
|---|---|---|
| bootloader / 内核 init= / 提前提供 initramfs | 可以在最早入口选择 | 发生在 OpenWrt failsafe 和 overlay 之前；当前 overlay 里的 Rust 此时还不可见。需要经验证的引导入口或镜像改动，现有证据没有提供这种一次性入口 |
| 原 init 的 spawn_procd 内、最终 exec 前 | **这是最直接的正常 PID 1 交接位置** | 原实现没有选择接口；修改持久早期 init 会越过当前“保留原 init、不刷机”的边界。只在 overlay 里替换 /sbin/init，不会影响下次挂载 overlay 前已经执行的 ROM init |
| preinit hooks | 可以准备共享文件、挂载等状态，但 shell 自身不是 PID 1 | hook 文件先于 overlay 被 source；仅往 overlay 的 /lib/preinit 增加一个晚编号脚本，不会让它自动加入这次已经装载的 hook 集合 |
| 正常 overlay 中的 /sbin/procd wrapper、链接或替代文件 | 可以影响最终固定路径的解析，让原 PID 1 exec 到它 | **依赖 overlay**；wrapper 自己的逻辑是在 init exec 到 wrapper 后才运行。若采用它，必须明确这与计划中“init exec 前选择”的措辞差别，并验证整个交接，不能冒充 init 原生提供的选择 hook |
| init.d / rcS / rc.local / 当前启动中的临时 bind mount | 不能单凭这些让“下一次启动的 PID 1”被安全选择 | init.d 等执行时 stock procd 已是 PID 1；临时 bind mount 不跨正常重启保留。普通服务启动、重启方式不能完成要求的接管 |

对 failsafe 的结论需要保持这个具体范围：**在未改动的早期链上，40_run_failsafe_hook 会停住 preinit 子进程，原 init 继续作为 PID 1 喂狗。** 救援 dropbear 和 shell 的 hooks 分别来自 [99_10_failsafe_dropbear](/tmp/ask3-evidence/rootfs/lib/preinit/99_10_failsafe_dropbear:25) 第 25–61 行，以及 [99_10_failsafe_login](/tmp/ask3-evidence/rootfs/lib/preinit/99_10_failsafe_login:4) 第 4–23 行；它们不要求先进入正常 procd 的服务状态机。

所以，单纯位于正常 overlay 中、只在最终路径解析时生效的改动，通常不会在这个普通 failsafe 分支被加载。但一旦把选择器提前，或替换了早期可见的 /sbin/procd，就必须从头检查它与 -h、按钮处理、preinit 和 watchdog 的关系，不能沿用一句“failsafe 不加载 overlay”作为整个新机制的证明。

还有两个边界不能漏掉：spawn_procd 自身并不检查 FAILSAFE；它只是等待 preinit 子进程退出。若这个子进程被杀掉或异常退出，就仍可能触发交接。并且 shell 导出的 FAILSAFE 不会自动传回父 init；`/tmp/failsafe` 也不是所有入口都必然生成——命令行 failsafe 在 [30_failsafe_wait](/tmp/ask3-evidence/rootfs/lib/preinit/30_failsafe_wait:97) 第 97 行直接设值，而 touch 在后面的条件分支中。因此，未来的选择器不能凭一个未经逐路径核对的环境变量或 marker 宣称 failsafe 一定安全。

对第二个问题，**watchdog 合同是“继承一个已打开的 FD，再由新程序重新负责喂狗”。**

原版的完整软件行为如下：

| 项目 | 匹配源码的行为 | 文件与行号 |
|---|---|---|
| 设备路径与默认值 | /dev/watchdog；请求 timeout=30 秒；frequency=5 秒；magicclose=false | [watchdog.c](/tmp/ask3-evidence/procd/watchdog.c:29)，29–35 |
| 获取 FD | 若有 WDTFD，atoi 后接管该整数 FD 并 unsetenv；否则 open(/dev/watchdog, O_WRONLY) | 同文件，50–71 |
| 初次启动 | 原 init 调用 watchdog_init(1)，不设置 FD_CLOEXEC；设置超时，然后立即喂一次并安排后续定时器 | [initd/init.c](/tmp/ask3-evidence/procd/initd/init.c:136)，136；[watchdog.c](/tmp/ask3-evidence/procd/watchdog.c:191)，191–204 |
| kmodloader 等待期 | 循环等待期间调用 watchdog_ping；循环中 sleep 约 10ms，最多 1200 次 | [initd/init.c](/tmp/ask3-evidence/procd/initd/init.c:152)，152–160 |
| 日常喂狗 | write(fd, "X", 1)，每次定时器回调后再安排 5 秒 | [watchdog.c](/tmp/ask3-evidence/procd/watchdog.c:37)，37–48 |
| init → procd | 以 WDTFD 环境变量告知 FD 数字；真正的打开文件描述仍通过 exec 继承 | [initd/preinit.c](/tmp/ask3-evidence/procd/initd/preinit.c:93)，93、106–114 |
| 新 procd 接管 | STATE_EARLY 调用 watchdog_init(0)，接管并设 FD_CLOEXEC，再立即喂狗；STATE_UBUS 再调用一次，兼顾此前设备不可用的情形 | [state.c](/tmp/ask3-evidence/procd/state.c:133)，133–142；[watchdog.c](/tmp/ask3-evidence/procd/watchdog.c:50)，50–71 |

FD_CLOEXEC 控制 exec 时是否关闭，并不阻止 fork 时复制 FD。因此早期 init 刻意让它跨最终 exec 留下来；正常 procd 接管后再加 FD_CLOEXEC，避免它继续泄漏到普通 exec 出去的服务中。

**exec 不会把原 init 的 uloop 定时器带进 Rust 的地址空间，也不会因为 WDTFD 还存在就自动重新开始一个完整超时周期。** 剩余窗口从上一次成功喂狗计时。Rust 必须在通用的“清理继承 FD”逻辑之前辨认并保留 WDTFD，在早期初始化时接管、尽快喂狗、建立自己的定时器，再对后续服务 exec 设置恰当的关闭标志。不能等 ubus、日志、网络或所有服务都起来后才做这件事。

原代码对失败的处理很有限：

- open 失败时，watchdog_init 直接返回。后续状态有再次尝试打开的机会，但这不构成“硬件此时一定没在运行”的证明。
- WDTFD 使用 atoi 接管，没有严格验证这个 FD 是否真指向 watchdog。若传进来的是一个非负但失效的 FD，代码也不会自动把它识别为“需要重新打开设备”。
- WDIOC_SETTIMEOUT 的返回值没有在 watchdog_init 中处理。因此源码请求 30 秒，不等于本机 ioctl 一定成功，也不等于运行时实际值必为 30。
- write 喂狗失败只记录错误，定时器继续按频率安排。没有自动执行原 procd、撤销 Rust 选择或修复 watchdog 的分支。
- watchdog_set_stopped(true) 会取消软件定时器，再按 magicclose 标志关闭 FD；默认 magicclose=false。这不能当作安全关闭硬件 watchdog 的承诺。

最后一点还有内核依据：[watchdog.c](/tmp/ask3-evidence/procd/watchdog.c:74) 第 74–88 行仅在 with_release=true 时写入 "V"；[Linux watchdog_dev.c](/tmp/ask3-evidence/linux-6.12.94/drivers/watchdog/watchdog_dev.c:942) 第 942–969 行表明，支持 MAGICCLOSE 的设备未收到允许释放的 magic close 时不会正常停止，关闭路径还会补一次 keepalive。nowayout 若启用又会限制停止。匹配 generic 配置中 NOWAYOUT 默认未启用，并不能据此推导“随便 close 就能关闭 watchdog”。

**“30 秒超时”还有一个对你很重要的修正：这套配置存在更早的 watchdog 预超时 panic 路径。**

证据链为：

1. Linux 的 [mt7981b.dtsi](/tmp/ask3-evidence/linux-6.12.94/arch/arm64/boot/dts/mediatek/mt7981b.dtsi:72) 第 72–77 行把设备声明为 mediatek,mt7986-wdt，并给出 IRQ 110。匹配 OpenWrt 板级 `target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-common.dtsi` 第 429–430 行启用该 watchdog。
2. [mtk_wdt.c](/tmp/ask3-evidence/linux-6.12.94/drivers/watchdog/mtk_wdt.c:415) 第 415–423 行在 IRQ 可用时启用 pretimeout，初值为 31/2。第 260–283 行在设置 timeout 时把已经启用的 pretimeout 更新为 timeout/2，代码注释明确说明 dual mode 在一半时间触发 IRQ，完整 timeout 到时复位。
3. 因此在上述路径成立、SETTIMEOUT(30) 成功的条件下，pretimeout 是约 15 秒。[mtk_wdt.c](/tmp/ask3-evidence/linux-6.12.94/drivers/watchdog/mtk_wdt.c:326) 第 326–335 行启用 IRQ/dual mode；第 364–370 行把 IRQ 交给 watchdog_notify_pretimeout。
4. 匹配 `target/linux/mediatek/filogic/config-6.12` 第 522–525 行选择默认 panic governor，并内建它。`drivers/watchdog/pretimeout_panic.c` [第 18–20 行](/tmp/ask3-evidence/linux-6.12.94/drivers/watchdog/pretimeout_panic.c:18) 直接调用 panic。
5. 匹配 `target/linux/generic/config-6.12` 第 4578 行是 CONFIG_PANIC_TIMEOUT=1。这又提供 panic 后较快重启的默认路径。

这些配置的逐行摘录在 [openwrt-config-excerpts.md](/tmp/ask3-evidence/openwrt-config-excerpts.md)。下载的发行 config.buildinfo 的 SHA-256 是 `d79d1c4b3a18dac919371f8d9f1a9350363d9b94261744bd2cc2f5c3e4c17115`，与项目 [SBOM.md](/Users/USER/Developer/owrt-control-plane-rs/reports/ax3000t-stock-openwrt-25.12.5/SBOM.md:52) 登记值一致。对匹配 OpenWrt 补丁树的检查没有发现修改这里所引用 mtk_wdt/watchdog_dev 行为的相关补丁。

这仍然是**匹配源码和构建配置所支持的失效路径**，并非在你的路由器上实际停喂测出的倒计时。本轮没有验证物理 IRQ 工作情况、运行时 governor、实际 timeout/pretimeout 或后续对 panic 参数的修改。因此我不会声称设备“必定在第 16 秒重启”；可以确定的是，**不能承诺给操作者完整的 30 秒，甚至不能把恢复设计建立在来得及重新连上 SSH 上。**

内核也没有在这个默认 active=30 秒配置下无限替用户态喂狗的保证。[watchdog_dev.c](/tmp/ask3-evidence/linux-6.12.94/drivers/watchdog/watchdog_dev.c:76) 第 76–96 行表明，已被用户态激活的 watchdog 需要内核续喂 worker 的相关条件是请求超时大于最大硬件 heartbeat；而 [mtk_wdt.c](/tmp/ask3-evidence/linux-6.12.94/drivers/watchdog/mtk_wdt.c:431) 第 431–433 行的硬件上限是 31 秒。默认的 30 秒并不满足该条件。不要把 watchdog 的启动期内核照看机制外推成 Rust 挂死后仍会被一直照看。

成功 exec Rust 后，旧 init 已被替换，没有一个旧 procd 留在外面监督它。选择器在 exec 失败时实施退回，与 exec 成功后 Rust 挂死、panic 或喂狗失败，是两类不同问题。前者可以由仍在运行的选择代码处理；后者不能依赖已经被 exec 掉的选择器。硬件重启也只负责重新启动，不会替你清除下一轮还会选中 Rust 的持久选择。

本轮做了三个隔离实验，直接检查这些交接事实。

使用的是镜像里的原始 init 二进制；stock 模式最终 exec 镜像里的原始 procd 二进制。环境是 oracle 上私有 PID、mount、net namespace 和复制的 rootfs，**唯一 watchdog 端点是一根管道**，通过继承 FD 和 WDTFD 注入。没有给实验暴露真实 /dev/watchdog。

实验中替换了 kmodloader、udevtrigger 和 /etc/preinit，清空 inittab，并用受控 /sbin/procd wrapper 记录交接。wrapper 对早期 -h 调用只记录后退出；failsafe 模式则加载镜像原样的 40_run_failsafe_hook。也就是说，它验证的是原 init 的父子进程、exec、FD 和喂狗行为，**没有完整演练原版早期 hotplug、按钮识别、overlay 挂载或实际 failsafe 网络**。

| 实验 | 控制条件 | 实际记录 | 可以推出的结论 |
|---|---|---|---|
| stock，观察 13.5 秒 | preinit 子进程 export 假 INIT/PROCD，约 6 秒后 exit 17；wrapper 随后 exec 原 procd | PREINIT pid=9、ppid=1；HANDOFF pid=1、ppid=0；WDTFD=4；父环境中 PROCD/INIT 均 unset；同一 pipe FD 从未设 CLOEXEC 变为已设；11.565 秒仍收到 X | 交接确在 PID 1；子进程导出环境不改变父 init；非零退出不阻止交接；原 procd 接管 FD 并重新喂狗 |
| failsafe，观察 8 秒 | FAILSAFE=true，运行原 40_run_failsafe_hook | 没有 HANDOFF；/proc/1/exe 仍是原 init；约 5.094 秒收到 X | 在该等待分支内，父 init 继续运行和喂狗，不进入正常 procd |
| hold，观察 13.5 秒 | 正常结束 preinit；交接后 PID 1 shell 持有 FD，但不喂狗 | 有 HANDOFF 和 HOLD_WITHOUT_FEED；最后一次 X 在约 5.094 秒；整个 exec 后观察阶段没有新 X | 仅仅继承 FD，不会使旧 init 的喂狗定时器继续运行 |

这里的 FD 4 只是本次实验得到的描述符编号，接口没有约定固定必须是 4。

stock 模式的 X 时间点为 0.044、0.056、5.050、6.062、6.566、11.565 秒；failsafe 模式为 0.088、0.098、5.094 秒；hold 模式为 0.088、0.098、5.094 秒。stock 后半段连续喂狗与 hold 后完全停止形成了直接对照。

实验里的管道不支持 watchdog ioctl；因此它也符合“原程序即使设置超时失败仍会继续 write”的软件行为。**这些结果不能证明硬件 SETTIMEOUT 成功，不能测出硬件实际复位时限，也不能证明 Rust 实现已经正确完成了 watchdog 接管。** 本轮未运行 Rust PID 1，更不能用这三个实验宣布整个 P3.2 或本机启动已通过。

可复核的实验文件为：

- 本机探针：[ask3_init_probe.py](/tmp/ask3_init_probe.py)。
- 实际执行版本副本：[experiment/probe.py](/tmp/ask3-evidence/experiment/probe.py)，第 15–47 行是受控 preinit/wrapper，第 55–67 行是 namespace 内启动，第 91–150 行是三组采集和断言。
- 汇总原始结果：[experiment/results.json](/tmp/ask3-evidence/experiment/results.json)。
- oracle 原记录目录：`/tmp/ask3-init-26jqoxkp/`，含 `results.json`、`probe.py` 及 `stock/`、`failsafe/`、`hold/` 的 trace、console、runner 日志。
- 所有探针断言通过，结束时清理了实验进程及其命名空间。下文附上 results.json 的完整内容。

对第三个问题，**当前没有可用证据支持符合全部要求的一次性选择机制，P3.3 应判定为受阻。**

你的要求包含两件不同的事：一次重启后能进入 Rust；以及无论这次 Rust 是否建立网络、是否正常启动、是否喂狗、是否成功运行后再重启，下一次都自动回到原版。第二件事要求试用授权在进入候选前就已被可靠地消费，后续默认路径独立于候选的健康状态。仅有“失败若干次后可能回另一槽”也不等于“成功试用一次后，下次同样必回 stock”。

在现有镜像里逐项看：

| 候选机制 | 是否满足你的完整要求 | 原因 |
|---|---|---|
| overlay 里的 marker + /sbin/procd wrapper，exec 前删除并持久化 marker | 不满足“机制不依赖 overlay” | 选择代码、选择状态或两者的可见性、消费和撤销依赖 overlay。即使补齐文件及目录 fsync，也没有改变这项依赖 |
| /tmp 里的 once 标志 | 不满足“下一次启动用 Rust” | 正常重启后 /tmp 会重新建立 tmpfs；原 init 的 [early.c](/tmp/ask3-evidence/procd/initd/early.c:75) 第 75 行明确挂载它 |
| 当前启动的 RAM 文件、bind mount、临时改路径 | 不构成跨重启选择 | 不会自行存在于下一次早期启动；若另设持久脚本重新建立它，又必须追踪该脚本从哪里被早期执行 |
| 原 procd 的 rcS 或回退服务 | 不满足 PID 1 启动选择与独立恢复 | 启动得太晚；Rust 全局 PID 1 崩溃或系统 panic 时，普通脚本不能提供执行保证 |
| 厂商 boot flags / 双槽计数 | 未建立可用保证 | 当前只掌握 OpenWrt 的部分读写调用方及少量运行观察，没有证明 bootloader 提供通用、一次性、可选择 Rust PID 1 的接口 |
| kexec 临时启动 | 当前镜像没有建立这条可用路径 | 匹配 generic config 第 3042–3044 行未启用 KEXEC/KEXEC_FILE；filogic 配置未把它们打开；发行 config.buildinfo 没有 KERNEL_KEXEC 或 kexec 包启用项 |
| 经验证的 bootloader RAM 启动临时 kernel/initramfs | 原理上可以提供一次启动后回到 flash 默认路径的办法 | **目前没有验证到这项现成能力**，不能把可能支持写成当前可用 |

boot flags 这部分尤其不能凭变量名作保证。

镜像的 [/etc/init.d/bootcount](/tmp/ask3-evidence/rootfs/etc/init.d/bootcount:4) 第 4 行是 START=99，本身就晚于 PID 1 选择；第 8–15 行对 AX3000T 检查 flag_try_sys2_failed，等于 8 时直接返回。已有 [H1_1B_BOOT_FLAGS.md](/Users/USER/Developer/owrt-control-plane-rs/reports/ax3000t-stock-openwrt-25.12.5/H1_1B_BOOT_FLAGS.md:10) 确认这台设备命中该分支。

同一报告 [第 44–58 行](/Users/USER/Developer/owrt-control-plane-rs/reports/ax3000t-stock-openwrt-25.12.5/H1_1B_BOOT_FLAGS.md:44) 还明确保留 bootloader counter 语义未知项。后来 [R23_BOOT_PATH.md](/Users/USER/Developer/owrt-control-plane-rs/reports/ax3000t-stock-openwrt-25.12.5/R23_BOOT_PATH.md:52) 观察到一次正常重启中 system-1 counter 增加、其他所列标志不变；这能支持该次转换的事实，不能单凭它建立“Rust 启动失败后下一次必然选回 stock”的状态机。报告中对计数用途的概括，也不能替代匹配厂商 bootloader 源码或故障路径证据。

同理，其他 U-Boot 平台中的 bootcount、bootlimit、altbootcmd，或 AX3000T 的 ubootmod 安装方案，不能直接套在这台 stock 引导布局上。存在 fw_printenv/fw_setenv 工具，仅证明可以访问某种环境存储，不证明 bootloader 会按一个新变量完成想要的一次性选择。

kexec 的判断也只限于匹配构建证据；本轮没有在设备上调用 syscall 做验证。`config/Config-kernel.in` 第 742–743 行的 KERNEL_KEXEC 是无默认启用值的选项，结合上述目标和发行配置，不能把“现成 kexec 一次启动”当作这份镜像已经提供的恢复能力。

最小新增操作建议按是否继续坚持“不刷机”分开说明：

**现在就能做的，是保留 P3.3“受阻”，继续 P3.1/P3.2 离线工作，并把缺口写成具体能力。** 缺口不是“缺少一条启动脚本”，而是：没有一个已验证的早期入口，能在不依赖 overlay 的情况下只放行一次候选，并保证之后仍从原版路径启动。离线可继续验证真实 init → Rust exec、FD 接管、exec 失败、错误 FD、喂狗失败、事件循环阻塞、服务回收和停止路径；这些工作不用修改设备，也不需要第二台路由器。

**若仍坚持不刷机，最小值得进一步核实的新增入口，是现有厂商 bootloader 是否支持可控的、只在 RAM 中加载并启动临时 kernel/initramfs。** 先用已有私有 bootloader 备份、匹配源码或可信文档做只读核对，确定确切命令、镜像格式、签名限制、控制台入口，以及它是否不执行 saveenv、不写 flash，并在 reset 后恢复默认 flash 启动。如果这项能力确实存在，再准备包含原 init、原 procd、候选及必要工具的 RAM 试验镜像，离线完成交接与回退验证；实际进入 bootloader、RAM 启动和验证下一次回原版仍属于未来单独授权的设备操作。

这是一项待证明的前提，不是我现在认定可执行的步骤。尤其不能把现有小米 TFTP 救援当成这个入口：[RUNBOOK_AX3000T_RECOVERY.md](/Users/USER/Developer/owrt-control-plane-rs/docs/RUNBOOK_AX3000T_RECOVERY.md:90) 第 90–101 行描述的是校验小米镜像后刷入、回到厂商固件的恢复过程，不是已经验证的任意 initramfs RAM 启动。

如果现有 bootloader 没有这种可验证的临时 RAM 启动能力，那么满足严格的一次性选择要求，就至少需要新增或修改不可变早期启动代码/引导配置，并提供独立于 overlay、能在候选执行前可靠消费的选择状态，同时验证原版恢复路径。这涉及当前不允许的持久启动改动；没有证据支持用一条 fw_setenv 命令安全替代它，也不能把它包装成普通安装脚本操作。

解除上机阻塞前，watchdog 还需要补上本机实际运行值的证据，例如现有 sysfs 可读的 identity、timeout、pretimeout 和 governor，以及相应 panic 配置；这类读取可以帮助确定合同，但本身不会补出一次性回退机制。本轮没有为取这些信息去打开物理 /dev/watchdog，也没有进行停喂实验。

因此可以把阶段状态具体写为：

> P3.3 本机 PID 1 接管与恢复：受阻。  
> 已定位原 init 的固定 exec 交接、overlay/failsafe 顺序和 watchdog FD 合同，并完成原版二进制的隔离交接实验。  
> 尚无经验证的、独立于 overlay 的一次性启动选择或临时 RAM 启动入口；不能保证候选挂死、watchdog 复位或正常结束试用后，下一次必回原版。  
> 继续 P3.1/P3.2 离线开发；不启用物理 PID 1 替换，不以普通回退脚本或未经证明的 boot flags 代替恢复保证。

这与计划 [RUST_CORE_CONTROL_PLAN.md](/Users/USER/Developer/owrt-control-plane-rs/docs/RUST_CORE_CONTROL_PLAN.md:203) 第 203–217 行的边界一致，尤其第 212–213 行明确允许在“不刷机且现有恢复机制下找不到可验证选择方案”时完成其余离线工作，并指出具体缺口。

以下是本轮三组实验的完整 results.json，时间单位为秒，起点为各组外部采集器启动后的单调时钟：

~~~json
[
  {
    "mode": "stock",
    "pings": [
      {
        "at": 0.044,
        "data": "X"
      },
      {
        "at": 0.056,
        "data": "X"
      },
      {
        "at": 5.05,
        "data": "X"
      },
      {
        "at": 6.062,
        "data": "X"
      },
      {
        "at": 6.566,
        "data": "X"
      },
      {
        "at": 11.565,
        "data": "X"
      }
    ],
    "snapshot": {
      "executable": "/tmp/ask3-init-26jqoxkp/rootfs/sbin/procd.stock",
      "fd_target": "pipe:[19536118]",
      "fd_flags_octal": "02000001",
      "fd_cloexec": true
    },
    "trace": "PREINIT pid=9 ppid=1 mode=stock WDTFD=unset\nHOTPLUG_CHILD pid=8 WDTFD=unset\nPREINIT_EXIT_17\nHANDOFF pid=1 ppid=0 WDTFD=4 PROCD=unset INIT=unset\npipe:[19536118]\npos:\t0\nflags:\t01\nmnt_id:\t17\nino:\t19536118\n",
    "duration": 13.5
  },
  {
    "mode": "failsafe",
    "pings": [
      {
        "at": 0.088,
        "data": "X"
      },
      {
        "at": 0.098,
        "data": "X"
      },
      {
        "at": 5.094,
        "data": "X"
      }
    ],
    "snapshot": {
      "executable": "/tmp/ask3-init-26jqoxkp/rootfs/sbin/init",
      "fd_target": "pipe:[19535394]",
      "fd_flags_octal": "01",
      "fd_cloexec": false
    },
    "trace": "HOTPLUG_CHILD pid=8 WDTFD=unset\nPREINIT pid=9 ppid=1 mode=failsafe WDTFD=unset\nENTER_FAILSAFE\n",
    "duration": 8.0
  },
  {
    "mode": "hold",
    "pings": [
      {
        "at": 0.088,
        "data": "X"
      },
      {
        "at": 0.098,
        "data": "X"
      },
      {
        "at": 5.094,
        "data": "X"
      }
    ],
    "snapshot": {
      "executable": "/tmp/ask3-init-26jqoxkp/rootfs/bin/busybox",
      "fd_target": "pipe:[19534480]",
      "fd_flags_octal": "01",
      "fd_cloexec": false
    },
    "trace": "PREINIT pid=9 ppid=1 mode=hold WDTFD=unset\nHOTPLUG_CHILD pid=8 WDTFD=unset\nPREINIT_EXIT_17\nHANDOFF pid=1 ppid=0 WDTFD=4 PROCD=unset INIT=unset\npipe:[19534480]\npos:\t0\nflags:\t01\nmnt_id:\t17\nino:\t19534480\nHOLD_WITHOUT_FEED\n",
    "duration": 13.5
  }
]
~~~
