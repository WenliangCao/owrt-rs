# R95：先修实际缺陷，再进入性能研究

2026-09-20。承接 [R94 成果审计](R94_COMPLETION_AUDIT.md)。
用户要求逐步提交；最终行为、性能和内存结论必须来自 AX3000T 本机。
本阶段只允许隔离测试：生产始终运行 C，不安装/启用候选；每次测试结束清理进程、挂载和临时文件。
构建机结果用于编译和前置筛查，不替代实机验收。

## A01：reload-config 正式打包依赖 — 已修复

将包内构建树改为相邻的 `reload-config/` 与 `uci/`，与 Cargo 的 `../uci` 路径一致，
复制完整的必要 UCI 源码及 build.rs；保留安装路径 `/usr/sbin/reload_config_rs`。

验证：

- Oracle 上实际执行 OpenWrt SDK `package/owrt-reload-config/clean`、`compile`，退出 0，生成 APK。
- 用 SDK 的 `apk extract` 提取实际包内二进制；实机测试的就是该文件，477,931 字节。
  APK 与二进制身份见 [验证清单](r95-defect-validation.json)。这是 SDK 正式配方验证，不是 canonical CI 发布。
- AX3000T 私有 mount/PID/network namespace 内运行规范化基线一致性、重复执行检查，退出 0。
  生产 C 身份、配置、boot 和主机挂载表前后相同；客户端健康通过，临时目录已移除。
- 首次实机尝试因镜像没有 `timeout` 命令而在启动候选前退出 127；清理和健康验证通过。
  随后新增小型 SDK 静态 guard，给 namespace launcher 设 120 秒生命周期，重跑通过。
  guard 的超时/正常退出控制在构建机通过；它不访问硬件 watchdog。

本步只修构建输入，没有性能改动，不作性能胜出结论。A03/A04 的运行时缺陷仍按下一步处理。
原始构建与实机记录保存在 ignored `private/r95/a01/`；恢复备份保存在 `private/r95/recovery-full/`。

## A02：UCI 正式包的 build.rs — 已修复

正式 Prepare 阶段复制 UCI 的 build.rs，保留 musl CLI 必需的 `getauxval` 链接输入。
实际 SDK clean/compile 和 APK 提取均通过；包内二进制为 `2b2e8090…`，与 R94 后期 CLI 身份一致。
路由器隔离检查通过：两个 export 与 C 输出一致，set/commit/get 往返一致。
生产 C 身份、配置、boot、主机挂载表保持一致，客户端健康及临时目录清理通过。
本步只补正式构建输入，不作新性能结论。原始记录：`private/r95/a02/`。

## A04：UCI 短读丢尾 — 已修复

文件大小只作分配提示，持续读取到 `read` 返回 0；正数短读继续读取，EINTR 重试。
初次分配提示最多 64 KiB，按需要增长；从当前文件偏移读取，保留 commit/delta 重读语义。
这里恢复了必要的 EOF 确认，不能再把“少一次 syscall”当作错误截断的理由。
[Linux read(2)](https://man7.org/linux/man-pages/man2/read.2.html) 明确区分正数短读与 EOF。

实际 SDK clean/compile、APK 提取通过。AX3000T 上运行同源码 SDK 构建的两个读取回归：
1/7/16 字节分段、一次中断、准确/过小/过大长度提示，以及非零偏移均保留完整字节；
再用 APK 内 CLI 验证两个 export 与 C 相同、set/commit/get 往返正确。全部通过。
路由器 C 栈、配置、boot、挂载和客户端健康不变，测试目录已清理。

前置构建机回归：unit、clippy、r16 差分、r24 1,000 例、r83 均退出 0。
共享库最终版本的其他依赖方仍将在 A03 结束后统一重验，不把本步检查外推成全栈验收。
原始记录：`private/r95/a04/`；性能影响暂不下结论。

## A03：配置与增量锁的超时/取消 — 已修复

UCI Context 增加显式启用的协作式 I/O 预算，借用取消标志，不引入线程、子进程或新依赖。
reload-config 为每个条目启动一次预算；base/override/delta 锁共用截止时间，竞争时采用
非阻塞 flock 与最多 10 ms 的重试间隔。普通 CLI 和其他调用方不启用预算，维持原阻塞行为。
delta 加载必须传播超时/取消，失败包不进入加载缓存；读取/解析检查预算，超时保留已经渲染的字节。
这是显式等待控制，不是任意内核文件系统操作的硬实时抢占，详见 [合同 §12](../contracts/config-change-dispatch.md)。

选型依据：[Linux flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html) 提供非阻塞请求；
[musl signal 实现](https://git.musl-libc.org/cgit/musl/tree/src/signal/signal.c) 默认启用 SA_RESTART，
因此不能只靠一个信号标志期待原来的阻塞 flock 自动退出。

AX3000T 证据：

- 旧 APK 候选 `4793a15b…`：持配置锁、`--timeout-ms 100`，超过 1 秒由 guard 杀死，确认旧缺陷在实机可复现。
- 最终 APK 候选 `2abc0bea…`：配置、delta、override 三种锁各跑超时和 SIGTERM，共六个行为场景通过。
  超时继续处理 beta 并推进基线，解除锁后下一次调用恢复 alpha；取消 exit 75，基线和投递保持不变。
- 同源码 SDK 测试可执行文件的三条公共加载路径测试在路由器通过，覆盖部分缓存清理、等待期间取消、期限内释放锁后的完整 delta。
- 最终 UCI `95a570ec…` 另跑实际 CLI export/提交往返检查通过。
- 两个窗口均验证生产仍为 C、配置/boot/主机挂载不变、客户端健康、测试目录与进程清理。

前置构建机验证：所有九组件及共享 ubus 的单测，加 UCI/reload-config 的 clippy 与历史差分门，共 16 门退出 0。
最后调整“超时保留已渲染字节”后，最终 reload-config 的 unit/clippy/r1 三门重新通过。
两种 CLI 均来自实际 SDK clean/compile 后提取的 APK；最终运行时源码逐文件与测试快照一致。
没有宣称其他依赖方的完整实机合同/性能验证已经完成。

首轮额外实机探针在配置超时通过后，因为精确镜像的 BusyBox sleep 不支持小数秒而停止；
当轮清理与健康检查通过。将探针改为整数秒后完整重跑通过；没有修改运行时来迁就探针。
原始记录：`private/r95/a03/`，包括失败尝试；脱敏身份和结果见 [验证清单](r95-defect-validation.json)。

## 最终源码统一构建与实机冒烟 — 已完成

将九组件冻结在 `5dabcb4`，逐文件核对全部运行时源码与该提交一致。
logd/httpd/rpcd/fw4 执行实际 SDK clean/compile/APK 提取；UCI/reload-config 复用 A03
已测 APK（运行时源码逐字节一致）；procd/ubusd/netifd 用相同 SDK 和固定路径的 core 配方构建。
这是统一来源的诊断构建，仍不冒称 canonical CI 发布。

九个最终候选分别在 AX3000T 的隔离 namespace 中通过基本行为检查，依赖保持原镜像 C。
每个窗口均核对主体二进制 SHA，确认生产 C 身份、配置、boot、主机挂载不变，
客户端健康通过，测试进程/目录清理通过。身份和脱敏结果见
[统一验证清单](r95-unified-validation.json)，原始记录为 `private/r95/final-build/`。
这只关闭“统一源码构建与九组件实机冒烟”的缺口，不代替完整历史合同、性能或全栈联动验收。

## 统一候选的构建机历史合同 — 已补齐候选检查

48 项（47 项必需、一项原版 procd 对照）完成，包含 netifd 全部 31 个子场景，
最终候选的必需行为检查全部满足。构建机结果仍是前置筛查，不替代路由器终验。

保留的过程问题：首次 CGI 压测缺少 ns-exec，未启动候选即 exit 127，补齐冻结工具后实际重跑通过。
首批辅助例程身份捕获与刷新存在时序差，受影响的五门另外重跑并重新记录身份，未沿用不一致的清单。
这五门之一的恢复门在复跑时 exit 1：原版 C 的 `ubusd_halfclose` 偶尔完整返回，
而旧判定要求它必须丢尾；两轮候选的十个恢复场景全部满足断言。

只对这个已观测到两种结果的 C 对照修正分类：成功时显式记录
`original_failure_not_reproduced=["complete_reply"]`，其他 C 预期和全部候选断言保持严格。
三个新增构建机窗口再次观察到 C 两次丢尾、一次完整返回，候选三次完整返回；
分类单测还逐项验证候选任一断言失败均不能获豁免。
[完整对照分类记录](r95-recovery-control-classification.json)保留旧 exit/判定及新结果，
没有将最初两批非零退出改写成“原始执行全绿”。

## 后续次序

1. 对统一候选补完整历史合同结果及新增缺陷的实机覆盖。
2. 按 [实机研究与验收规则](../R95_PERFORMANCE_RESEARCH.md) 逐组件和整栈研究。
   A01–A04 关闭不代表“全面胜 C”已经达成。
