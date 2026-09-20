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

## 后续次序

1. 冻结最终九组件源码/产物身份，重跑受影响方合同门。
2. 明确实机性能与内存的比较方法，再逐组件和整栈研究。A01–A04 关闭不代表“全面胜 C”已经达成。
