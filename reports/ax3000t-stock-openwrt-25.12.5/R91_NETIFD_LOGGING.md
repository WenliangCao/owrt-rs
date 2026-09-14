# R91：恢复 netifd 的运行日志通道

> 本修复已纳入正式 R92 并完成部署与实机验收，见 [R92 报告](R92_REMAINING_BATCHES.md)。
> 以下“本地候选/未部署”描述仅指 R91 当时的独立阶段。

日期：2026-09-14。代码起点 `d669b05`，分支 `codex/r91-netifd-logging`。
R90 的部署与验收已经结束；本轮从 R88 遗留项继续，只修改 netifd 日志及相应验证工具。
本轮没有连接或修改物理路由器，设备的最后验收版本仍是 R90。

当前状态：**本批开发修复与构建机验证完成**。九个日志/接口场景双侧通过，157 个
单元测试与 clippy 通过，netifd 完整回归 31/31、无跳过。该候选不是正式发布构建。
逐项证明和来源摘要见 [validation.json](R91_parts/validation.json)。

## 1. 从精确镜像确认问题

镜像 `/etc/init.d/network` 只设置 netifd 的 command、respawn、watch 和 limits，
没有设置 `procd_set_param stderr`。精确上游 `main.c` 默认
`openlog("netifd", 0, LOG_DAEMON)`，将接口和子进程输出送到 syslog。
R90 所有正常日志都写 stderr，且拒绝 `-S`、`-l`，因此启动成功和 ubus 正常
不能证明网络日志进入了 logd。

在独立 mount/net/PID namespace 中，用原版 ubusd、合成协议脚本及真实
`/dev/log` 数据报接收端对照：原版的 setup/up/down、脚本 stdout/stderr 均到达
syslog，PRI=29、ident=`netifd`；正式 R90 在这些场景下只有 stderr 输出。
这是 R88 F8 的可重复证据，不依赖在物理路由器上制造故障。

精确上游提交是 `cbb83a1857407a28a63dc09412a1f209195914ef`。本机参考文件
与构建机 Git 中该提交的内容逐字节核对；没有使用 `stage9/netifd` 的当前 HEAD。

| 参考 | SHA256 |
|---|---|
| 镜像 `/sbin/netifd` | `8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90` |
| 镜像 `/etc/init.d/network` | `1c27ae29b6702f51e96d1aacd5181f0041e3672635ed9026fae179afa4e94b6e` |
| 上游 `main.c` | `659cd502d660c062d777a79d7ed4bd60d01121d99d98f9bae94d1708e9940079` |
| 上游 `netifd.h` | `ff9e66ea37b4e3e762f1c014741075f498c0a66b236b20baadb217c442170108` |
| 上游 `ubus.c` | `3ae2788070d1b0160ffaca536d33bf7514c7c1c546e3067fc975173ab0646205` |

## 2. 修复与边界

- 新增 `logging.rs`，统一正常运行日志。默认调用 musl 的 syslog；`-S` 改写 stderr，
  写入失败不触发 Rust panic。CLI/启动失败和显式调试环境变量的 stderr 诊断保留。
- `-l <level>` / `-l<level>` 按 C `atoi` 解析并仅钳上限 4。notice=2；负数禁用正常日志，
  非数字为 0，带尾随非数字的十进制前缀仍有效。
- 补上正常 setup 和 static UP 两处缺失的生命周期日志；协议、无线和 hotplug
  子进程日志携带真实 PID。脚本与 helper 分别取 PID，避免把两者混为一条来源。
- 在格式化之前过滤消息；静默模式继续排空子进程管道。libc 负责数据报格式和
  日志 socket 重建后的重连，不新增日志线程、发送队列或第三方 Rust 依赖。

本轮不把所有日志文本、顺序和子进程分帧宣称为逐字节等价。Rust 仍有额外
诊断消息，`-d`/udebug 未实现；既有子进程 UTF-8 转换与末尾处理差异没有扩大为本批修复。
没有修改 ubus 方法、网络配置解析、协议状态机或无线编排规则。
恢复默认 syslog 会使用 libc 持有的日志 socket；不宣称资源计数或性能完全不变。

## 3. 撤销 R88 netifd F6

精确 `ubus.c:iface_object_methods` 与原版运行时接口都没有接口级 `restart`，
R90 的 11 个方法与原版一致。因此“缺少 `network.interface.* restart`”是混用
较新上游导致的误报，不能以补兼容为理由增加这个方法。

全局 `network restart` 是现有接口，其 re-exec 行为（R88 F9）仍是另一个待办。
netlink 溢出恢复（F7）也不在本轮范围。合同与 R88 遗留清单已同步纠正。

## 4. 验证

入口：`tools/r91_netifd_logging.py ROOTFS CANDIDATE OUTPUT`，通过
`r91_netifd_logging.sh` 加入 `netifd_suite.sh`，套件共 31 项。
每场景使用新 rootfs 副本及 mount/net/PID namespace，核验运行中的二进制身份、
接口确实 UP、teardown 确实执行、daemon 存活及必需断言全集。失败/超时后 PID
namespace 清理其子进程；本次完整旧套件也套在独立 PID namespace 中运行。

九个场景：方法表、默认 syslog、`-S`、`-l1`、`-l99tail`、`-l -1`、
`-l nonnumeric`、日志 socket 重建、写满的非阻塞 stderr。非静默场景核验
setup/up/down、stdout/stderr、子进程 PID 和含 `%s/%n/%%` 的字面消息。

正式 R90 对照的接口方法场景通过，八个日志场景判红；原版九场景通过。
开发候选九场景与原版各自通过。开发绿证位于 `raw/green-v2`；完整回归和最终
同探针红证位于 `raw/acceptance-v2`，有 `COMPLETE`。R90 反例目录的 `FAILED`
是预期红证，不能将它误判为 R91 验收失败，也不改写为候选通过。

| 验证 | 当前结果 |
|---|---|
| netifd 单元测试 | 157/157 |
| clippy | exit 0；沿用 unsafe 注释检查，42 条既有 dead-code 警告与 R90 数量相同 |
| 脚本语法 | `make check-tools` 通过 |
| 日志/接口专项 | 原版、开发候选各 9/9 |
| netifd 完整套件 | 31/31、无跳过；含 R90 生命周期与新增 R91 门 |
| 正式 R90 反例 | 方法表通过，八个日志场景失败；同探针的原版九项均通过 |

开发期间两项夹具问题单独记录：首版探针用了会隐藏方法签名的 `ubus -S -v`，
两侧方法断言均失败；去掉 `-S` 后原版/R90 方法表均通过，`raw/red-01` 保留。
第一次源码快照漏带现有 profile example 引用的 `rpcd/examples/profile_support`，
导致 examples 构建失败；补齐快照后同运行时代码构建通过，完整日志为 `raw/build-v2.log`。
首次构建只保留工具诊断摘要，没有另存完整 stderr；不将该摘要称为完整原始日志。

## 5. 候选身份与后续

这是构建机 `oracle` 上 pinned Rust 1.98.1 的开发 release 构建，目标
`aarch64-unknown-linux-musl`，不是 GitHub Actions 的正式发布产物。

- netifd SHA256：`6915569a21fa05f81944c0070d52d71db8f0ff08b3a2be1e505afe836a36bbc4`
- netifd MD5：`a73819d883bec87a64415740df1c1155`；大小 1,052,824 字节。
- 源码清单：238 个组件/工具/工具链文件，构建前逐文件核验一致。
- 清单 SHA256：`da9e765bd56addb2caaed082f07d41d3cb0cbc5604d0ca0ea8f55d8f271d5f96`。

最终将 238 项清单与本机代码再次逐文件核验，没有变化；相关源码摘要见
[source.json](R91_parts/source.json)。完整套件约 935 秒；运行结束后构建机没有
残留 netifd/procd 测试进程。原始证据已复制回本机，派生步骤再次核对门日志哈希、
31 项完整性、双侧 18 条绿证和 18 条反例观察，以及两轮使用同一探针与正确二进制身份。
验收结束后长时间运行的 SSH 客户端没有自动退出；确认远端验证进程已结束、读回并核验
证据后，按准确命令核验本地 PID 并关闭该连接。其客户端退出码为 255，门结论来自
已核验的远端 `results.json`、`COMPLETE` 和各门日志。

构建机工作目录 `/home/ubuntu/r91-netifd-logging/`，本机证据镜像 `private/r91/`。
原始数据报、配置副本、二进制与完整日志只存 private；Git 只保存代码、工具、合同和派生记录。
本轮未执行正式构建、性能矩阵或实机部署，不复用 R90 的部署证明为 R91 背书。
后续状态入口为 [R91_RESUME](../../docs/R91_RESUME.md)。
