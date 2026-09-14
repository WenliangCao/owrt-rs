# R91 续接说明（2026-09-14）

由 `d669b05` / [R90 已完成状态](R90_RESUME.md)继续，当前分支
`codex/r91-netifd-logging`。本轮默认推进剩余兼容性修复，范围收窄为 netifd 日志。
没有连接、修改或重启物理路由器；最后的实机验收状态仍为 R90。

先看 [R91 报告](../reports/ax3000t-stock-openwrt-25.12.5/R91_NETIFD_LOGGING.md)。

- 已复现并修复 R88 netifd F8：默认 syslog、`-S`、`-l`，生命周期及子进程日志。
- F6 撤销：镜像精确版本也没有接口级 `restart`；方法表不增加新方法。
- F7（netlink 溢出）、F9（全局 restart/re-exec）仍是后续独立项。
- 九个日志/接口场景：原版与开发候选通过；正式 R90 只有方法表通过，八个日志场景报红。
- 157 个单元测试、clippy 与语法检查通过；完整 netifd 31/31，无跳过。
- 本批本地修复与构建机验证已完成，证明见报告旁 `R91_parts/validation.json`；
  原始证据已回存本机 `private/r91/oracle-evidence/`。

候选是 oracle 上 Rust 1.98.1 的开发 musl release 构建，非正式发布产物。
SHA256 `6915569a21fa05f81944c0070d52d71db8f0ff08b3a2be1e505afe836a36bbc4`。
构建前核验的源码清单为 `private/r91/source-v2.json`，238 个文件。

构建机 `/home/ubuntu/r91-netifd-logging/`：

- `source/`：本批源码；`source-v2.json`：逐文件 SHA256；`target/`：开发构建。
- `raw/red-01/`：方法签名解析夹具错误，保留，不作通过依据。
- `raw/red-02/`：原版 9/9，正式 R90 日志 8 项报红，方法表通过。
- `raw/green-v2/`：加入子进程 PID 与格式字符串检查后的双侧 9/9。
- `raw/acceptance-v2/`：单测、clippy、31 项套件及同探针 R90 红证，有 `COMPLETE`。
  其中 `r90-negative/FAILED` 是预期红证，不是 R91 候选失败。

本轮没有正式发布、性能矩阵或新部署证明。R90 已完成的正式构建和整套验收仍不需要重跑。
本批候选通过的 31 项也不需要因换会话重复运行；仅在源码、输入或未解决疑点变化时复核。
