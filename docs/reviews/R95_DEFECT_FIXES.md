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

## 后续次序

1. A02：UCI 正式包补 build.rs，实际 SDK 构建及路由器隔离检查。
2. A04：修共享 UCI 读取的短读丢尾，并在路由器运行分段读取回归和 CLI 行为检查。
3. A03：恢复进程内规范化的有界、可取消等待；覆盖配置与 delta 锁、超时、取消、基线和后续事件。
4. 冻结最终九组件源码/产物身份，重跑受影响方合同门；制定性能研究和统计判定方法，再进行实机比较。
