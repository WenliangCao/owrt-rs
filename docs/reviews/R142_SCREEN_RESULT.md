# R142：monitor 候选未通过 Oracle 性能主门

**拒绝将本次 monitor 候选推进为性能升级，保留 R136。** monitor mean(candidate/R136) 六 block 比值中位变化为 **−0.800218%，5/6 下降**；满足方向要求，未达到预冻结的严格 `<−3%` 主门，且处于 ±1% 未分辨区间。九项延迟否决为零，不能替代主门或证明等效。未挑 block、补样本、调整规则或运行路由器筛选。

以下为同期 candidate/R136 六 block 配对比值中位变化；完整逐 block 数值见 JSON：

| 模式 | mean | p95 | p99 |
|---|---:|---:|---:|
| grouped | −0.047814% | −0.235692% | +0.462287% |
| interleaved | +0.595914% | +0.424197% | −1.494090% |
| monitor | −0.800218% | −0.911078% | −1.821426% |

monitor 对同期 C 的 mean 为 **+2.369204%，6/6 上升**，p95 +2.622469%、6/6 上升；对 C 的比较按冻结规则仅报告，没有事后增加全胜门。grouped/interleaved 对 C 的 mean 分别 −9.272952%/−2.653794%，均 6/6 下降；这些正项不能撤销 monitor 主门失败。

CPU 正负项均保留：monitor daemon CPU 对 R136 **−9.489171%，6/6 下降**，caller CPU **+5.095528%，6/6 上升**；对 C 分别 −7.341502%/+5.816724%，也均同向 6/6。CPU 是 process clock 的独立测量，没有用 wall 减 CPU 推导等待，也不能据此判定调度或工作转移机制。CPU 无硬门，不替代延迟主门。

候选 SHA `367badc11fb93b25208cda041048133b8439e1c703c2cb07d740312cc140db54`，与 R136 ELF 同为 **514,771 字节**。正式构建每侧 30 个 source hash，仅 server.rs 改动，使用相同 generic flags；控制逐字节复现 R136。[独立正确性](R142_CORRECTNESS_RESULT.md) 的 56 项单测、wire/FD/recovery、旧 helper 四模式和独立 monitor 边界全部通过。初次带 AppleDouble 元数据的输入导入记录保留，未使用其构建结果或计时；正式 manifest 只绑定合格 build-01。

**完整性通过：54 case、108,000 个测量周期、866 个哈希清单内文件全部核验。** 使用原 `1705d989…` helper，caller CPU 0、daemon CPU 1，六个全排列串行执行，54 个新 daemon 的身份、映射、命令、affinity、空日志、FD 恢复与退出清理均通过。七个工具输入、源码/构建/正确性 proof 和全部运行时库均在正式运行前后核验。detached launcher 已退出。

独立审计对全部 raw、54 组 daemon 身份/argv/CPU/映射 inode 与清理、866 个文件、42 组配对和九项否决逐项核验，与主 JSON 完全一致；审计 SHA `6facde4c27b5a9444c95de4c9fd872ca04d59a9aaf682f59ea89ae786d099748`，原始证据保留于 `private/r142/`。

旧 helper 仅使用一个 monitor 和小 payload，延迟包含 caller 的逐 owner poll、收包与验证，数组未预触页；结果不代表纯 daemon 延迟、多个 monitor、大消息、长期内存或路由器表现。JSON 中即时内存快照仅作诊断；另一个大消息 memory helper 的三方功能 smoke 不进入性能数据，也不是完整内存接受证据。本轮不能修复或抵销 R136 无 monitor 注册慢尾。

[完整 JSON](r142-screen-results.json) 含全部 case 七指标、即时内存快照、两控制下 42 组配对比较和九项否决检查。[冻结规则](R142_SCREEN_PLAN.md) 和[采集/分析工具](../../tools/r142/monitor_screen.py) 未改。manifest SHA `d26992778e90e17cf6c33b71f760d65f0048919ac89b672a87309de8d67bc161`；JSON SHA `00ba2b1500501a9d459d4603f84b4437cba04aaeb046b6f508fcd2e07d9e9936`。原始归档、精确启动命令和 launcher 身份位于 ignored `private/r142/`。

```sh
python3 tools/r142/monitor_screen.py analyze private/r142/screen-manifest-01.json \
  private/r142/screen-01 --output private/r142/rederived-new.json
```
