# R93 第二次暂停交接

**2026-09-15，用户因额度要求暂停。本文是最新接续入口。**
首次暂停的全组件异常清单仍在 [R93_PAUSED_HANDOFF](R93_PAUSED_HANDOFF.md)，
其中的旧验证进度已被本轮记录更新；不要从旧的“尚未构建/尚未验证”重新开始。

## 当前确定完成的事

- 唯一工作分支 `codex/exploratory-fixes-and-performance`，R90/R91/R92 已统一，main/远端未改。
- source05 九组件正确性闭合见 [SDK 验证摘要](reviews/r93-sdk-05-validation.json)。
- **新修复已提交 `3262a56`**：大签名 prefix LOOKUP 背压时漏对象却返回成功。
  同输入 C/R89/source05 都为 62/64 DATA，修复版 64/64 完整字节正确。
  五历史门、27 单测、专项及最终九组故障门通过。
  [完整身份与验收范围](reviews/r93-ubusd-prefix-validation.json)。
- **工具修复 `239a41b`**：logd 接收器改为增量解析帧头，避免反复扫描累计历史。
  最终字段、字节、ID、顺序检查不变；9 单测、5 流恢复、三侧 15 smoke 通过。
- 新实机矩阵完成 logd、ubusd、rpcd、procd 四组件，分别 24/120/216/96 个观测，合计 **456**。
  每侧四轮，当前被测 Rust 仍是冻结 source05，**不含上述新 prefix 修复或任何性能候选**。
- netifd、UCI、fw4、reload-config、完整 HTTP 矩阵尚未启动；三侧整栈冷启动验收尚未执行。

## 暂停时仍未解决的现象

### HTTP：停放后仍明显输 C；新候选还没有收益证据

已有 AX3000T、16 KiB、4 客户端、四轮 CPU 中位数：

| 间隔 | C µs/请求 | R89 | source05 |
|---|---:|---:|---:|
| 0 ms | 259 | 204 | 203 |
| 40 ms | 290 | 210 | 210 |
| 60 ms | 290 | 625 | 630 |
| 80 ms | 290 | 685 | 685 |

此问题仍未解决。[实机原始对照与限制](reviews/R93_HTTP_DEVICE_BASELINE.md)。
worker-cache 及追加 parser-cache 候选已通过各自主要功能、TLS/SSE、模糊、12 万 CGI、
连接上限、真实 EAGAIN 恢复门；但没有新实机性能结果。

parser-cache 一次 Linux 诊断：冷态/64 连接保持 200 ms/关闭两秒 RSS 为
**956/1232/1116 KiB**，C 为 **976/1420/980 KiB**；候选 FD 7→71→7、线程 1→5→1。
候选退出缓存线程后仍比自身冷态高 **160 KiB**。不能据此宣称全面省内存。
原 static 测试的 200 ms 基线线程 3、关闭后三秒线程 1，精确相等断言报红；真实回收证据
另存，原红不覆盖。旧并发单测有一次 CGI ETXTBSY，串行通过，尚无 trace 定因。

本轮五侧短 pilot **仅第一侧 C、gap0、20000 请求完成**。随后 runner 向 root 所有的
`raw/derived.json` 写入时报 PermissionError；第二个样本未启动。这是工具输出权限故障，
没有任何五侧胜负结论。下次先修输出路径，使用全新目录，不混用该单侧样本。

### RPCD：新实机确认部分权限查询比 R89 贵

- `session_access_granted` 自身 CPU 四轮范围：R89 **22–24**，source05 **27–28 µs**。
- `session_access_64_c4` 平均延迟中位数 **241.98→275.37 µs（+13.80%）**，
  CPU **17.86→22.82 µs（+27.78%）**。C 平均延迟 274.63 µs；与 C 的小差值不足以证明稳定退步。
- 同镜像字节正确性仍通过；[18 项完整矩阵](reviews/R93_RPCD_DEVICE_BASELINE.md)。

源码线索已保存：该负载实际使用 `net*`/`r*`，source05 每次匹配需要两个 CString，
一次成功权限查询两次匹配，共四对申请/释放；R89 旧匹配器没有这些申请。
**这是源码推导，尚未计数实测，也未证明解释多少 CPU 差值。**
总线期限检查也是额外成本的候选；不能撤掉超时保护来换分数。
ASCII 单尾星号快路只有私有草稿，没有编译/测试/SDK 产物。

### logd：固定输入胜双基线，整机旧退步仍没解释完

新实机固定写入 C/R89/source05 CPU 为 **32.3/8.5/7.2 µs**；读取 100 条为
**808/420.5/389.5 µs**。RSS 中位数 **1010/504/568 KiB**，source05 比 R89 高 64 KiB，
但匿名页两侧都是 172 KiB，文件/共享映射类型不同，不能全部归因于堆。
[完整实机结果](reviews/R93_LOGD_DEVICE_BASELINE.md)。

旧整机日志 lane 相对历史 R89 高 29.49%，仍未拆清输入正文、进程历史与实现成本。
span 私有候选减少瞬时分配，但本机计数表明最终 ring 存活容量不变。
Oracle 旧单轮 no-subscriber 的 source05/span 均 1.9 µs/条，未证明额外 CPU 收益；
follow 样本只有 6–7 ticks，不能判小幅改善。新版接收器尚未跑正式四轮。

### ubusd：漏对象已修，延迟与慢读算法收益仍待测

source05 新实机 `lookup_all_64/128` 平均延迟 **786.27/1548.64 µs**，
C **774.87/1510.22 µs**，自身 CPU 更低。部分查询比 R89 高约 0.9–2.5%。
[十项完整矩阵](reviews/R93_UBUSD_DEVICE_BASELINE.md)。
新 prefix 正确性修复仍会每轮收集剩余 ID；借用遍历候选已经验证正确性，但未测 CPU。
一次续传分配探针在 64→1024 对象时，修复版 **33347→41027 B**，借用候选
**32851→32851 B**。只能说明分配机制改善。
旧 contract 的 `txq_ofs` 残值污染下一消息说法没有运行反例，已更正，不能当确证故障。

### procd：本轮普通查询仍胜 C，部分 CPU 没赢 R89

四轮新实机：`service_list_32` C/R89/source05 CPU **88/69/69.5 µs**；
`system_info` **169/143/145.5 µs**；`service_list_128_c4` **250.50/185.02/188.99 µs**。
这些小差值不构成全面胜 R89；[96 个观测与逐轮范围](reviews/r93-procd-device-baseline.json)。
原 set-return/service.start 时序回归已修，大规模 watch 性能仍无对照。
netifd/UCI/fw4/reload-config 和整机内存的未完成项见首次交接，没有本轮新数据可宣布解决。

## 产物与接续入口

| 内容 | 本地 ignored 目录 | 状态 |
|---|---|---|
| source05 基线 | `private/r93/candidate-sdk-05/` | 不可覆盖；源码快照 SHA 6f8700bf…abd7c |
| prefix 正确性修复 | `private/r93/ubusd-star-backpressure/RESULT.md` | 已合入；SDK 49b0244d…0685e1，GNU 54d81507…02c9a |
| 最终九组故障门 | `private/r93/star-integrated/evidence/` | 9/9，工具与 binary hash 固定 |
| ubusd 借用遍历 | `private/r93/ubusd-star-lookup-borrow/RESULT.md` | 未合入；SDK d2132a8d…60adc2，29 单测、5 历史、专项/恢复/smoke 通过；未测性能 |
| HTTP worker-cache | `private/r93/http-worker-experiment/race-verified/sdk-r2/README.md` | 未合入；SDK f2fe52c6…2d9130 |
| HTTP parser-cache | `private/r93/http-worker-experiment/head-cache/sdk-ab/README.md` | 未合入；SDK 0140478c…1d0332，48 Linux 串行单测及主要运行门通过 |
| HTTP 未完 pilot | `private/r93/http-worker-experiment/five-side/README.md` | 单侧成功后工具权限失败，PARTIAL 和清理证据保留 |
| logd span | `private/r93/logd-span-validation-20260915/README.md` | 未合入；SDK d0bd0a3b…2e3947，正确性已过 |
| logd 分配说明 | `private/r93/logd-span-local-review/REVIEW.md` | 本机诊断，非设备收益 |
| RPCD 快路草稿 | `private/r93/rpcd-glob-audit/RESUME.md` | 未合入、未编译、未计数/测试；macOS/Linux fnmatch flags 不同，照说明验证 |
| 实机原始矩阵 | `private/r93/device-components-sdk-05/` | 四组件 COMPLETE；集合 PAUSED.json；不是九组件 COMPLETE |
| 此次停工证据 | `private/r93/pause-final-20260915/` | health/cleanup/summary |

所有性能候选均为独立副本，不是当前生产或分支运行时代码。SDK recipe 诊断构建并非
canonical x86 CI 发布。完整 SHA 和输入清单在各目录 manifest/identity，不用短 hash 部署。

## 下次明确恢复后

1. 阅读本文及各候选 README，核验 Git/二进制身份、备份与设备健康；不要重跑已完成工作。
2. 实机 source05 剩余五组件从 netifd 开始，使用新组件输出目录和原冻结产物。
   原两个 driver 都是一次性脚本，不可直接重跑：procd 已完成，而外层 driver 被停止，
   `driver-results.json` 没有最后一条 procd；以各组件 COMPLETE、PAUSED.json 为准。
3. HTTP 先修 pilot 的 derived 输出路径权限，在新目录完整五侧短测；再决定实机窗口。
4. RPCD 草稿先做准确语义/分配验证；ubusd/logd 候选先公平性能对照，未证实收益不合入。
5. Oracle 计时窗口只允许一组压测，原始失败全部保留。任何新代码不得覆盖 source05 基线。

**停工状态：所有任务已停止，四个已完成组件的设备临时目录已清理。路由器仍运行 R92，
配置、boot 与生产身份一致，Wi-Fi/客户端健康通过。没有部署新候选、重启或刷机。**
