# R130：ADD 合并回复的机制验证

独立候选 `fc8bb458b585412658ae524ca8df183eee4081bf` 仅合并成功、无 monitor 的 ADD DATA+OK STATUS。
R124 控制逐字复现；候选 ELF SHA256 为
`2e8316cc3719a789efe266f01047998e0cfe46d1eedc19d31434a56d66b34528`。
`remove_object` 与 `free_object` 函数逐字未变。Linux native 和目标 musl 单元测试均 49/49 通过。

Oracle `strace` 仅跟踪精确 ELF 的 sendmsg，不重编译运行时加入计数器。每个 fixture 有 100 个计时周期、
20 个预热周期、1 个签名预检周期，共 121 次成功 ADD；固定额外发送为 HELLO、一次完整 exact LOOKUP、
两次空 LOOKUP STATUS。

| 方法数 | R124 sendmsg | R130 sendmsg | 差值 |
|---|---:|---:|---:|
| 1 | 488 | 367 | −121 |
| 16 | 488 | 367 | −121 |

计数恰好符合每个成功 ADD 少一次 sendmsg，注册/删除回复从四次变三次。所有调用完整成功，caller 协议检查通过。
被跟踪的耗时和 CPU 一律不作为性能结果；该结构改进能否降低路由器耗时，仍需独立固定系列。
ADD/REMOVE 精确字节、monitor、队列上限、短写恢复、事件顺序和 FD 关闭由单测与协议差分门支持；
计时 register-cycle 本身每周期仅检查成功状态和可解析的 ADD OBJID，完整签名只在预检 lookup 校验。

构建发生三次工具性失败：全 native 测试的输入包漏带 profile example 的同版本依赖；重跑遇到已有备份目录；
cargo 缓存没有重新生成已归档 linker map。失败日志全保留，补齐同版本输入并以新目标目录构建后通过，
期间未修改候选源码或弱化测试。[机器结果](r130-add-reply-mechanism.json)包含产物、输入、日志和原始跟踪哈希。

本页为机制里程碑，不是接受或部署结论。R127/R128 启动条件与注册计时校验范围的勘误已另行记录，
本候选不依赖旧 R128 的 +3.1% 观测值成立。
