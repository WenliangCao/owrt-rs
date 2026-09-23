# R141：单一 PGO 实验可行性与工具准备

**PGO 有可执行的独立方案；当前仅完成只读研究和工具安装，尚未构建、训练或测量候选。** 等 R140 结束确定开发基线后，保持其 CPU target、源码、canonical 源码根、SDK、LTO/profile、strip 和其他参数不变，只研究 PGO。不能同时换 CPU target；旧注册/事件慢尾失败继续保留。

## 已有能力与本次准备

Oracle pinned Rust `1.98.1`（`48a229cea`）使用 LLVM `22.1.8`。aarch64-musl 的 `libprofiler_builtins` 已存在，静态 archive 中可见 profile 写盘和 atexit 注册符号；无需添加 daemon 源码埋点。该 Rust 提交的[编译器逻辑](https://raw.githubusercontent.com/rust-lang/rust/48a229ceaefd4985c50990b14116b6d856af0985/compiler/rustc_metadata/src/creader.rs)只在 profile-generate/coverage 阶段注入 profiler runtime，[runtime 构建定义](https://raw.githubusercontent.com/rust-lang/rust/48a229ceaefd4985c50990b14116b6d856af0985/library/profiler_builtins/build.rs)包含 LLVM 文件、计数器和写盘实现。

准备前仅有系统 `llvm-profdata-18`（18.1.3），同 Rust toolchain 没有 profdata。上游 LLVM 18 的 raw profile version 为 [9](https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-18.1.8/llvm/include/llvm/ProfileData/InstrProfData.inc)，LLVM 22 为 [10](https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-22.1.8/llvm/include/llvm/ProfileData/InstrProfData.inc)；[raw 格式无前后版本兼容保证](https://llvm.org/docs/InstrProfileFormat.html#raw-profile-format)。不能用已有 18 替代本工具链的 merger，也不通过丢弃坏 profile 凑出成功。

本次已获授权安装 `rustup component add --toolchain 1.98.1-aarch64-unknown-linux-gnu llvm-tools-preview`，退出 0。取得 `LLVM version 22.1.8-rust-1.98.1-stable` 的 `llvm-profdata`，459,448 字节，SHA-256 `c7160d195180796edf7cc4c3f087f72b5425fc9ec2d9734b956a265e506f982e`。位置为该 toolchain 的 `lib/rustlib/aarch64-unknown-linux-gnu/bin/llvm-profdata`，不依赖 PATH 选择。安装日志、前后 component 清单、版本和 SHA 位于 ignored `private/r141/preparation-01/`，本地副本逐项核对通过。没有访问路由器、改变 R140 冻结文件或构建候选。

## 建议的一次训练与一次候选

复用 R137 私有 namespace，将三个构建都映射到 `/tmp/owrt-build/r135/r136-combined-01`：先重建无改动控制并要求精确身份；再以 `-Cprofile-generate=ABS_DIR` 构建训练 ELF；最后仅以 `-Cprofile-use=ABS_PROFDATA` 生成一个候选。generate/use 使用同 compiler、source 和其余 flags；使用阶段启用 Rust 文档建议的 missing-function 警告，记录并解释未覆盖函数，不把缺失静默当完整训练。[精确 Rust 提交的流程](https://raw.githubusercontent.com/rust-lang/rust/48a229ceaefd4985c50990b14116b6d856af0985/src/doc/rustc/src/profile-guided-optimization.md)

建议训练只在 Oracle 做一次预冻结八类组合，每类一个新 daemon 和独立 raw 输出目录：

1. ADD/REMOVE：1/16 方法，短/长签名，交替成功与已存在路径。
2. LOOKUP：精确、prefix、all；1/64/128 对象。
3. INVOKE：单 caller 和四 caller，正常 DATA/STATUS。
4. 对象事件：1/8 handler 与不匹配监听。
5. 直接 SEND：单/多 handler、无匹配。
6. owner/monitor：已有 grouped/interleaved/monitor 夹具。
7. 传输边界：已有 FD、分片、短写与队列恢复夹具。
8. 生命周期/失败：断连、移除、权限拒绝、未知对象和既有 slow-reader recovery。

这是待冻结的训练范围建议，不是已运行结果。常规类可固定各 1,000 个逻辑操作，边界类各运行一次既有完整夹具；不按计时表现重配权重。每类 raw 独立保留，用确定列表一次合并，记录数量、字节、SHA、函数/计数摘要及所有错误。LLVM 默认按实际计数相加，不能把相同操作数称为相同权重；若采用类别权重，必须在训练前指定，不能为候选结果调参。[merge 规则](https://llvm.org/docs/CommandGuide/llvm-profdata.html#merge)

现有 `SIGTERM` handler 设置 STOP 并唤醒 self-pipe，事件循环返回、清理 socket，main 正常结束。LLVM profiler 的[初始化与退出钩子](https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-22.1.8/compiler-rt/lib/profile/InstrProfilingFile.c)在正常结束时写 raw；训练必须验证退出 0、非空可解析 raw 和预定函数计数。SIGKILL、abort、超时或写盘失败使对应训练失败并保留证据，不补写 profile。该路径尚需第一份 instrumented ELF 实际 smoke，不能把源码可行性写成已验证落盘。

## 跨 CPU 边界、成本和判断

N1 上的插桩收集的是函数/分支/值计数，不是 A53 周期或调度成本。相同 aarch64 ISA 可承载训练，但 N1 的可读字节数、EAGAIN、并发和背压比例可能与 A53 不同；插桩本身也改变这些比例。以上边界类只能扩大覆盖，不能证明复现设备流量、kernel/IRQ 竞争、长期连接分布或全部故障。训练耗时不能当性能结论；只有未插桩 profile-use ELF 的独立实机比较能决定保留，且仍需自身正确性/恢复门。

成本预计为三个构建加八类训练，分钟级准备；仅作排程估计，尚未测得 PGO 编译或训练耗时。现有无 PGO 构建约 9 秒仅是参考。训练 ELF 会增加 profiler runtime、计数器和 raw 磁盘使用；现存 profiler archive 为 788,576 字节，含 archive 内容，**不能当成实际 ELF 增量**。最终仅 profile-use 不注入 profiler runtime，因此没有该机制要求的固定常驻采样成本；内联/布局可能增减 `.text`、文件大小和驻留，必须报告实测全部代价。性能优先不等于用 CPU 或训练分数掩盖尾延迟退步。
