# R140：仅将 ubusd 的编译目标改为 Cortex-A53

本研究只比较 R136 原构建与追加 `-Ctarget-cpu=cortex-a53` 的候选。运行时代码、Cargo profile、Rust 1.98.1/LLVM 22.1.8、SDK musl/GCC14.3/bfd、链接参数、strip/sstrip、标准库均保持既有 recipe；不引入 PGO、BOLT 或其他 flag。固定源码根 `/tmp/owrt-build/r135/r136-combined-01`，复用未修改的 R137 mount/PID namespace builder，两侧同一源码快照。控制必须逐字重建为 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`，否则停止。

0017 的 target-cpu 否决仅来自 UCI 的短进程测试，其六包不含 ubusd。ubusd 从创建起使用 opt3/LTO；代码历史没有该组件的 A53、PGO 或 BOLT 对照。R107 的 codegen 实验是 const 泛型专门化，不是 CPU 编译目标实验。

机制依据是匹配 [LLVM 22.1.8 的 processor 定义](https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-22.1.8/llvm/lib/Target/AArch64/AArch64Processors.td)：generic 使用 CortexA510Model，cortex-a53 使用 CortexA53Model，并具有不同的调度/指令成本选项；[A53 模型](https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-22.1.8/llvm/lib/Target/AArch64/AArch64SchedA53.td)明确描述顺序执行、双发射及 load/branch 成本。这里预测可能改变本组件生成代码，不预测收益方向，也不宣称其能解决内核主导的慢尾。

硬件依据为既有 `private/r136/completion-01/matrix/01-stock/raw/cpuinfo.txt`：两核 CPU part 均为 `0xd03`，均含 fp/asimd/aes/pmull/sha1/sha2/crc32。构建器在运行前核对这份存档，并冻结其哈希；不重新访问路由器。A53 目标启用的 CRC/AES/SHA 能力在该证据内。精确 [Rust target](https://raw.githubusercontent.com/rust-lang/rust/48a229ceaefd4985c50990b14116b6d856af0985/compiler/rustc_target/src/spec/targets/aarch64_unknown_linux_musl.rs)已有 A53 843419 linker mitigation，此项保持不变。

构建前冻结全部 source-file、原/生成 recipe、wrapper、namespace runner、研究计划与 CPU 证据哈希。生成 recipe 与原 recipe 只允许一行 RUSTFLAGS 多一个末尾参数。编译后还核对 Cargo fingerprint 的有效 rustflags 恰好多该参数，并保存两个完整 ELF、大小、日志、namespace 与源文件未变证明。本地结果目标 `private/r140/build-01/`；构建只在 Oracle，禁止改既有 R135/R137 冻结工具。

候选 ELF 身份固定后，先通过对应 SDK/release/A53 flags 的 55 项单测，以及该 ELF 自己的 wire、FD 和限定 ubusd recovery。原有手工 FD 契约差异继续保留。Oracle 的 Neoverse 性能排名不作晋级或否决门；不做 Oracle wall 性能筛选。

下一阶段由主线程另行冻结实机计划：精确 C、R136、新 A53 ELF 三方，覆盖既定七条负载（五条 Rust caller 注册/对象事件、原生 libubus 注册、直接 SEND）并同时报告 mean/p50/p95/p99、daemon/caller CPU 及全部代价。主项与独立配对规则必须在采集前固定；当前文档不授权从任何单个探索胜项晋级，也不撤销 R136 的四项既有尾延迟负项。新 ELF 不部署，生产保持 C；实机仅由主线程在既有恢复/健康/清理门内运行。
