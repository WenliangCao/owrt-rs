# R141：R136 generic 基线上的单一 PGO 研究

R140 未通过独立实机主门（七负载 mean 比值几何均值的八窗中位变化 −0.47%，仅 5/8 窗降低），不采纳 A53 target。R141 的开发基线固定为原 generic R136 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`；不把 PGO 与换 CPU target 混为一项。

本页在构建前冻结范围：源码直接复用 `/home/ubuntu/r140/source-01/components`，与 R140 冻结清单的 30 个文件逐项相同；canonical 源码根保持 `/tmp/owrt-build/r135/r136-combined-01`。复用未修改的 R135 SDK recipe 与 R137 私有 mount/PID namespace helpers。Rust 1.98.1、LLVM 22.1.8、musl/GCC14.3/bfd、LTO/opt3、单 codegen unit、panic abort、strip/sstrip、路径映射和全部链接参数保持不变，不重建 std。

第一阶段同时构建两产物：原 recipe 控制必须逐字重现 `ce3d1aa…`；训练 ELF 仅在 RUSTFLAGS 末尾追加 `-Cprofile-generate=ABS_OWNED_DIR`。默认 profile 目录位于该次全新构建输出内，不使用宿主共享 `/tmp` 全局目录。工具只构建，不运行 daemon、不训练、不访问路由器。初次输出为 Oracle `/home/ubuntu/r141/build-generate-01`，下载对应本地 ignored `private/r141/build-generate-01/`。

训练由独立 runner 另行冻结和执行，使用 `LLVM_PROFILE_FILE=<绝对、该case独占目录>/default_%m_%p.profraw`，保留每个 case 的原始 profile。SIGTERM 必须沿当前 self-pipe/STOP 路径正常退出并实际落盘；非零退出、缺失/不可解析 profile 不重试掩盖。八类代表性范围、跨 N1/A53 边界、合并权重与最终常驻成本解释见 [已完成研究](R141_PGO_FEASIBILITY.md)，不把训练数据当性能结果。

第二阶段只有主线程提供已冻结 profdata 路径和 SHA 后才能执行。`build_pgo.py --stage use` 必须显式指定两者，再次精确重建控制；候选仅追加 `-Cprofile-use=ABS_PROFDATA`，另记录官方建议的 `-Cllvm-args=-pgo-warn-missing-function` 作为诊断选项。不得根据候选计时反复换训练权重或追加其他 flags。当前构建任务不执行 use 阶段。

两个阶段均在编译前冻结 source、原/生成 recipe、wrapper、namespace runner、研究计划、compiler/merger/runtime 身份和完整 flags；编译后核对 Cargo fingerprint 的有效 rustflags 恰好多冻结参数，以及源文件和 profile 输入未变。merger 固定为同 toolchain 安装的 `22.1.8-rust-1.98.1-stable`，SHA `c7160d195180796edf7cc4c3f087f72b5425fc9ec2d9734b956a265e506f982e`。不使用系统 profdata18。

profile-use ELF 自己的完整正确性、wire/FD/recovery 和独立实机对比另行冻结。Oracle 性能、CPU 改善或训练 profile 覆盖不能替代实机延迟门；R136 的旧尾延迟负项仍有效。全部 ELF 大小、CPU、驻留及延迟代价都需报告，生产保持 C，不授权部署。
