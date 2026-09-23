# R140 A53 单因子产物已建立

两次 Oracle 构建通过；**控制逐字重现 R136**，A53 候选已固定身份。尚无性能或采纳结论。

| 产物 | SHA-256 | 字节 |
| --- | --- | ---: |
| R136 control | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` | 514771 |
| A53 candidate | `d491a90b8c4c518648d7aa034acd64b0046ea6c2e6c46c19fda3229bf9285488` | 531155 |

候选增加 16,384 字节（约 3.18%），作为产物代价保留。两侧全部 30 个源码文件哈希一致；各自使用 R137 私有 mount/PID namespace，将源码映射到同一个 canonical 根。原 R135 recipe 未修改；生成的候选 recipe 只在 RUSTFLAGS 末尾增加 `-Ctarget-cpu=cortex-a53`。编译后 Cargo fingerprint 的有效 flags 也核对为仅多该参数。Rust 1.98.1、LLVM 22.1.8 与 target-cpus 支持检查通过；源码在各自构建前后未变。

本地原件与日志保留于 ignored `private/r140/build-01/`。全部下载 ELF、日志与 plan/result 哈希已经复核。冻结构建计划 SHA-256：`50a4b4433f68ca9af7690512720cae69d83a1ec3e9c4f0f9f7204195ef1e9503`；构建结果 SHA-256：`b058554b6f0365cdf305da17250e4a4c4c6cd7c25ffe3c3dc94b18c548572077`。

这一步只建立可审查的两种编译产物。候选自己的 SDK 单测、wire/FD/recovery 与后续实机比较另行报告，不能借用控制 ELF 的正确性或性能结论。研究边界与硬件能力依据见 [冻结研究计划](R140_A53_PLAN.md)。
