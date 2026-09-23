# R141 PGO 训练产物已建立

原 generic 控制逐字重现 R136；训练 ELF 构建成功。两侧同一 30 文件源码清单、canonical 源码根和 SDK recipe，Cargo 有效 rustflags 仅多 `-Cprofile-generate=/home/ubuntu/r141/build-generate-01/profile-default`。

| 产物 | SHA-256 | 字节 |
| --- | --- | ---: |
| R136 control | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` | 514771 |
| profile-generate | `9452594e10f36ea2008382ea513525e5bdadfa7f32bf954031f1fca36a7451c9` | 826433 |

插桩产物增加 311,662 字节（约 60.54%）；这是仅用于训练的 ELF，不是最终 profile-use 候选大小。原始产物、生成 recipe、计划、日志与 namespace 记录在 ignored `private/r141/build-generate-01/`，下载文件已按结果哈希核对。冻结计划 SHA `f5c7c5b8ab5b77f3f6a43619dcee738e352b375707a0bbae42f587b6c71ae25b`，结果 SHA `eda5501674bc2190659c7649b2b7724e6f1e06ef11c8dfc2e926d442432b7181`。

训练 runner 应显式设置绝对、case 独占的 `LLVM_PROFILE_FILE`，覆盖上述本次输出内默认目录；能力 smoke 与正式八类训练分别留存，不能混合。当前仅完成构建：正常 SIGTERM 落盘、训练 profile、merge 和 use 阶段尚由各自后续证据确认。没有性能或部署结论，研究范围见 [冻结构建计划](R141_PGO_PLAN.md)。
