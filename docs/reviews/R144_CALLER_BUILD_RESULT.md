# R144 shared caller：精确控制复现与正确性通过

已在私有源码快照中完成一个请求回复借用候选。原 caller 精确重现 `85dd537…`；候选与控制等大，共享库完整单测通过。没有执行性能采集，不能据此声称端到端收益或 daemon 改善。

| 产物 | SHA-256 | 字节 | 共享库单测 |
| --- | --- | ---: | ---: |
| 历史 caller 控制 | `85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d` | 720968 | 46/46 |
| 回复借用 caller | `7adea8683e2ccd726ea918c700fec595fc77200c3f5c2cfc59bb1abc27b1d9ca` | 720968 | 49/49 |

两侧均有 0 failed/ignored/filtered，doc-tests 均为 0。release 与独立 test ELF 的 Cargo fingerprint 已核对完整有效 RUSTFLAGS；两 caller 的源码规范路径、Rust1.98.1、LLVM22.1.8、SDK、release profile 和 flags 一致。共享库 test 使用相同 target/flags、opt3/LTO/单 codegen-unit，测试 panic 行为仍由 Rust test harness 决定。

18 个源文件唯一差异为 `components/ubus/src/conn.rs`，包含局部运行时变更和三个新增单测。原 SHA `3b8a0df7a5c6c3e87655803fd2a308f410037e61d30101dfa1d277e5f72d6c7b`；候选 SHA `f76a1972d7ca8a60259845b9e65f296ffe4dfe87209f922c2e9c863c0bdb7d8a`。正式主树保持原 SHA。生成器与回归提交 `a6bd9a4`，方案见 [冻结计划](R144_CALLER_PLAN.md)。

候选直接借用匹配 DATA/STATUS 的 body，去掉小回复的中间 Message Vec；最终 Reply 仍拥有 DATA，Owned 大帧保留原复制成本。新增真实 socket 回归验证了：DATA FD 在等待 STATUS 前关闭；STATUS FD 包括非零状态仍移交；旧 pending 不被新请求消费；错 peer、异步 INVOKE 和匹配异类帧保持拥有与 FIFO；重复 STATUS 最后项覆盖，包括非法最后项、短字段和有符号状态；大帧后小帧不会覆盖旧数据；完整 DATA 后超时保留连接，迟到 STATUS 不混进下一次回复。原有部分帧超时、背压、FD 清理和缓冲边界测试也全部通过，另有独立只读分支审阅，未发现阻断。

私有证据位于 `private/r144/control-rebuild-02/`、`candidate-build-01/`，包含 plan/result、原始构建和测试日志、生成 recipe、namespace/Cargo fingerprints、caller 与 test ELF；`artifacts/unit-proof.json` 另绑定真实 test fingerprint 与 test ELF。下载后核对全部身份。主机路径与 namespace 细节只在私有记录内。

| 证据 | 控制 SHA-256 | 候选 SHA-256 |
| --- | --- | --- |
| 构建计划 | `641492f7fdabbbafb5b5cbb252d6f92c1f1f9ff621337870f5ad7e8bcdeee832` | `8dcf510cc2135a063343d7380aecc7808a10ea442c2f366f17eab68eaa955c2d` |
| 构建结果 | `4cbfa22d2aab88710a02a7adec2ed5c1fb8671df26c2dc4111efd3ff356102d0` | `70995d93a883f84109acd14f1a0b588414b50c8a387f630b54f8d75089a7ebbf` |
| 测试日志 | `479220043d4c3414bf0ce2893315f9f798c6778f0da9caa098cec8d503e769b7` | `3eb2902f47e401cf9337ed43b449e7f4ec038d17932ca6f32edcdc25cd306eda` |

初次控制的 release 与 46 项测试已成功，但 namespace 元数据脚本的换行转义错误导致收尾失败；记录保留于 `control-rebuild-01`。修正工具后在新目录完整重建，仍精确复现相同 caller；没有改源或选择性能结果。两侧原始日志都保留了旧 benchmark 的 unused-import 警告和 SDK preload ignored 消息。

下一阶段只可按另冻计划比较同一 daemon 下的新/旧 caller，provider 固定旧 caller。daemon 保持精确 C/R136，原 caller 下的旧尾延迟负项继续有效。本报告不授权路由器操作或部署。
