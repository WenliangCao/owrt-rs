# M6b 最终功能复验模式

输入 JSON 显式设置 `"validation_mode": "m6b"`，由 `m5_final_validation.py prepare` 产生新的冻结身份和命令表。省略该字段或设置 `m5` 仍是完整 M5 八阶段合同，不能通过输入 `phases` 缩减必需范围。

M6b 固定要求：`families → m2 → perf-guard → resources → pressure → package → lifecycle`。准备时仍要求完整 44 族与冻结源的 canonical registry 相等；源码/ELF/build/link map、镜像 C、原始运行输入、精确 SDK、APK payload/solver 依赖、source-bound deferred/safety reviews 和原体积预算门保持。fuzz 源文件仍在身份哈希里。

M6b 不新运行 `fuzz-build` 与 `fuzz`。这两项在 summary 中列为 `excluded-not-required`，`passed=null`，不写入完成表、不导入虚构 receipt，也不把 M5 旧 fuzz 证据说成新 ELF 通过。请求执行排除阶段会在建立 attempt 前拒绝。M5 默认仍要求三个实际 instrumented target 各 1800 秒，以及真实构建和完整证据。

package/lifecycle 的前置门从固定模式链计算；M6b 缺任何一项 families/M2/perf-guard/资源/压力都不能提前构建或进入生命周期。所有前置 receipt 仍须绑定同一 manifest/source/ELF，未执行不算通过。结果写 `summary.json` 和 `M6B_FUNCTIONAL_REPORT.draft.md`；这个控制器只声明功能资格，正式性能结论来自另一个冻结协议。

`perf-guard` 已接入 M6b 固定链，在 M2 后和 resources 前。输入必须给出 `perf_guard_plan`，三个阈值显式冻结且非空；native helper 的 manifest/ELF/源哈希与阈值 plan 一起绑定。门使用 feature-off 最终 ELF；无阈值、缺测、错答、线程/FD/清理异常不能通过。详细接口见 [M6B_PERF_GUARD.md](M6B_PERF_GUARD.md)。当前没有预填实测阈值，须由主线程依据最终候选数据冻结后再 prepare 新 manifest。

此变更只在本地工具分支验证。门测试覆盖 M5 缺省仍缺真实 fuzz、M6b 功能与性能保护门完成但排除项不是通过、必需资源失败不能被排除项豁免、非法/缩减模式拒绝、M6b 执行 fuzz 不创建输出、summary 明确排除；既有 family union、失败保留、fuzz 时长/退出/身份/超时、APK 身份/预算和归档门测试保持通过。
