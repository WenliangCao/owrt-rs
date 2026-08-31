# 决策 0002：含点文件名合同按 UCI tuple 解析结果收窄

> 日期：2026-08-31
> 状态：已定
> 阶段：R1 进入审查

## 背景

C1-01 最初把 Q15 的设备事实“7 个含点文件对应 7 条空基线”写成了通则：
“文件名含点号者，基线条目必为空”。这个通则比证据更宽。

精确 UCI revision `66127cd7` 的 `cli.c:package_cmd()` 先调用
`uci_lookup_ptr(ctx, &ptr, tuple, true)`。`CMD_SHOW` 只有在 lookup 不完整时返回
`UCI_ERR_NOTFOUND`；若 tuple 指向已有 section 或 option，则分别调用
`uci_show_section()` 或 `uci_show_option()`，输出非空内容。

## 决策

合同 C-03 收窄为：

- 本设备观察到的 7 个含点文件名所对应的 tuple 均无法解析，因此产出空条目；
- 只要对应 tuple 继续不存在，修改这些备份文件自身不会改变规范化结果；
- 含点号本身不是判据。替换实现必须服从真实 `uci show <name>` 的结果。

新增 SRC-only 用例 `c11-dotted-name-can-resolve-section`，证明一个可解析的
`package.section` 会产出非空条目。R1 精确 rootfs oracle 也执行并通过该反例。

## 后果

- 不允许 Rust 实现使用 `filename.contains('.')` 直接生成空条目；
- 当前 7 个空条目的兼容行为仍必须保留；
- C1 的设备结论不变，改变的只是从单一配置向所有含点文件名的错误外推；
- 这是合同勘误，不是扩大 R05 职责。
