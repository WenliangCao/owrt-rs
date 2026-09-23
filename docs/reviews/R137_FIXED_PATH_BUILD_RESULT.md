# R137 固定路径并行构建结果

**两份独立输入快照并行重建，均逐字得到 R136 已测 ELF。** 这是消除构建路径引发的实验混杂，不是性能改进；没有重开候选筛选。

[新 wrapper](../../tools/r137/README.md) 在各自 Linux mount namespace 内把私有空目录映射到 `/tmp/owrt-build/r135`，再由冻结的 R135 脚本创建相同源码根 `/tmp/owrt-build/r135/r136-combined-01`。宿主原目录只在子 namespace 内被隐藏。两路 Cargo 都以 `ubuntu`（UID 1001）在 `/home/ubuntu` 运行，使用独立、全新 output／target；工具链、profile、路径映射、链接参数和 `sstrip -z` 均保持原值。

输入分别复制到 `inputs-01/control-a/components` 与 `inputs-01/control-b/components`；两份各 30 个文件的 SHA-256 都与 [R136 记录](r136-build-identity-results.json) 的主线 `195e45f` 一致。构建前 `frozen-plan.json` 已冻结输入哈希、预期 ELF、wrapper 与原 builder 的哈希。

| 构建 | mount namespace | release SHA-256 |
|---|---|---|
| control-a | `4026533253` | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` |
| control-b | `4026533255` | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` |

两路构建时间区间重叠；两个 ELF 的 `cmp` 返回 0，大小均为 514771 字节。`sstrip` 前也均为 `8d86a8dc876cab195089b4b369408b72c712f3cd13d79bc085ceb014e75c0528`。`owrt_ubus` Cargo fingerprint 完全相同，路径 fingerprint 均为原始控制值 `5879673876014263723`。

宿主原 canonical 树的全部 37 个目录／文件条目，构建前后内容哈希、inode、mode、size、mtime 与 ctime 都未变。输入哈希复检通过；两个临时源码目录已自动移除，两个子 mount namespace 已消失，宿主没有残留挂载。冻结 R135／R136 脚本和原实测产物均未覆盖，也没有访问路由器或修改运行时代码。

本地语法及输入 guard 检查通过，包括重复 label、源码 symlink、会被挂载隐藏的路径及已有证据覆写拒绝。原 SDK 的 `runas.so` preload warning 仍保留于日志；没有为消除 warning 改构建环境，最终产物身份精确一致。

[派生结果与证据哈希](r137-fixed-path-build-results.json)；原始计划、日志和宿主前后状态位于 `private/r137/fixed-build-01/`。实现先提交为 `404d623`，本报告单独记录运行结果。
