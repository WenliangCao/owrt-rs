# R142 monitor 候选：构建与 56 项 SDK 单测通过

按 [冻结设计](R142_MONITOR_PLAN.md) 构建了一项独立 monitor 候选，控制精确重现 R136。源码、注释和新增回归均保持 `source-01` 冻结内容；主运行时未修改。

| 产物 | SHA-256 | 字节 |
| --- | --- | ---: |
| generic R136 control | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` | 514771 |
| monitor candidate | `367badc11fb93b25208cda041048133b8439e1c703c2cb07d740312cc140db54` | 514771 |

两侧均为冻结的 30 个文件，唯一差异是 `ubusd/src/server.rs`：控制 SHA `438ba02dc9180b1fd52d55ce965217856862666922bae7968c2dd3d536e33805`，候选 SHA `5a1f0969a0ea11e4364ca1284747803dc4481fdab70788412a2018f969940aad`。保留原 R135 recipe、R137 私有 namespace、canonical 路径 `/tmp/owrt-build/r135/r136-combined-01` 和 pinned Rust 1.98.1。两侧 Cargo fingerprint 的有效 rustflags 完全相同，均为原 generic 配置，没有 PGO 或 A53 override。

构建原始记录位于 Oracle `/home/ubuntu/r142/build-01/` 和已逐项核验的本地 ignored `private/r142/build-01/`。冻结计划 SHA `1d2872cd1d3a943a766891a659ec498f7bb96eb1040af40d43229004ef388721`；结果 SHA `b51b71c76e850cd276f76d0e59c3e03803b90565a3beae0e6f22f6ac6f3e0777`，`passed:true`。ELF 等大不代表运行时 retained capacity 或 RSS 等同。

56 项 SDK 单测全部通过，0 failed/ignored/filtered。新增真实多 monitor 回归通过：重复 add 后按注册顺序遍历，两项独立序号含 u16 回绕，一名 monitor 直写、另一名阻塞排队；连续大小不同的 PING 重用 scratch，最后逐字节核对慢队列、所有镜像和 touched 顺序。单测使用独立 test ELF，并非部署 ELF；canonical 路径和完整有效 rustflags 与 release 候选一致。

单测证据在 `/home/ubuntu/r142/units-01/`，本地 `private/r142/units-01/`；父目录保留 `units-plan-01.json`、命令、退出码和总日志，`unit-scripts-01/` 保留实际 recipe、namespace wrapper 和 runner。计划 SHA `4c7a08990d7128b2995df7577dfc4e256ee8697eb4f50fc5f9ccfa71e87c6db1`；结果 SHA `54599fdcdde51cd44536a2c01946f6feda5f2f9bfd99525c8c64b95fb3447135`；测试日志 SHA `80bb72d26d7d83341fce444dabc879ab9a22a581bb56b3a9e2d9bdf1265c07a8`。源码、脚本和 release ELF 前后身份均未变。

导入记录：首次 macOS tar 自动附带 AppleDouble 元数据，产生 66 文件清单，不满足冻结的 30 文件要求，因此未采用其 source proof。该次目录保留为 `source-01-metadata-import` / `build-01-metadata-import`；随后使用 Python tarfile 仅归档冻结的 62 个实际文件（两侧各 30 加 manifest/diff），在正式 `build-01` 重建。两次 release ELF 身份相同，没有改源码或选择性能结果。

本报告只确认构建和单测。精确 release 已交给独立协议/FD/恢复/monitor 功能门，性能与大消息后常驻内存仍需各自证据。本次未运行性能或访问路由器；不改变旧注册尾延迟失败，不授权部署。
