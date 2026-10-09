# Native APK 验证器修正

2026-10-09。在准备 r3 离线验收时，复核到 r2 源码仍带着一次已在
2026-09-29 私有验收中发现的假绿检查。旧 `native_image_check.py` 使用
`apk fix --reinstall`；实际日志包含八次 `APK unavailable, skipped`，命令仍
返回成功。随后核对既存 ELF 和文件所有权，只能证明原文件没有改变，不能
证明重装发生。历史 `final-offline-evidence-02.json` 已明确废弃旧重装结果，
但当时修正仅保存在 `native_image_check-final-02.py`。

本轮把该脚本的重装修正纳入仓库：使用显式本地 APK 的
`add --force-reinstall`，先删除八个原包的文件清单，再要求逐字节恢复；
原生包重装前删除 C 救援 procd，要求重新出现且 SHA-256 匹配。九个 Rust
文件身份、全部 C 救援身份和归属检查继续执行。只修改验证工具。

在 Linux aarch64 构建机上，用正式 r2 镜像副本执行
`native_package_reinstall_selftest.py ROOTFS APK_DIR NEW_OUTPUT`：真实原包和
原生包重装均通过；原包重装替换为成功空操作四次，原生包重装替换为成功
空操作四次，八次均被拒绝。负控确认被删文件仍缺失、目标成功标记未写入；
正控确认八份清单的完整字节和 C 救援 procd 的哈希实际恢复。没有访问路由器。

[脱敏验证记录](HEALTH_20261008_NATIVE_PACKAGE_VALIDATION.json)保存镜像、工具、
历史及本轮日志 SHA-256，以及八次负控结果。APK 素材是从固定官方镜像重建的
未签名载荷，只验证 `--no-scripts` 文件归属与重装，不代表验证原包签名或
生命周期脚本。r3 正式产物仍需另跑完整离线验收。
