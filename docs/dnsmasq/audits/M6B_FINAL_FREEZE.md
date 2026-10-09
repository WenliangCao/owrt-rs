# M6b 最终产品冻结

2026-10-09。从 main `284376c484cf0d3d5d0b2a1d6e3fb9325cc0ec28`
的精确 Git PAX archive 构建；A 产品提交为 `f2a59167`。两产品使用同一源码、
精确 SDK、共享 Cargo target 和 `oracle_build.sh` 锁内复制，均关闭 diagnostics，
保留各自实际 build receipt 与 link map。

| 产品 | 字节 | SHA256 |
| --- | ---: | --- |
| 最终 opt3 | 1,962,024 | `e53fbdcb7cb29e0ac0d2d5bcfaa9c5f284849af2114f8d37720bb644485c6c79` |
| 同源 s | 1,642,536 | `6cb5bcbe3ea2677e4e898a94e90f5407611bbdd0591d44a183344c36d519d09c` |
| 精确镜像 C | 283,464 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |

opt3 为最终功能、资源与 APK 对象；s 仅为正式性能对照。
此处只关闭构建与身份冻结，不授予功能或性能资格。
冻结后产品代码不再修改；任何新产品缺陷均保留证据并停止，交由用户决定。
工具修订与产品身份分开记录。

证据根为 `private/dnsmasq-rewrite/evidence/M6B/final-284376c4/`：
`source.tar`、`product-freeze.json`、`release-opt3/`、`release-s/` 和
`preflight/`。源码 archive 与全部产品/包输入逐 SHA 对照；ELF、大小、
feature、opt level、build receipt 与 link map 均经本地回拷核验。
原始 ELF 与构建日志仅保存在 private。

oracle 构建前完整进程观察未发现其他任务会话；常驻用户服务保持运行。
物理路由器未访问。
