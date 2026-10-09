# M6b 最终产品冻结

## 修复后的有效冻结（2026-10-09）

最终源码为 `889fe4f5c59da514529e31173d346ec93bae03a9`。UDP 修复 `3492bbde`
共用原 admit 名字规则；TFTP 修复 `8bd80024` 只复用共享 owner 现有
接口 collector 与完成续步，`889fe4f5` 修正其新测试夹具字节转义。
授权的 1 小时时间窗从 17:52:45 UTC 开始，18:05:52 UTC 已完成
Linux 实际 caller 与精确镜像 C rename 配对；没有触发止损回退。

| 产品 | 字节 | SHA256 |
| --- | ---: | --- |
| 最终 feature-off opt3 | 1,966,120 | `791a7c33987fbb21887c51041f27722b9cc1bd8bd4cffab0fc03a292517fb10f` |
| 同源 feature-off s | 1,642,536 | `d8d3c1ea2ed0a3c29ab260aea21534e6c326a371342a15442a540d62cd3539dc` |
| 精确镜像 C | 269,305 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |

源码 archive、172 项产品/包输入、157 项编译输入、两 build receipt、
link map 和实际 ELF 已逐 SHA 回拷核验，证据在
`E/M6B/final-889fe4f5/`。原 `284376c4` 与其失败保留原身份；
旧 13 步结果不导入新资格，44 族/68 步及169选项从第1步完整重跑。

Linux musl main 74、库753、新 TFTP main caller 3、既有 TFTP socket 3
实际通过；默认20 ignored仍未计作通过。TFTP配对改名前正确、改名后两侧
均拒绝、两側清理退出0。源码测试与这项修复配对不替代最终统一验收。

产品自此再次冻结；后续发现新产品缺陷先停并告知用户，不边测边改。
main 后续文档/工具提交不改本次源码/ELF身份；无关 health 合入仍按历史注明。

## 首次冻结及保留的失败身份


2026-10-09。从 main `284376c484cf0d3d5d0b2a1d6e3fb9325cc0ec28`
的精确 Git PAX archive 构建；A 产品提交为 `f2a59167`。两产品使用同一源码、
精确 SDK、共享 Cargo target 和 `oracle_build.sh` 锁内复制，均关闭 diagnostics，
保留各自实际 build receipt 与 link map。

| 产品 | 字节 | SHA256 |
| --- | ---: | --- |
| 最终 opt3 | 1,962,024 | `e53fbdcb7cb29e0ac0d2d5bcfaa9c5f284849af2114f8d37720bb644485c6c79` |
| 同源 s | 1,642,536 | `6cb5bcbe3ea2677e4e898a94e90f5407611bbdd0591d44a183344c36d519d09c` |
| 精确镜像 C | 269,305 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |

opt3 为最终功能、资源与 APK 对象；s 仅为正式性能对照。
此处只关闭构建与身份冻结，不授予功能或性能资格。
冻结后产品代码不再修改；任何新产品缺陷均保留证据并停止，交由用户决定。
工具修订与产品身份分开记录。
main 随后合入无关的 health r3 热修复 `16ac3cea`，未改变 dnsmasq
源码或构建输入；本轮仍绑定冻结时的 `284376c4`，没有因此重建产品。

证据根为 `private/dnsmasq-rewrite/evidence/M6B/final-284376c4/`：
`source.tar`、`product-freeze.json`、`release-opt3/`、`release-s/` 和
`preflight/`。源码 archive 与全部产品/包输入逐 SHA 对照；ELF、大小、
feature、opt level、build receipt 与 link map 均经本地回拷核验。
原始 ELF 与构建日志仅保存在 private。

oracle 构建前完整进程观察未发现其他任务会话；常驻用户服务保持运行。
物理路由器未访问。
