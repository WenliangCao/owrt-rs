# FIX6：构建、输入身份与普通测试

冻结产品为 `3335a978c38b60faa348058ee22ee9a1a848f961`，增量基线 `2113d540b7ed7398446aa8184d2434c18f935940`，main `be531cee49e366bb5044443d473944dbea45b87e`。本工作域没有发现新增构建、普通测试或启动保护阻断；F2 和终点回答语义由同轮精确 C 报文对照裁定，不能用单测通过代替。

## 身份与构建

使用完整冻结 `git archive` 在新 Oracle `source` 目录解包，未修改该源码。本轮在执行构建前确认 `source`、`private/release` 和 `private/tests` 不存在；创建和构建均使用新路径。178 项产品/依赖/配方输入由 `build_package.inputs()` 独立枚举，与 Git blob、工作区和 Oracle 源码逐项一致，摘要 **`8e56e6742cbeb3d19df5ef51547a082da1503871fa6d3f1c2ddba3b1212130e5`**。归档、构建脚本、隔离脚本、镜像准备工具、保护探针及测试驱动另有 SHA 收据。[当前输入](local-input-identity.json)、[归档](archive.json)、[执行及工具身份](invocations.json)

| 角色 | 实际 ELF SHA-256 | 字节 |
| --- | --- | ---: |
| 精确镜像 C，2.93-r1 / nodhcpv6 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 269,305 |
| 保留 main release | `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863` | 1,970,216 |
| FIX5 / F2 修复前 release | `7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c` | 2,056,672 |
| FIX6 fresh release | `a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66` | 2,056,672 |

全部 SHA 对 Oracle 实际文件重新计算。保留 main 的 172 项输入逐项匹配 main Git；保留 FIX5 源码的 178 项输入逐项匹配本轮 `2113d540` 基线 Git（报告提交没有改变产品输入）。两组摘要分别为 `b1d2bed48938c8393ce828e10a39583b93711b5915de2adb09b136138266a560` 和 `547bbd55bda3b13ec75c42b24e71f18b97f7fea35cd30ca27552fe5bfa1cd231`。[保留输入清单](retained-input-identity.json)、[实际核验结果](result.json)

匹配 OpenWrt patches 的参考源码位于 `/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93`，148 文件全部重新按其保留身份清单核验，recipe revision 为 `f0a60eee2fe051741c643ea6118718aae1ef17fb`；`src/rfc1035.c` SHA 为 `231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`。语义对照运行的是精确镜像 C，并未以宿主重新编译的 C 替代。

新 release 经自身 `oracle_build.sh` 的共享 `flock`、包级 clean、Cargo fresh build 和锁内复制产生，Rust **1.98.1**、AArch64 musl、opt3、feature-off、static PIE；位于 `/home/ubuntu/dnsmasq-audit-fix6-20261014/private/release/dnsmasq-rs`。[构建 manifest](release-build.json)

## 本轮 fresh 验证

- 普通 test-profile fresh 构建成功，**779 lib + 77 bin = 856 pass，0 fail，23 ignored 未运行**。两个测试 ELF 分别在独立 network/mount/PID namespace 内串行执行，各自挂载 tmpfs `/tmp` 和独立 `TMPDIR`。结果包括实际 argv、测试 ELF SHA、日志 SHA、耗时和测试总结。[结果](result.json)
- 本地 **20 个包工具测试全部通过**，覆盖既有构建/冻结身份/recipe/static PIE wrapper/package metadata 门限；这不等于本轮真实 APK 构建或 procd 生命周期验证。[结果](package-tests.json)
- 当前 release 和精确 C 各 fresh 启动 3 次：实际 `/proc/PID/exe` SHA 正确，UDP/TCP 查询回答相同、正常退出。Rust **11 页 RELRO 全只读、3 个 ASLR 基址不同、无 WX 映射、stack 为 `rw-p`**。[实际保护与查询结果](relro.json)
- 普通测试结束后再次核验 Oracle 178 项输入，下载收据后再次核验本地 178 项输入、冻结 HEAD 和 main ref，全部不变。其他任务的 namespace 与输出目录互相独立。

本轮首次本地预检采用系统 `python3`，因其没有 `tomllib` 而在导入包工具时终止，尚未产生归档或开始编译；换用 Python 3.14.8 后通过。该预检失败未被当作产品测试失败，也未覆盖任何已有输出。

## 复跑与范围

在新的 Oracle 根目录放入冻结源码及本目录两份输入清单、`verify_and_test.py` 后执行：

```sh
sh "$ROOT/source/tools/dnsmasq/oracle_build.sh" \
  "$ROOT/source" "$ROOT/private/release" release
python3 "$ROOT/private/verify_and_test.py" "$ROOT" \
  "$ROOT/private/local-input-identity.json" \
  "$ROOT/private/retained-input-identity.json"
sudo -n sh "$ROOT/source/tools/dnsmasq/run_isolated.sh" python3 \
  "$ROOT/source/docs/dnsmasq/audits/20261011/independent/build_protections_probe.py" \
  "$ROOT/source" "$ROOT/private/release/dnsmasq-rs" "$ROOT/private/build-relro" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --require-relro
```

本次 `ROOT=/home/ubuntu/dnsmasq-audit-fix6-20261014`。保留 main/FIX5 的路径和 SHA 由驱动固定检查；若迁移保存位置需相应更新路径并保留同样的身份核验。输出必须全新，脚本不会覆盖既有构建或验证结果。

本轮只完成 fresh SDK-linker Cargo release/test-profile 构建，**未 fresh 完整 SDK prepare/strip/APK 打包**，未声称产生包含修复的 APK；也未运行 23 个 ignored、长期 fuzz/soak、OOM/allocator/mprotect fault、其他页大小或路由器部署。main/C 及当前的普通构建配置并非完全同构，保留 main 仅用于语义归属；不能仅凭不同配置 ELF 大小作体积回归结论。没有修改产品代码、参考树、物理路由器或推送；镜像、ELF、完整日志和 overlay 留在 Oracle private。

## 追加独立语义审查

构建验证完成后，主审要求独立复核另一审查者发现的 14-bit owner 边界。已用新 decoder 和独立 fresh 运行确认普通 TXT + MX 配置下的新增 TCP EOF 回归，详情见 [第二名审查者说明](new-boundary-independent.md)。本页构建、单测和启动保护通过不构成对此语义阻断的豁免。
