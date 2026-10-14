# FIX5：构建、身份与普通测试

审计对象为 `5b914d32891a5166f8075d108fc98610abc1f885`，main 为 `be531cee49e366bb5044443d473944dbea45b87e`。本工作域没有发现 `d9565f46..5b914d32` 新增的构建、普通单测或启动保护阻断；F1 回答语义由同轮实际报文对照裁定。

## 输入与程序身份

[local-input-identity.json](local-input-identity.json) 按包工具的输入范围独立枚举了 178 项产品、依赖和配方文件，每项工作区 SHA 与冻结 Git blob 一致。Oracle `git archive` 源码在构建前后逐项一致，摘要为 `547bbd55bda3b13ec75c42b24e71f18b97f7fea35cd30ca27552fe5bfa1cd231`。[现场核验](result.json)

| 角色 | SHA-256 | 字节 |
| --- | --- | ---: |
| 精确镜像 C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 269,305 |
| 保留 main release | `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863` | 1,970,216 |
| F1 修复前、FIX4 所测 SDK ELF | `55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca` | 2,054,939 |
| 本轮 fresh release | `7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c` | 2,056,672 |

以上均在 Oracle 对实际文件重新计算 SHA。新 release 是当前源码通过固定 SDK linker 生成的 Cargo release，**不是再次完成完整 SDK prepare/compile/strip/APK 打包的产物**，不能将它与旧 SDK ELF 大小直接用作代码体积差分。[release manifest](release-build.json) 与 [result.json](result.json) 分开绑定了 release、test-profile 和保留程序身份。

同时复算匹配 OpenWrt patches 后参考源码的 148 个文件，全部符合保留 `identity.json`；recipe revision 为 `f0a60eee2fe051741c643ea6118718aae1ef17fb`，其中 `rfc1035.c` SHA 为 `231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`。正确参考目录为 `/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93`。首次身份预检误选了 `owrt-evidence/.../sources/components/dnsmasq` 的上游树，SHA 检查立即终止，尚未开始测试；改为已匹配 patches 的参考目录后通过。没有重新编译 C 来替代镜像程序，也没有修改任一参考目录。

## fresh 验证

- 固定 Rust 1.98.1、AArch64 musl、opt3、feature-off release 构建成功。`oracle_build.sh` 在共享 `flock` 下清理该包缓存、编译并复制不可变输出；实际 release 位于 `/home/ubuntu/dnsmasq-audit-fix5-20261014/private/release/dnsmasq-rs`。
- fresh 普通 test-profile 构建成功；**778 lib + 77 bin = 855 通过，0 失败，23 ignored 未运行**。两个测试 ELF 分别在独立 network/mount/PID namespace 内串行执行，各自挂载 tmpfs `/tmp` 并创建独立 `TMPDIR`，避免 PID namespace 重复 PID 与宿主 FIFO 残留冲突。执行 argv、耗时、日志 SHA 与测试 ELF SHA 全部记录在 [result.json](result.json)。
- 本地重新运行 [20 个包工具测试](package-tests.json)，全部通过；范围包括 Make compiler 查找、static PIE wrapper、产物身份和包 metadata 门限，不等于实际 APK/procd 生命周期验证。
- 新 release 与精确镜像 C 各 fresh 启动 3 次：实际 `/proc/PID/exe` SHA 正确，UDP/TCP A 回答相同，进程正常退出。Rust 的 **11 页 RELRO 全部只读**，三个 ASLR 基址不同，没有 WX 映射，stack 为 `rw-p`。[完整运行时结果](relro.json)

本增量没有修改 package recipe、linker wrapper、`startup_relro.rs` 或 `oracle_build.sh`。以上是当前实际 ELF 的启动与构建验证，不能外推到其他页大小、不同工具链或完整部署环境。

## 复现与范围

使用新的 Oracle 根目录，放入冻结 Git archive 的 `source` 和本目录的输入清单。先运行：

```sh
sh "$ROOT/source/tools/dnsmasq/oracle_build.sh" \
  "$ROOT/source" "$ROOT/private/release" release
python3 verify_and_test.py "$ROOT" local-input-identity.json
sudo -n sh "$ROOT/source/tools/dnsmasq/run_isolated.sh" python3 \
  "$ROOT/source/docs/dnsmasq/audits/20261011/independent/build_protections_probe.py" \
  "$ROOT/source" "$ROOT/private/release/dnsmasq-rs" "$ROOT/private/build-relro" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --require-relro
```

本次 `ROOT=/home/ubuntu/dnsmasq-audit-fix5-20261014`。原始构建日志、单测输出、ELF、参考文件及 rootfs overlay 留在 private，Git 只收录驱动和派生记录。单测与其他隔离功能探针可并行，本轮没有性能计时任务。

未重跑完整 SDK 打包、23 个 ignored 测试、长时 fuzz/soak、allocator/mprotect fault、其他页大小或物理路由器部署。FIX4 既有 ELF/APK 预算问题不因本次 Cargo release 成功而消失；本页也不沿用旧 APK 身份来声称 F1 修复已被打入 APK。

## 补充：修复前的同构建配置对照

后续终点审计发现新的 raw CNAME 组合反例。为排除旧 SDK strip 与当前 Cargo release 的构建差异，将 `d9565f462ebc9e9616b00fe72f7d6ceeb9003beb` 完整 `git archive` 到独立 `source-before`，用其自身 `oracle_build.sh` fresh 构建 `private/release-before`，没有复用旧二进制。

修复前 178 项 Git 输入与 Oracle `source-before`、保留 `source-final`、两份原 SDK manifest 的 `source_files` 逐项相同，摘要仍为 `aeab077f18f7ffbeed216372d9a27da8d6c291628e62bcc17017c46daf7f05a1`；构建后再次验证源码未变。两份 SDK manifest 均为源码构建、`frozen_elf=false`，其实际 ELF 也重新核对 SHA。[完整输入、命令与身份记录](before-identity.json)

修复前 fresh release 为 `/home/ubuntu/dnsmasq-audit-fix5-20261014/private/release-before/dnsmasq-rs`，**2,056,672 B**，SHA-256 **`45375655c62112c6d99fd1f46034352f1b37350fa92c38b0ccd8fcbdff301827`**。它与当前 fresh release 都是 release、opt3、feature-off；将各自源码根路径归一化后，完整 `RUSTFLAGS` 相同；`oracle_build.sh` 和 static PIE linker wrapper 字节相同。因此主审可直接用这两份程序重跑新增反例，避免以 SDK strip 差异解释产品行为。这里确认构建配置和来源，不声称不同源码路径下的产物能够逐字复现。

复现构建命令：

```sh
sh "$ROOT/source-before/tools/dnsmasq/oracle_build.sh" \
  "$ROOT/source-before" "$ROOT/private/release-before" release
```

该补充没有重跑修复前普通单测，也没有执行 SDK 打包。新增反例的实际三方/四方报文结论见同轮终点审计；本页前述构建和普通单测通过不构成对此类语义反例的豁免。
