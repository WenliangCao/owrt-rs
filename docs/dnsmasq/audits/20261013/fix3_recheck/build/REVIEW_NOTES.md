# HEAD 构建与保留证据复审

本次对象 `74c6b4531111819439e38881ff9be7dc025d57ca`，修复前比较点 `5e20291d`，main 仍为 `be531cee49e366bb5044443d473944dbea45b87e`。仅审计、构建和保存派生证据；没有修改产品代码、推送或接触物理路由器。

## 输入身份

按 `build_package.inputs` 的完整范围重新枚举 HEAD Git 文件，得到 **177 项**产品/配方/打包输入。逐项与当前工作区、`fix3_repairs/build/types-identity.json` 及其 `types-summary.json` 比较，均完全相同；缺失、额外、hash 不匹配均为空。总摘要：

`f6271f17755ff32cedbca5baaa822fbc356e9e1fa4491c485503006af9bf4ab1`

旧证据标记的源码提交 `ceea2ec6eb5eeee8e61e3da1c97aeb38aaf999b3`、产品点 `f47220306d09a480376aa667bb66eb51d002c8be` 与本次 HEAD 的这 177 项相同。旧证据的 Git witness 停在更早的 `c7568ceb`，本轮的逐文件 HEAD 比对补足了这一后续提交链，未直接信任旧 witness 的 HEAD 名称。见 [head-input-identity.json](head-input-identity.json)。

`5e20291d..HEAD` 未修改 `oracle_build.sh`、OpenWrt Makefile / static-PIE wrapper、`build_package.py`、Cargo.toml / lockfile、`rust-toolchain.toml` 或 `startup_relro.rs`。因此没有发现这轮修复新增的构建方式或链接保护变化。

## 本轮 fresh 构建与执行

新隔离目录 `/home/ubuntu/dnsmasq-fix3-recheck-20261013` 的精确 HEAD 源码在构建前后均与上述 177 项一致。串行执行官方 Oracle helper 的 release、tests 构建；两个构建退出 0。

- Fresh release：**2,056,672 B**，SHA256 `25b7291d0074b8c7a854aa9f63f7b5edb12bc1315e60dd26f8f6eed36d362fd8`。
- 新测试二进制：**769 lib + 77 bin = 846 通过，0 失败，23 ignored 未运行**。测试实际是 unoptimized/debug profile；receipt 中的 `opt_level: 3` 是 helper 设置的 release 环境值，不应误称单测以 opt3 运行。
- 主线沿用前轮新建产物，本轮重新 SHA：`ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`，1,970,216 B。
- 旧独立 protection probe 用本次 fresh release 和精确镜像 C 各启动 3 次，共 6 次。分支每次 11 页 RELRO 全只读、3 个不同 ASLR 基址、无 WX 映射和 executable stack、唯一文件映射为自身；映射前 UDP 和映射后 TCP A 回答正确，全部退出 0。C 为每次 3 个 RELRO 页只读、3 个不同基址。

命令、测试摘要、身份、日志摘要和映射结果见 [fresh-build.json](fresh-build.json)；可复跑驱动 [fresh_build.py](fresh_build.py)，必须传入具有精确 source、head-input-identity.json、旧 protection probe 的**全新** `--root`，不得覆盖本轮证据。测试用新的 net/mount/PID namespace 与 tmpfs `/tmp`。

## 保留的 SDK 证据已经重新校验，没有重新编译 SDK

只读核验旧 `types-summary.json` 所引用的两份 SDK manifest、源码 archive/identity、release/test artifacts、构建日志、最终 ELF/APK、link map、private map wrappers 和 SDK 输入。共重新散列 **137 个不同文件**；两份 manifest 中各 **106 项 SDK 输入**的现存文件与冻结值相同，总摘要为 `1c5a8201578bdc768de01eaa5d75cda6e43952ee618b7b990cdf1278e9835c67`。原源码目录和固定 SDK source copy 的 177 输入也与新 HEAD 相同。见 [retained-build-rehash.json](retained-build-rehash.json)、[verify_retained_build.py](verify_retained_build.py)。

保留的两次 SDK 构建均是真正源码 prepare/compile，阶段退出 0，无 frozen ELF 跳过；第二次 clean 重建输出的 ELF 和 APK 与第一次逐字相同：

| 产物 | 字节数 | SHA256 |
|---|---:|---|
| SDK payload ELF | 2,054,939 | `61b02fa66a1c2b07753c236c79b4d2be5cbbf4ddc34125b3c00a1aff171671b6` |
| SDK APK | 1,117,233 | `1561009e28f831b4b476c3eadb34d141b0772608d6258ac384f46db666626f99` |

第二次为取得真实 map，通过私有 Cargo/CC passthrough 加入 `-Wl,-Map`，未改变产品 recipe 或 Rustflags；map 只有在完整 ELF/APK 同一性验证后才被采信。本轮重核了两个 wrapper 及 map 的实际字节。旧预算 ELF 1,000,000 B / APK 700,000 B 仍失败，两次审计驱动的返回 1 明确属于 `size-target`，不是编译失败。这是 main 已有的验收问题；本轮没有提高预算或新增例外。

## 构建身份的限制：同源不等于跨路径同 ELF

本次 fresh release 与旧 types release 的 177 输入相同，字节数也相同，但 **ELF 不相同**：旧 SHA `0410d96c9c42e0fc3616d499547fe4ba7d7657b236d8d55daa0664a483b8b743`，新 SHA 如上。实际有 1,220,888 字节不同，覆盖 `.text`、`.rodata`、`.data.rel.ro`、unwind 和 relocation 内容；各 section header 的位置/大小一致。不能把它说成只有 build-id 改变，也不能声称旧 types 的性能窗口直接执行了本次新 ELF。详见 [release-path-comparison.json](release-path-comparison.json)。

构建路径/Cargo package identity 影响符号及布局是可能原因，本轮没有做符号映射归因，故这只是**原因疑似**；跨路径产物不一致本身已实测。它不推翻旧 SDK **同固定路径** clean rebuild 的字节一致性。此类跨路径差异也不是此轮首次出现：历史 main 同一 `be531cee` 的 `fix2/performance-plan.json` 保存的 release 为 `0846cb40…`，本次沿用、重 hash 的 main 为 `ad103449…`，两者均是 1,970,216 B、同 helper opt3 参数；本轮没有重新 hash 那个更早的 main 文件，历史记录只作维护边界参考，不作新故障证明。

因此本轮把新 release 功能/性能运行和旧 SDK/旧 types 证据分别绑定真实 SHA。尚无依据认定有新增构建阻断，但也没有跨路径可重复性或所有同源 ELF 性能恒定的保证。

## 未覆盖

没有再次运行两轮 SDK 编译、SDK payload 的新运行映射、完整包安装/升级/卸载/procd/ujail 生命周期或原 36 次 startup 资源矩阵；N3 重复配置 hosts 初始化明确未修，未将它重新声明为通过。没有覆盖其他工具链/目标架构/页大小、canonical x86_64 SDK 宿主、跨宿主可重复性、physical router 或长期资源压力。构建日志仍存在原编译器/host wrapper 警告；未声称 warning-free。
