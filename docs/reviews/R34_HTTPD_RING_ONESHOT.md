# 给 Opus 的 One-Shot：在一次证据闭环里解决 httpd/ring 可重复性

日期：2026-09-05。基线 `0c050a6`，Rust 1.98.1，锁定 ring 0.17.14 / cc 1.4.4。
这是执行建议；审查者本轮没有修改构建代码、下载远端产物或部署设备。

## 一句话路线

**先把 CI 与构建机两次 clean 构建的中间产物保留下来，从 APK 向前定位“第一个产生不同字节的步骤”，只修那个步骤；如目标是可靠的正式发布而不是研究跨宿主编译器差异，统一使用同一摘要固定的 Linux 构建器。**

不要先改 ring、换 TLS 库、关闭汇编优化或反复增加 remap 参数。现有报告“来自 ring C/汇编链接顺序”只是嫌疑，不是已经证实的根因。

## 0. 已经知道什么，排除什么

本轮直接检查了锁定的 crates 源码：

- ring/build.rs：build_library 按 sources_for_arch、asm_srcs 的顺序调用 cc.file；发布 crate 没有 `.git` 时使用自带 `pregenerated` 汇编。不能默认认为每台主机都在重新跑 Perl。
- cc/command_helpers.rs：object 文件名确实带源目录哈希，但**会先剥掉 CARGO_MANIFEST_DIR**。所以“registry home 不同必然导致 object 名不同”在这个版本不成立；必须对实际路径和 ar 成员名取证。
- cc/lib.rs：assemble 遍历对象向量，并默认尝试 deterministic ar 的 D 修饰符。直接加 ARFLAGS=D 不一定修任何东西。
- ring/configure_cc 即使 release 也可能传 `-g3`；项目的 Rust `--remap-path-prefix` 不会自动变成 C 编译器的 debug/file-prefix map。这是值得检查的候选，**不能先当根因**。
- 只有带外部依赖的 httpd 不一致，不足以证明不同字节一定在 C/汇编；也可能在 Rust ring/rustls 对象、host build-script 输出、LTO、linker、strip 或 APK 层。
- “同尺寸、80 多万偏移不同”可能只是少数布局差异传播到大量地址/重定位，不能解释为有80多万字节逻辑错误。

## 1. 先收集一对可比较输入，别直接重建整仓库

在已有用户授权的 CI/构建环境执行；不涉及物理路由器。先只构建 owrt-httpd。

要求两边同一 git SHA、无工作区修改、同一 Cargo.lock、同一 target/profile/CPU 特性与 SDK 来源。使用独立诊断输出目录并 clean crate/SDK stamp；保留原有产物，不覆盖唯一证据。

每侧保存以下内容（Git 外，报告仅提交路径标签、哈希与派生结论）：

1. APK 原始文件、从 APK 提取的 httpd-rs、打包前 httpd-rs。不要把 .pkgdir 未 strip binary 与另一侧 APK 内已 strip binary 比。
2. `cargo build -vv --locked` 和 SDK verbose 日志；完整 target ring `out/`，包括 `.a`、`.o`、生成头、build-script 的 `output`；ring 的 `.rlib`；最终链接 map。
3. 如当前 strip 阻碍诊断，建立两边一致的诊断构建（保留符号），并另保留正式参数的产物。诊断结果不能直接当正式可复现验收。
4. 实际 rustc -vV、Cargo、CC、AR、LD、strip 的版本/路径与可识别的构建信息，SDK 压缩包及配置哈希；rustc host 与 target 分开记录。
5. 只收集构建相关环境白名单：HOST/TARGET、CARGO_HOME、OUT_DIR、CARGO_TARGET_DIR、CC/AR/CFLAGS/CPPFLAGS/ARFLAGS、RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS、SOURCE_DATE_EPOCH、LC_ALL、TZ、umask；不要 dump 全部环境或 secrets。

x86_64 CI 与 ARM64 构建机的 host executable 哈希本来就不同。比较的是**目标 aarch64-musl 产物**，不要把 host build-script executable 不同误报为异常。

可在诊断构建开启 `CC_ENABLE_DEBUG_OUTPUT=1`，但必须先确认本次锁定 cc 版本支持并实际打印编译命令；否则用受控诊断 wrapper 记录参数和退出码。wrapper 构建按项目策略标非正式，最终验收移除 wrapper。

## 2. 一次由后向前的比较，找到最早分叉

先对同层产物执行 sha256 和 diffoscope。GNU/binutils 工具请使用 SDK 目标工具，避免用 macOS Mach-O 工具解释 ELF。

| 哪层不同 | 下一步 | 有证据后怎么修 |
| --- | --- | --- |
| APK 不同，提取的 binary 相同 | 看包内清单、成员顺序、时间/UID/GID、压缩、签名/构建密钥差异 | 修打包环境/元数据；不要改 ring。不同签名不能通过删签名伪造验收 |
| strip 前相同、strip 后不同 | 比较 strip 版本、参数、执行顺序 | 固定同一发布 strip 工具与参数 |
| 最终 ELF 不同 | `readelf -W -S -l -n`，链接 map，符号大小与节分布 | 先辨认仅 note/debug 差异还是 alloc/text/rodata/reloc 差异 |
| ring `.a` 相同，但 ring `.rlib`/最终 ELF 不同 | 比 Rust 编译参数、crate metadata、feature、build-script output、链接输入顺序、LTO | 修 Cargo/构建脚本/链接输入；不要继续追 C 编译 |
| ring `.a` 不同 | `ar t` 列有序成员，逐成员比哈希、readelf、反汇编与重定位 | 成员序不同才修稳定顺序；成员名不同才追路径哈希；对象内容不同再追编译 |
| 单个 `.o` 不同 | 按源码身份匹配，比较精确 CC 命令、预处理结果/生成 `.S`、节/重定位 | 明确是哪一个输入/工具/参数第一次变了 |

注意：ar 若有重复成员名，要保留成员索引，不能 `ar x` 到同一目录后覆盖。可用 diffoscope 或按成员顺序提取。

`objdump -drwC`/符号差异必须结合重定位解释，不能只按反汇编地址逐行比较。为定位而忽略 debug/build-id 可以，但最终验收必须比较**完整未加工的正式 binary**，不得靠移除差异节宣布成功。

## 3. 只做一次针对性修复

根据第一处分叉选择下面一条，不要全部同时改：

### A. 路径/生成输入差异

- 固定实际源码/registry/vendor、工作目录与 target/out 目录布局；发布 crate 使用相同来源与 pregenerated 文件。
- 只有 C 对象证明确含路径差异，才给目标 CC 添加对应 `-ffile-prefix-map` / `-fdebug-prefix-map` / 必要的 macro 映射。保持现有优化和目标参数；从 verbose 命令确认生效。
- Rust remap 保留；它和 C 映射是不同层。不要把 dependency 目录复制进 `.git` 工作树后意外改变 ring 的 `is_git` 分支。
- 如果证据指出对象名/顺序确有差异，再最小化修正稳定输入顺序或实际根路径；不先 patch 第三方源码。

### B. 编译器、binutils 或跨宿主差异

最稳妥的正式发布方案是：**CI 与构建机调用同一个摘要固定的 Linux 构建镜像，内含同一版本 SDK/toolchain/strip，使用同一绝对路径布局及锁定依赖。**

如果选 x86_64 Linux builder，ARM64 构建机可在已具备/获准使用的仿真环境运行该 builder，产物 target 仍然是 aarch64-musl。不用为构建可重复性改路由器架构或软件行为。避免本轮擅自安装系统级虚拟化组件；缺环境则明确记录并选已有 CI 环境。

这是消除构建输入差异，不是证明“两个不同宿主的原生 GCC 一定生成相同字节”。若用户要求**原生 x86_64 与原生 ARM64 构建也一致**，这只能作为对照组，不能拿统一 builder 替代该验收。

不要依赖 `ubuntu-latest` + 在线 apt 最新版作为最终精确工具链规范；至少固定真正影响 target binary 的 SDK、编译器、binutils 和依赖。记录 builder digest。

### C. 确实只有 linker/ar/打包顺序问题

保存产生不同顺序的具体清单，再修产生清单的地方（稳定排序/固定工具/确定性归档），保留应有链接顺序语义。不要不分组地把所有链接参数字典序排序。

若仅 build-id/debug 不同，先修造成输入差异的路径/时间/工具，再验证该差异是否传播到正式 ELF。不要把 `--build-id=none` 当默认万能解法。

## 4. 必须交付的验收（让这一轮真正结束）

- 同一 canonical builder 两次独立 clean 构建（A1/A2），正式 httpd-rs 完整 sha256 一致。
- CI 与构建机按选定支持策略构建（A/B），APK 提取 binary 完整 sha256 一致；若要求 APK 也一致，继续核对完整 APK，解释签名边界。
- 不复制一侧的 `.a`/`.o` 给另一侧作为“独立重建”，两边都从同一声明输入实际编译。
- TLS 握手/静态内容/8.97 MiB 与 32 MiB 上传、异常生命周期回归通过；APK 实际发货 binary 做既有 httpd reference 差分。若加编译参数还要检查体积与关键性能没有倒退。
- SDK 的同名旧 APK/stamp/cache 清除，manifest 对应本次真实构建，不允许拿旧包哈希混入结果。
- 提交一页结论：**首个不同的中间产物 → 导致它的具体输入 → 最小修复 → A1/A2/A/B 哈希 → 行为验证**。
- 临时诊断 wrapper、绝对私有路径日志与大型二进制留 Git 外；仓库只提交配方/工具/无秘密 manifest/派生报告。

不需要碰物理路由器。这个老问题的最终验收是两份独立产物，不是再安装一次 APK。

## 发给执行者的简短指令

> 先确认第一处分叉再改代码。保留两侧 APK、提取 ELF、strip 前 ELF、ring .a/.o/.rlib、build-script output 和完整编译命令。按本文比较树定位根因，优先修可控输入；若差异来自异构宿主工具链，统一摘要固定的正式 builder 并说明支持边界。保留所有加密算法与优化。最后用两次 clean 加 CI/构建机独立重建证明完整 binary 哈希一致，并跑 TLS/上传/生命周期/reference 验证。不要以“应该是 ring”或“移除了 build-id”作为完成结论。
