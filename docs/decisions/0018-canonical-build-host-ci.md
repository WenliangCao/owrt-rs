# 0018：正式发布固定在 CI（canonical builder = release-image workflow，2026-09-06）

## 背景

七个包里只有 `owrt-httpd` 在 CI（x86_64 GitHub runner）与构建主机 `oracle`（aarch64，
经 qemu 跑 x86_64 SDK）之间字节不一致。其余六个逐字节相同。R34/R35 的 E0–E8 八组实验
定位了根因（完整调查见 [R35_RING_INVESTIGATION](../reviews/R35_RING_INVESTIGATION.md)）：

Cargo 为「依赖图经过 build script（Host-kind unit）的 crate」计算的 `-C metadata`
把宿主三元组算进哈希，两台宿主必然不同。该值进入 `StableCrateId` → v0 符号里的 crate
消歧串（ring：`Cskia6MYFH9dt_` vs `Csd2U2ioFfwR_`，**长度不同**）→ LTO 位码 → 最终布局。
只有 httpd 受影响，因为只有它链接 ring/rustls；另外六个包没有带 build script 的依赖。

E8 用单变量实测闭环：同一宿主、只改 `-C metadata`，得到三个不同的发货二进制。

## 决策

**正式发布产物由 `.github/workflows/release-image.yml` 生成，构建主机降级为差分回归与对照用途。**

理由：这是发布来源核验问题，基线必须能被第三方重跑。CI 的环境写在 workflow 里、
runner 由 GitHub 提供、SDK 与 ImageBuilder 按官方 `sha256sums` 校验，整条链是可审计的；
构建主机是一台长期机器，环境漂移只能靠自律。

## 为什么没有「配方级」修复

没有任何 flag 够得到这个输入。已被实验证伪的方向：

- `-ffile-prefix-map=$CARGO_HOME=/cargo`（E1）：11 个纯汇编对象跨宿主收敛，但二进制不变。
- `--remap-path-prefix=<target dir>=/target`（E2，flag 验证在 `cargo-vv.log` 出现 16 次）：完全空结果。
- ar / 链接顺序（E0）：成员名、顺序、archive 元数据本来就一致。
- rustc codegen 与宿主有关（E3/E4）：无依赖最小 fixture 两侧逐字节相同。

要让原生 x86_64 与原生 aarch64 也一致，需要 Cargo 上游改变 Host-kind unit 的哈希输入，
不在本项目范围内。因此「跨异构宿主字节一致」不作为验收项。

## 影响

- **运行行为无影响**。两个二进制是同样的代码换了排布：文件总大小、section 表、program
  header 完全相同，`.text` 261898 条指令、助记符直方图逐项一致，`.gcc_except_table` 逐字节相同。
  CI 产物对 stock uhttpd 跑 r14 差分 **38/38 全过**，与构建主机产物一致。
- **设备当前的 r5 httpd 是构建主机产物**（`04eb7b0b…`），与 CI 一系（`a56ef067…`）字节不同但等价。
  下次发布走 CI 后哈希会变成 CI 一系；这不是回归，不需要为此单独刷机。
- 打包 Makefile、RUSTFLAGS、profile **全部不动**。`/tmp/owrt-build/<pkg>` 固定构建路径和
  两条 `--remap-path-prefix` 保留：它们仍在消除路径泄漏，只是不解决本问题。

## 配套改动

1. `tools/ci_build_image.sh`：离线验证阶段从解开的 rootfs 里 sha256 六个发货二进制，
   写入 `binary-sha256.txt` 并进 `manifest.json` 的 `binary_sha256`。APK 与镜像哈希还覆盖打包
   元数据，六个二进制才是真正跑起来的代码，作为来源核验锚点。
2. `.github/workflows/release-image.yml`：`binary-sha256.txt` 进 artifact、job summary 和 GitHub Release。
3. `tools/release.sh`：`apk` 开头打印非 canonical 提示，文件头说明用途限于差分回归。

## 核验方法

跑两次 `release-image`（同一 commit），比较两次的 `binary-sha256.txt`：六行应完全相同。
构建主机产物用于比对时，预期只有 `httpd-rs` 一行不同，其余五行相同。
