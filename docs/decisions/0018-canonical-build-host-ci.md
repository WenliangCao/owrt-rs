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

## 核验结果（2026-09-06，commit `daef6ee`，runs 33995307108 / 33995487475）

同一 commit 跑两次 `release-image`，**六个发货二进制逐字节相同**：

```
ebf62134ce52264c2d9b170221b1ca62d37215833a7d7679d32ee2c6072edbde  uci-rs
3f29fb7a9234dddfd863f59a51838af181c197653c259ce55c1bd2b0a8e77d9a  fw4-rs
424cf7190ebf7ae0041b74d93fe2a646f35c2e81631a045b5a4c96d5a4dc67e7  reload_config_rs
092da339dfe4631f969aadaaf3d9dcdce5b1734c7740bb933c81f5c6352759a9  logd-rs
3af335b1682926cd6481e7fc2fccdbd227d855cdf7345041e6fbe31ab92d6b34  httpd-rs
95af6169fd7c14b8e0738bcc082630b588f484112fc15296f8421540cabd607f  rpcd-rs
```

**七个 APK 也逐字节相同。** 只有 sysupgrade 镜像不同，原因已查清并且只有一个：

解开两个镜像的 root squashfs，**926 个普通文件里只有 1 个不同**，221 个符号链接全部相同。
不同的那个是 `/etc/apk/keys/local-public-key.pem`——ImageBuilder 的 `ADD_LOCAL_KEY=1`
每次运行现生成一对 ECDSA 密钥。六个二进制在两个镜像里逐字节相同。

要让镜像也可复现，需要把本地签名私钥固定下来（例如存成 Actions secret 复用）。
那是引入一个长期签名密钥的安全决策，本决策不含这一步；发布来源核验以二进制哈希为锚点。

### 关于 httpd-rs 的哈希与诊断产物不同

canonical 发货哈希是 `3af335b1…`，诊断脚本 `repro_diag.sh` 收到的 CI 产物是 `a56ef067…`。
差别是打包的 `INSTALL_BIN` 又做了一次 strip：镜像里的 ELF `e_shnum=0`（section header
表整个去掉），比 cargo 直接产出小 1425 字节 = section header 表 1152 + `.comment` 112 +
`.shstrtab` 154 + 对齐。**按同样的文件偏移逐段比对，`.text` / `.rodata` / `.eh_frame` /
`.gcc_except_table` / `.data.rel.ro` / `.got` / `.data` 全部逐字节相同**，两个文件在较短者
长度内只有 6 个字节不同，全在 ELF header 的 `e_shoff` / `e_shnum` / `e_shstrndx`。
即：同一份代码，多脱了一层元数据。

## 核验方法（复用）

跑两次 `release-image`（同一 commit），比较两次的 `binary-sha256.txt`：六行应完全相同。
构建主机产物用于比对时，预期只有 `httpd-rs` 一行不同，其余五行相同。

## R85：补齐三个核心组件的来源链（2026-09-11）

`release-image` 增加 `tools/ci_build_core.sh`，在同一提交和已校验 SDK 下构建
`procd-rs`、`ubusd-rs`、`netifd-rs`。它们的固定构建路径为
`/tmp/owrt-core-release/<component>`，使用项目固定工具链、release 参数和目标 ABI 检查。

新增产物为 `core-binaries.tar.gz`、`core-binary-sha256.txt` 和 `core-manifest.json`。
清单记录源码提交、目标、SDK、三个文件及归档哈希，并绑定同次构建的 image manifest；
生成时逐项核对归档成员、执行权限和文件哈希。将原有六个 `binary_sha256` 与该清单合并后，
才覆盖九个组件的正式来源。

生成的 sysupgrade 镜像仍按既有方案启用六个包内组件。三个核心文件作为独立产物发布，
其正式切换继续使用已验证恢复门；生成、下载或验证这些产物不执行设备部署或刷写。
