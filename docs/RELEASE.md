# 发布与维护：OpenWrt 新版本之后怎么保住这一层

## 现状与前提

- 设备上的 sysupgrade 会重建 overlay，只按保留列表（`/etc/sysupgrade.conf`、`/lib/upgrade/keep.d/*`）恢复配置文件；
  本项目的 apk、rc.d 链接、`/etc/owrt-*.boot-enable` 标记都不在其中。**升级后设备自动回到原厂 OpenWrt**，
  这是安全的默认，但意味着每次升级必须重装本层。
- owut / attendedsysupgrade 只能打包官方源里的包，塞不进自建包；它对本层没有用。
- 六个组件对着**特定版本**的 C 原实现做的移植（rpcd、fw4 ucode、libuci、libiwinfo f5dd57a8……）。新版本里
  这些 C 程序会变，所以真正的维护成本不是构建，而是**差分回归**。

## 流水线（`tools/release.sh`，通过根 `Makefile` 调用）

> **正式发布产物由 `release-image` GitHub Actions workflow 生成**（决策 0018）。
> 下面这条构建主机流水线保留给第 1、2 步的差分回归和跨宿主对照；第 3、4 步的产物不作为发布物。

| 步 | 命令 | 做什么 |
|---|---|---|
| 0 | `sh tools/release.sh fetch <ver>` | 在构建机下载该版本的 SDK 与 ImageBuilder，按官方 `sha256sums` 校验并解包 |
| 1 | （手工）IMAGE_INTAKE | 从新版官方 sysupgrade 镜像提取 rootfs 到构建机（`reports/.../IMAGE_INTAKE.md` 的流程），作为差分沙箱 |
| 2 | 差分回归 | 用新 rootfs 重跑 harness：r09（fw4 print 逐字节）、r13/r17/r18/r19（rpcd 对象）、r16（uci）、r15/r21（logd）、r14（httpd）、r1（reload_config）。任何差异先修代码 |
| 3 | `make apk VERSION=<ver>` | 新 SDK 构建七个 owrt-\* 包（`V1_PACKAGE_RELEASE` 按需递增）。**非 canonical**，见决策 0018 |
| 4 | `make image VERSION=<ver>` | ImageBuilder 生成 `xiaomi_mi-router-ax3000t` 的 sysupgrade 镜像。**非 canonical** |
| 5 | 离线验证 | 从生成的镜像提取 rootfs，确认七个包、六个标记、三个 disabled 服务都在；再跑一次 harness |
| 6 | 刷写 | 见下一节 |

`make image` 的实现要点（ImageBuilder 25.12 已支持，不需要 uci-defaults 脚本）：

- 我们的 apk 放进 ImageBuilder 的 `packages/` 目录，它用 `apk mkndx` 生成本地索引并用本地密钥签名；
  `ADD_LOCAL_KEY=1` 把该公钥写进镜像的 `/etc/apk/keys/`，装机后 `apk` 也认这些包。
- `PACKAGES` 取自设备当前 `apk info`（或 `PKGLIST=文件`），保证镜像与现役设备的软件集一致，再加七个 owrt-\* 包。
- `DISABLED_SERVICES="rpcd uhttpd log"`：原 rpcd/uhttpd/logd 保留在镜像里（是 `disable` 的退路），但开机不启动。
- `FILES=` 只放六个 `/etc/owrt-*.boot-enable` 空文件：owrt-\* 的 init 脚本看到标记才接管。
- 输出在构建机 `/home/ubuntu/release/<ver>/bin/`，附 sha256。

## GitHub Actions：`release-image`（2026-09-04 起）

`.github/workflows/release-image.yml` 在 GitHub 的 ubuntu runner 上跑 `tools/ci_build_image.sh`，与上面第 0、3、4、5 步等价，不需要构建机、不碰路由器：

1. 下载该版本官方 SDK 与 ImageBuilder，按官方 `sha256sums` 校验（下载缓存按版本键）；
2. Rust 1.98.1 + `aarch64-unknown-linux-musl`（版本只写在根 `rust-toolchain.toml`，CI、`tools/release.sh`、`tools/ci_build_image.sh` 都从那里读；`make check-toolchain` 校验七个 crate 的 `rust-version` 与它一致），用 SDK 的 `make package/owrt-*/compile` 构建七个 apk（`PKG_RELEASE` 默认值现在写在各包 Makefile 里，与设备现役一致；`V1_PACKAGE_RELEASE` 可覆盖）；
3. ImageBuilder 生成 `xiaomi_mi-router-ax3000t` sysupgrade 镜像，软件包清单来自仓库里的 `packaging/image/packages-<ver>.txt`（设备 `apk info` 的快照，170 个）；
4. 离线验证：解开 sysupgrade tar 与 root squashfs，确认七个包、六个 `boot-enable` 标记、三个被禁用的服务、六个二进制、本地 apk 公钥，并 sha256 这六个发货二进制（`binary-sha256.txt`）；
5. 产物（apk、镜像、`SHA256SUMS`、`binary-sha256.txt`、`manifest.json`、构建日志）作为 workflow artifact 保留 90 天；推 `v*` 标签时另建 GitHub Release 并附上同一批文件。

触发：Actions 页面 "Run workflow"（可填 OpenWrt 版本），或 `gh workflow run release-image.yml -f openwrt_version=25.12.5`，或 `git tag v0.5.0 && git push --tags`。
支持新版本只需要：把新版设备的 `apk info` 存为 `packaging/image/packages-<ver>.txt`，并先在构建机上用新 rootfs 跑完第 2 步的差分回归（这一步仍在构建机，CI 不做）。

首次成功运行：`actions/runs/33810286174`（2026-09-03 21:53Z，整个 job 约 6 分钟，其中构建步骤 4 分 43 秒）：七个 apk（uci r5、reload-config r5、logd r5、httpd r3、fw4 r5、rpcd r9、switch r2）+
`openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin`（11 643 168 B，sha256 `ba28ef40…a0a2`），内容检查通过。

### 可复现性与 canonical builder（决策 0018）

打包 Makefile 的 RUSTFLAGS 带 `--remap-path-prefix=$(PKG_BUILD_DIR)=/build --remap-path-prefix=$(V1_CARGO_HOME)=/cargo`，
去掉二进制里的构建路径；并且 cargo 在 `/tmp/owrt-build/<pkg>` 这个固定路径下构建（cargo 把 path 依赖的绝对路径算进 crate 元数据哈希，
进而进符号名，所以仅 remap 不够）。验证（run `33811595718`）：**uci、fw4、reload-config、logd、rpcd 五个二进制 CI 与构建机逐字节相同**。

`httpd-rs` 跨宿主不一致，根因已查清（[R35_RING_INVESTIGATION](reviews/R35_RING_INVESTIGATION.md)，E0–E8 八组实验）：
cargo 把宿主三元组算进「依赖图经过 build script 的 crate」的 `-C metadata`（libc / ring / rustls 及其下游），
该值进 `StableCrateId` → v0 符号消歧串 → LTO 位码 → 最终布局。只有 httpd 链接 ring/rustls，所以只有它受影响。
E8 单变量实测闭环：同一宿主只改 `-C metadata` → 三个不同的发货二进制。

这**不是**配方能修的：`-ffile-prefix-map`（E1）、`--remap-path-prefix`（E2）、ar/链接顺序（E0）都已被实验证伪。
两个二进制语义等价——总大小、section 表、program header 完全相同，`.text` 261898 条指令、助记符直方图逐项一致，
`.gcc_except_table` 逐字节相同，CI 产物 r14 差分 38/38 全过。

**因此正式发布固定在 CI：`release-image` workflow 是 canonical builder，构建主机只做差分回归与对照。**
每次构建把六个发货二进制的 sha256 写进 `binary-sha256.txt` 与 `manifest.json` 的 `binary_sha256`（APK 与镜像哈希
还覆盖打包元数据，二进制哈希才是真正跑起来的代码）。核验方法：同一 commit 跑两次 `release-image`，
两份 `binary-sha256.txt` 六行应完全相同。

已核验（2026-09-06，commit `daef6ee`，runs `33995307108` / `33995487475`）：**六个二进制与七个 APK 两次运行逐字节相同**。
只有 sysupgrade 镜像不同——解开两个镜像的 root squashfs，926 个普通文件里只有
`/etc/apk/keys/local-public-key.pem` 一个不同（`ADD_LOCAL_KEY=1` 每次现生成密钥对），
221 个符号链接全部相同。要让镜像也可复现需要固定本地签名私钥，那是独立的安全决策，见决策 0018。

**刷写仍是手工步骤**，见下一节。

## 刷写（每次升级真正的风险点）

刷写是 flash 写入，目前仍在 §10 禁止项里；真要升级时按决策 0016 的条件（到场、网线接 `lan4`、电脑另有上网途径、
救援手册在手）另立一条决策解禁，然后：

```
scp -O <image>-squashfs-sysupgrade.bin root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'sysupgrade -v /tmp/<image>-squashfs-sysupgrade.bin'   # 保留配置
```

- 刷写中断会损坏 UBI → 救援手册第四级（TFTP 原厂固件）。这是任何 OpenWrt 升级都有的风险。
- 首次开机后跑 `tools/r23_reboot_gate.sh post`（用升级前的 pre 作参考），确认六个组件接管、状态一致。
- 升级失败或差分未过时的退路：刷官方原版镜像（同样的 sysupgrade 命令），设备就是纯原厂 OpenWrt。

## 版本矩阵

| OpenWrt | 设备状态 | 包 | 镜像 |
|---|---|---|---|
| 25.12.5 | 现役（apk 逐个安装 + boot-enable；R23 重启验证通过） | uci r5、reload-config r5、logd r5、httpd 0.1.1-r3、fw4 r5、rpcd r9、switch r2（2026-09-03 夜） | 首个镜像（r2/r3/r2/r1/r2/r4，sha256 `fffb1589…5cd6`）已离线验证、**未刷写**（`manifests/release-25.12.5.json`）；当前包集的镜像由 `release-image` workflow 生成 |
