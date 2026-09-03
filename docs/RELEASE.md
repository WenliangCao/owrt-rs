# 发布与维护：OpenWrt 新版本之后怎么保住这一层

## 现状与前提

- 设备上的 sysupgrade 会重建 overlay，只按保留列表（`/etc/sysupgrade.conf`、`/lib/upgrade/keep.d/*`）恢复配置文件；
  本项目的 apk、rc.d 链接、`/etc/owrt-*.boot-enable` 标记都不在其中。**升级后设备自动回到原厂 OpenWrt**，
  这是安全的默认，但意味着每次升级必须重装本层。
- owut / attendedsysupgrade 只能打包官方源里的包，塞不进自建包；它对本层没有用。
- 六个组件对着**特定版本**的 C 原实现做的移植（rpcd、fw4 ucode、libuci、libiwinfo f5dd57a8……）。新版本里
  这些 C 程序会变，所以真正的维护成本不是构建，而是**差分回归**。

## 流水线（`tools/release.sh`，通过根 `Makefile` 调用）

| 步 | 命令 | 做什么 |
|---|---|---|
| 0 | `sh tools/release.sh fetch <ver>` | 在构建机下载该版本的 SDK 与 ImageBuilder，按官方 `sha256sums` 校验并解包 |
| 1 | （手工）IMAGE_INTAKE | 从新版官方 sysupgrade 镜像提取 rootfs 到构建机（`reports/.../IMAGE_INTAKE.md` 的流程），作为差分沙箱 |
| 2 | 差分回归 | 用新 rootfs 重跑 harness：r09（fw4 print 逐字节）、r13/r17/r18/r19（rpcd 对象）、r16（uci）、r15/r21（logd）、r14（httpd）、r1（reload_config）。任何差异先修代码 |
| 3 | `make apk VERSION=<ver>` | 新 SDK 构建七个 owrt-\* 包（`V1_PACKAGE_RELEASE` 按需递增） |
| 4 | `make image VERSION=<ver>` | ImageBuilder 生成 `xiaomi_mi-router-ax3000t` 的 sysupgrade 镜像 |
| 5 | 离线验证 | 从生成的镜像提取 rootfs，确认七个包、六个标记、三个 disabled 服务都在；再跑一次 harness |
| 6 | 刷写 | 见下一节 |

`make image` 的实现要点（ImageBuilder 25.12 已支持，不需要 uci-defaults 脚本）：

- 我们的 apk 放进 ImageBuilder 的 `packages/` 目录，它用 `apk mkndx` 生成本地索引并用本地密钥签名；
  `ADD_LOCAL_KEY=1` 把该公钥写进镜像的 `/etc/apk/keys/`，装机后 `apk` 也认这些包。
- `PACKAGES` 取自设备当前 `apk info`（或 `PKGLIST=文件`），保证镜像与现役设备的软件集一致，再加七个 owrt-\* 包。
- `DISABLED_SERVICES="rpcd uhttpd log"`：原 rpcd/uhttpd/logd 保留在镜像里（是 `disable` 的退路），但开机不启动。
- `FILES=` 只放六个 `/etc/owrt-*.boot-enable` 空文件：owrt-\* 的 init 脚本看到标记才接管。
- 输出在构建机 `/home/ubuntu/release/<ver>/bin/`，附 sha256。

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
| 25.12.5 | 现役（apk 逐个安装 + boot-enable；R23 重启验证通过） | uci r2、reload-config r3、logd r2、httpd 0.1.1-r1、fw4 r2、rpcd r4、switch r2 | 见 `manifests/release-25.12.5.json`（离线验证，未刷写） |
