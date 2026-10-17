# AX3000T 救援手册（离线可用）

**当前状态（2026-10-17）：已刷入 v0.2.1 十组件原生 Rust 固件，当前恢复入口以[发布说明](RELEASE.md#恢复路径)为准。**
`owrt-recover-c` 从 `/usr/libexec/owrt-stock/` 成套恢复十个 C 程序及 dnsmasq 原 init/ACL，共十二份文件；
`/rom` 内对应入口也是 Rust，不能作为 C 原件。该操作不等同于刷回 v0.2.0；本次版本回滚使用已核验的
v0.2.0 镜像和独立配置备份，保存在 `private/backup/release-v0.2.1/`。验收期临时自动回退守卫以
v0.2.0 为目标，最终验收后移除并另取干净配置备份，完成状态见[部署记录](reviews/DEPLOYMENT_V0_2_1_20261017.md)。
回滚固件 SHA256 为 `2f8083e44a548802de1738ecd8ef5231f74fda950a0a69a44f0e10e2e1d30ffd`；
TFTP 救援镜像 `private/images/stock-rd03/miwifi_rd03_firmware_ef0ee_1.0.47.bin`，SHA256 为
`77bf35b27b6ec29fbfe2c3f4280618cd70bade5e9998d407b634ce8a12825cc6`。
本页第 1–3 节针对历史 stock/overlay，第 7 节针对历史九组件镜像；不要将其旧文件集合套用到十组件。
按键、lan4 和 TFTP 步骤继续作为硬件恢复参考。

适用：Xiaomi AX3000T（RD03，MT7981，原厂小米 bootloader），OpenWrt 25.12.5 stock 布局，
本项目六个 Rust 组件以 boot-enable 运行，procd/ubusd/netifd 在 overlay 中替换。写给失联时独自操作的人；每一级都比上一级更重，
**先试轻的**。数字与路径都按 2026-09-03 设备实测。

**部署策略更新（2026-09-12）：** 用户已授权通过 Wi-Fi 部署，不再要求预先连接 lan4 网线。
部署前核对离线备份、二进制身份和自动回退；重启后从客户端验收 DHCP、双频无线、DNS、
IPv4/IPv6 出网和服务状态。需要时由用户将电脑切到热点继续协作。
以下 lan4／有线步骤保留为实际进入 failsafe 或 TFTP 救援时的操作方法，不是日常部署前置条件。

**清理更新（2026-09-29）：** 九组件继续运行；试验采集器、临时自动回退和 `/root` 部署包已离机归档并删除。
三份 `.c-orig` 冗余副本也已删除，以下恢复步骤使用当前 stock 镜像中经过哈希核验的 `/rom/sbin/*`。
离线备份见 `private/production-cleanup-20260929/`。将来若刷入 Rust 集成镜像，必须按新镜像重新验证恢复入口；
本页的 `/rom` 恢复命令仅适用于这里固定的 stock 镜像。
完整九组件集成镜像使用本页第 7 节的专用恢复入口；其构建与配置迁移约定见[发布说明](RELEASE.md)。

## 0. 先记住的四件事

1. **reset 键**：正常运行时短按 = 重启，长按 5 秒以上 = 恢复出厂（清掉全部配置与本项目改动）。
   开机瞬间按住 reset = 小米 TFTP 救援模式。不要随手按。
2. **mesh 键**：正常运行时没有任何作用；开机过程中按它 = 进入 OpenWrt failsafe。救援用它。
3. **灯**：上电后黄灯闪 = 正在启动；转蓝 = 启动完成；黄灯比平时快得多地闪 = failsafe 已进入。
4. **failsafe 只在 `lan4` 口出网**，地址 192.168.1.1，无 Wi-Fi。正常运行时用
   `cat /sys/class/net/lan4/carrier`（插网线后应为 1）确认哪个物理口是 lan4；来不及确认就逐个口试。

需要进入 failsafe 时，电脑侧网线接扩展坞 → Mac；Mac 的 Wi-Fi 可连手机热点保持上网。
此时将有线口设静态 IP 192.168.1.2/24（failsafe 与恢复出厂都没有 DHCP）。

## 1. 第一级：SSH 还通，只是某个服务没起

```
ssh root@192.168.1.1
owrt-switch status              # 六个组件的 switch / boot-enable / pid
# procd / ubusd / netifd 不走 switch；分别核对运行映像和下一次启动文件
sha256sum /proc/1/exe /proc/$(pidof ubusd)/exe /proc/$(pidof netifd)/exe
sha256sum /sbin/procd /sbin/ubusd /sbin/netifd
logread | grep -iE "owrt|rpcd-rs|httpd-rs|logd-rs|fw4|uci-rs"
```

单个组件回退（各自独立，随时可逆）：

```
owrt-<name>-switch disable        # name: uci reload-config logd httpd fw4 rpcd
owrt-<name>-switch boot-enable off
```

上述六组件全部切回 C：`owrt-switch disable-all && owrt-switch boot-enable off`。
rpcd 特别说明：`owrt-rpcd-switch disable` 会重新 enable 并启动原 `/etc/init.d/rpcd`。

**完整九组件回退并重启**用下面一段。先校验只读 C 原件，再复制到临时文件并逐字节核验，最后改名替换下一次启动文件。
改名保留当前运行进程的映像；不要直接覆盖正在执行的文件，也不要通过删除 `/sbin/<x>` 试图露出 ROM：overlay 的 whiteout 会继续遮住原件。

```sh
/bin/sh -eu <<'RECOVER' && reboot
    sha256sum -c <<'SHA256'
36269ae10ae267b9753233bfecdea48bd6fed4b2f7980f722f96413bd2ca681a  /rom/sbin/procd
cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88  /rom/sbin/ubusd
8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90  /rom/sbin/netifd
SHA256
    for c in procd ubusd netifd; do
        cp -p "/rom/sbin/$c" "/sbin/$c.restore"
        test -x "/sbin/$c.restore"
        cmp -s "/rom/sbin/$c" "/sbin/$c.restore"
    done
    for c in procd ubusd netifd; do
        mv -f "/sbin/$c.restore" "/sbin/$c"
        cmp -s "/rom/sbin/$c" "/sbin/$c"
    done
    for c in uci reload-config logd httpd fw4 rpcd; do
        rm -f "/etc/owrt-$c.boot-enable"
        /etc/init.d/owrt-$c disable
    done
    for service in log rpcd uhttpd; do
        /etc/init.d/$service enable
    done
    sync
RECOVER
```

所有复制与启动项调整成功后才会重启；任何校验失败时保留现场排查。
当前 stock 镜像的 failsafe 使用只读 C 控制面，不依赖已经删除的试验脚本。

## 2. 第二级：SSH 不通、蓝灯不亮 → failsafe

1. 拔电源，网线接 `lan4`，Mac 有线 192.168.1.2/24。
2. 插电。黄灯开始闪的 4 秒内**连按 mesh 键几次**（不是 reset）。黄灯变成快闪即成功。
3. 登录（failsafe 用临时主机密钥、原厂 shadow，root 无密码，回车即可；设备上没有 telnetd）：

```
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@192.168.1.1
```
4. failsafe 未挂载 overlay，先挂载再改：

```
mount_root
```

5. 执行第一级的“完整九组件回退并重启”代码，将其中的 `reboot` 改为 `reboot -f`。
   `owrt-rpcd-switch boot-enable off` 只删除标记，不会重新 enable C rpcd；完整步骤已显式恢复三个 C 服务。
   若 `/etc/init.d/owrt-* disable` 无法执行，可将该代码中的两个启动项循环替换为下面的手工命令；
   三个核心文件仍须完成前面的复制与核验：

```
rm -f /etc/owrt-*.boot-enable
rm -f /etc/rc.d/S00owrt-uci /etc/rc.d/S11owrt-reload-config /etc/rc.d/S11owrt-rpcd \
      /etc/rc.d/S12owrt-logd /etc/rc.d/S18owrt-fw4 /etc/rc.d/S50owrt-httpd
ln -sf ../init.d/rpcd /etc/rc.d/S12rpcd
ln -sf ../init.d/log /etc/rc.d/S12log
ln -sf ../init.d/uhttpd /etc/rc.d/S50uhttpd
```

## 3. 第三级：failsafe 也修不好 → 恢复出厂 + 恢复配置备份

在 failsafe 中：

```
mount_root
firstboot -y        # 清空 overlay，回到干净的 25.12.5（所有配置与本项目改动都没了）
reboot -f
```

重启后 192.168.1.1、无密码、Wi-Fi 关闭。恢复配置：

```
scp -O private/backup/2026-09-03/cfg-backup.tar.gz root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'sysupgrade -r /tmp/cfg-backup.tar.gz && reboot'
```

这份备份只含 `/etc/config` 等 sysupgrade 保留列表，不含本项目的 apk 包；本项目的东西需要
按 `reports/.../DEVICE_BUILD_RECIPE.md` 重装（也可以不装，设备就是原厂 OpenWrt）。

## 4. 第四级：完全不启动、failsafe 进不去 → 小米 TFTP 原厂救援（最后手段）

只在怀疑 flash 内容损坏时使用；本项目任何步骤都不写 flash 的启动分区，所以正常情况下到不了这里。
后果：设备回到**小米原厂固件 1.0.47**，OpenWrt 要重装（走 XMiR-Patcher / 1.0.47 的 ssh 漏洞，
见 OpenWrt 提交 f11e6e221ea1 的安装说明），耗时数小时，不用拆机。

材料：`private/images/stock-rd03/miwifi_rd03_firmware_ef0ee_1.0.47.bin`
（小米官方 CDN `cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rd03/`，SHA-256 见同目录 `SHA256SUMS`）。

原理：开机时按住 reset 约 8–10 秒，bootloader 以 192.168.31.1 起 TFTP 客户端，向 192.168.31.100
请求一个按服务器 IP 十六进制命名的文件（192.168.31.100 → `C0A81F64.img`），校验小米签名后刷入并
重启。Windows 上是 MIWIFIRepairTool；macOS/Linux 用 dnsmasq 同时提供 DHCP + TFTP：

```
mkdir -p /tmp/tftp && cp miwifi_rd03_firmware_ef0ee_1.0.47.bin /tmp/tftp/C0A81F64.img
# Mac 有线口设 192.168.31.100/24；网线接路由器 LAN 口；WAN 口拔掉
sudo dnsmasq --no-daemon --interface=<有线口名> --bind-dynamic \
  --dhcp-range=192.168.31.20,192.168.31.200,5m \
  --enable-tftp --tftp-root=/tmp/tftp --tftp-no-blocksize --port=0 --log-dhcp
```

拔电 → 按住 reset 插电 → 黄灯开始闪后松手 → 看 dnsmasq 日志里请求的文件名（若不是
`C0A81F64.img`，按日志里的名字改名重来）→ 传输完成后等待几分钟，灯转蓝，设备已是原厂固件。

## 5. 明确不做

- 不接 UART、不拆机、不写 BL2/FIP/Nvram/Factory 分区、不 `fw_setenv`。
- 不用 `sysupgrade` 刷 OpenWrt 镜像"救"设备：bootloader 逻辑本身没坏，刷镜像解决不了问题，
  反而在停电时可能把 UBI 弄坏。`private/images/25.12.5/` 里的官方镜像只在确认 UBI 损坏、
  且已经用第四级回到原厂后重装时才用。

## 6. 备份清单（2026-09-03，`private/backup/2026-09-03/`）

| 内容 | 文件 |
|---|---|
| `sysupgrade -b` 配置 | `cfg-backup.tar.gz` |
| overlay 全量（含所有 apk、开关标记、rc.d 链接） | `overlay-upper.tgz` |
| BL2 / Nvram / Bdata / Factory(Wi-Fi 校准) / FIP / crash / crash_log / KF | `mtd/mtd0-…mtd7-*.bin`（设备端与本地 SHA-256 一致） |
| U-Boot 环境全文 | `info/fw_printenv.txt` |
| 分区表、ubinfo、cmdline、board.json、mount、rc.d、apk 列表、进程 | `info/system.txt`、`info/ps.txt` |
| 重启前参考态（r23 pre） | `r23/pre/` |

Factory 分区含 Wi-Fi 校准数据，丢失后无法从任何镜像补回；其余分区都可从官方镜像重建。

## 7. 完整九组件集成镜像的 C 恢复

适用于 `/usr/share/owrt-control-plane/release.json` 标识 `native-nine` 的固件。
2026-09-29 真机已从前述 stock + overlay 部署迁移到此布局，保留配置验收通过。

集成镜像在标准路径直接内置 Rust，`/rom/sbin/procd` 等也已是 Rust。九份固定版本的 C 原件改存于
`/usr/libexec/owrt-stock/`，保留原目录结构。原版内核、早期 init、preinit/failsafe 与执行面保留。

SSH 仍可用时执行 `owrt-recover-c`；failsafe 中先执行 `mount_root`，再执行同一命令。
它逐项校验全部 C 原件、准备九份临时副本后再改名替换，不依赖 ubus，也不主动重启。
成功提示后普通运行状态用 `reboot`，failsafe 用 `reboot -f`。任何校验失败时先保留现场排查。

这个入口保留用户配置，仅安排九组件恢复原版。首次迁移时用的是原 `log/rpcd/uhttpd` 启动服务，
所以恢复 C 不需要重建另一套开关脚本。若服务被用户手工禁用，按实际故障恢复对应服务的启动项。

首次部署使用过的 `/root/owrt-native-trial/` 和 `S01owrt-native-trial` 已在用户物理复测通过后移除，
资料归档在电脑上的 `private/native-deploy-20260929/`。当前没有试验自动回退进程，按本节手动恢复。
固定的可刷写版本与身份清单保存在 [AX3000T Rust9 v0.1.0 Release](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/ax3000t-rust9-v0.1.0)。

恢复出厂会清空 overlay 并重新使用镜像内的 Rust。需要永久恢复官方固件时，应使用独立验证过的
官方镜像与配置备份，不能把当前集成镜像的 `/rom` 当成完整 C 根文件系统。
