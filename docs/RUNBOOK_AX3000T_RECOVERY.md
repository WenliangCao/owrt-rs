# AX3000T 救援手册（离线可用）

适用：Xiaomi AX3000T（RD03，MT7981，原厂小米 bootloader），OpenWrt 25.12.5 stock 布局，
本项目六个 Rust 组件以 boot-enable 运行。写给失联时独自操作的人；每一级都比上一级更重，
**先试轻的**。数字与路径都按 2026-09-03 设备实测。

## 0. 先记住的四件事

1. **reset 键**：正常运行时短按 = 重启，长按 5 秒以上 = 恢复出厂（清掉全部配置与本项目改动）。
   开机瞬间按住 reset = 小米 TFTP 救援模式。不要随手按。
2. **mesh 键**：正常运行时没有任何作用；开机过程中按它 = 进入 OpenWrt failsafe。救援用它。
3. **灯**：上电后黄灯闪 = 正在启动；转蓝 = 启动完成；黄灯比平时快得多地闪 = failsafe 已进入。
4. **failsafe 只在 `lan4` 口出网**，地址 192.168.1.1，无 Wi-Fi。正常运行时用
   `cat /sys/class/net/lan4/carrier`（插网线后应为 1）确认哪个物理口是 lan4；来不及确认就逐个口试。

电脑侧：网线接扩展坞 → Mac；Mac 的 Wi-Fi 连手机热点保持上网，这样路由器失联时对话不中断。
Mac 有线口设静态 IP 192.168.1.2/24（failsafe 与恢复出厂都没有 DHCP）。

## 1. 第一级：SSH 还通，只是某个服务没起

```
ssh root@192.168.1.1
owrt-switch status              # 六个组件的 switch / boot-enable / pid
logread | grep -iE "owrt|rpcd-rs|httpd-rs|logd-rs|fw4|uci-rs"
```

单个组件回退（各自独立，随时可逆）：

```
owrt-<name>-switch disable        # name: uci reload-config logd httpd fw4 rpcd
owrt-<name>-switch boot-enable off
```

全部回退到原厂实现：`owrt-switch disable && owrt-switch boot-enable off`。
rpcd 特别说明：`owrt-rpcd-switch disable` 会重新 enable 并启动原 `/etc/init.d/rpcd`。

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
owrt-switch boot-enable off       # 六个组件开机都不再接管
# 或者只关一个： owrt-<name>-switch boot-enable off
sync; reboot -f
```

5. 重启后原厂 uci/reload_config/logd/uhttpd/fw4/rpcd 全部恢复（注意：`owrt-logd-switch`、
   `owrt-httpd-switch`、`owrt-rpcd-switch` 的 `boot-enable off` 会重新 enable 原服务；
   若在 failsafe 里没法执行脚本，手工做：

```
mount_root
rm -f /etc/owrt-*.boot-enable
rm -f /etc/rc.d/S00owrt-uci /etc/rc.d/S11owrt-reload-config /etc/rc.d/S11owrt-rpcd \
      /etc/rc.d/S12owrt-logd /etc/rc.d/S18owrt-fw4 /etc/rc.d/S50owrt-httpd
ln -sf ../init.d/rpcd /etc/rc.d/S12rpcd
ln -sf ../init.d/log /etc/rc.d/S12log
ln -sf ../init.d/uhttpd /etc/rc.d/S50uhttpd
sync; reboot -f
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
