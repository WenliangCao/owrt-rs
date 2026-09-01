# H1 物理设备只读观察计划

> 状态：H1.1a 已完成并通过；H1.1b 未授权
> 目标：Xiaomi Mi Router AX3000T，stock layout，OpenWrt 25.12.5
> 机器清单：
> [h1-read-only-commands.json](../manifests/ax3000t-stock-openwrt-25.12.5/h1-read-only-commands.json)

## 1. 边界

本计划只补齐物理准入需要的身份、存储元数据、空间和恢复前提。它不是部署授权。

- H1.1a 的单次授权已经消费完毕，不自动延续到 H1.1b 或其他阶段；
- 不安装 package，不上传文件，不创建临时文件，不重启，不改变服务或网络；
- 不读取 MTD/UBI payload、校准、MAC、密钥或配置内容；
- 原始输出只进入仓库外的私有 evidence 目录；Git 只接收脱敏派生结论；
- SSH 本身也要单独授权。不得为了连接而启用 SSH、改密码或改 Dropbear 配置；
- 每批命令执行前重新核对命令清单的 SHA-256，执行后核对数量、退出码和设备身份。

这批观察不能证明备份可恢复，也不能授权安装、bind mount、reboot 或 canary。

## 2. 分批顺序

### H1.1a：只读身份与元数据

H1.1a 先重新确认 release、board、kernel、stock dispatcher 身份，再读取 `/proc`、`/sys`、
UBI 元数据、空间和已安装 package 数据库。命令只调用已审查的只读入口：`cat`、`ubus call
system board`、`sha256sum`、`awk`、`readlink`、`dmesg`、`grep`、`df`、`command -v`、
`ubinfo -a`。

2026-09-01 已按冻结清单完成 11/11 条命令；脱敏结果见
[H1_1A_OBSERVATIONS.md](../reports/ax3000t-stock-openwrt-25.12.5/H1_1A_OBSERVATIONS.md)。

重点裁决：

1. 当前设备仍报告 `xiaomi,mi-router-ax3000t`、`mediatek/filogic`、kernel `6.12.94`，与
   已有运行态和 exact image/source 身份一致；
2. `/proc/mtd` 与 stock DTS 的十个 label/size 一致，未出现 `ubootmod` 单 UBI 布局；
3. NAND 与 switch 的实际变体属于 25.12 支持范围；
4. NMBM、UBI attach、rootfs/overlay 和可用空间没有异常；
5. `/sbin/reload_config` 仍是
   `f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15`，且没有遗留
   candidate bind mount；
6. 目标 image 静态 inventory 显示设备没有 `nanddump`；H1-RO-08 只重新确认这一事实，不运行
   或安装工具。H1.0 已在服务器私有 evidence 中准备 matching-feed 的单一 `nanddump`，但未
   授权向设备传输。

`dmesg` 和 package DB 原文仍按私有证据处理。派生报告只能保留硬件型号、计数、版本、
partition label/size、空间数值和布尔结论。

### H1.1b：白名单 U-Boot 环境读取

H1.1b 与 H1.1a 分开授权。只有先确认 `/etc/fw_env.config`、`/proc/mtd` 和 exact source 的
offset/size 一致，才允许运行 `fw_printenv`。只读取以下变量：

```text
boot_wait
uart_en
flag_boot_rootfs
flag_last_success
flag_boot_success
flag_ota_reboot
flag_try_sys1_failed
flag_try_sys2_failed
```

这些名称来自固定 revision 的 AX3000T `bootcount` 与 `xiaomi_initial_setup`。本批明确禁止
`fw_setenv`、`nvram set/commit` 和任何 MTD write。输出只保留“存在/缺失、值是否符合源码
定义域、active branch 推断”，不保留其他 environment。

## 3. 逐批停止条件

任一条件出现即停止当前批次，不继续后续命令：

- release、revision、target、kernel、board name 或 rootfs type 不匹配；
- 出现 `xiaomi,mi-router-ax3000t-ubootmod`、单 UBI/FIT 或未知 partition label/size；
- `/sbin/reload_config` hash 不匹配，或已存在 candidate bind mount/package；
- NMBM/UBI 报错、ECC/坏块异常无法解释、overlay 只读或空间不足；
- 命令清单、命令数量、退出码、输出文件或脱敏检查不一致；
- SSH 断开、管理路径不稳定、设备意外重启或任何状态变化；
- H1.1b 中 `fw_env.config` 无法与 observed MTD 和 exact source 三方闭合。

停止后只保存已有私有输出，不尝试“顺手修复”。任何修复、重启或配置变更都要另行请求。

## 4. 输出与脱敏

一次 run 使用仓库外目录，建议：

```text
<private-evidence>/h1/<UTC-run-id>/
├── command-manifest.json
├── raw/                 # 0600；不进 Git
├── exit-status.json
├── hashes.json
└── redacted-summary.json
```

提交前必须拒绝包含以下内容的派生文件：MAC、IP、序列号、主机名、SSH host key、密码/hash、
Wi-Fi key、完整配置、Factory/Bdata/Nvram bytes、完整 U-Boot environment。即使一个值看似
公开，也不从 raw 输出复制到 Git；只提交当前 gate 所需的结构结论。

## 5. 明确不在本计划内

以下命令类别即使“只是为了验证”也不属于 H1.1：

```text
apk add/del/upgrade
mount/umount
owrt-reload-config-switch enable/disable
nanddump/dd
mtd/ubiformat/ubiupdatevol/ubidetach/ubiattach
fw_setenv 或 nvram set/commit
service/network/wifi/firewall restart/reload
firstboot/jffs2reset/factoryreset
reboot/power cycle/sysupgrade
```

H1.1 完成只意味着“可以据此重算下一道 gate”，不自动批准下一阶段。
