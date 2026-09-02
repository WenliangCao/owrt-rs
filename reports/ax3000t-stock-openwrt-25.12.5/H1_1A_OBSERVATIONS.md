# AX3000T stock / OpenWrt 25.12.5：H1.1a 只读观察报告

> 阶段状态：通过
> 执行日期：2026-09-01
> 命令结果：11/11 成功，stderr 全空
> 设备写入：无

## 1. 判定

H1.1a 通过。当前设备的新鲜运行身份与固定 image/source 完全一致；十个 MTD label/size、
NMBM、UBI volumes、SquashFS + UBIFS overlay 都符合 stock layout。原 `/sbin/reload_config`
未被替换或 bind mount，candidate 与 switch 均不存在。

本次只执行 H1-RO-00 至 H1-RO-10。没有执行 H1-RO-11 `fw_printenv`，也没有上传文件、读取
raw MTD payload、安装 package、改变 mount/service/network、重启或刷写固件。H1.1a 的单次
授权已经消费完毕。

## 2. 新鲜身份

| 字段 | 观测值 | 判定 |
|---|---|---|
| board | `xiaomi,mi-router-ax3000t` | 与 intake/image/source 一致 |
| model | Xiaomi Mi Router AX3000T | 一致 |
| release / revision | `25.12.5` / `r33051-f5dae5ece4` | 一致 |
| target / arch | `mediatek/filogic` / `aarch64_cortex-a53` | 一致 |
| kernel | `6.12.94` | 一致 |
| rootfs | `squashfs` | 一致 |
| dispatcher SHA-256 | `f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15` | 原实现未变 |

运行态 package DB 有 163 个 package；image inventory 有 159 个。差异仍然只是 I0.7 已记录的
四个 LuCI 简体中文翻译包，没有 package 被删除，也没有 image package 发生版本漂移。

## 3. 硬件与 stock 存储布局

内核实际识别到 `FORESEE SPI NAND`，容量 128 MiB，erase block 128 KiB，page 2048 bytes，
OOB 64 bytes；SPI driver 是 `spi-nand`。交换芯片 driver 是 `an8855`，内部 PHY driver 是
`Airoha AN8855 internal PHY`。

| MTD | label | size | erase / write | type |
|---|---|---:|---:|---|
| mtd0 | BL2 | 1 MiB | 128 KiB / 2048 B | NAND |
| mtd1 | Nvram | 256 KiB | 128 KiB / 2048 B | NAND |
| mtd2 | Bdata | 256 KiB | 128 KiB / 2048 B | NAND |
| mtd3 | Factory | 2 MiB | 128 KiB / 2048 B | NAND |
| mtd4 | FIP | 2 MiB | 128 KiB / 2048 B | NAND |
| mtd5 | crash | 256 KiB | 128 KiB / 2048 B | NAND |
| mtd6 | crash_log | 256 KiB | 128 KiB / 2048 B | NAND |
| mtd7 | KF | 256 KiB | 128 KiB / 2048 B | NAND |
| mtd8 | ubi_kernel | 34 MiB | 128 KiB / 2048 B | NAND |
| mtd9 | ubi | 78 MiB | 128 KiB / 2048 B | NAND |

MTD index 只作为本次运行的 label 映射，不作为物理 offset。NMBM 管理区从 block 960
（`0x07800000`）开始，内核报告 attach 成功。

`ubi0` attached 到 label `ubi`（本次为 mtd9），共有 624 LEB、0 bad PEB、19 reserved PEB，
maximum erase counter 13。`rootfs` 为 41 LEB，`rootfs_data` 为 558 LEB，两者 state 都是
`OK`。UBI 报告 0 unallocated LEB 是所有空间已经分配给 volumes，不等于 overlay 已满；实际
UBIFS 仍有 58,768 KiB 可用。

启动日志记录 UBIFS 需要 journal recovery，随后明确记录 recovery completed，再成功挂载
`rootfs_data`。因此本次把它记作“启动时恢复完成”，不是当前错误；若后续运行再次出现未完成
recovery 或新增 UBI/ECC/bad-block 错误，必须重新阻断 gate。

## 4. 容量与工具

| filesystem | total | used | available | 判定 |
|---|---:|---:|---:|---|
| `/overlay` | 62,044 KiB | 68 KiB | 58,768 KiB | 高于 8 MiB 准入阈值 |
| `/tmp` | 119,512 KiB | 472 KiB | 119,040 KiB | 足够后续独立评审 |

设备现有 `ubinfo`、`fw_printenv`、`sha256sum`、`tar` 和 `sysupgrade`；`nanddump` 不存在。
这只是工具存在性观察：本阶段没有执行后四个工具，也没有把服务器准备的 `nanddump` 传到
设备。

## 5. H1.1b 前提

`/etc/fw_env.config` 的单行布局为 `/dev/mtd1 0x0 0x10000 0x20000`。它与本次观测到的
`mtd1 = Nvram, size 0x40000, erase size 0x20000` 以及固定 OpenWrt revision 中
`package/boot/uboot-tools/uboot-envtools/files/mediatek_filogic:164-168` 三方一致。
该 source checkout 是 release buildroot commit
`f0a60eee2fe051741c643ea6118718aae1ef17fb`；文件 SHA-256 为
`bad297e3e28eb25f5cea937cdc6dd1d685511bf02fd149aaa175f216e94f3e9f`。

因此只关闭 **H1.1b 的 layout 前提**。八个 boot flag 值仍未读取，H1.1b 本身仍是 false，
且需要新的明确授权。

## 6. 执行纠正

collector 遇到问题时 fail-closed；修正均未扩大授权能力：

1. BusyBox glob `mtd[0-9]*` 同时匹配 `mtdXro` symlink；命令增加 `*ro` 跳过规则后只重读同一
   组 sysfs 元数据。
2. BusyBox 1.37 `df` 不支持 `-i`；去掉不支持的 inode 查询，保留只读 capacity 查询。
3. 缺失工具分支没有换行，导致两个 label 拼接；增加显式 `absent\n` 后只重跑 path lookup。

三项都已写入 authorization manifest，最终冻结的逐命令 SHA-256 由 H1.0 与 H1.1a gate
重新校验。

## 7. Gate 与证据边界

正向 gate 重新解析 raw 输出，而不是信任本报告中的布尔值。它验证：授权和 command-plan
hash、11 个命令 ID/顺序/退出码、空 stderr、精确身份、dispatcher hash、MTD/proc/sysfs
一致性、NMBM/UBI、空间阈值、工具集合、package drift、`fw_env.config` 和脱敏规则。

负向测试分别篡改授权为 `device_writes=true`、伪造 firmware revision、删除 H1-RO-03 输出、
伪造 exact buildroot commit；gate 四次都 fail-closed，并准确指出被破坏的约束。

提交的 manifest 不含设备地址、MAC、hostname 或 filesystem UUID。raw dmesg、package DB、
SSH 连接信息和逐命令原文保留在 Git 外私有 evidence；Git 只保存每个 stdout 的 SHA-256 和
脱敏派生值。

本地私有 run 已复制到服务器的仓库外 evidence 根目录。39 个文件的相对路径 + SHA-256
排序清单在两端得到相同 aggregate：
`10ea18169657855b055843093bf7ab2651f523d854275ad3d7805a6189d38094`。这证明当前两份证据副本
逐文件一致，不等同于 H1.2 的 raw MTD/device backup 验收。

机器记录与可复现 gate：

- [H1.1a observation manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-1a-observations.json)
- [H1.1a authorization](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-1a-authorization.json)
- [H1.1a review tool](../../archive/stage-gates/h1_1a_review.py)
- [H1 只读命令](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-read-only-commands.json)
