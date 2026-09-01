# AX3000T stock / OpenWrt 25.12.5：H1.3a recovery candidate

> 状态：`passed_offline_static_only`
> 日期：2026-09-01
> 设备操作：没有连接、重启或修改路由器
> 下一 gate：H1.3b，尚未授权

## 1. 判定

H1.3a 已完成一个只供后续 RAM boot 审核的 stock-layout initramfs candidate。它来自 exact
OpenWrt 25.12.5 buildroot/feeds，连续两次构建得到相同的 FIT SHA-256。补丁、配置、恢复
overlay、构建身份和静态审计都已纳入机器 gate。

这个结果只允许把 candidate 提交给一个**另行授权**的 H1.3b 审查。它不是运行态零写入证明，
没有证明 stock U-Boot 接受该 FIT，没有证明 UART/网络传输链可用，也没有授权任何 bootloader
命令、文件传输、路由器重启、RAM boot 或 flash 操作。

## 2. 固定输入与产物

| 项 | 值 |
|---|---|
| board / layout | `xiaomi,mi-router-ax3000t` / stock |
| release | OpenWrt `25.12.5` / `r33051-f5dae5ece4` |
| target / kernel | `mediatek/filogic` / `6.12.94` |
| buildroot | `f0a60eee2fe051741c643ea6118718aae1ef17fb` |
| patch SHA-256 | `e4e2051510864c6fdd18ff0db6b3aa792b75398d9fd1ca51e0b7bf1eeed9454e` |
| resolved config SHA-256 | `b19c3ebb08e68c86d98bce271f5d5a0f6fb5f8bf5d7b65998ac5eeb7121afe4e` |
| candidate | `openwrt-mediatek-filogic-xiaomi_mi-router-ax3000t-initramfs-kernel.bin` |
| candidate SHA-256 | `c9ce88f597dea3e552c05cdcf9ed2d3f9683161731dc12747cc7627783247a5a` |
| candidate size | 8,762,644 bytes |
| repeat build | 同一 SHA-256，exit 0 |

binary、完整 build tree、解包结果和 log 均留在服务器私有 evidence 目录，不进入 Git。Git
只保存可复核的 patch、最小 config、overlay、hash manifest 和本报告。

## 3. 为什么不能只给 `nanddump` 加只读参数

H1.2 已证明这台机型的 MTD 经过 MediaTek BMT/NMBM wrapper。发生读错误、bitflip 阈值或
bad-block 条件时，read/badblock 路径可能进入 remap，并擦除备用块、复制数据和持久化映射表。
所以 `/dev/mtdXro` 和用户态 `O_RDONLY` 都不是 flash 零写入边界。

H1.3a 将边界放在实际执行 remap/write/erase/markbad 的内核路径。还有一个容易漏掉的事实：
`mtk_bmt_attach()` 的 attach 返回值被 SPI-NAND probe 忽略；因此补丁不能只让 attach 失败，
而是在 attach 以前清除 master MTD 的 `MTD_WRITEABLE`，并在 BMT/NMBM 的每一层 mutation 路径
再次拒绝。

## 4. 强制只读设计

补丁只修改 exact tree 中五个文件：BMT header、BMT wrapper、NMBM backend、stock DTS 和
stock image recipe。开启 `mediatek,bmt-read-only` 后：

- MTD master 在 attach 前清除 `MTD_WRITEABLE`；
- BMT write、erase、markbad 返回 `-EROFS`；
- BMT read/badblock 不再触发 remap，debugfs mutation 面不创建；
- NMBM physical write、erase、markbad、map/remap 全部拒绝；
- attach 不修复 information table；签名或 table 缺失时 fail closed；
- stock DTS 的十个 partition 全标为 read-only，Wi-Fi 禁用；
- stock profile 不再生成 `initramfs-factory.ubi`，只保留 RAM-loadable initramfs kernel。

这里采用多层 guard 是因为任意一个上层调用约束都不足以替代底层拒写。它不修改正常安装的
OpenWrt 固件；这些行为只存在于专用 recovery candidate。

## 5. initramfs 自动路径审计

从最终 FIT 解出的 rootfs 还发现五条可能自动访问持久存储的启动路径。recovery overlay 用
六个同路径脚本将其显式 no-op：boot environment 更新、`mount_root done`、persistent overlay
mount 注册、`ubihealthd` 默认启用/服务、FIP read-trigger scrub。

`nanddump` 是 matching signed feed 提取的单一 binary，SHA-256 为
`21d7c3daa9e792a9b892af956ce64c59c4588c99eb7084b93ef5ee6f4bd47b92`；同包的
`flash_erase`、`nandwrite`、`nandtest`、`nandbiterrs` 均未进入 rootfs。

但基础 OpenWrt rootfs 仍包含 `mtd`、`sysupgrade` 和若干 UBI mutation 工具。没有隐瞒这些
工具，也没有把“操作时不调用它们”算作安全证明：它们即使被误调用也必须由上述内核 guard
拒绝。H1.3b 还要在运行态验证这些拒绝是否真实成立。

## 6. 静态审计结果

- FIT 的 kernel、initrd、DTB 三个节点均成功提取，节点 SHA-1 与 FIT metadata 相符；
- kernel 为 AArch64 Linux 6.12.94，load/entry 均为 `0x48000000`；
- DTB compatible 精确为 `xiaomi,mi-router-ax3000t`、`mediatek,mt7981`；
- DTB 含 `mediatek,bmt-read-only`，十个 stock partition 全部 read-only，Wi-Fi disabled；
- 编译产物包含 BMT/NMBM 两个实际 object，`vmlinux` 中存在 forced-read-only warning；
- artifact 中 `ubootmod` 字符串计数为 0，输出目录没有本机型 `.itb`/factory wrapper；
- checkpatch 为 0 errors、0 warnings；patch 可对 exact source 正向及反向校验；
- 两次完整最终构建均 exit 0 且 candidate byte-identical。

完整 hash 和 guard 集在
[h1-3a-recovery-design.json](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-3a-recovery-design.json)。

## 7. 方法纠正

本阶段保留六项纠正，不把失败尝试藏在最终成功后面：

1. 最初 profile symbol 多写了一层前缀，`defconfig` 静默选成 `DEVICE_openwrt_one`；在正式构建
   前发现并改为 exact stock symbol。
2. 仅让 BMT attach 返回错误不够，因为 exact SPI-NAND probe 忽略返回值；改为 attach 前清除
   writeable，并在 backend fail closed。
3. 中断串行诊断后留下截断的 generated dependency；使用 `target/linux/clean` 回到一致状态，
   之后才接受构建结果。
4. 上游 stock initramfs factory recipe 依赖缺失 helper，并且会产生可刷 wrapper；专用 profile
   明确移除该 artifact，只输出 RAM candidate。
5. 初次 audit 错用了不存在的 build-local `dumpimage`/`dtc` 路径；最终审计改用实际 host tool，
   并在全新目录重新完成。
6. 草拟 manifest 时把 generic BMT source 错记到 target-specific 目录；提交前用服务器
   `git diff --name-only` 和 object lookup 复核，修正为 `target/linux/generic/...` 与
   `drivers/mtd/nand/...`，并把精确路径集加入 gate。

## 8. H1.3b 的边界

H1.3b 必须重新获得用户的明确授权，并且只做有回退条件的 RAM boot 运行态验证。它至少需要：

- 物理 UART、独立有线管理与可控供电同时在场；
- bootloader 身份、RAM 地址、FIT 大小边界和命令逐字复核；
- 不使用 `.itb`、factory image、sysupgrade、TFTP OEM recovery 或任何 flash command；
- 启动后先证明 rootfs 在 RAM、persistent partitions 未挂载、Wi-Fi 未启用；
- 对 MTD/UBI mutation 接口做无害拒绝验证，并核对重启前后的 flash metadata；
- 任一身份、console、load、guard 或可达性异常立即停止，不临场改走刷写恢复。

当前 gate 固定为 `recovery_boot_verified=false`。在 H1.3b 完成以前，H1.2 私有备份也仍为
false，因为还没有运行态证明读取不会触发 NMBM mutation。

## 9. 证据

- [内核/DTS/image patch](../../patches/h1-3a/0001-mediatek-nmbm-read-only-recovery-mode.patch)
- [recovery config](../../patches/h1-3a/recovery.config)
- [H1.3a machine gate](../../tools/h1_3a_recovery_gate.py)
- [H1 runbook](../../docs/H1_RUNBOOK.md)
- [OpenWrt AX3000T device page](https://openwrt.org/toh/xiaomi/ax3000t)
- [OpenWrt AX3000T hardware data](https://openwrt.org/toh/hwdata/xiaomi/xiaomi_mi_router_ax3000t)
