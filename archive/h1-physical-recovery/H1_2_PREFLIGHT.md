# H1.2 私有备份预检：NMBM 读侧写入边界

> 状态：`blocked_before_device_contact`
> 日期：2026-09-01
> 设备接触：无
> 设备写入 / firmware flash：无 / 无
> 后续处置：用户固定无拆机边界后，本阶段为 `not_applicable_under_no_disassembly_policy`；
> raw backup 未执行，也不再作为 R05 H1.4 的前置

## 1. 判定

**H1.2 不能在当前授权下执行。** 用户已经授权进入 H1.2，但该阶段冻结的边界是“允许读取
设备专属数据，不允许写 flash”。精确 OpenWrt 25.12.5 源码证明，这台 stock-layout
AX3000T 的 MTD 读取不是无副作用的只读通道：MediaTek BMT 包装层能在读取失败或达到 ECC
bitflip 阈值时调用 `mtk_bmt_remap_block`；NMBM 后端随后分配并擦除备用块、复制旧数据并把
新映射写回信息表。

这个写入是条件触发，不代表一次健康读取必然改写 NAND；但它也不是零写入保证。因此预检
在上传工具、读取配置或 raw MTD 以前停止。此次没有连接路由器，没有上传或运行
`nanddump`，没有读取 raw payload，也没有生成可运行 collector。

## 2. 为什么用户态“只读”不足

`nanddump` 2.3.0 自身以 `O_RDONLY` 打开 MTD。原计划的
`--bb=padbad --omitoob --length=<observed-size>` 也能稳定输出逻辑长度、忽略 OOB 并保留 ECC。
问题发生在它之下：设备树启用 `mediatek,nmbm`，精确内核在 attach 时将 MTD 的
`_read_oob` 和 `_block_isbad` 换成 BMT wrapper。

| 精确路径 | 条件 | 后果 |
|---|---|---|
| `mtk_bmt.c:136-146` | 底层读取返回非 bitflip 的负错误 | remap 后最多重试 10 次 |
| `mtk_bmt.c:149-150` | corrected bitflips 达到 threshold | remap 当前逻辑块 |
| `mtk_bmt.c:263-279` | bad-block query 返回坏块 | remap 当前逻辑块 |
| `mtk_bmt_nmbm.c:2215-2233` | NMBM 执行 remap | 标坏、分配、擦除、复制、更新信息表 |

`/dev/mtdXro` 只阻止用户态 write ioctl，不会绕过被替换的读取函数。`--noecc --bb=dumpbad`
可以避免 ECC-threshold 与显式 bad-block query 两个入口，却仍不能排除负 I/O 错误触发 remap，
并且产物不再是经 ECC 修正的逻辑备份。通过 UBI 或 MTD block 层读取同样位于 wrapper 之上。

## 3. 证据固定

| 对象 | 精确身份 | 审查位置 |
|---|---|---|
| OpenWrt buildroot | `f0a60eee2fe051741c643ea6118718aae1ef17fb` | exact 25.12.5 source tree |
| AX3000T DTS | SHA-256 `d53b906e…ac6632` | lines 11–16 |
| MediaTek BMT wrapper | SHA-256 `39420c4d…0b639` | lines 106–171, 263–310, 405–465 |
| NMBM backend | SHA-256 `3643fed9…5249` | lines 1515–1540, 1941–1967, 2215–2272 |
| mtd-utils tar | SHA-256 `2db10290…98c10` | exact OpenWrt `PKG_HASH` |
| `nanddump.c` | SHA-256 `825e761d…4135` | lines 45–99, 361–575 |
| prepared `nanddump` | SHA-256 `21d7c3da…7b92`, 28,677 bytes | official signed feed extraction |
| known-good sysupgrade | SHA-256 `a94ac2c7…9eea`, 9,400,608 bytes | offline private evidence |

H1.1a 的运行态已经确认本机 NMBM attached、SPI-NAND 和 stock 十分区；因此这不是只由 DTS
推出的未部署路径。所有源码和大文件仍在服务器的 Git 外 evidence 中，仓库只保存哈希、
行号和脱敏结论。

## 4. Gate 与负向验证

`tools/h1_2_preflight_gate.py` 只在下列条件同时成立时通过：H1.1a/H1.1b 输入未变、exact
source/tool hashes 匹配、三个读侧 remap 入口和五个 flash action 完整记录、设备接触与
H1.2 backup gate 仍为 false、报告明确要求新授权。

负向实测全部被拒绝：伪造 H1.2 backup 已通过、伪造 zero-write guarantee、声称已经上传
工具、删去 bitflip trigger，以及删去 NMBM 信息表写入。固定输入另由逐文件 SHA-256 比对
保护；任一输入变化同样 fail-closed。

## 5. 可选后续路线

1. **推荐：先设计并单独批准 RAM-only 恢复/采集路径。** 使用不带自动 remap 的审核版
   initramfs/kernel 从 RAM 启动再读取 NAND；这涉及 reboot、bootloader/UART 和真实恢复能力，
   必须进入 H1.3 级别的新授权，不能由 H1.2 自动外推。
2. **接受 NMBM 条件写入风险后继续逻辑 dump。** 需要用户明确扩大授权，承认读取可能改变
   物理块映射；即使不执行 firmware flash，它也不再是“设备零写入”阶段。
3. **只备份文件系统配置。** 读取范围更小，但 overlay/UBI 最终仍经过同一 MTD wrapper，不能
   取得零写入保证；同时还缺少 BL2/Factory/Nvram/UBI 等设备专属 raw 备份。因此它也需要
   风险授权，且 H1.2 gate 仍不能通过，H1.3/H1.4 不能据此放行。

运行态 detach BMT 或触发 debugfs repair 不列为方案：它们直接改动 live kernel/NAND 映射，
风险更高且超出当前范围。

## 6. 机器记录

- [H1.2 preflight manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-2-preflight.json)
- [H1.2 preflight gate](../../tools/h1_2_preflight_gate.py)
- [H1 runbook](../../docs/H1_RUNBOOK.md)
